package kernel

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
)

// ErrLinkJSON reports iproute2 output that does not have the expected shape.
var ErrLinkJSON = errors.New("malformed iproute2 link JSON")

var safeIfname = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,14}$`)

const maxLinkJSON = 1 << 20

func checkIfname(ifname string) error {
	if !safeIfname.MatchString(ifname) {
		return fmt.Errorf("%w: invalid interface name", ErrArgument)
	}
	return nil
}

// Link runs ip link for the guest and uplink interfaces.
type Link struct{ x *Exec }

// NewLink wraps an Exec validated for the configured ip path.
func NewLink(x *Exec) *Link { return &Link{x: x} }

func (l *Link) exec() *Exec {
	if l == nil {
		return nil
	}
	return l.x
}

// SetDown sets ifname administratively down (ip link set dev IFNAME down).
func (l *Link) SetDown(ctx context.Context, ifname string) error { return l.set(ctx, ifname, "down") }

// SetUp sets ifname administratively up (ip link set dev IFNAME up).
func (l *Link) SetUp(ctx context.Context, ifname string) error { return l.set(ctx, ifname, "up") }

func (l *Link) set(ctx context.Context, ifname, state string) error {
	if err := checkIfname(ifname); err != nil {
		return err
	}
	_, err := l.exec().Run(ctx, nil, "link", "set", "dev", ifname, state)
	return err
}

// Inspect returns details for exactly ifname (ip -j -d link show dev IFNAME).
func (l *Link) Inspect(ctx context.Context, ifname string) (LinkInfo, error) {
	if err := checkIfname(ifname); err != nil {
		return LinkInfo{}, err
	}
	out, err := l.exec().Run(ctx, nil, "-j", "-d", "link", "show", "dev", ifname)
	if err != nil {
		return LinkInfo{}, err
	}
	info, err := ParseIPLinkJSON(out)
	if err != nil {
		return LinkInfo{}, err
	}
	if info.Name != ifname {
		return LinkInfo{}, fmt.Errorf("%w: asked for %q, got %q", ErrLinkJSON, ifname, info.Name)
	}
	return info, nil
}

// LinkInfo is the subset of iproute2 link details that topology attestation
// depends on.
type LinkInfo struct {
	Name      string
	Up        bool // "UP" in flags (administratively up)
	OperState string
	Master    string // bridge/bond/VRF master, if enslaved
	Kind      string // linkinfo.info_kind
	SlaveKind string // linkinfo.info_slave_kind
	XDP       bool   // an "xdp" key is present (a program is attached)
	MTU       int
}

// ParseIPLinkJSON parses ip -j -d link show output: an array holding exactly
// one object with required keys ifname and flags. Keys that attestation reads
// must have the expected JSON type when present, and duplicate keys are
// rejected, so ambiguous output fails closed instead of being interpreted.
func ParseIPLinkJSON(data []byte) (LinkInfo, error) {
	if len(data) == 0 || len(data) > maxLinkJSON {
		return LinkInfo{}, fmt.Errorf("%w: empty or larger than %d bytes", ErrLinkJSON, maxLinkJSON)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := expectDelim(dec, '['); err != nil {
		return LinkInfo{}, err
	}
	var objs []map[string]json.RawMessage
	for dec.More() {
		obj, err := decodeObject(dec)
		if err != nil {
			return LinkInfo{}, err
		}
		objs = append(objs, obj)
	}
	if err := expectDelim(dec, ']'); err != nil {
		return LinkInfo{}, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return LinkInfo{}, fmt.Errorf("%w: trailing data", ErrLinkJSON)
	}
	if len(objs) != 1 {
		return LinkInfo{}, fmt.Errorf("%w: expected exactly one link, got %d", ErrLinkJSON, len(objs))
	}
	obj := objs[0]
	var info LinkInfo
	if err := field(obj, "ifname", '"', true, &info.Name); err != nil {
		return LinkInfo{}, err
	}
	if info.Name == "" || len(info.Name) > 15 {
		return LinkInfo{}, fmt.Errorf("%w: invalid ifname", ErrLinkJSON)
	}
	var flags []string
	if err := field(obj, "flags", '[', true, &flags); err != nil {
		return LinkInfo{}, err
	}
	for _, f := range flags {
		if f == "UP" {
			info.Up = true
		}
	}
	if err := field(obj, "operstate", '"', false, &info.OperState); err != nil {
		return LinkInfo{}, err
	}
	if err := nonEmptyField(obj, "master", &info.Master); err != nil {
		return LinkInfo{}, err
	}
	if raw, ok := obj["mtu"]; ok {
		mtu, err := strconv.Atoi(string(bytes.TrimSpace(raw)))
		if err != nil || mtu < 0 {
			return LinkInfo{}, fmt.Errorf("%w: invalid mtu", ErrLinkJSON)
		}
		info.MTU = mtu
	}
	if raw, ok := obj["linkinfo"]; ok {
		li, err := decodeObject(json.NewDecoder(bytes.NewReader(raw)))
		if err != nil {
			return LinkInfo{}, err
		}
		if err := nonEmptyField(li, "info_kind", &info.Kind); err != nil {
			return LinkInfo{}, err
		}
		if err := nonEmptyField(li, "info_slave_kind", &info.SlaveKind); err != nil {
			return LinkInfo{}, err
		}
	}
	_, info.XDP = obj["xdp"]
	return info, nil
}

func expectDelim(dec *json.Decoder, d json.Delim) error {
	tok, err := dec.Token()
	if err != nil || tok != d {
		return fmt.Errorf("%w: expected %q", ErrLinkJSON, d)
	}
	return nil
}

// decodeObject reads one JSON object, keeping values raw and rejecting
// duplicate keys.
func decodeObject(dec *json.Decoder) (map[string]json.RawMessage, error) {
	if err := expectDelim(dec, '{'); err != nil {
		return nil, err
	}
	obj := map[string]json.RawMessage{}
	for dec.More() {
		tok, err := dec.Token()
		key, ok := tok.(string)
		if err != nil || !ok {
			return nil, fmt.Errorf("%w: invalid object key", ErrLinkJSON)
		}
		if _, dup := obj[key]; dup {
			return nil, fmt.Errorf("%w: duplicate key %q", ErrLinkJSON, key)
		}
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrLinkJSON, err)
		}
		obj[key] = raw
	}
	if err := expectDelim(dec, '}'); err != nil {
		return nil, err
	}
	return obj, nil
}

// field decodes obj[key] into v, requiring the raw value to start with kind
// ('"' string, '[' array) so that null or mistyped values are errors.
func field(obj map[string]json.RawMessage, key string, kind byte, required bool, v any) error {
	raw, ok := obj[key]
	if !ok {
		if required {
			return fmt.Errorf("%w: missing %q", ErrLinkJSON, key)
		}
		return nil
	}
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || raw[0] != kind || json.Unmarshal(raw, v) != nil {
		return fmt.Errorf("%w: %q has the wrong type", ErrLinkJSON, key)
	}
	return nil
}

// nonEmptyField decodes an optional string that must not be empty when
// present: an empty master would be indistinguishable from "not enslaved".
func nonEmptyField(obj map[string]json.RawMessage, key string, v *string) error {
	if err := field(obj, key, '"', false, v); err != nil {
		return err
	}
	if _, ok := obj[key]; ok && *v == "" {
		return fmt.Errorf("%w: %q is empty", ErrLinkJSON, key)
	}
	return nil
}
