package hostpreflight

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const maxPlanBytes = 8192

var interfaceName = regexp.MustCompile("^[A-Za-z0-9_][A-Za-z0-9_.-]{0,14}$")

// Plan is a versioned, operator-authored set of expected identities. Parsing
// plans never installs networking configuration or grants authorization.
type Plan struct {
	SchemaVersion int       `json:"schema_version"`
	Selection     Selection `json:"selection"`
}

// LoadPlan reads a small local manifest without following it with any side
// effect. The caller is responsible for keeping manifests private.
func LoadPlan(path string) (Selection, error) {
	f, err := os.Open(path)
	if err != nil {
		return Selection{}, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxPlanBytes+1))
	if err != nil {
		return Selection{}, err
	}
	return ParsePlan(data)
}

// ParsePlan rejects unknown keys, trailing data, missing pins and nonphysical
// interface identities. Even a valid plan cannot authorize deployment.
func ParsePlan(data []byte) (Selection, error) {
	if len(data) == 0 || len(data) > maxPlanBytes {
		return Selection{}, errors.New("host plan is missing or exceeds 8192 bytes")
	}
	if err := rejectDuplicateJSONKeys(data); err != nil {
		return Selection{}, fmt.Errorf("invalid host plan: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var p Plan
	if err := dec.Decode(&p); err != nil {
		return Selection{}, fmt.Errorf("invalid host plan: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return Selection{}, errors.New("host plan contains trailing data")
	}
	if p.SchemaVersion != SchemaVersion {
		return Selection{}, fmt.Errorf("unsupported host plan schema %d", p.SchemaVersion)
	}
	sel := p.Selection
	for _, name := range []string{sel.Guest, sel.Uplink, sel.Management} {
		if !interfaceName.MatchString(name) {
			return Selection{}, fmt.Errorf("invalid or missing interface name %q", name)
		}
	}
	if sel.Guest == sel.Uplink || sel.Guest == sel.Management || sel.Uplink == sel.Management {
		return Selection{}, errors.New("host interface roles must differ")
	}
	mac, err := net.ParseMAC(sel.PinnedGuestMAC)
	if err != nil || len(mac) != 6 || mac[0]&1 != 0 {
		return Selection{}, errors.New("host plan requires a six-byte unicast guest MAC pin")
	}
	if !strings.HasPrefix(sel.PinnedGuestSysfs, "/sys/devices/") ||
		filepath.Clean(sel.PinnedGuestSysfs) != sel.PinnedGuestSysfs ||
		strings.ContainsAny(sel.PinnedGuestSysfs, "\x00\n\r") {
		return Selection{}, errors.New("host plan requires a canonical sysfs device path under /sys/devices")
	}
	return sel, nil
}


// rejectDuplicateJSONKeys traverses the bounded manifest using JSON tokens,
// including nested objects. encoding/json otherwise silently keeps the last
// value of a repeated key, which makes operator plans ambiguous.
func rejectDuplicateJSONKeys(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	var walk func() error
	walk = func() error {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		delim, ok := tok.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]struct{}{}
			for dec.More() {
				keyToken, err := dec.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return errors.New("expected JSON object key")
				}
				if _, exists := seen[key]; exists {
					return fmt.Errorf("duplicate JSON key %q", key)
				}
				seen[key] = struct{}{}
				if err := walk(); err != nil {
					return err
				}
			}
			_, err := dec.Token()
			return err
		case '[':
			for dec.More() {
				if err := walk(); err != nil {
					return err
				}
			}
			_, err := dec.Token()
			return err
		default:
			return errors.New("unexpected JSON delimiter")
		}
	}
	if err := walk(); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("trailing JSON content")
	}
	return nil
}
