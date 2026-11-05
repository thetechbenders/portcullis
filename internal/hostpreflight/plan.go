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
	"syscall"
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
	// Open first, nonblocking and without following the final symlink, then
	// inspect the opened descriptor. This closes the Lstat/Open FIFO-swap race.
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return Selection{}, err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return Selection{}, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return Selection{}, errors.New("host plan must be a private regular file (mode 0600 or stricter; symlinks and FIFOs refused)")
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); !ok || (stat.Uid != uint32(os.Geteuid()) && stat.Uid != 0) {
		return Selection{}, errors.New("host plan must be owned by the invoking user or root")
	}
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
	return ValidateSelection(p.Selection)
}

// ValidateSelection is shared by plan and individual CLI flags.
func ValidateSelection(sel Selection) (Selection, error) {
	for _, name := range []string{sel.Guest, sel.Uplink, sel.Management} {
		if !interfaceName.MatchString(name) || name == "lo" || name == "all" || name == "default" {
			return Selection{}, fmt.Errorf("invalid or missing interface name %q", name)
		}
	}
	if sel.Guest == sel.Uplink || sel.Guest == sel.Management || sel.Uplink == sel.Management {
		return Selection{}, errors.New("host interface roles must differ")
	}
	pins := []struct {
		role string
		mac  *string
		path string
	}{
		{"guest", &sel.PinnedGuestMAC, sel.PinnedGuestSysfs},
		{"uplink", &sel.PinnedUplinkMAC, sel.PinnedUplinkSysfs},
		{"management", &sel.PinnedManagementMAC, sel.PinnedManagementSysfs},
	}
	seenMAC := map[string]bool{}
	seenPath := map[string]bool{}
	for _, pin := range pins {
		mac, err := net.ParseMAC(*pin.mac)
		if err != nil || len(mac) != 6 || mac[0]&1 != 0 || bytes.Equal(mac, make([]byte, 6)) {
			return Selection{}, fmt.Errorf("host plan requires a six-byte unicast %s MAC pin", pin.role)
		}
		*pin.mac = mac.String()
		if seenMAC[*pin.mac] { return Selection{}, errors.New("host plan assigns one MAC to multiple roles") }
		seenMAC[*pin.mac] = true
		if !strings.HasPrefix(pin.path, "/sys/devices/") ||
			strings.HasPrefix(pin.path, "/sys/devices/virtual/") ||
			strings.Contains(pin.path, "/net/") ||
			filepath.Clean(pin.path) != pin.path ||
			strings.ContainsAny(pin.path, "\x00\n\r") {
			return Selection{}, fmt.Errorf("host plan requires a canonical physical %s sysfs parent path", pin.role)
		}
		if seenPath[pin.path] { return Selection{}, errors.New("host plan assigns one physical device path to multiple roles") }
		seenPath[pin.path] = true
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
				// All schema keys are lowercase ASCII. Reject alternate casing
				// before encoding/json can case-fold into another field.
				if key != strings.ToLower(key) || !validHostPlanKey(key) {
					return fmt.Errorf("unknown or non-canonical host plan key %q", key)
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

// Only the exact documented key spellings are accepted. Unknown keys
// fail even if encoding/json would otherwise match them case-insensitively.
func validHostPlanKey(key string) bool {
	switch key {
	case "schema_version", "selection", "guest", "uplink", "management", "pinned_guest_mac", "pinned_guest_sysfs", "pinned_uplink_mac", "pinned_uplink_sysfs", "pinned_management_mac", "pinned_management_sysfs":
		return true
	default:
		return false
	}
}
