package kernel

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

const invocation = "@@invocation"

// fakeBin is a #!/bin/sh stand-in for nft/ip/conntrack. It appends its
// arguments to argv (one per line, invocations separated by a marker) and
// records its exact execve environment, working directory and stdin.
type fakeBin struct {
	dir, path string
}

func newFake(t *testing.T, name, body string) *fakeBin {
	t.Helper()
	dir := t.TempDir()
	if strings.ContainsAny(dir, "'\\\n") {
		t.Skipf("temp dir %q unsuitable for shell quoting", dir)
	}
	f := &fakeBin{dir: dir, path: filepath.Join(dir, name)}
	script := "#!/bin/sh\n" +
		"printf '%s\\n' '" + invocation + "' \"$@\" >> '" + f.file("argv") + "'\n" +
		"tr '\\000' '\\n' < /proc/$$/environ > '" + f.file("env") + "'\n" +
		"pwd > '" + f.file("cwd") + "'\n" +
		"cat > '" + f.file("stdin") + "'\n" +
		body + "\n"
	if err := os.WriteFile(f.path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *fakeBin) file(name string) string { return filepath.Join(f.dir, name) }

func (f *fakeBin) read(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(f.file(name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func (f *fakeBin) invocations(t *testing.T) [][]string {
	t.Helper()
	b, err := os.ReadFile(f.file("argv"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	var out [][]string
	for _, line := range strings.Split(strings.TrimSuffix(string(b), "\n"), "\n") {
		if line == invocation {
			out = append(out, []string{})
			continue
		}
		out[len(out)-1] = append(out[len(out)-1], line)
	}
	return out
}

func (f *fakeBin) exec(t *testing.T, timeout time.Duration) *Exec {
	t.Helper()
	x, err := NewExec(f.path, timeout, InsecureAllowNonRootForTests())
	if err != nil {
		t.Fatal(err)
	}
	return x
}

func TestRunArgvEnvStdinAndDir(t *testing.T) {
	t.Setenv("PORTCULLIS_LEAK", "must-not-reach-child")
	f := newFake(t, "nft", "printf 'listing'")
	n := NewNFT(f.exec(t, 5*time.Second))
	batch := "add element inet portcullis_guard granted_v4 { 10.203.0.100 . 02:00:00:00:00:0a timeout 300s }\n"
	if err := n.Apply(context.Background(), batch); err != nil {
		t.Fatal(err)
	}
	if got := f.read(t, "stdin"); got != batch {
		t.Fatalf("stdin = %q", got)
	}
	if got, want := f.read(t, "env"), "LC_ALL=C\nPATH=/usr/sbin:/usr/bin:/sbin:/bin\n"; got != want {
		t.Fatalf("child environment = %q, want %q", got, want)
	}
	if got := f.read(t, "cwd"); got != "/\n" {
		t.Fatalf("cwd = %q", got)
	}
	if err := n.Check(context.Background(), batch); err != nil {
		t.Fatal(err)
	}
	out, err := n.ListGuard(context.Background())
	if err != nil || string(out) != "listing" {
		t.Fatalf("ListGuard = %q, %v", out, err)
	}
	if _, err := n.ListRuleset(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := [][]string{
		{"-f", "-"},
		{"-c", "-f", "-"},
		{"-j", "list", "table", "inet", "portcullis_guard"},
		{"-j", "list", "ruleset"},
	}
	if got := f.invocations(t); !reflect.DeepEqual(got, want) {
		t.Fatalf("argv = %q, want %q", got, want)
	}
	cmd := f.exec(t, 5*time.Second).command(context.Background(), nil, []string{"-j"}, &boundedBuffer{}, &boundedBuffer{})
	if cmd.Args[0] != "nft" || cmd.Path != f.path || !cmd.SysProcAttr.Setpgid {
		t.Fatalf("command: path %q argv0 %q", cmd.Path, cmd.Args[0])
	}
}

func TestRunRejectsBadInputWithoutStarting(t *testing.T) {
	f := newFake(t, "nft", "")
	x := f.exec(t, 5*time.Second)
	n := NewNFT(x)
	for name, batch := range map[string]string{
		"empty": "", "nul": "flush set inet t s\x00", "cr": "a\rb", "oversized": strings.Repeat("a", maxBatch+1),
	} {
		if err := n.Apply(context.Background(), batch); !errors.Is(err, ErrArgument) {
			t.Errorf("%s batch: %v", name, err)
		}
	}
	for _, args := range [][]string{{""}, {"a\x00"}, {"a\nb"}, {"\x1b[31m"}, {strings.Repeat("a", maxArgBytes+1)}} {
		if _, err := x.Run(context.Background(), nil, args...); !errors.Is(err, ErrArgument) {
			t.Errorf("args %q: %v", args, err)
		}
	}
	if _, err := x.Run(context.Background(), make([]byte, maxStdin+1)); !errors.Is(err, ErrArgument) {
		t.Errorf("oversized stdin: %v", err)
	}
	for _, name := range []string{"", "-guest", ".x", "a b", "g;reboot", "a/b", "0123456789abcdef"} {
		if err := NewLink(x).SetDown(context.Background(), name); !errors.Is(err, ErrArgument) {
			t.Errorf("ifname %q: %v", name, err)
		}
	}
	if got := f.invocations(t); got != nil {
		t.Fatalf("fake ran despite invalid input: %q", got)
	}
}

func TestRunTimeoutKillsProcessGroup(t *testing.T) {
	// The shell forks sleep, so killing only the shell would leave the pipe
	// open; the group kill plus WaitDelay must return promptly.
	f := newFake(t, "nft", "sleep 30")
	x := f.exec(t, time.Second)
	start := time.Now()
	_, err := x.Run(context.Background(), nil)
	if !errors.Is(err, ErrCommand) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected timeout error, got %v", err)
	}
	if elapsed := time.Since(start); elapsed > 4*time.Second {
		t.Fatalf("timeout took %v", elapsed)
	}
}

func TestRunOutputBoundsAndStderrExcerpt(t *testing.T) {
	big := newFake(t, "nft", "head -c 9000000 /dev/zero")
	if _, err := big.exec(t, 10*time.Second).Run(context.Background(), nil); !errors.Is(err, ErrCommand) || !strings.Contains(err.Error(), "stdout exceeded") {
		t.Fatalf("oversized stdout: %v", err)
	}
	loud := newFake(t, "nft", "head -c 70000 /dev/zero >&2")
	if _, err := loud.exec(t, 10*time.Second).Run(context.Background(), nil); !errors.Is(err, ErrCommand) || !strings.Contains(err.Error(), "stderr exceeded") {
		t.Fatalf("oversized stderr with exit 0: %v", err)
	}
	noisy := newFake(t, "nft", "head -c 3000 /dev/zero | tr '\\000' 'A' >&2; printf '\\033[31m\\nforged log line\\n' >&2; exit 3")
	_, err := noisy.exec(t, 10*time.Second).Run(context.Background(), nil, "-f", "-")
	if !errors.Is(err, ErrCommand) || !strings.Contains(err.Error(), "exit status 3") {
		t.Fatalf("expected exit status error, got %v", err)
	}
	_, ex, _ := strings.Cut(err.Error(), "stderr: ")
	if len(ex) > maxExcerpt || strings.ContainsAny(ex, "\n\x1b") {
		t.Fatalf("stderr excerpt not bounded/sanitized (%d bytes): %q", len(ex), ex)
	}
}

func TestListGuardTableAbsent(t *testing.T) {
	cases := []struct {
		body   string
		absent bool
	}{
		{"printf 'Error: No such file or directory\\nlist table inet portcullis_guard\\n                ^^^^^^^^^^^^^^^^\\n' >&2; exit 1", true},
		{"printf \"Error: No such file or directory; did you mean table 'x' in family inet?\\n\" >&2; exit 1", true},
		{"printf 'Error: Operation not permitted\\n' >&2; exit 1", false},
		{"printf 'netlink: Error: cache initialization failed: No such file or directory\\n' >&2; exit 1", false},
		{"printf 'Error: No such file or directory\\n' >&2; exit 2", false},
		{"exit 0", false}, // empty listing is an error, never absence
	}
	for _, tc := range cases {
		f := newFake(t, "nft", tc.body)
		_, err := NewNFT(f.exec(t, 5*time.Second)).ListGuard(context.Background())
		if err == nil || errors.Is(err, ErrTableAbsent) != tc.absent || !errors.Is(err, ErrCommand) {
			t.Errorf("%q: absent=%v err=%v", tc.body, tc.absent, err)
		}
	}
}

func TestConntrackFlushAddr(t *testing.T) {
	const zero = "printf 'conntrack v1.4.8 (conntrack-tools): 0 flow entries have been deleted.\\n' >&2; exit 1"
	cases := []struct {
		name, body string
		ok         bool
	}{
		{"nothing to delete", zero, true},
		{"deleted entries", "printf 'conntrack v1.4.8 (conntrack-tools): 2 flow entries have been deleted.\\n' >&2", true},
		{"other exit 1", "printf 'conntrack v1.4.8 (conntrack-tools): Operation failed: Operation not permitted\\n' >&2; exit 1", false},
		{"zero message plus error", "printf 'conntrack v1.4.8 (conntrack-tools): 0 flow entries have been deleted.\\nOperation failed\\n' >&2; exit 1", false},
		{"zero message exit 2", "printf 'conntrack v1.4.8 (conntrack-tools): 0 flow entries have been deleted.\\n' >&2; exit 2", false},
		{"only source fails", `if [ "$4" = -s ]; then exit 1; fi; ` + zero, false},
	}
	for _, tc := range cases {
		f := newFake(t, "conntrack", tc.body)
		err := NewConntrack(f.exec(t, 5*time.Second)).FlushAddr(context.Background(), netip.MustParseAddr("10.203.0.100"))
		if (err == nil) != tc.ok {
			t.Errorf("%s: err=%v", tc.name, err)
		}
		want := [][]string{{"-D", "-f", "ipv4", "-s", "10.203.0.100"}, {"-D", "-f", "ipv4", "-d", "10.203.0.100"}}
		if got := f.invocations(t); !reflect.DeepEqual(got, want) {
			t.Errorf("%s: both directions must always be attempted: %q", tc.name, got)
		}
	}
	f := newFake(t, "conntrack", "")
	c := NewConntrack(f.exec(t, 5*time.Second))
	for _, a := range []netip.Addr{{}, netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("::ffff:10.0.0.1"), netip.MustParseAddr("0.0.0.0")} {
		if err := c.FlushAddr(context.Background(), a); !errors.Is(err, ErrArgument) {
			t.Errorf("%v: %v", a, err)
		}
	}
	if f.invocations(t) != nil {
		t.Fatal("conntrack ran for an invalid address")
	}
}

func TestLinkCommands(t *testing.T) {
	fixture, err := filepath.Abs("testdata/ip_link_veth.json")
	if err != nil {
		t.Fatal(err)
	}
	f := newFake(t, "ip", `if [ "$1" = -j ]; then cat '`+fixture+`'; fi`)
	l := NewLink(f.exec(t, 5*time.Second))
	if err := l.SetDown(context.Background(), "guest0"); err != nil {
		t.Fatal(err)
	}
	if err := l.SetUp(context.Background(), "guest0"); err != nil {
		t.Fatal(err)
	}
	info, err := l.Inspect(context.Background(), "guest0")
	if err != nil || info.Name != "guest0" {
		t.Fatalf("Inspect = %+v, %v", info, err)
	}
	if _, err := l.Inspect(context.Background(), "uplink0"); !errors.Is(err, ErrLinkJSON) {
		t.Fatalf("name mismatch accepted: %v", err)
	}
	want := [][]string{
		{"link", "set", "dev", "guest0", "down"},
		{"link", "set", "dev", "guest0", "up"},
		{"-j", "-d", "link", "show", "dev", "guest0"},
		{"-j", "-d", "link", "show", "dev", "uplink0"},
	}
	if got := f.invocations(t); !reflect.DeepEqual(got, want) {
		t.Fatalf("argv = %q", got)
	}
}

func TestNewExecValidation(t *testing.T) {
	dir := t.TempDir()
	mk := func(name string, mode os.FileMode) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("#!/bin/sh\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
		return p
	}
	good := mk("good", 0o755)
	worldWritable := mk("ww", 0o777)
	link := filepath.Join(dir, "link")
	if err := os.Symlink(worldWritable, link); err != nil {
		t.Fatal(err)
	}
	opt := InsecureAllowNonRootForTests()
	if _, err := NewExec(good, time.Second, opt); err != nil {
		t.Fatalf("good fake rejected: %v", err)
	}
	for name, path := range map[string]string{
		"relative": "nft", "dot relative": "./nft", "unclean": dir + "/../" + filepath.Base(dir) + "/good",
		"group writable": mk("gw", 0o775), "not executable": mk("noexec", 0o644),
		"symlink to world-writable": link, "directory": dir, "missing": filepath.Join(dir, "missing"),
	} {
		if _, err := NewExec(path, time.Second, opt); !errors.Is(err, ErrUnsafeBinary) {
			t.Errorf("%s: %v", name, err)
		}
	}
	for _, d := range []time.Duration{0, 999 * time.Millisecond, 31 * time.Second} {
		if _, err := NewExec(good, d, opt); !errors.Is(err, ErrArgument) {
			t.Errorf("timeout %v accepted: %v", d, err)
		}
	}
	// Without the test option a file owned by this (non-root) user, in a
	// directory under world-writable /tmp, must be refused.
	if os.Geteuid() != 0 {
		if _, err := NewExec(good, time.Second); !errors.Is(err, ErrUnsafeBinary) {
			t.Fatalf("non-root-owned executable accepted: %v", err)
		}
	}
}

func TestParseIPLinkJSON(t *testing.T) {
	read := func(name string) []byte {
		b, err := os.ReadFile(filepath.Join("testdata", name))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	cases := map[string]LinkInfo{
		"ip_link_veth.json":        {Name: "guest0", Up: true, OperState: "UP", Kind: "veth", MTU: 1500},
		"ip_link_bridge_port.json": {Name: "guest0", Up: true, OperState: "UP", Master: "br0", Kind: "veth", SlaveKind: "bridge", MTU: 1500},
		"ip_link_xdp.json":         {Name: "guest0", Up: true, OperState: "UP", Kind: "veth", XDP: true, MTU: 1500},
	}
	for name, want := range cases {
		got, err := ParseIPLinkJSON(read(name))
		if err != nil || got != want {
			t.Errorf("%s: got %+v, %v; want %+v", name, got, err, want)
		}
	}
	down, err := ParseIPLinkJSON([]byte(`[{"ifname":"guest0","flags":["BROADCAST","MULTICAST","LOWER_UP"],"operstate":"DOWN"}]`))
	if err != nil || down.Up {
		t.Fatalf("admin-down link: %+v, %v", down, err)
	}
	for _, bad := range []string{
		``, `[]`, `{}`, `null`, `[null]`,
		`[{"ifname":"a","flags":[]},{"ifname":"b","flags":[]}]`,
		`[{"flags":["UP"]}]`, `[{"ifname":"guest0"}]`,
		`[{"ifname":5,"flags":[]}]`, `[{"ifname":"","flags":[]}]`, `[{"ifname":"guest0","flags":"UP"}]`,
		`[{"ifname":"guest0","flags":[1]}]`, `[{"ifname":"guest0","flags":[],"master":7}]`,
		`[{"ifname":"guest0","flags":[],"master":""}]`, `[{"ifname":"guest0","flags":[],"master":null}]`,
		`[{"ifname":"guest0","flags":[],"master":"br0","master":"x"}]`,
		`[{"ifname":"guest0","flags":[],"linkinfo":[]}]`, `[{"ifname":"guest0","flags":[],"linkinfo":{"info_slave_kind":1}}]`,
		`[{"ifname":"guest0","flags":[],"mtu":1.5}]`, `[{"ifname":"guest0","flags":[],"mtu":-1}]`,
		`[{"ifname":"guest0","flags":[]}] x`, `[{"ifname":"guest0","flags":[]}][]`,
		`[{"ifname":"guest0","flags":[]` + strings.Repeat(" ", maxLinkJSON) + `}]`,
	} {
		if _, err := ParseIPLinkJSON([]byte(bad)); !errors.Is(err, ErrLinkJSON) {
			t.Errorf("accepted %.80q: %v", bad, err)
		}
	}
}

func TestTopology(t *testing.T) {
	proc := func(t *testing.T, ipv6 *string) string {
		root := t.TempDir()
		if err := os.MkdirAll(filepath.Join(root, "sys/net/ipv4/conf/guest0"), 0o755); err != nil {
			t.Fatal(err)
		}
		if ipv6 != nil {
			d := filepath.Join(root, "sys/net/ipv6/conf/guest0")
			if err := os.MkdirAll(d, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(d, "disable_ipv6"), []byte(*ipv6), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		return root
	}
	str := func(s string) *string { return &s }
	for _, tc := range []struct {
		value    *string
		disabled bool
		ok       bool
	}{
		{str("1\n"), true, true}, {str("0\n"), false, true}, {nil, true, true},
		{str("2\n"), false, false}, {str(""), false, false}, {str("1 1\n"), false, false}, {str("01\n"), false, false},
	} {
		got, err := Topology{ProcRoot: proc(t, tc.value)}.IPv6Disabled("guest0")
		if (err == nil) != tc.ok || got != tc.disabled {
			t.Errorf("value %v: got %v, %v", tc.value, got, err)
		}
	}
	root := proc(t, str("1\n"))
	for _, name := range []string{"uplink0", "all", "default", "../guest0", ""} {
		if got, err := (Topology{ProcRoot: root}).IPv6Disabled(name); err == nil || got {
			t.Errorf("%q: got %v, %v", name, got, err)
		}
	}
	// No /proc tree at all must not read as "no IPv6 stack".
	if got, err := (Topology{ProcRoot: t.TempDir()}).IPv6Disabled("guest0"); err == nil || got {
		t.Errorf("empty proc root: %v, %v", got, err)
	}
	if _, err := (Topology{ProcRoot: "proc"}).IPv6Disabled("guest0"); !errors.Is(err, ErrArgument) {
		t.Errorf("relative proc root: %v", err)
	}

	guest := LinkInfo{Name: "guest0", Kind: "veth"}
	uplink := LinkInfo{Name: "uplink0", Kind: "veth"}
	if err := CheckGuestLink(guest, uplink, true); err != nil {
		t.Fatal(err)
	}
	mut := func(f func(g, u *LinkInfo)) (LinkInfo, LinkInfo) { g, u := guest, uplink; f(&g, &u); return g, u }
	for name, f := range map[string]func(g, u *LinkInfo){
		"master":       func(g, u *LinkInfo) { g.Master = "br0" },
		"slave kind":   func(g, u *LinkInfo) { g.SlaveKind = "bond" },
		"bridge":       func(g, u *LinkInfo) { g.Kind = "bridge" },
		"bond":         func(g, u *LinkInfo) { g.Kind = "bond" },
		"team":         func(g, u *LinkInfo) { g.Kind = "team" },
		"guest xdp":    func(g, u *LinkInfo) { g.XDP = true },
		"uplink xdp":   func(g, u *LinkInfo) { u.XDP = true },
		"same":         func(g, u *LinkInfo) { u.Name = g.Name },
		"missing name": func(g, u *LinkInfo) { g.Name = "" },
	} {
		g, u := mut(f)
		if err := CheckGuestLink(g, u, true); !errors.Is(err, ErrTopology) {
			t.Errorf("%s accepted: %v", name, err)
		}
	}
	if err := CheckGuestLink(guest, uplink, false); !errors.Is(err, ErrTopology) {
		t.Error("IPv6-enabled guest accepted")
	}
}
