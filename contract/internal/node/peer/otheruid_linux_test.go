//go:build linux

package peer

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/daemon"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/install"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/ipc"
)

// The other-uid attack needs root to launch two real accounts, so it runs only
// in a disposable runner that passes this flag. Ordinary suites skip it.
var otherUIDAttack = flag.Bool("other-uid-attack", false, "run the two-account socket attack (root in a disposable Linux runner, owner uid 1000, attacker uid 1001)")

const (
	otherUIDOwner    = 1000
	otherUIDAttacker = 1001
	otherUIDMarker   = "other-uid-helper"
	otherUIDPrefix   = "OTHERUID> "
)

type otherUIDAttempt struct {
	Name    string `json:"name"`
	Reached bool   `json:"reached,omitempty"`
	Refused bool   `json:"refused"`
	Detail  string `json:"detail"`
}

// TestOtherUIDSocketAttack launches the owner daemon as uid 1000 and drives
// attacks from uid 1001. Every attack must be refused and the owner daemon must
// stay healthy. It also proves same-uid processes other than the installed
// image are refused at the peer authority check.
func TestOtherUIDSocketAttack(t *testing.T) {
	if !*otherUIDAttack {
		t.Skip("requires -other-uid-attack in a disposable two-account Linux runner")
	}
	if os.Geteuid() != 0 {
		t.Skip("launcher must be root to start the owner and attacker accounts")
	}
	owner := otherUIDAccount(t, otherUIDOwner)
	attacker := otherUIDAccount(t, otherUIDAttacker)
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ownerProc := startOtherUIDHelper(t, self, owner, "owner")
	ready := ownerProc.next(t)
	t.Logf("owner ready %v", ready)
	if ready["euid"] != float64(otherUIDOwner) {
		t.Fatalf("owner euid %v", ready["euid"])
	}
	paths, _ := json.Marshal(ready)

	// Phase 1: default owner-only layout.
	result := runOtherUIDAttacker(t, self, attacker, "attack-default", string(paths))
	requireRefused(t, "default layout", result, false)

	// Phase 2: the owner deliberately widens the socket and run-dir modes so the
	// attacker reaches the socket. The kernel peer check must still refuse.
	if r := ownerProc.send(t, "loosen"); r["error"] != nil {
		t.Fatalf("loosen %v", r["error"])
	}
	result = runOtherUIDAttacker(t, self, attacker, "attack-loosened", string(paths))
	requireRefused(t, "loosened modes", result, true)
	if r := ownerProc.send(t, "restore"); r["error"] != nil {
		t.Fatalf("restore %v", r["error"])
	}

	// Owner health, nudge delivery, and same-uid peer authority.
	check := ownerProc.send(t, "check")
	t.Logf("owner check %v", check)
	requireCheck(t, check)

	// Phase 3: the attacker pre-creates the long-path fallback run directory,
	// first as a directory and then as a symlink, with a listening squatter.
	plan := ownerProc.send(t, "fallback-plan")
	run, _ := plan["run"].(string)
	if !strings.HasPrefix(run, fmt.Sprintf("/tmp/telara-memory-%d/", otherUIDOwner)) {
		t.Fatalf("fallback run %q", run)
	}
	for _, mode := range []string{"squat-dir", "squat-link"} {
		squat := startOtherUIDHelper(t, self, attacker, mode, run)
		armed := squat.next(t)
		if armed["error"] != nil {
			t.Fatalf("%s %v", mode, armed["error"])
		}
		refused := ownerProc.send(t, "fallback-run")
		t.Logf("%s owner %v", mode, refused)
		for _, key := range []string{"run_error", "dial_error", "probe_error"} {
			if s, _ := refused[key].(string); s == "" {
				t.Errorf("%s: owner %s accepted attacker run dir", mode, key)
			}
		}
		if refused["ready"] == true {
			t.Errorf("%s: owner daemon started in attacker run dir", mode)
		}
		report := squat.send(t, "report")
		t.Logf("%s squatter %v", mode, report)
		if report["accepted"] != float64(0) {
			t.Errorf("%s: squatter accepted %v owner connections", mode, report["accepted"])
		}
		if entries, _ := report["entries"].([]any); len(entries) != 1 {
			t.Errorf("%s: owner wrote into attacker dir %v", mode, report["entries"])
		}
		squat.wait(t)
	}
	// Positive control: without a squatter the same fallback path starts.
	control := ownerProc.send(t, "fallback-run")
	t.Logf("fallback control %v", control)
	if control["ready"] != true {
		t.Errorf("fallback path refused without an attacker %v", control)
	}

	final := ownerProc.send(t, "check")
	t.Logf("owner final %v", final)
	requireCheck(t, final)
	if r := ownerProc.send(t, "exit"); r["run_error"] != "context canceled" {
		t.Errorf("owner daemon exit %v", r)
	}
	ownerProc.wait(t)
}

func requireRefused(t *testing.T, phase string, r map[string]any, reach bool) {
	t.Helper()
	if r["euid"] != float64(otherUIDAttacker) {
		t.Fatalf("%s: attacker euid %v", phase, r["euid"])
	}
	raw, _ := json.Marshal(r["attempts"])
	var attempts []otherUIDAttempt
	if json.Unmarshal(raw, &attempts) != nil || len(attempts) == 0 {
		t.Fatalf("%s: no attempts %v", phase, r)
	}
	for _, a := range attempts {
		t.Logf("%s: %-40s reached=%v refused=%v %s", phase, a.Name, a.Reached, a.Refused, a.Detail)
		if !a.Refused {
			t.Errorf("%s: %s was not refused: %s", phase, a.Name, a.Detail)
		}
		if reach && strings.HasPrefix(a.Name, "frame ") && !a.Reached {
			t.Errorf("%s: %s never reached the kernel peer check: %s", phase, a.Name, a.Detail)
		}
	}
}

func requireCheck(t *testing.T, c map[string]any) {
	t.Helper()
	if s, _ := c["probe_error"].(string); s != "" {
		t.Errorf("owner probe failed: %s", s)
	}
	if c["probe_pid_match"] != true {
		t.Error("owner probe pid mismatch")
	}
	if c["owner_nudge"] != true {
		t.Error("owner nudge not delivered")
	}
	if c["foreign_nudges"] != float64(0) || c["foreign_handles"] != float64(0) {
		t.Errorf("attacker frames reached the backend: nudges=%v handles=%v", c["foreign_nudges"], c["foreign_handles"])
	}
	if s, _ := c["installed_peer"].(string); s != "authorized" {
		t.Errorf("installed image refused: %v", c["installed_peer"])
	}
	if s, _ := c["unverified_peer"].(string); s != ErrAuthority.Error() {
		t.Errorf("same-uid unverified image was not refused at the peer check: %v", c["unverified_peer"])
	}
	if s, _ := c["spoofed_hello"].(string); s != "invalid_hello" {
		t.Errorf("same-uid hello claiming the installed pid was not refused: %v", c["spoofed_hello"])
	}
}

func otherUIDAccount(t *testing.T, uid int) *user.User {
	t.Helper()
	u, err := user.LookupId(strconv.Itoa(uid))
	if err != nil {
		t.Skipf("account uid %d absent: %v", uid, err)
	}
	return u
}

type otherUIDProc struct {
	cmd   *exec.Cmd
	stdin io.WriteCloser
	lines chan string
}

func otherUIDEnv(u *user.User) []string {
	return []string{"HOME=" + u.HomeDir, "USER=" + u.Username, "LOGNAME=" + u.Username, "PATH=/usr/local/bin:/usr/bin:/bin"}
}

func startOtherUIDHelper(t *testing.T, image string, u *user.User, args ...string) *otherUIDProc {
	t.Helper()
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	cmd := exec.Command(image, append([]string{"-test.run=^TestOtherUIDHelper$", "--", otherUIDMarker}, args...)...)
	cmd.Env = otherUIDEnv(u)
	cmd.Dir = u.HomeDir
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid), Groups: []uint32{}}}
	cmd.Stderr = os.Stderr
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	p := &otherUIDProc{cmd: cmd, stdin: stdin, lines: make(chan string, 64)}
	go func() {
		defer close(p.lines)
		s := bufio.NewScanner(stdout)
		s.Buffer(make([]byte, 1<<20), 1<<20)
		for s.Scan() {
			line := s.Text()
			if strings.HasPrefix(line, otherUIDPrefix) {
				p.lines <- strings.TrimPrefix(line, otherUIDPrefix)
			} else {
				fmt.Fprintf(os.Stderr, "[%s %s] %s\n", u.Username, args[0], line)
			}
		}
	}()
	t.Cleanup(func() {
		stdin.Close()
		if cmd.ProcessState == nil {
			cmd.Process.Kill()
			cmd.Wait()
		}
	})
	return p
}

func (p *otherUIDProc) next(t *testing.T) map[string]any {
	t.Helper()
	select {
	case line, ok := <-p.lines:
		if !ok {
			t.Fatal("helper exited before replying")
		}
		var out map[string]any
		if err := json.Unmarshal([]byte(line), &out); err != nil {
			t.Fatalf("helper reply %q: %v", line, err)
		}
		return out
	case <-time.After(60 * time.Second):
		t.Fatal("helper reply timeout")
	}
	return nil
}

func (p *otherUIDProc) send(t *testing.T, command string) map[string]any {
	t.Helper()
	if _, err := fmt.Fprintln(p.stdin, command); err != nil {
		t.Fatal(err)
	}
	return p.next(t)
}

func (p *otherUIDProc) wait(t *testing.T) {
	t.Helper()
	p.stdin.Close()
	done := make(chan error, 1)
	go func() { done <- p.cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("helper exit: %v", err)
		}
	case <-time.After(30 * time.Second):
		p.cmd.Process.Kill()
		t.Error("helper did not exit")
	}
}

func runOtherUIDAttacker(t *testing.T, image string, u *user.User, mode, paths string) map[string]any {
	t.Helper()
	p := startOtherUIDHelper(t, image, u, mode, paths)
	out := p.next(t)
	p.wait(t)
	return out
}

// TestOtherUIDHelper is the child entry point. It does nothing in normal runs.
func TestOtherUIDHelper(t *testing.T) {
	args := otherUIDArgs()
	if args == nil {
		return
	}
	emit := func(v any) {
		b, _ := json.Marshal(v)
		fmt.Println(otherUIDPrefix + string(b))
	}
	switch args[0] {
	case "owner":
		otherUIDOwnerMain(emit)
	case "attack-default":
		emit(map[string]any{"euid": os.Geteuid(), "attempts": otherUIDDefaultAttacks(args[1])})
	case "attack-loosened":
		emit(map[string]any{"euid": os.Geteuid(), "attempts": otherUIDLoosenedAttacks(args[1])})
	case "squat-dir", "squat-link":
		otherUIDSquat(emit, args[0], args[1])
	case "client":
		pid, _ := strconv.Atoi(args[2])
		emit(map[string]any{"result": otherUIDClient(args[1], pid, args[3])})
	case "hold":
		emit(map[string]any{"pid": os.Getpid()})
		io.Copy(io.Discard, os.Stdin)
	}
}

func otherUIDArgs() []string {
	for i, a := range os.Args {
		if a == otherUIDMarker && i+1 < len(os.Args) {
			return os.Args[i+1:]
		}
	}
	return nil
}

type otherUIDPaths struct {
	Data     string `json:"data"`
	Run      string `json:"run"`
	Endpoint string `json:"endpoint"`
	Install  string `json:"install"`
	Cache    string `json:"cache"`
	PID      int    `json:"pid"`
	EUID     int    `json:"euid"`
}

func attempt(name string, err error) otherUIDAttempt {
	a := otherUIDAttempt{Name: name, Refused: err != nil}
	if err != nil {
		a.Detail = err.Error()
	} else {
		a.Detail = "succeeded"
	}
	return a
}

func otherUIDDefaultAttacks(raw string) []otherUIDAttempt {
	var p otherUIDPaths
	if err := json.Unmarshal([]byte(raw), &p); err != nil {
		return []otherUIDAttempt{{Name: "decode paths", Detail: err.Error()}}
	}
	var out []otherUIDAttempt
	dial := func(network, addr string) error {
		c, err := net.DialTimeout(network, addr, 2*time.Second)
		if err == nil {
			c.Close()
		}
		return err
	}
	out = append(out, attempt("connect socket", dial("unix", p.Endpoint)))
	out = append(out, attempt("ipc.Dial owner paths", func() error {
		c, err := ipc.Dial(context.Background(), ipc.Paths{Data: p.Data, Run: p.Run, Endpoint: p.Endpoint})
		if err == nil {
			c.Close()
		}
		return err
	}()))
	out = append(out, attempt("nudge owner daemon", ipc.Nudge(context.Background(), ipc.Paths{Data: p.Data, Run: p.Run, Endpoint: p.Endpoint}, "attacker")))
	out = append(out, attempt("lstat socket", func() error { _, err := os.Lstat(p.Endpoint); return err }()))
	out = append(out, attempt("unlink socket", os.Remove(p.Endpoint)))
	decoy := filepath.Join(os.TempDir(), fmt.Sprintf("decoy-%d.sock", os.Getpid()))
	if l, err := net.Listen("unix", decoy); err == nil {
		defer l.Close()
	}
	out = append(out, attempt("rename decoy over socket", os.Rename(decoy, p.Endpoint)))
	out = append(out, attempt("symlink at socket path", os.Symlink(decoy, p.Endpoint)))
	out = append(out, attempt("symlink beside socket", os.Symlink(decoy, filepath.Join(p.Run, "node2.sock"))))
	out = append(out, attempt("replace run dir", os.Rename(p.Run, p.Run+".old")))
	out = append(out, attempt("pre-create sibling run dir", os.Mkdir(filepath.Join(p.Cache, "telara-memory-0000000000000000"), 0777)))
	out = append(out, attempt("list run dir", func() error { _, err := os.ReadDir(p.Run); return err }()))
	out = append(out, attempt("read owner.pid", func() error { _, err := os.ReadFile(filepath.Join(p.Run, "owner.pid")); return err }()))
	out = append(out, attempt("list data dir", func() error { _, err := os.ReadDir(p.Data); return err }()))
	for _, name := range []string{"db.lock", "start.lock", "shutdown.receipt"} {
		out = append(out, attempt("open data/"+name, func() error {
			f, err := os.OpenFile(filepath.Join(p.Data, name), os.O_RDWR, 0)
			if err == nil {
				f.Close()
			}
			return err
		}()))
	}
	out = append(out, attempt("create in data dir", os.WriteFile(filepath.Join(p.Data, "planted"), []byte("x"), 0666)))
	out = append(out, attempt("list install dir", func() error { _, err := os.ReadDir(p.Install); return err }()))
	out = append(out, attempt("read install receipt", func() error { _, err := os.ReadFile(filepath.Join(p.Install, "install.json")); return err }()))
	out = append(out, attempt("list daemon /proc fd", func() error { _, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", p.PID)); return err }()))
	out = append(out, attempt("read daemon /proc environ", func() error { _, err := os.ReadFile(fmt.Sprintf("/proc/%d/environ", p.PID)); return err }()))
	out = append(out, attempt("open daemon /proc root", func() error { _, err := os.ReadDir(fmt.Sprintf("/proc/%d/root%s", p.PID, p.Data)); return err }()))
	return out
}

func otherUIDLoosenedAttacks(raw string) []otherUIDAttempt {
	var p otherUIDPaths
	if err := json.Unmarshal([]byte(raw), &p); err != nil {
		return []otherUIDAttempt{{Name: "decode paths", Detail: err.Error()}}
	}
	frames := map[string][]string{
		"frame mcp hello + tools/call": {
			fmt.Sprintf(`{"t":"hello","v":1,"kind":"mcp","pid":%d,"client":"attacker"}`, os.Getpid()),
			`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"probe","arguments":{}}}`,
		},
		"frame hello claiming daemon pid": {
			fmt.Sprintf(`{"t":"hello","v":1,"kind":"control","pid":%d,"client":"status"}`, p.PID),
			`{"jsonrpc":"2.0","id":1,"method":"status"}`,
		},
		"frame control drain-and-exit": {
			fmt.Sprintf(`{"t":"hello","v":1,"kind":"control","pid":%d,"client":"status"}`, os.Getpid()),
			`{"jsonrpc":"2.0","id":1,"method":"drain-and-exit"}`,
		},
		"frame nudge":           {`{"t":"nudge","v":1,"client":"attacker"}`},
		"frame setup ping":      {fmt.Sprintf(`{"t":"hello","v":1,"kind":"mcp","pid":%d,"client":"attacker"}`, os.Getpid()), `{"jsonrpc":"2.0","id":2,"method":"ping"}`},
		"frame malformed bytes": {"not json"},
	}
	var out []otherUIDAttempt
	for _, name := range []string{"frame mcp hello + tools/call", "frame hello claiming daemon pid", "frame control drain-and-exit", "frame nudge", "frame setup ping", "frame malformed bytes"} {
		a := otherUIDAttempt{Name: name}
		c, err := net.DialTimeout("unix", p.Endpoint, 2*time.Second)
		if err != nil {
			a.Detail = "connect: " + err.Error()
			out = append(out, a)
			continue
		}
		a.Reached = true
		c.SetDeadline(time.Now().Add(5 * time.Second))
		var werr error
		for _, f := range frames[name] {
			if _, werr = io.WriteString(c, f+"\n"); werr != nil {
				break
			}
		}
		b, rerr := io.ReadAll(c)
		c.Close()
		var ne net.Error
		switch {
		case len(b) != 0:
			a.Detail = fmt.Sprintf("daemon replied %q", b)
		case errors.As(rerr, &ne) && ne.Timeout():
			a.Detail = "daemon held the connection open without replying"
		default:
			a.Refused = true
			a.Detail = fmt.Sprintf("closed with no reply (write=%v read=%v)", werr, rerr)
		}
		out = append(out, a)
	}
	out = append(out, attempt("ipc.Dial with widened modes", func() error {
		c, err := ipc.Dial(context.Background(), ipc.Paths{Data: p.Data, Run: p.Run, Endpoint: p.Endpoint})
		if err == nil {
			c.Close()
		}
		return err
	}()))
	out = append(out, attempt("unlink socket with widened modes", os.Remove(p.Endpoint)))
	out = append(out, attempt("symlink in widened run dir", os.Symlink("/tmp", filepath.Join(p.Run, "node2.sock"))))
	out = append(out, attempt("list widened run dir", func() error { _, err := os.ReadDir(p.Run); return err }()))
	out = append(out, attempt("list data dir", func() error { _, err := os.ReadDir(p.Data); return err }()))
	return out
}

// otherUIDSquat pre-creates the owner's fallback run directory (or a symlink to
// an attacker directory) and listens on node.sock there, counting connections.
func otherUIDSquat(emit func(any), mode, run string) {
	parent := filepath.Dir(run)
	target := parent
	fail := func(err error) { emit(map[string]any{"error": err.Error()}); io.Copy(io.Discard, os.Stdin) }
	if mode == "squat-link" {
		target = filepath.Join(os.TempDir(), fmt.Sprintf("squat-target-%d", os.Getpid()))
		if err := os.Symlink(target, parent); err != nil {
			fail(err)
			return
		}
		defer os.Remove(parent)
	}
	dir := filepath.Join(target, filepath.Base(run))
	if err := os.MkdirAll(dir, 0777); err != nil {
		fail(err)
		return
	}
	defer os.RemoveAll(target)
	os.Chmod(target, 0777)
	os.Chmod(dir, 0777)
	l, err := net.Listen("unix", filepath.Join(dir, "node.sock"))
	if err != nil {
		fail(err)
		return
	}
	os.Chmod(filepath.Join(dir, "node.sock"), 0777)
	var mu sync.Mutex
	accepted := 0
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			accepted++
			mu.Unlock()
			c.Close()
		}
	}()
	emit(map[string]any{"armed": dir})
	r := bufio.NewScanner(os.Stdin)
	for r.Scan() {
		if r.Text() == "report" {
			entries, _ := os.ReadDir(dir)
			var names []string
			for _, e := range entries {
				names = append(names, e.Name())
			}
			mu.Lock()
			n := accepted
			mu.Unlock()
			emit(map[string]any{"accepted": n, "entries": names})
		}
	}
	l.Close()
}

func otherUIDClient(endpoint string, helloPID int, method string) string {
	if helloPID == 0 {
		helloPID = os.Getpid()
	}
	c, err := net.DialTimeout("unix", endpoint, 2*time.Second)
	if err != nil {
		return "connect: " + err.Error()
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	if err = ipc.WriteFrame(c, ipc.Hello{T: "hello", V: ipc.WireVersion, Kind: "mcp", PID: helloPID, Client: "fixture"}); err != nil {
		return "write hello: " + err.Error()
	}
	r := bufio.NewReader(c)
	b, err := ipc.ReadFrame(r)
	if err != nil {
		return "read ack: " + err.Error()
	}
	var ack struct {
		T     string `json:"t"`
		Error string `json:"error"`
	}
	if json.Unmarshal(b, &ack) != nil || ack.T != "hello" {
		if ack.Error != "" {
			return ack.Error
		}
		return fmt.Sprintf("unexpected ack %q", b)
	}
	if _, err = io.WriteString(c, `{"jsonrpc":"2.0","id":7,"method":"`+method+`","params":{"name":"probe","arguments":{}}}`+"\n"); err != nil {
		return "write request: " + err.Error()
	}
	if b, err = ipc.ReadFrame(r); err != nil {
		return "read response: " + err.Error()
	}
	var out daemon.Response
	if err = json.Unmarshal(b, &out); err != nil {
		return fmt.Sprintf("bad response %q", b)
	}
	if out.Error != nil {
		return out.Error.Message
	}
	if m, ok := out.Result.(map[string]any); ok && m["authorized"] == true {
		return "authorized"
	}
	return fmt.Sprintf("unexpected result %q", b)
}

// otherUIDBackend mirrors the installed provider's credential gate: every
// backend call passes the installed peer authority before anything else.
type otherUIDBackend struct {
	authority Authority
	mu        sync.Mutex
	nudges    map[string]int
	handles   map[string]int
	nudged    chan string
}

func (b *otherUIDBackend) Handle(ctx context.Context, h ipc.Hello, r daemon.Request) daemon.Response {
	b.mu.Lock()
	b.handles[h.Client]++
	b.mu.Unlock()
	if err := b.authority.VerifyAndDrain(ctx, h, "credential"); err != nil {
		return daemon.Error(r.ID, err.Error())
	}
	return daemon.Response{Result: map[string]any{"authorized": true}}
}
func (b *otherUIDBackend) Close() error { return nil }
func (b *otherUIDBackend) Nudge(client string) {
	b.mu.Lock()
	b.nudges[client]++
	b.mu.Unlock()
	select {
	case b.nudged <- client:
	default:
	}
}
func (b *otherUIDBackend) foreign() (int, int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n, h := 0, 0
	for client, count := range b.nudges {
		if client != "owner" {
			n += count
		}
	}
	for client, count := range b.handles {
		if client != "fixture" {
			h += count
		}
	}
	return n, h
}

func otherUIDOwnerMain(emit func(any)) {
	fail := func(stage string, err error) { emit(map[string]any{"error": stage + ": " + err.Error()}) }
	home, _ := os.UserHomeDir()
	cache, _ := os.UserCacheDir()
	p, err := ipc.Resolve("", "")
	if err != nil {
		fail("resolve", err)
		return
	}
	dir, err := install.DefaultDir()
	if err != nil {
		fail("install dir", err)
		return
	}
	self, _ := os.Executable()
	digest, err := fileDigest(self)
	if err != nil {
		fail("digest", err)
		return
	}
	report, err := install.Install(context.Background(), install.Config{Dir: dir, Home: home, Executable: self, SHA256: digest, Version: "fixture", DataDir: p.Data, RunDir: p.Run})
	if err != nil && !errors.Is(err, install.ErrUnavailable) {
		fail("install", err)
		return
	}
	backend := &otherUIDBackend{authority: Authority{InstallDir: dir, DataDir: p.Data}, nudges: map[string]int{}, handles: map[string]int{}, nudged: make(chan string, 4)}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- daemon.Run(ctx, daemon.Config{BindConnection: BindConnection, Paths: p, Open: func(context.Context) (daemon.Backend, error) { return backend, nil }, Ready: func() { close(ready) }})
	}()
	select {
	case <-ready:
	case err = <-done:
		fail("daemon", err)
		return
	}
	emit(otherUIDPaths{Data: p.Data, Run: p.Run, Endpoint: p.Endpoint, Install: dir, Cache: cache, PID: os.Getpid(), EUID: os.Geteuid()})
	in := bufio.NewScanner(os.Stdin)
	var modes []struct {
		path string
		mode os.FileMode
	}
	for in.Scan() {
		switch in.Text() {
		case "loosen":
			modes = nil
			var lerr error
			for _, m := range []struct {
				path string
				mode os.FileMode
			}{{cache, 0711}, {p.Run, 0711}, {p.Endpoint, 0666}} {
				st, err := os.Lstat(m.path)
				if err != nil {
					lerr = err
					break
				}
				modes = append(modes, struct {
					path string
					mode os.FileMode
				}{m.path, st.Mode().Perm()})
				if err = os.Chmod(m.path, m.mode); err != nil {
					lerr = err
					break
				}
			}
			emit(map[string]any{"error": errString(lerr)})
		case "restore":
			var rerr error
			for _, m := range modes {
				if err := os.Chmod(m.path, m.mode); err != nil {
					rerr = err
				}
			}
			emit(map[string]any{"error": errString(rerr)})
		case "check":
			emit(otherUIDOwnerCheck(p, report.Record, backend))
		case "fallback-plan":
			p2, err := otherUIDFallbackPaths(home, cache)
			emit(map[string]any{"run": p2.Run, "endpoint": p2.Endpoint, "error": errString(err)})
		case "fallback-run":
			emit(otherUIDFallbackRun(home, cache))
		case "exit":
			cancel()
			err := <-done
			emit(map[string]any{"run_error": errString(err)})
			return
		}
	}
}

func errString(err error) any {
	if err == nil {
		return nil
	}
	return err.Error()
}

func otherUIDFallbackPaths(home, cache string) (ipc.Paths, error) {
	long := filepath.Join(cache, strings.Repeat("l", 90))
	return ipc.Resolve(filepath.Join(home, ".config", "telara-memory-fallback"), long)
}

func otherUIDFallbackRun(home, cache string) map[string]any {
	p, err := otherUIDFallbackPaths(home, cache)
	if err != nil {
		return map[string]any{"run_error": err.Error(), "dial_error": err.Error(), "probe_error": err.Error()}
	}
	out := map[string]any{"run": p.Run}
	// Create the requested long path so dial and probe reach the fallback
	// directory check rather than failing on a missing owner directory.
	if err := ipc.ValidateDir(filepath.Join(cache, strings.Repeat("l", 90)), true); err != nil {
		out["prepare_error"] = err.Error()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if c, err := ipc.Dial(ctx, p); err != nil {
		out["dial_error"] = err.Error()
	} else {
		c.Close()
	}
	if _, err := daemon.Probe(ctx, p); err != nil {
		out["probe_error"] = err.Error()
	}
	runCtx, stop := context.WithCancel(ctx)
	defer stop()
	ready := false
	err = daemon.Run(runCtx, daemon.Config{BindConnection: BindConnection, Paths: p, Ready: func() { ready = true; stop() }})
	out["ready"] = ready
	out["run_error"] = errString(err)
	return out
}

func otherUIDOwnerCheck(p ipc.Paths, record install.Record, backend *otherUIDBackend) map[string]any {
	out := map[string]any{}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	status, err := daemon.Probe(ctx, p)
	out["probe_error"] = errString(err)
	if m, ok := status.Result.(map[string]any); ok {
		out["probe_pid_match"] = m["pid"] == float64(os.Getpid())
	}
	if err := ipc.Nudge(ctx, p, "owner"); err == nil {
		select {
		case c := <-backend.nudged:
			out["owner_nudge"] = c == "owner"
		case <-time.After(5 * time.Second):
			out["owner_nudge"] = false
		}
	} else {
		out["owner_nudge"] = "nudge: " + err.Error()
	}
	n, h := backend.foreign()
	out["foreign_nudges"], out["foreign_handles"] = n, h

	run := func(image string, args ...string) string {
		cmd := exec.CommandContext(ctx, image, append([]string{"-test.run=^TestOtherUIDHelper$", "--", otherUIDMarker}, args...)...)
		cmd.Stderr = os.Stderr
		b, err := cmd.Output()
		for _, line := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(line, otherUIDPrefix) {
				var r map[string]any
				json.Unmarshal([]byte(strings.TrimPrefix(line, otherUIDPrefix)), &r)
				s, _ := r["result"].(string)
				return s
			}
		}
		return fmt.Sprintf("no result (%v)", err)
	}
	self, _ := os.Executable()
	out["installed_image"] = record.Executable
	out["installed_peer"] = run(record.Executable, "client", p.Endpoint, "0", "tools/call")
	// Same bytes and uid, but not the installed image path.
	out["unverified_image"] = self
	out["unverified_peer"] = run(self, "client", p.Endpoint, "0", "tools/call")

	// A same-uid process claims the pid of a live installed-image process.
	hold := exec.CommandContext(ctx, record.Executable, "-test.run=^TestOtherUIDHelper$", "--", otherUIDMarker, "hold")
	stdin, _ := hold.StdinPipe()
	stdout, _ := hold.StdoutPipe()
	hold.Stderr = os.Stderr
	if err := hold.Start(); err != nil {
		out["spoofed_hello"] = "hold: " + err.Error()
		return out
	}
	defer func() { stdin.Close(); hold.Wait() }()
	s := bufio.NewScanner(stdout)
	pid := 0
	for s.Scan() {
		if line := s.Text(); strings.HasPrefix(line, otherUIDPrefix) {
			var r struct {
				PID int `json:"pid"`
			}
			json.Unmarshal([]byte(strings.TrimPrefix(line, otherUIDPrefix)), &r)
			pid = r.PID
			break
		}
	}
	out["spoofed_pid"] = pid
	out["spoofed_hello"] = run(self, "client", p.Endpoint, strconv.Itoa(pid), "tools/call")
	return out
}

func fileDigest(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err = io.Copy(h, f); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}
