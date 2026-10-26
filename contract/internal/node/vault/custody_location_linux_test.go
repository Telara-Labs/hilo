//go:build linux

package vault

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/disclosure"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/install"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/peer"
	"github.com/godbus/dbus/v5"
)

// This is an OS Secret Service double on a real, private session bus, not a
// mocked Telara service. It intentionally supports alias changes and restarts.
// In gnome mode it reproduces GNOME Keyring 48: only the default alias can be
// created or set, and a deleted item path answers UnknownMethod.
type testSecrets struct {
	mu           sync.Mutex
	conn         *dbus.Conn
	gnome        bool
	alias        dbus.ObjectPath
	defaultAlias dbus.ObjectPath
	collections  map[dbus.ObjectPath]map[dbus.ObjectPath]*testSecretItem
	next         int
	creates      int
	promptCreate bool
	stallCreate  chan struct{}
	beforeCreate func() error
	loseReply    bool
	loseSetReply bool
	hideSearch   bool
	beforeSet    func() error
	// unknownMethod makes every item answer UnknownMethod, even a live one.
	unknownMethod bool
	// ignoreDelete reports success without removing the item.
	ignoreDelete bool
	itemsFail    bool
}

func testNotSupported() *dbus.Error {
	return dbus.NewError("org.freedesktop.DBus.Error.NotSupported", []any{"Only the 'default' alias is supported"})
}
func testUnknownMethod(path dbus.ObjectPath) *dbus.Error {
	return dbus.NewError("org.freedesktop.DBus.Error.UnknownMethod", []any{fmt.Sprintf("Object does not exist at path “%s”", path)})
}

type testSecretItem struct {
	attrs map[string]string
	value []byte
}
type testCollection struct {
	s    *testSecrets
	path dbus.ObjectPath
}
type testItem struct {
	s                *testSecrets
	collection, path dbus.ObjectPath
}
type testSession struct{}

func (testSession) Close() *dbus.Error { return nil }
func testBusError() *dbus.Error {
	return dbus.NewError("org.freedesktop.DBus.Error.Failed", []any{"synthetic OS service refusal"})
}
func (s *testSecrets) OpenSession(_ string, _ dbus.Variant) (dbus.Variant, dbus.ObjectPath, *dbus.Error) {
	return dbus.MakeVariant(""), "/org/freedesktop/secrets/session/test", nil
}
func (s *testSecrets) ReadAlias(name string) (dbus.ObjectPath, *dbus.Error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch name {
	case defaultAlias:
		return s.defaultAlias, nil
	case collectionAlias:
		return s.alias, nil
	}
	return "/", nil
}
func (s *testSecrets) SetAlias(name string, path dbus.ObjectPath) *dbus.Error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.gnome && name != defaultAlias {
		return testNotSupported()
	}
	if s.collections[path] == nil {
		return testBusError()
	}
	if name == defaultAlias {
		s.defaultAlias = path
	} else {
		s.alias = path
	}
	return nil
}
func (s *testSecrets) CreateCollection(_ map[string]dbus.Variant, alias string) (dbus.ObjectPath, dbus.ObjectPath, *dbus.Error) {
	s.mu.Lock()
	s.creates++
	stall := s.stallCreate
	s.mu.Unlock()
	if stall != nil {
		// Model a service that never replies; the caller's deadline expires.
		<-stall
		return "/", "/", testBusError()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.gnome && alias != "" && alias != defaultAlias {
		return "/", "/", testNotSupported()
	}
	if s.promptCreate {
		return "/", "/org/freedesktop/secrets/prompt/create", nil
	}
	s.next++
	path := dbus.ObjectPath(fmt.Sprintf("/org/freedesktop/secrets/collection/created_%d", s.next))
	s.collections[path] = map[dbus.ObjectPath]*testSecretItem{}
	if s.conn.Export(testCollection{s, path}, path, "org.freedesktop.Secret.Collection") != nil || s.conn.Export(testCollection{s, path}, path, "org.freedesktop.DBus.Properties") != nil {
		return "/", "/", testBusError()
	}
	if alias == defaultAlias {
		s.defaultAlias = path
	} else if alias != "" {
		s.alias = path
	}
	return path, "/", nil
}
func (c testCollection) Get(iface, prop string) (dbus.Variant, *dbus.Error) {
	if iface != "org.freedesktop.Secret.Collection" {
		return dbus.Variant{}, testBusError()
	}
	switch prop {
	case "Locked":
		return dbus.MakeVariant(false), nil
	case "Items":
		c.s.mu.Lock()
		defer c.s.mu.Unlock()
		if c.s.itemsFail || c.s.collections[c.path] == nil {
			return dbus.Variant{}, testBusError()
		}
		items := []dbus.ObjectPath{}
		for path := range c.s.collections[c.path] {
			items = append(items, path)
		}
		return dbus.MakeVariant(items), nil
	}
	return dbus.Variant{}, testBusError()
}
func (c testCollection) SearchItems(attrs map[string]string) ([]dbus.ObjectPath, *dbus.Error) {
	c.s.mu.Lock()
	defer c.s.mu.Unlock()
	if c.s.collections[c.path] == nil {
		return nil, testBusError()
	}
	found := []dbus.ObjectPath{}
	if c.s.hideSearch {
		return found, nil
	}
	for path, item := range c.s.collections[c.path] {
		match := true
		for k, v := range attrs {
			if item.attrs[k] != v {
				match = false
			}
		}
		if match {
			found = append(found, path)
		}
	}
	return found, nil
}
func (c testCollection) CreateItem(props map[string]dbus.Variant, secret wireSecret, _ bool) (dbus.ObjectPath, dbus.ObjectPath, *dbus.Error) {
	c.s.mu.Lock()
	defer c.s.mu.Unlock()
	if c.s.beforeCreate != nil {
		if e := c.s.beforeCreate(); e != nil {
			return "/", "/", testBusError()
		}
	}
	if len(secret.Value) != 0 {
		return "/", "/", testBusError()
	}
	attrs, ok := props["org.freedesktop.Secret.Item.Attributes"].Value().(map[string]string)
	if !ok {
		return "/", "/", testBusError()
	}
	c.s.next++
	path := dbus.ObjectPath(fmt.Sprintf("%s/item_%d", c.path, c.s.next))
	c.s.collections[c.path][path] = &testSecretItem{attrs, append([]byte(nil), secret.Value...)}
	if e := c.s.conn.Export(testItem{c.s, c.path, path}, path, "org.freedesktop.Secret.Item"); e != nil {
		return "/", "/", testBusError()
	}
	if c.s.loseReply {
		return "/", "/", testBusError()
	}
	return path, "/", nil
}
func (i testItem) GetSecret(session dbus.ObjectPath) (wireSecret, *dbus.Error) {
	i.s.mu.Lock()
	defer i.s.mu.Unlock()
	item := i.s.collections[i.collection][i.path]
	if i.s.unknownMethod || (item == nil && i.s.gnome) {
		return wireSecret{}, testUnknownMethod(i.path)
	}
	if item == nil {
		return wireSecret{}, dbus.NewError("org.freedesktop.DBus.Error.NoSuchObject", []any{"item absent"})
	}
	return wireSecret{session, []byte{}, append([]byte(nil), item.value...), "application/octet-stream"}, nil
}
func (i testItem) SetSecret(secret wireSecret) *dbus.Error {
	i.s.mu.Lock()
	defer i.s.mu.Unlock()
	if i.s.beforeSet != nil {
		if e := i.s.beforeSet(); e != nil {
			return testBusError()
		}
	}
	item := i.s.collections[i.collection][i.path]
	if item == nil {
		return testBusError()
	}
	clear(item.value)
	item.value = append([]byte(nil), secret.Value...)
	if i.s.loseSetReply {
		return testBusError()
	}
	return nil
}
func (i testItem) Delete() (dbus.ObjectPath, *dbus.Error) {
	i.s.mu.Lock()
	defer i.s.mu.Unlock()
	item := i.s.collections[i.collection][i.path]
	if item == nil {
		if i.s.gnome {
			return "/", testUnknownMethod(i.path)
		}
		return "/", testBusError()
	}
	if i.s.ignoreDelete {
		return "/", nil
	}
	clear(item.value)
	delete(i.s.collections[i.collection], i.path)
	return "/", nil
}

const testC1 dbus.ObjectPath = "/org/freedesktop/secrets/collection/first"
const testC2 dbus.ObjectPath = "/org/freedesktop/secrets/collection/second"
const linuxTestHandle = "0123456789abcdef0123456789abcdef"

// secretModes runs a fixture against a service that supports the dedicated
// alias and against one that behaves like GNOME Keyring. Both select testC1.
func secretModes(t *testing.T, run func(t *testing.T, mode string)) {
	for _, mode := range []string{"dedicated", "gnome"} {
		t.Run(mode, func(t *testing.T) { run(t, mode) })
	}
}
func privateSecretService(t *testing.T, mode string) (*testSecrets, string) {
	t.Helper()
	daemon, e := exec.LookPath("dbus-daemon")
	if e != nil {
		t.Fatal("private Secret Service tests require dbus-daemon", e)
	}
	// Unix socket paths must remain short even under a long test-name directory.
	busDir, e := os.MkdirTemp("", "memory-bus-")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { os.RemoveAll(busDir) })
	cmd := exec.Command(daemon, "--session", "--nofork", "--nopidfile", "--address=unix:path="+filepath.Join(busDir, "bus"), "--print-address=1")
	stdout, e := cmd.StdoutPipe()
	if e != nil {
		t.Fatal(e)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if e = cmd.Start(); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	ready := make(chan string, 1)
	go func() { line, _ := bufio.NewReader(stdout).ReadString('\n'); ready <- strings.TrimSpace(line) }()
	var address string
	select {
	case address = <-ready:
	case <-time.After(5 * time.Second):
		t.Fatal("private dbus startup timed out")
	}
	if !strings.HasPrefix(address, "unix:") {
		t.Fatal("private dbus did not start", stderr.String())
	}
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", address) // existing OS transport only
	s := &testSecrets{alias: testC1, defaultAlias: testC2, collections: map[dbus.ObjectPath]map[dbus.ObjectPath]*testSecretItem{testC1: {}, testC2: {}}}
	switch mode {
	case "dedicated":
	case "gnome":
		s.gnome, s.alias, s.defaultAlias = true, "/", testC1
	default:
		t.Fatal("unknown Secret Service mode", mode)
	}
	s.start(t, address)
	t.Cleanup(func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.conn != nil {
			s.conn.Close()
		}
		for _, items := range s.collections {
			for _, i := range items {
				clear(i.value)
			}
		}
	})
	return s, address
}
func (s *testSecrets) start(t *testing.T, address string) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	conn, e := dbus.Connect(address)
	if e != nil {
		t.Fatal(e)
	}
	s.conn = conn
	export := func(value any, path dbus.ObjectPath, iface string) {
		t.Helper()
		if e := conn.Export(value, path, iface); e != nil {
			t.Fatal(e)
		}
	}
	export(s, secretRoot, "org.freedesktop.Secret.Service")
	export(testSession{}, "/org/freedesktop/secrets/session/test", "org.freedesktop.Secret.Session")
	for path, items := range s.collections {
		export(testCollection{s, path}, path, "org.freedesktop.Secret.Collection")
		export(testCollection{s, path}, path, "org.freedesktop.DBus.Properties")
		for item := range items {
			export(testItem{s, path, item}, item, "org.freedesktop.Secret.Item")
		}
	}
	reply, e := conn.RequestName(secretService, dbus.NameFlagDoNotQueue)
	if e != nil || reply != dbus.RequestNameReplyPrimaryOwner {
		t.Fatal("service name", reply, e)
	}
}
func (s *testSecrets) restart(t *testing.T, address string) {
	t.Helper()
	s.conn.Close()
	s.start(t, address)
}
func (s *testSecrets) aliasTo(t *testing.T, address string, path dbus.ObjectPath) {
	t.Helper()
	c, e := dbus.Connect(address)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	// GNOME Keyring can reassign only the default alias.
	name := collectionAlias
	if s.gnome {
		name = defaultAlias
	}
	if e = c.Object(secretService, secretRoot).Call("org.freedesktop.Secret.Service.SetAlias", 0, name, path).Err; e != nil {
		t.Fatal(e)
	}
}

// linuxItemRecord reads the fixture handle's own custody record.
func linuxItemRecord(data string) (*secretServiceLocation, error) {
	return readLinuxRecord(data, custodyItemFile(linuxTestHandle))
}

// linuxEvidence is every durable custody byte of a profile: the selection
// record and every per-handle record, in name order.
func linuxEvidence(data string) ([]byte, error) {
	names, e := filepath.Glob(filepath.Join(data, "custody-*.json"))
	if e != nil {
		return nil, e
	}
	var out []byte
	for _, name := range names {
		b, e := os.ReadFile(name)
		if e != nil {
			return nil, e
		}
		out = append(append(append(out, filepath.Base(name)...), 0), b...)
	}
	return out, nil
}
func linuxProfile(t *testing.T) string {
	t.Helper()
	data := t.TempDir()
	if e := os.Chmod(data, 0700); e != nil {
		t.Fatal(e)
	}
	return data
}
func TestSecretServiceProfileProcessHelper(t *testing.T) {
	for i, arg := range os.Args {
		if arg != "--" {
			continue
		}
		if len(os.Args) != i+4 {
			t.Fatal("invalid helper arguments")
		}
		v := ForProfile(os.Args[i+1])
		ctx := context.Background()
		switch os.Args[i+3] {
		case "delete":
			if e := v.Delete(ctx, os.Args[i+2]); e != nil {
				t.Fatal(e)
			}
		case "get":
			b, e := v.Get(ctx, os.Args[i+2])
			defer clear(b)
			if e != nil || string(b) != "synthetic profile authority" {
				t.Fatal("profile read failed", e)
			}
		default:
			t.Fatal("invalid helper action")
		}
		return
	}
}
func linuxProcess(t *testing.T, data, action string) {
	t.Helper()
	exe, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, "-test.run=^TestSecretServiceProfileProcessHelper$", "--", data, linuxTestHandle, action)
	if b, e := cmd.CombinedOutput(); e != nil {
		t.Fatalf("fresh process %s %v %s", action, e, b)
	}
}
func TestSecretServiceRecordedIdentitySurvivesAliasReassignment(t *testing.T) {
	secretModes(t, func(t *testing.T, mode string) {
		for _, admitted := range []bool{false, true} {
			t.Run(fmt.Sprint(admitted), func(t *testing.T) {
				s, address := privateSecretService(t, mode)
				data := linuxProfile(t)
				v := ForProfile(data)
				ctx := context.Background()
				if e := v.bindCustody(ctx, data, true); e != nil {
					t.Fatal(e)
				}
				m, e := readLinuxLocation(data)
				if e != nil || m.State != "selected" || m.Collection != string(testC1) {
					t.Fatal("selection not persisted", m, e)
				}
				s.mu.Lock()
				s.beforeCreate = func() error {
					m, e := linuxItemRecord(data)
					if e != nil || m.State != "creating" || m.Handle != linuxTestHandle || m.Collection != string(testC1) || m.Item != "" {
						return errors.New("creation intent missing")
					}
					return nil
				}
				s.beforeSet = func() error {
					m, e := linuxItemRecord(data)
					if e != nil || m.State != "bound" || m.Item == "" || m.Collection != string(testC1) || m.Handle != linuxTestHandle {
						return errors.New("item identity missing before authority")
					}
					return nil
				}
				s.mu.Unlock()
				// Reassignment before Put must not change the pre-published collection.
				s.aliasTo(t, address, testC2)
				if e := v.Put(ctx, linuxTestHandle, []byte("synthetic profile authority")); e != nil {
					t.Fatal(e)
				}
				m, e = linuxItemRecord(data)
				if e != nil || m.State != "ready" || m.Item == "" || m.Collection != string(testC1) {
					t.Fatal("item identity missing", m, e)
				}
				if admitted {
					linuxProcess(t, data, "get")
				}
				linuxProcess(t, data, "delete")
				s.mu.Lock()
				count := len(s.collections[testC1])
				second := len(s.collections[testC2])
				s.mu.Unlock()
				if count != 0 || second != 0 {
					t.Fatal("alias hid retained credential", count, second)
				}
				linuxProcess(t, data, "delete")
			})
		}
	})
}
func TestSecretServiceRecordedIdentityAcrossServiceRestart(t *testing.T) {
	secretModes(t, func(t *testing.T, mode string) {
		s, address := privateSecretService(t, mode)
		data := linuxProfile(t)
		ctx := context.Background()
		if e := ForProfile(data).Put(ctx, linuxTestHandle, []byte("synthetic profile authority")); e != nil {
			t.Fatal(e)
		}
		s.aliasTo(t, address, testC2)
		s.restart(t, address)
		linuxProcess(t, data, "get")
		linuxProcess(t, data, "delete")
		s.mu.Lock()
		count := len(s.collections[testC1])
		s.mu.Unlock()
		if count != 0 {
			t.Fatal("restart retained item")
		}
	})
}
func TestSecretServiceLostIdentityRefusesCleanup(t *testing.T) {
	secretModes(t, func(t *testing.T, mode string) {
		for _, kind := range []string{"missing-location", "corrupt-location", "missing-item-record", "corrupt-item-record", "foreign-collection-record", "missing-item-after-restart", "reassigned-item-path", "missing-collection"} {
			t.Run(kind, func(t *testing.T) {
				s, address := privateSecretService(t, mode)
				data := linuxProfile(t)
				ctx := context.Background()
				if e := ForProfile(data).Put(ctx, linuxTestHandle, []byte("synthetic profile authority")); e != nil {
					t.Fatal(e)
				}
				m, e := linuxItemRecord(data)
				if e != nil {
					t.Fatal(e)
				}
				switch kind {
				case "missing-location":
					if e = os.Remove(filepath.Join(data, custodyLocationFile)); e != nil {
						t.Fatal(e)
					}
				case "corrupt-location":
					if e = os.WriteFile(filepath.Join(data, custodyLocationFile), []byte("{}"), 0600); e != nil {
						t.Fatal(e)
					}
				case "missing-item-record":
					// The item exists, but no record proves this profile made it.
					if e = os.Remove(filepath.Join(data, custodyItemFile(linuxTestHandle))); e != nil {
						t.Fatal(e)
					}
				case "corrupt-item-record":
					if e = os.WriteFile(filepath.Join(data, custodyItemFile(linuxTestHandle)), []byte("{}"), 0600); e != nil {
						t.Fatal(e)
					}
				case "foreign-collection-record":
					moved := *m
					moved.Collection = string(testC2)
					if e = writeLinuxRecord(data, custodyItemFile(linuxTestHandle), moved); e != nil {
						t.Fatal(e)
					}
				case "missing-item-after-restart":
					s.mu.Lock()
					s.collections[testC1] = map[dbus.ObjectPath]*testSecretItem{}
					s.mu.Unlock()
					s.restart(t, address)
				case "reassigned-item-path":
					s.mu.Lock()
					item := s.collections[testC1][dbus.ObjectPath(m.Item)]
					delete(s.collections[testC1], dbus.ObjectPath(m.Item))
					s.collections[testC1][testC1+"/moved"] = item
					s.mu.Unlock()
					s.restart(t, address)
				case "missing-collection":
					s.mu.Lock()
					delete(s.collections, testC1)
					s.mu.Unlock()
					s.restart(t, address)
				}
				s.aliasTo(t, address, testC2)
				before, _ := linuxEvidence(data)
				if e := ForProfile(data).Delete(ctx, linuxTestHandle); !errors.Is(e, ErrUnavailable) {
					t.Fatal("lost identity accepted as deletion", e)
				}
				after, _ := linuxEvidence(data)
				if !bytes.Equal(before, after) {
					t.Fatal("refusal changed evidence")
				}
			})
		}
	})
}
func TestSecretServiceInterruptedCreationUsesOriginalCollection(t *testing.T) {
	secretModes(t, func(t *testing.T, mode string) {
		s, address := privateSecretService(t, mode)
		data := linuxProfile(t)
		ctx := context.Background()
		s.mu.Lock()
		s.loseReply = true
		s.mu.Unlock()
		if e := ForProfile(data).Put(ctx, linuxTestHandle, []byte("synthetic profile authority")); e != ErrUnavailable {
			t.Fatal(e)
		}
		m, e := linuxItemRecord(data)
		if e != nil || m.State != "creating" || m.Item != "" {
			t.Fatal(m, e)
		}
		s.aliasTo(t, address, testC2)
		s.restart(t, address)
		// The interrupted empty placeholder has no authority. Recover its exact
		// path in the original collection for cleanup after service restart.
		if b, e := ForProfile(data).Get(ctx, linuxTestHandle); e != ErrUnavailable || len(b) != 0 {
			clear(b)
			t.Fatal("empty placeholder became authority", e)
		}
		linuxProcess(t, data, "delete")
		s.mu.Lock()
		count := len(s.collections[testC1])
		s.mu.Unlock()
		if count != 0 {
			t.Fatal("interrupted creation retained item")
		}
	})
}
func TestSecretServiceLocationPrivacyAndParsing(t *testing.T) {
	data := linuxProfile(t)
	for _, raw := range []string{"{", `{}`, `{"version":9}`, strings.Repeat("x", 17000)} {
		p := filepath.Join(data, custodyLocationFile)
		if e := os.WriteFile(p, []byte(raw), 0600); e != nil {
			t.Fatal(e)
		}
		if _, e := readLinuxLocation(data); e == nil {
			t.Fatal("invalid record accepted")
		}
	}
	p := filepath.Join(data, custodyLocationFile)
	if e := os.Remove(p); e != nil {
		t.Fatal(e)
	}
	target := filepath.Join(data, "other")
	if e := os.WriteFile(target, []byte("{}"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink(target, p); e != nil {
		t.Fatal(e)
	}
	if _, e := readLinuxLocation(data); e == nil {
		t.Fatal("symlink accepted")
	}
}

func linuxInstalledRecord(t *testing.T, data string) install.Record {
	t.Helper()
	// Installed images forbid mutable ancestors. CI supplies a private temporary
	// root; its /home/runner directory may grant other principals write access.
	homeBase := os.TempDir()
	root, e := os.MkdirTemp(homeBase, ".memory-vault-fixture-")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { os.RemoveAll(root) })
	root, e = filepath.EvalSymlinks(root)
	if e != nil {
		t.Fatal(e)
	}
	self, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	raw, e := os.ReadFile(self)
	if e != nil {
		t.Fatal(e)
	}
	sum := sha256.Sum256(raw)
	digest := hex.EncodeToString(sum[:])
	dir := filepath.Join(root, "install")
	exe := filepath.Join(dir, "bin", digest, "telara-memory")
	home := filepath.Join(root, "home")
	run := filepath.Join(root, "run")
	for _, path := range []string{filepath.Dir(exe), home, run} {
		if e = os.MkdirAll(path, 0700); e != nil {
			t.Fatal(e)
		}
	}
	if e = os.WriteFile(exe, raw, 0700); e != nil {
		t.Fatal(e)
	}
	r := install.Record{Schema: 1, Dir: dir, Home: home, Label: "dev.memory.custody.fixture", Platform: "linux", UserID: strconv.Itoa(os.Geteuid()), Executable: exe, SHA256: digest, Version: "fixture", DataDir: data, RunDir: run}
	for name, value := range map[string]any{"install.json": r, "intent.json": map[string]string{"mode": "stop", "sha256": digest, "version": r.Version, "session": ""}} {
		raw, e := json.Marshal(value)
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(filepath.Join(dir, name), raw, 0600); e != nil {
			t.Fatal(e)
		}
	}
	status, err := install.Status(context.Background(), dir)
	if err != nil && !errors.Is(err, install.ErrUnavailable) {
		t.Fatal("installed custody fixture could not verify", err)
	}
	if status.Record != r {
		t.Fatal("installed custody fixture receipt mismatch")
	}
	return r
}
func TestSecretServiceInstalledAuthorityReassignmentBeforeAndAfterLoad(t *testing.T) {
	secretModes(t, func(t *testing.T, mode string) {
		for _, loaded := range []bool{false, true} {
			t.Run(fmt.Sprint(loaded), func(t *testing.T) {
				s, address := privateSecretService(t, mode)
				data := linuxProfile(t)
				r := linuxInstalledRecord(t, data)
				ctx := context.Background()
				v := New()
				if e := v.PrepareForInstall(ctx, r); e != nil {
					t.Fatal(e)
				}
				// Installation first creates and deletes a disposable probe, then starts
				// a new handle generation for the actual authority.
				if e := v.PutForInstall(ctx, r, linuxTestHandle, []byte("disposable custody probe")); e != nil {
					t.Fatal(e)
				}
				if e := v.DeleteForInstall(ctx, r, linuxTestHandle); e != nil {
					t.Fatal(e)
				}
				if e := v.PrepareForInstall(ctx, r); e != nil {
					t.Fatal(e)
				}
				if e := disclosure.BootstrapInstalled(ctx, data, "Linux native custody fixture", disclosure.Grant{Repos: disclosure.AllLocalRepos(), Channels: []disclosure.Channel{disclosure.S}}, disclosure.TaskWriteGrant{}, Installed{Vault: v, Record: r}); e != nil {
					t.Fatal(e)
				}
				// The probe's record stays deleted; the authority has its own.
				var m *secretServiceLocation
				for h, state := range recordedHandles(t, data) {
					if h != linuxTestHandle {
						if m != nil {
							t.Fatal("ambiguous installed authority")
						}
						var e error
						if m, e = readLinuxRecord(data, custodyItemFile(h)); e != nil || state != "ready" {
							t.Fatal(m, e)
						}
					}
				}
				if probe, e := linuxItemRecord(data); m == nil || e != nil || probe.State != "deleted" {
					t.Fatal("installed authority or probe record missing", e)
				}
				if loaded {
					runtime, e := (disclosure.InstalledProvider{Dir: data, Vault: ForProfile(data), Peers: peer.Authority{}}).Load(ctx)
					if e != nil {
						t.Fatal(e)
					}
					runtime.Material.Clear()
				}
				s.aliasTo(t, address, testC2)
				// A different vault object models uninstall from a new process; the actual
				// receipt is revalidated and its durable backend identity is used.
				if e := New().DeleteForInstall(ctx, r, m.Handle); e != nil {
					t.Fatal(e)
				}
				s.mu.Lock()
				count := len(s.collections[testC1])
				s.mu.Unlock()
				if count != 0 {
					t.Fatal("installed credential survived cleanup")
				}
				if e := New().DeleteForInstall(ctx, r, m.Handle); e != nil {
					t.Fatal("idempotent installed delete", e)
				}
			})
		}
	})
}

func TestSecretServiceCrashBeforeCreateAndNextGeneration(t *testing.T) {
	secretModes(t, func(t *testing.T, mode string) {
		s, address := privateSecretService(t, mode)
		data := linuxProfile(t)
		ctx := context.Background()
		v := ForProfile(data)
		if e := v.bindCustody(ctx, data, true); e != nil {
			t.Fatal(e)
		}
		s.aliasTo(t, address, testC2)
		if e := ForProfile(data).Delete(ctx, linuxTestHandle); e != nil {
			t.Fatal("pre-CreateItem crash not recoverable", e)
		}
		if e := ForProfile(data).Put(ctx, linuxTestHandle, []byte("synthetic profile authority")); e != nil {
			t.Fatal("new generation refused", e)
		}
		linuxProcess(t, data, "get")
		linuxProcess(t, data, "delete")
	})
}

func TestSecretServiceLostSetSecretReplyRetainsExactIdentity(t *testing.T) {
	secretModes(t, func(t *testing.T, mode string) {
		s, address := privateSecretService(t, mode)
		data := linuxProfile(t)
		ctx := context.Background()
		s.mu.Lock()
		s.loseSetReply = true
		s.mu.Unlock()
		if e := ForProfile(data).Put(ctx, linuxTestHandle, []byte("synthetic profile authority")); e != ErrUnavailable {
			t.Fatal(e)
		}
		m, e := linuxItemRecord(data)
		if e != nil || m.State != "bound" || m.Item == "" {
			t.Fatal("authority sent before path was durable", m, e)
		}
		s.aliasTo(t, address, testC2)
		s.restart(t, address)
		linuxProcess(t, data, "get")
		linuxProcess(t, data, "delete")
		s.mu.Lock()
		count := len(s.collections[testC1])
		s.mu.Unlock()
		if count != 0 {
			t.Fatal("lost SetSecret reply retained authority")
		}
	})
}

func TestSecretServiceSearchAbsenceDoesNotProveRecordedItemDeletion(t *testing.T) {
	secretModes(t, func(t *testing.T, mode string) {
		s, _ := privateSecretService(t, mode)
		data := linuxProfile(t)
		ctx := context.Background()
		if e := ForProfile(data).Put(ctx, linuxTestHandle, []byte("synthetic profile authority")); e != nil {
			t.Fatal(e)
		}
		before, e := linuxEvidence(data)
		if e != nil {
			t.Fatal(e)
		}
		s.mu.Lock()
		s.hideSearch = true
		s.mu.Unlock()
		if e := ForProfile(data).Delete(ctx, linuxTestHandle); e != ErrUnavailable {
			t.Fatal("search absence hid retained item", e)
		}
		after, e := linuxEvidence(data)
		if e != nil || !bytes.Equal(before, after) {
			t.Fatal("refusal changed identity", e)
		}
		s.mu.Lock()
		count := len(s.collections[testC1])
		s.hideSearch = false
		s.mu.Unlock()
		if count != 1 {
			t.Fatal("unexpected item mutation")
		}
		linuxProcess(t, data, "get")
		linuxProcess(t, data, "delete")
	})
}
func TestSecretServiceCrashAfterPhysicalDeleteUsesExactAbsence(t *testing.T) {
	secretModes(t, func(t *testing.T, mode string) {
		s, _ := privateSecretService(t, mode)
		data := linuxProfile(t)
		ctx := context.Background()
		if e := ForProfile(data).Put(ctx, linuxTestHandle, []byte("synthetic profile authority")); e != nil {
			t.Fatal(e)
		}
		m, e := linuxItemRecord(data)
		if e != nil {
			t.Fatal(e)
		}
		s.mu.Lock()
		item := s.collections[testC1][dbus.ObjectPath(m.Item)]
		clear(item.value)
		delete(s.collections[testC1], dbus.ObjectPath(m.Item))
		s.mu.Unlock()
		// Same service owner plus explicit absence at the recorded object path
		// permits retry after Item.Delete but before the deleted record was synced.
		linuxProcess(t, data, "delete")
		m, e = linuxItemRecord(data)
		if e != nil || m.State != "deleted" {
			t.Fatal(m, e)
		}
	})
}

// plant adds an item this profile did not create, as another client would.
func (s *testSecrets) plant(t *testing.T, collection dbus.ObjectPath, attrs map[string]string) dbus.ObjectPath {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.next++
	path := dbus.ObjectPath(fmt.Sprintf("%s/foreign_%d", collection, s.next))
	s.collections[collection][path] = &testSecretItem{attrs, []byte("foreign value")}
	if e := s.conn.Export(testItem{s, collection, path}, path, "org.freedesktop.Secret.Item"); e != nil {
		t.Fatal(e)
	}
	return path
}

func TestSecretServiceCollectionSelection(t *testing.T) {
	for _, kind := range []string{"dedicated-existing", "dedicated-created", "gnome-default", "prompt-default", "gnome-no-default", "create-no-reply"} {
		t.Run(kind, func(t *testing.T) {
			mode := "dedicated"
			if strings.HasPrefix(kind, "gnome") {
				mode = "gnome"
			}
			s, _ := privateSecretService(t, mode)
			data := linuxProfile(t)
			ctx := context.Background()
			s.mu.Lock()
			switch kind {
			case "dedicated-created", "prompt-default", "create-no-reply":
				s.alias = "/"
			case "gnome-no-default":
				s.defaultAlias = "/"
			}
			s.promptCreate = kind == "prompt-default"
			var stall chan struct{}
			if kind == "create-no-reply" {
				stall = make(chan struct{})
				s.stallCreate = stall
			}
			s.mu.Unlock()
			e := ForProfile(data).Put(ctx, linuxTestHandle, []byte("synthetic profile authority"))
			if stall != nil {
				close(stall)
			}
			m, re := linuxItemRecord(data)
			s.mu.Lock()
			creates, collections := s.creates, len(s.collections)
			s.mu.Unlock()
			switch kind {
			case "gnome-no-default", "create-no-reply":
				// Absent default custody or an unanswered creation refuses
				// before any selection, handle or item exists.
				_, me := readLinuxLocation(data)
				if !errors.Is(e, ErrUnavailable) || !os.IsNotExist(re) || !os.IsNotExist(me) || collections != 2 {
					t.Fatal("refusal left state", e, re, collections)
				}
				return
			}
			if e != nil || re != nil || m.State != "ready" {
				t.Fatal(e, re, m)
			}
			want := map[string]struct {
				alias      string
				collection dbus.ObjectPath
				creates    int
			}{
				"dedicated-existing": {collectionAlias, testC1, 0},
				"dedicated-created":  {collectionAlias, "", 1},
				"gnome-default":      {defaultAlias, testC1, 1},
				"prompt-default":     {defaultAlias, testC2, 1},
			}[kind]
			if m.Alias != want.alias || creates != want.creates {
				t.Fatal("selection", m.Alias, creates)
			}
			if want.collection != "" && dbus.ObjectPath(m.Collection) != want.collection {
				t.Fatal("collection", m.Collection)
			}
			if kind == "dedicated-created" && (collections != 3 || !strings.Contains(m.Collection, "/created_")) {
				t.Fatal("dedicated collection not created", m.Collection, collections)
			}
			if kind != "dedicated-created" && collections != 2 {
				t.Fatal("unexpected collection", collections)
			}
			if valid(ctx, m.Creation) != nil {
				t.Fatal("creation value missing")
			}
			s.mu.Lock()
			item := s.collections[dbus.ObjectPath(m.Collection)][dbus.ObjectPath(m.Item)]
			s.mu.Unlock()
			if item == nil || item.attrs["creation"] != m.Creation || item.attrs["handle"] != linuxTestHandle || item.attrs["service"] != service {
				t.Fatal("item not bound by exact attributes", item)
			}
			linuxProcess(t, data, "get")
			linuxProcess(t, data, "delete")
			if m, e = linuxItemRecord(data); e != nil || m.State != "deleted" {
				t.Fatal(m, e)
			}
		})
	}
}

// GNOME's UnknownMethod is accepted only with an empty exact search and an
// item listing that no longer holds the recorded path.
func TestSecretServiceUnknownMethodAloneIsNotDeletionProof(t *testing.T) {
	for _, kind := range []string{"live-item-unknown-method", "listed-but-unsearchable", "items-unreadable"} {
		t.Run(kind, func(t *testing.T) {
			s, _ := privateSecretService(t, "gnome")
			data := linuxProfile(t)
			ctx := context.Background()
			if e := ForProfile(data).Put(ctx, linuxTestHandle, []byte("synthetic profile authority")); e != nil {
				t.Fatal(e)
			}
			before, e := linuxEvidence(data)
			if e != nil {
				t.Fatal(e)
			}
			s.mu.Lock()
			switch kind {
			case "live-item-unknown-method":
				s.unknownMethod, s.ignoreDelete = true, true
			case "listed-but-unsearchable":
				s.unknownMethod, s.ignoreDelete, s.hideSearch = true, true, true
			case "items-unreadable":
				s.itemsFail = true
			}
			s.mu.Unlock()
			if e := ForProfile(data).Delete(ctx, linuxTestHandle); !errors.Is(e, ErrUnavailable) {
				t.Fatal("UnknownMethod alone accepted as deletion", e)
			}
			after, e := linuxEvidence(data)
			if e != nil || !bytes.Equal(before, after) {
				t.Fatal("refusal changed evidence", e)
			}
			s.mu.Lock()
			count := len(s.collections[testC1])
			s.unknownMethod, s.ignoreDelete, s.hideSearch, s.itemsFail = false, false, false, false
			s.mu.Unlock()
			if want := map[bool]int{true: 0, false: 1}[kind == "items-unreadable"]; count != want {
				t.Fatal("unexpected item state", count)
			}
			// With complete evidence available again the retry proves absence.
			linuxProcess(t, data, "delete")
			if m, e := linuxItemRecord(data); e != nil || m.State != "deleted" {
				t.Fatal(m, e)
			}
			s.mu.Lock()
			count = len(s.collections[testC1])
			s.mu.Unlock()
			if count != 0 {
				t.Fatal("retained item", count)
			}
		})
	}
}

// A shared default collection can hold items from other clients. None is ever
// adopted, overwritten or deleted, including one that reuses the handle.
func TestSecretServiceNeverAdoptsForeignItem(t *testing.T) {
	secretModes(t, func(t *testing.T, mode string) {
		t.Run("before-create", func(t *testing.T) {
			s, _ := privateSecretService(t, mode)
			data := linuxProfile(t)
			ctx := context.Background()
			foreign := s.plant(t, testC1, map[string]string{"service": service, "handle": linuxTestHandle})
			if e := ForProfile(data).Put(ctx, linuxTestHandle, []byte("synthetic profile authority")); !errors.Is(e, ErrExists) {
				t.Fatal("foreign item adopted", e)
			}
			if e := ForProfile(data).Delete(ctx, linuxTestHandle); !errors.Is(e, ErrUnavailable) {
				t.Fatal("foreign item deleted", e)
			}
			s.mu.Lock()
			item := s.collections[testC1][foreign]
			s.mu.Unlock()
			if item == nil || string(item.value) != "foreign value" {
				t.Fatal("foreign item changed")
			}
		})
		t.Run("lost-create-reply", func(t *testing.T) {
			s, _ := privateSecretService(t, mode)
			data := linuxProfile(t)
			ctx := context.Background()
			s.mu.Lock()
			s.loseReply = true
			s.mu.Unlock()
			if e := ForProfile(data).Put(ctx, linuxTestHandle, []byte("synthetic profile authority")); e != ErrUnavailable {
				t.Fatal(e)
			}
			m, e := linuxItemRecord(data)
			if e != nil || m.State != "creating" || m.Creation == "" {
				t.Fatal(m, e)
			}
			// Replace the placeholder with an item carrying the same handle but
			// another creation value. Recovery must not bind it.
			s.mu.Lock()
			for path := range s.collections[testC1] {
				delete(s.collections[testC1], path)
			}
			s.mu.Unlock()
			foreign := s.plant(t, testC1, map[string]string{"service": service, "handle": linuxTestHandle, "creation": strings.Repeat("0", 32)})
			if b, e := ForProfile(data).Get(ctx, linuxTestHandle); e == nil || len(b) != 0 {
				clear(b)
				t.Fatal("foreign item bound by search", e)
			}
			linuxProcess(t, data, "delete")
			s.mu.Lock()
			item := s.collections[testC1][foreign]
			s.mu.Unlock()
			if item == nil || string(item.value) != "foreign value" {
				t.Fatal("foreign item deleted")
			}
			if m, e = linuxItemRecord(data); e != nil || m.State != "deleted" || m.Item != "" {
				t.Fatal(m, e)
			}
		})
	})
}
