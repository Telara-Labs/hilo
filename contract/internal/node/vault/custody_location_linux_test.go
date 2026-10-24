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
type testSecrets struct {
	mu           sync.Mutex
	conn         *dbus.Conn
	alias        dbus.ObjectPath
	collections  map[dbus.ObjectPath]map[dbus.ObjectPath]*testSecretItem
	next         int
	beforeCreate func() error
	loseReply    bool
	loseSetReply bool
	hideSearch   bool
	beforeSet    func() error
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
func (s *testSecrets) ReadAlias(_ string) (dbus.ObjectPath, *dbus.Error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.alias, nil
}
func (s *testSecrets) SetAlias(_ string, path dbus.ObjectPath) *dbus.Error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.collections[path] == nil {
		return testBusError()
	}
	s.alias = path
	return nil
}
func (c testCollection) Get(iface, prop string) (dbus.Variant, *dbus.Error) {
	if iface != "org.freedesktop.Secret.Collection" || prop != "Locked" {
		return dbus.Variant{}, testBusError()
	}
	return dbus.MakeVariant(false), nil
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
		return "/", testBusError()
	}
	clear(item.value)
	delete(i.s.collections[i.collection], i.path)
	return "/", nil
}

const testC1 dbus.ObjectPath = "/org/freedesktop/secrets/collection/first"
const testC2 dbus.ObjectPath = "/org/freedesktop/secrets/collection/second"
const linuxTestHandle = "0123456789abcdef0123456789abcdef"

func privateSecretService(t *testing.T) (*testSecrets, string) {
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
	s := &testSecrets{alias: testC1, collections: map[dbus.ObjectPath]map[dbus.ObjectPath]*testSecretItem{testC1: {}, testC2: {}}}
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
	if e = c.Object(secretService, secretRoot).Call("org.freedesktop.Secret.Service.SetAlias", 0, collectionAlias, path).Err; e != nil {
		t.Fatal(e)
	}
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
	for _, admitted := range []bool{false, true} {
		t.Run(fmt.Sprint(admitted), func(t *testing.T) {
			s, address := privateSecretService(t)
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
				m, e := readLinuxLocation(data)
				if e != nil || m.State != "creating" || m.Handle != linuxTestHandle || m.Collection != string(testC1) || m.Item != "" {
					return errors.New("creation intent missing")
				}
				return nil
			}
			s.beforeSet = func() error {
				m, e := readLinuxLocation(data)
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
			m, e = readLinuxLocation(data)
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
}
func TestSecretServiceRecordedIdentityAcrossServiceRestart(t *testing.T) {
	s, address := privateSecretService(t)
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
}
func TestSecretServiceLostIdentityRefusesCleanup(t *testing.T) {
	for _, kind := range []string{"missing-location", "corrupt-location", "missing-item-after-restart", "reassigned-item-path", "missing-collection"} {
		t.Run(kind, func(t *testing.T) {
			s, address := privateSecretService(t)
			data := linuxProfile(t)
			ctx := context.Background()
			if e := ForProfile(data).Put(ctx, linuxTestHandle, []byte("synthetic profile authority")); e != nil {
				t.Fatal(e)
			}
			m, e := readLinuxLocation(data)
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
			before, _ := os.ReadFile(filepath.Join(data, custodyLocationFile))
			if e := ForProfile(data).Delete(ctx, linuxTestHandle); !errors.Is(e, ErrUnavailable) {
				t.Fatal("lost identity accepted as deletion", e)
			}
			after, _ := os.ReadFile(filepath.Join(data, custodyLocationFile))
			if !bytes.Equal(before, after) {
				t.Fatal("refusal changed evidence")
			}
		})
	}
}
func TestSecretServiceInterruptedCreationUsesOriginalCollection(t *testing.T) {
	s, address := privateSecretService(t)
	data := linuxProfile(t)
	ctx := context.Background()
	s.mu.Lock()
	s.loseReply = true
	s.mu.Unlock()
	if e := ForProfile(data).Put(ctx, linuxTestHandle, []byte("synthetic profile authority")); e != ErrUnavailable {
		t.Fatal(e)
	}
	m, e := readLinuxLocation(data)
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
	// Installed images deliberately forbid mutable ancestors, including /tmp.
	homeBase, e := os.UserHomeDir()
	if e != nil {
		t.Fatal(e)
	}
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
	return r
}
func TestSecretServiceInstalledAuthorityReassignmentBeforeAndAfterLoad(t *testing.T) {
	for _, loaded := range []bool{false, true} {
		t.Run(fmt.Sprint(loaded), func(t *testing.T) {
			s, address := privateSecretService(t)
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
			m, e := readLinuxLocation(data)
			if e != nil || m.State != "ready" {
				t.Fatal(m, e)
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
}

func TestSecretServiceCrashBeforeCreateAndNextGeneration(t *testing.T) {
	s, address := privateSecretService(t)
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
}

func TestSecretServiceLostSetSecretReplyRetainsExactIdentity(t *testing.T) {
	s, address := privateSecretService(t)
	data := linuxProfile(t)
	ctx := context.Background()
	s.mu.Lock()
	s.loseSetReply = true
	s.mu.Unlock()
	if e := ForProfile(data).Put(ctx, linuxTestHandle, []byte("synthetic profile authority")); e != ErrUnavailable {
		t.Fatal(e)
	}
	m, e := readLinuxLocation(data)
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
}

func TestSecretServiceSearchAbsenceDoesNotProveRecordedItemDeletion(t *testing.T) {
	s, _ := privateSecretService(t)
	data := linuxProfile(t)
	ctx := context.Background()
	if e := ForProfile(data).Put(ctx, linuxTestHandle, []byte("synthetic profile authority")); e != nil {
		t.Fatal(e)
	}
	before, e := os.ReadFile(filepath.Join(data, custodyLocationFile))
	if e != nil {
		t.Fatal(e)
	}
	s.mu.Lock()
	s.hideSearch = true
	s.mu.Unlock()
	if e := ForProfile(data).Delete(ctx, linuxTestHandle); e != ErrUnavailable {
		t.Fatal("search absence hid retained item", e)
	}
	after, e := os.ReadFile(filepath.Join(data, custodyLocationFile))
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
}
func TestSecretServiceCrashAfterPhysicalDeleteUsesExactAbsence(t *testing.T) {
	s, _ := privateSecretService(t)
	data := linuxProfile(t)
	ctx := context.Background()
	if e := ForProfile(data).Put(ctx, linuxTestHandle, []byte("synthetic profile authority")); e != nil {
		t.Fatal(e)
	}
	m, e := readLinuxLocation(data)
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
	m, e = readLinuxLocation(data)
	if e != nil || m.State != "deleted" {
		t.Fatal(m, e)
	}
}
