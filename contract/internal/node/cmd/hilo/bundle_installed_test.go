//go:build darwin || linux

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/Telara-Labs/hilo/contract/internal/node/bundle"
	"github.com/Telara-Labs/hilo/contract/internal/node/daemon"
	"github.com/Telara-Labs/hilo/contract/internal/node/disclosure"
	"github.com/Telara-Labs/hilo/contract/internal/node/ipc"
	"github.com/Telara-Labs/hilo/contract/internal/node/mcp"
	"github.com/Telara-Labs/hilo/contract/internal/node/store"
	nodesync "github.com/Telara-Labs/hilo/contract/internal/node/sync"
	"github.com/Telara-Labs/hilo/contract/internal/node/syncnode"
	"github.com/Telara-Labs/hilo/contract/jcs"
	"github.com/Telara-Labs/hilo/contract/record"
	"github.com/Telara-Labs/hilo/contract/sig"
	"github.com/Telara-Labs/hilo/contract/transport"
)

// bundleDevice is one real profile: actual SQLite store, disclosure, capture
// and daemon. Only the OS vault and the peer image check are doubles.
type bundleDevice struct {
	t     *testing.T
	paths ipc.Paths
	home  string
	vault *eraseVault
	node  *installedNode
}

var bundleVaults = struct {
	sync.Mutex
	m map[string]*eraseVault
}{m: map[string]*eraseVault{}}

// useBundleVaults routes the bundle command's vault to each device's double.
func useBundleVaults(t *testing.T) {
	t.Helper()
	old := bundleVault
	bundleVault = func(dir string) bundle.Vault {
		bundleVaults.Lock()
		defer bundleVaults.Unlock()
		return bundleVaults.m[dir]
	}
	// Cheap scrypt keeps the many backup cases fast; the recipient type and
	// sole-recipient rule are unchanged.
	oldWork := bundle.ScryptWorkFactor
	bundle.ScryptWorkFactor = 10
	t.Cleanup(func() { bundleVault, bundle.ScryptWorkFactor = old, oldWork })
}

func newBundleProfile(t *testing.T) *bundleDevice {
	t.Helper()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(base, 0700); err != nil {
		t.Fatal(err)
	}
	p, err := ipc.Resolve(filepath.Join(base, "data"), filepath.Join(base, "run"))
	if err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(base, "home")
	if err = os.MkdirAll(home, 0700); err != nil {
		t.Fatal(err)
	}
	d := &bundleDevice{t: t, paths: p, home: home, vault: &eraseVault{}}
	bundleVaults.Lock()
	bundleVaults.m[p.Data] = d.vault
	bundleVaults.Unlock()
	return d
}

func newGenesisDevice(t *testing.T) *bundleDevice {
	t.Helper()
	d := newBundleProfile(t)
	if err := disclosure.BootstrapInstalled(context.Background(), d.paths.Data, "Bundle test", disclosure.Grant{Repos: disclosure.AllLocalRepos(), Channels: []disclosure.Channel{disclosure.S}}, disclosure.TaskWriteGrant{Repos: disclosure.AllLocalRepos(), AllowUnscoped: true, Actions: []disclosure.TaskMutation{disclosure.Create, disclosure.Checkpoint}}, d.vault); err != nil {
		t.Fatal(err)
	}
	return d
}

// start runs the real daemon over this profile, as installation would.
func (d *bundleDevice) start() *installedNode {
	t := d.t
	t.Helper()
	provider := mcp.InstalledRuntimeProvider{Provider: disclosure.InstalledProvider{Dir: d.paths.Data, Vault: d.vault, Peers: erasePeer{}}, CaptureHome: d.home}
	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- daemon.Run(ctx, daemon.Config{Paths: d.paths, Ready: func() { close(ready) }, Open: installedOpener(d.paths.Data, "", provider)})
	}()
	select {
	case <-ready:
	case err := <-done:
		cancel()
		t.Fatal(err)
	case <-time.After(10 * time.Second):
		cancel()
		t.Fatal("daemon not ready")
	}
	var once sync.Once
	n := &installedNode{t: t, paths: d.paths, home: d.home}
	n.stop = func() {
		once.Do(func() {
			cancel()
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				t.Error("daemon did not stop")
			}
		})
	}
	t.Cleanup(n.stop)
	d.node = n
	return n
}

func (d *bundleDevice) stop() {
	if d.node != nil {
		d.node.stop()
		d.node = nil
	}
}

// cli runs one real command line in process.
func (d *bundleDevice) cli(stdin string, args ...string) (string, error) {
	var out bytes.Buffer
	full := append([]string{args[0], args[1], "--data-dir", d.paths.Data}, args[2:]...)
	err := run(context.Background(), full, strings.NewReader(stdin), &out)
	return out.String(), err
}

func (d *bundleDevice) mustCLI(stdin string, args ...string) string {
	d.t.Helper()
	out, err := d.cli(stdin, args...)
	if err != nil {
		d.t.Fatalf("%v: %s\n%s", args, publicCode(err), out)
	}
	return out
}

func (d *bundleDevice) identity() bundle.Identity {
	d.t.Helper()
	id, err := bundle.ProfileIdentity(d.paths.Data)
	if err != nil {
		d.t.Fatal(err)
	}
	return id
}

// deviceKey reads this profile's signing key from its vault double.
func (d *bundleDevice) deviceKey() ed25519.PrivateKey {
	d.t.Helper()
	_, _, key, err := disclosure.InstalledDeviceKey(context.Background(), d.paths.Data, d.vault)
	if err != nil {
		d.t.Fatal(err)
	}
	return key
}

// joinDevice runs the complete invite, join, add-device and enroll exchange.
func joinDevice(t *testing.T, surviving *bundleDevice) *bundleDevice {
	t.Helper()
	fresh := newBundleProfile(t)
	invite := surviving.mustCLI("", "bundle", "invite")
	joined := fresh.mustCLI(invite, "bundle", "join")
	request := joined[:strings.IndexByte(joined, '\n')+1]
	var q bundle.JoinRequest
	if err := json.Unmarshal([]byte(request), &q); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(joined, "Verification code "+q.Code+"\n") || !strings.Contains(joined, noSurvivingDeviceLimit) {
		t.Fatal("join did not show the code and the limit", joined)
	}
	if _, err := surviving.cli(request, "bundle", "add-device", "--code", "wrong code words here now please"); publicCode(err) != "verification_code_mismatch" {
		t.Fatal("mismatched code co-signed", err)
	}
	enrollment := surviving.mustCLI(request, "bundle", "add-device", "--code", q.Code)
	out := fresh.mustCLI(enrollment, "bundle", "enroll")
	if !strings.Contains(out, `"state":"enrolled"`) {
		t.Fatal(out)
	}
	return fresh
}

type typedRecord struct{ id, kind string }

func dataRecords(t *testing.T, dir string) []typedRecord {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(dir, "memory.sqlite")+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, err := db.Query("SELECT id,json_extract(CAST(header AS TEXT),'$.type') FROM record ORDER BY seq")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []typedRecord
	for rows.Next() {
		var r typedRecord
		if rows.Scan(&r.id, &r.kind) != nil {
			t.Fatal("scan")
		}
		switch record.Kind(r.kind) {
		case record.KindKeyOp, record.KindErasure, record.KindRetraction, record.KindPolicy:
			continue
		}
		out = append(out, r)
	}
	return out
}

func idsOf(rs []typedRecord) []string {
	var out []string
	for _, r := range rs {
		out = append(out, r.id)
	}
	return out
}

func withIDs(args []string, ids []string) []string {
	for _, id := range ids {
		args = append(args, "--id", id)
	}
	return args
}

// trustEachOther exchanges export keys both ways after code comparison.
func trustOffer(t *testing.T, from, to *bundleDevice) bundle.Offer {
	t.Helper()
	raw := from.mustCLI("", "bundle", "key")
	var o bundle.Offer
	if err := json.Unmarshal([]byte(raw), &o); err != nil {
		t.Fatal(err)
	}
	if _, err := to.cli(raw, "bundle", "trust", "--code", "not the code"); publicCode(err) != "verification_code_mismatch" {
		t.Fatal("untyped code trusted", err)
	}
	to.mustCLI(raw, "bundle", "trust", "--code", o.Code)
	return o
}

func plantTask(t *testing.T, n *installedNode, canary string) {
	t.Helper()
	created := n.callTool("telara_task_create", map[string]any{"goal": "Investigate the " + canary + " fixture"})
	text := strings.ReplaceAll(created.Content[0].Text, `-`, "-")
	var task string
	for _, f := range strings.FieldsFunc(text, func(r rune) bool { return !(r == '-' || r >= '0' && r <= '9' || r >= 'a' && r <= 'f') }) {
		if record.IsUUIDv4(f) {
			task = f
		}
	}
	if task == "" {
		t.Fatal("no task id", text)
	}
	n.callTool("telara_task_checkpoint", map[string]any{"task_id": task, "milestone": "checkpoint " + canary, "next_steps": "resume " + canary})
}

func checkLimits(t *testing.T, out string, want ...string) {
	t.Helper()
	for _, w := range want {
		if !strings.Contains(out, w) {
			t.Fatalf("output lacks %q\n%s", w, out)
		}
	}
}

// TestV20TransferRestoreAfterDeviceAddAndExactErasure exports explicitly
// selected task, checkpoint and call records to a device added by a co-signed
// device_add, restores them through the receiver's normal admission path,
// restarts it, erases the checkpoint by exact id with the erase command and
// requires the restored bytes gone from every file and FTS shadow table.
func TestV20TransferRestoreAfterDeviceAddAndExactErasure(t *testing.T) {
	useBundleVaults(t)
	a := newGenesisDevice(t)
	an := a.start()
	canary := "transferredquokkalanterncanary"
	plantTask(t, an, canary)
	records := dataRecords(t, a.paths.Data)
	kinds := map[string]bool{}
	for _, r := range records {
		kinds[r.kind] = true
	}
	if !kinds["task"] || !kinds["checkpoint"] || !kinds["call"] {
		t.Fatalf("expected task, checkpoint and call records, have %v", kinds)
	}

	b := joinDevice(t, a)
	bID := b.identity()
	if bID.Device == bID.Genesis || bID.Genesis != a.identity().Genesis {
		t.Fatal("joined device identity", bID)
	}
	file := filepath.Join(t.TempDir(), "transfer.age")
	// An untrusted recipient is refused before anything is written.
	if _, err := a.cli("", withIDs([]string{"bundle", "export", "--to", strings.Repeat("cd", 16), "--out", file}, idsOf(records))...); publicCode(err) != "bundle_recipient_invalid" {
		t.Fatal("export to an unverified export key", err)
	}
	// Selecting a call without its commitment root never auto-adds the root.
	var callID string
	for _, r := range records {
		if r.kind == "call" {
			callID = r.id
		}
	}
	partial := filepath.Join(t.TempDir(), "partial.age")
	out := a.mustCLI("", "bundle", "export", "--to", bID.Device, "--out", partial, "--id", callID, "--json")
	var partialReport bundleReport
	if err := json.Unmarshal([]byte(out), &partialReport); err != nil || partialReport.Data != 0 || len(partialReport.Excluded) != 1 || partialReport.Excluded[0].Reason != store.ExcludedLineageIncomplete {
		t.Fatal("call exported without its selected root", out, err)
	}

	out = a.mustCLI("", withIDs([]string{"bundle", "export", "--to", bID.Device, "--out", file}, idsOf(records))...)
	checkLimits(t, out, "Transfer bundle written", noSurvivingDeviceLimit, unmanagedCopyNotice)
	sealed, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, []byte(canary)) || !bytes.HasPrefix(sealed, []byte("age-encryption.org/v1\n-> X25519 ")) {
		t.Fatal("transfer bundle is not an X25519 age file")
	}
	// The exporting device cannot open a bundle sealed only to the target.
	if _, err = a.cli("", "bundle", "restore", "--in", file); publicCode(err) != "export_key_unavailable" && publicCode(err) != "bundle_decrypt_failed" {
		t.Fatal("non-recipient opened the bundle", err)
	}

	out = b.mustCLI("", "bundle", "restore", "--in", file, "--json")
	var restored bundleReport
	if err = json.Unmarshal([]byte(out), &restored); err != nil || restored.Data != len(records) || restored.Facts == 0 || len(restored.Excluded) != 0 || restored.Fenced {
		t.Fatal("restore did not admit every selected record with its exposure facts", out, err)
	}
	if len(restored.Limits) != 2 || restored.Limits[0] != rollbackWarning || restored.Limits[1] != noSurvivingDeviceLimit {
		t.Fatal("restore limits", restored.Limits)
	}
	for _, r := range records {
		if e := snapshotOf(t, b, r.id); e.State != "live" || e.BodyJCS == nil {
			t.Fatalf("restored %s %s is %q", r.kind, r.id[:8], e.State)
		}
	}
	bn := b.start()
	if hits := bn.filesContaining(canary); len(hits) == 0 {
		t.Fatal("restored bytes never reached the receiver")
	}
	// Restored fields carry no completeness facts from this device's own
	// builder, so the receiver never indexes them; its index stays clean.
	if hits := bn.ftsShadowHits(canary); len(hits) != 0 {
		t.Fatal("unclassified restored fields were indexed", hits)
	}
	// Restart the receiver before erasing.
	b.stop()
	bn = b.start()
	var checkpoint string
	for _, r := range records {
		if r.kind == "checkpoint" {
			checkpoint = r.id
		}
	}
	args := []string{"erase", "--data-dir", b.paths.Data, "--run-dir", b.paths.Run, "--yes", "--json", "--id", checkpoint}
	var receipt bytes.Buffer
	if err = run(context.Background(), args, strings.NewReader(""), &receipt); err != nil {
		t.Fatal(publicCode(err), receipt.String())
	}
	if !strings.Contains(receipt.String(), "bundle and backup files exported before this erasure") {
		t.Fatal("erasure receipt does not disclose exported bundles", receipt.String())
	}
	db := bn.db()
	var n int
	if err = db.QueryRow("SELECT count(*) FROM record_body WHERE id IN(?,?)", checkpoint, callID).Scan(&n); err != nil || n != 0 {
		t.Fatal("restored checkpoint or its call survived exact checkpoint erasure", n, err)
	}
	db.Close()
	// The call's checkpoint text is gone everywhere; only the task keeps the goal.
	if hits := bn.filesContaining("checkpoint " + canary); len(hits) != 0 {
		t.Fatal("restored checkpoint bytes remain in", hits)
	}
	if hits := bn.ftsShadowHits("resume " + canary); len(hits) != 0 {
		t.Fatal("restored checkpoint bytes remain in FTS", hits)
	}
	// A rollback restore of the same older bundle cannot resurrect them.
	b.stop()
	checkLimits(t, b.mustCLI("", "bundle", "restore", "--in", file), "Restore complete", rollbackWarning, noSurvivingDeviceLimit)
	bn = b.start()
	if hits := bn.filesContaining("checkpoint " + canary); len(hits) != 0 {
		t.Fatal("rollback restore resurrected erased bytes in", hits)
	}

	// The same restored standalone full body is refused by hosted PUSH framing.
	snap := snapshotOf(t, b, checkpoint)
	if snap.BodyJCS != nil {
		t.Fatal("erased body served")
	}
	sel := selectionOf(t, a, []string{records[0].id})
	r, err := record.Parse(sel.Data[0].HeaderJCS, sel.Data[0].BodyJCS, sel.Data[0].AdvisoryID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = nodesync.NewOperation("bundle-only-body", []nodesync.SignedRecord{{Record: r, Sigs: sel.Data[0].Sigs}}); err == nil {
		t.Fatal("bundle-only full body accepted for hosted PUSH")
	}
}

func snapshotOf(t *testing.T, d *bundleDevice, id string) store.Entry {
	t.Helper()
	ident := d.identity()
	st, err := store.Open(context.Background(), store.Options{Dir: d.paths.Data, PinnedGenesisID: ident.Genesis, LocalMachineID: ident.Machine})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	snap, err := st.Snapshot(context.Background(), store.ReadRequest{IDs: []string{id}})
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range snap.Entries {
		if e.ID == id {
			return e
		}
	}
	t.Fatal("not present", id)
	return store.Entry{}
}

func selectionOf(t *testing.T, d *bundleDevice, ids []string) store.BundleSelection {
	t.Helper()
	ident := d.identity()
	st, err := store.Open(context.Background(), store.Options{Dir: d.paths.Data, PinnedGenesisID: ident.Genesis, LocalMachineID: ident.Machine})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	sel, err := st.SelectBundle(context.Background(), ids)
	if err != nil {
		t.Fatal(err)
	}
	return sel
}

// keyForms returns the encodings in which a secret could be copied.
func keyForms(secret []byte) [][]byte {
	forms := [][]byte{secret, []byte(hex.EncodeToString(secret)), []byte(base64.RawURLEncoding.EncodeToString(secret)), []byte(base64.StdEncoding.EncodeToString(secret)), []byte(base64.RawStdEncoding.EncodeToString(secret))}
	if len(secret) == ed25519.PrivateKeySize {
		forms = append(forms, keyForms(secret[:32])...)
	}
	return forms
}

func scanForbidden(t *testing.T, where string, haystack []byte, forbidden map[string][][]byte) {
	t.Helper()
	for name, forms := range forbidden {
		for _, f := range forms {
			if len(f) >= 16 && bytes.Contains(haystack, f) {
				t.Fatalf("%s contains %s", where, name)
			}
		}
	}
}

func scanDataDir(t *testing.T, dir string, forbidden map[string][][]byte) {
	t.Helper()
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || !d.Type().IsRegular() {
			return err
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		scanForbidden(t, path, b, forbidden)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestV20PhysicalBundleInspectionHasNoKeysOrGrantedData plants every secret a
// profile holds (device signing key, client credential token, export key and
// hosted DPoP key) plus tenant-granted policy and key records, then byte-scans
// the sealed file, the decrypted NDJSON and, after a restore into a fresh
// joined data directory, its database, WAL and FTS shadow tables.
func TestV20PhysicalBundleInspectionHasNoKeysOrGrantedData(t *testing.T) {
	useBundleVaults(t)
	ctx := context.Background()
	a := newGenesisDevice(t)
	an := a.start()
	canary := "inspectedmarmotharpsichordcanary"
	plantTask(t, an, canary)
	records := dataRecords(t, a.paths.Data)
	an.stop()
	a.node = nil
	b := joinDevice(t, a)
	if _, err := syncnode.CreateKey(ctx, a.paths.Data, a.vault); err != nil {
		t.Fatal(err)
	}
	a.mustCLI("", "bundle", "key")
	trustOffer(t, b, a)

	forbidden := map[string][][]byte{}
	for _, dev := range []*bundleDevice{a, b} {
		dev.vault.mu.Lock()
		for handle, secret := range dev.vault.values {
			forbidden["vault secret "+handle] = keyForms(append([]byte(nil), secret...))
			if len(secret) == 96 {
				forbidden["device key "+handle] = keyForms(append([]byte(nil), secret[:64]...))
				forbidden["credential token "+handle] = keyForms(append([]byte(nil), secret[64:]...))
			}
			if strings.HasPrefix(string(secret), "AGE-SECRET-KEY-1") {
				forbidden["export key "+handle] = [][]byte{secret, bytes.ToLower(secret)}
			}
		}
		dev.vault.mu.Unlock()
	}
	if len(forbidden) < 6 {
		t.Fatalf("expected planted secrets on both devices, have %d", len(forbidden))
	}

	// First bundle: permitted content, no tenant.
	file := filepath.Join(t.TempDir(), "first.age")
	a.mustCLI("", withIDs([]string{"bundle", "export", "--to", b.identity().Device, "--out", file}, idsOf(records))...)

	// Plant tenant-granted records: an installed tenant policy root, its
	// signed policy and their per-record salt.
	tenantCanary := "repo-tenantgrantedpelicancanary"
	policyKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{77}, 32))
	pub := policyKey.Public().(ed25519.PublicKey)
	ident := a.identity()
	st, err := store.Open(ctx, store.Options{Dir: a.paths.Data, PinnedGenesisID: ident.Genesis, LocalMachineID: ident.Machine})
	if err != nil {
		t.Fatal(err)
	}
	root, err := sig.BuildKeyOp(record.KeyOpBody{Op: record.OpTenantKey, Subject: sig.KeyRefOf(pub, record.RolePolicy, ""), Genesis: "tenant-bundle"}, pub, "", time.Now().UnixMilli(), policyKey)
	if err != nil {
		t.Fatal(err)
	}
	if err = st.InstallTenantPolicyContext(ctx, store.TenantPolicyContext{Tenant: "tenant-bundle", UserID: "bundle-user", Origin: "https://tenant.example", Root: store.SignedRecord{HeaderJCS: root.Rec.HeaderJCS, BodyJCS: root.Rec.BodyJCS, Sigs: root.Sigs, AdvisoryID: root.Rec.ID}}); err != nil {
		t.Fatal(err)
	}
	pb := &record.PolicyBody{Tenant: "tenant-bundle", Seq: 1, IssuedAt: time.Now().UnixMilli() - 1000, NotAfter: time.Now().UnixMilli() + 3600000, RefreshAfter: time.Now().UnixMilli() + 1800000}
	pb.Applies.Users = []string{"bundle-user"}
	pb.Push.AllowRepos = []string{tenantCanary}
	pr, err := record.Build(record.Header{Type: record.KindPolicy, LID: record.PolicyLID(pb.Tenant), At: time.Now().UnixMilli(), Author: record.Author{KeyID: sig.KeyID(pub)}, Prov: record.ProvUser, Red: record.Redact{Profile: record.ProfileLocal}}, pb)
	if err != nil {
		t.Fatal(err)
	}
	psg, err := sig.SignRecord(policyKey, pr.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = st.Append(ctx, store.SignedRecord{HeaderJCS: pr.HeaderJCS, BodyJCS: pr.BodyJCS, Sigs: []record.Signature{psg}, AdvisoryID: pr.ID}); err != nil {
		t.Fatal(err)
	}
	st.Close()
	var policyBody map[string]any
	if err = json.Unmarshal(pr.BodyJCS, &policyBody); err != nil {
		t.Fatal(err)
	}
	forbidden["tenant policy body"] = [][]byte{pr.BodyJCS, []byte(tenantCanary)}
	forbidden["tenant policy salt"] = [][]byte{[]byte(policyBody["salt"].(string))}
	forbidden["tenant key record"] = [][]byte{root.Rec.BodyJCS}
	forbidden["policy key seed"] = keyForms(policyKey)

	// Second bundle under an active tenant policy: governed full bodies are
	// denied, while the keyring still transfers.
	second := filepath.Join(t.TempDir(), "second.age")
	out := a.mustCLI("", withIDs([]string{"bundle", "export", "--to", b.identity().Device, "--out", second, "--json"}, idsOf(records))...)
	var rep bundleReport
	if err = json.Unmarshal([]byte(out), &rep); err != nil || rep.Data != 0 || rep.Keyring < 2 {
		t.Fatal("governed full bodies exported", out, err)
	}
	for _, e := range rep.Excluded {
		if e.Reason != store.ExcludedPolicy {
			t.Fatal("unexpected exclusion", e)
		}
	}

	bIdentity, err := bundle.LoadExportIdentity(ctx, b.paths.Data, b.vault, b.identity())
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{file, second} {
		sealed, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		scanForbidden(t, "sealed "+filepath.Base(f), sealed, forbidden)
		if bytes.Contains(sealed, []byte(canary)) {
			t.Fatal("sealed bundle shows content")
		}
		plain, kinds, err := bundle.OpenTransfer(sealed, bIdentity)
		if err != nil || len(kinds) != 1 || kinds[0] != "x25519" {
			t.Fatal(kinds, err)
		}
		scanForbidden(t, "decrypted "+filepath.Base(f), plain, forbidden)
		c, err := bundle.Decode(plain, ident.Genesis)
		if err != nil {
			t.Fatal(err)
		}
		// Every per-record salt travels only inside its complete signed body.
		head := plain[:bytes.IndexByte(plain, '\n')]
		for _, part := range [][]store.SignedRecord{c.Keyring, c.Controls, c.Data} {
			for _, r := range part {
				if r.BodyJCS == nil {
					t.Fatal("incomplete carried record")
				}
				var body map[string]any
				if json.Unmarshal(r.BodyJCS, &body) != nil {
					t.Fatal("body")
				}
				if salt, ok := body["salt"].(string); ok {
					if bytes.Contains(r.HeaderJCS, []byte(salt)) || bytes.Contains(head, []byte(salt)) || bytes.Contains(plain, []byte(salt)) {
						t.Fatal("salt outside its encoded complete body")
					}
				}
				if p, err := record.Parse(r.HeaderJCS, r.BodyJCS, r.AdvisoryID); err != nil || p.Header.Prov == record.ProvGateway || p.Header.Pol != "" {
					t.Fatal("granted or governed record carried", err)
				}
			}
		}
		if f == file {
			if len(c.Data) != len(records) {
				t.Fatalf("first bundle carried %d of %d records", len(c.Data), len(records))
			}
			found := false
			for _, r := range c.Data {
				found = found || bytes.Contains(r.BodyJCS, []byte(canary))
			}
			if !found || bytes.Contains(plain, []byte(canary)) {
				t.Fatal("permitted content is not carried only inside its encoded body")
			}
		}
	}

	b.mustCLI("", "bundle", "restore", "--in", file)
	bn := b.start()
	if hits := bn.filesContaining(canary); len(hits) == 0 {
		t.Fatal("restore did not reach the receiver")
	}
	bn.stop()
	b.node = nil
	scanDataDir(t, b.paths.Data, forbidden)
	db, err := sql.Open("sqlite", "file:"+filepath.Join(b.paths.Data, "memory.sqlite")+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	tables, err := db.Query("SELECT name FROM sqlite_master WHERE type='table'")
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for tables.Next() {
		var name string
		tables.Scan(&name)
		names = append(names, name)
	}
	tables.Close()
	shadow := 0
	for _, name := range names {
		if strings.HasPrefix(name, "search") {
			shadow++
		}
		rows, err := db.Query("SELECT * FROM \"" + name + "\"")
		if err != nil {
			continue
		}
		cols, _ := rows.Columns()
		for rows.Next() {
			vals := make([]any, len(cols))
			ptrs := make([]any, len(cols))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			rows.Scan(ptrs...)
			for _, v := range vals {
				switch x := v.(type) {
				case []byte:
					scanForbidden(t, "table "+name, x, forbidden)
				case string:
					scanForbidden(t, "table "+name, []byte(x), forbidden)
				}
			}
		}
		rows.Close()
	}
	if shadow < 2 {
		t.Fatal("FTS shadow tables were not inspected")
	}
	var tenantRows int
	if err = db.QueryRow("SELECT (SELECT count(*) FROM tenant_policy)+(SELECT count(*) FROM tenant_key)+(SELECT count(*) FROM tenant_context)").Scan(&tenantRows); err != nil || tenantRows != 0 {
		t.Fatal("tenant-granted state reached the receiver", tenantRows, err)
	}
}

// sealedFor frames lines exactly as a bundle under a manifest signed by key,
// then seals them to recipient. Tests use it to build hostile bundles that a
// compromised or buggy exporter could send.
func sealedFor(t *testing.T, key ed25519.PrivateKey, genesis string, keyring, facts, controls, data [][]byte, recipient string, mutate func(*transport.Manifest)) []byte {
	t.Helper()
	var lines [][]byte
	for _, part := range [][][]byte{keyring, facts, controls, data} {
		lines = append(lines, part...)
	}
	m := transport.Manifest{Bundle: "mnc/3", CreatedAt: time.Now().UnixMilli(), ExporterKeyID: sig.KeyID(key.Public().(ed25519.PublicKey)), Genesis: genesis, Keyring: len(keyring), Exposures: len(facts), Control: len(controls), Data: len(data), ItemsDigest: transport.ItemsDigest(lines)}
	if mutate != nil {
		mutate(&m)
	}
	unsigned, err := jcs.MarshalRecord(m)
	if err != nil {
		t.Fatal(err)
	}
	m.Sigs = []record.Signature{sig.Sign(key, sig.CtxBundle, sig.BundleMessage(unsigned))}
	head, err := jcs.MarshalRecord(m)
	if err != nil {
		t.Fatal(err)
	}
	var plain bytes.Buffer
	plain.Write(head)
	plain.WriteByte('\n')
	for _, l := range lines {
		plain.Write(l)
		plain.WriteByte('\n')
	}
	sealed, err := bundle.SealTransfer(plain.Bytes(), []string{recipient})
	if err != nil {
		t.Fatal(err)
	}
	return sealed
}

func envelopeLines(t *testing.T, rs []store.SignedRecord) [][]byte {
	t.Helper()
	var out [][]byte
	for _, r := range rs {
		line, err := jcs.MarshalRecord(nodesync.Envelope(r.HeaderJCS, r.BodyJCS, r.Sigs, r.AdvisoryID))
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, line)
	}
	return out
}

func writeTemp(t *testing.T, name string, b []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, b, 0600); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestV20RefusalsCannotClearHolds covers tamper, foreign genesis, bad tags,
// unknown origins, false completeness, policy expiry on import, wrong
// passphrases, wrong modes, mixed recipients and devices without a co-signed
// device_add. A held restore stays held through every one of them.
func TestV20RefusalsCannotClearHolds(t *testing.T) {
	useBundleVaults(t)
	ctx := context.Background()
	a := newGenesisDevice(t)
	an := a.start()
	canary := "refusedwalrusmandolincanary"
	plantTask(t, an, canary)
	records := dataRecords(t, a.paths.Data)
	an.stop()
	a.node = nil
	b := joinDevice(t, a)
	bID := b.identity()
	aID := a.identity()
	key := a.deviceKey()
	defer clear(key)
	sel := selectionOf(t, a, idsOf(records))
	if len(sel.Data) != len(records) {
		t.Fatal(sel.Excluded)
	}
	var offer bundle.Offer
	if err := json.Unmarshal([]byte(b.mustCLI("", "bundle", "key")), &offer); err != nil {
		t.Fatal(err)
	}
	keyring, data := envelopeLines(t, sel.Keyring), envelopeLines(t, sel.Data)

	// Hosted-enrolled receiver: the first restore is held until a control
	// enforcement pass. Nothing below may release that hold.
	if _, err := syncnode.CreateKey(ctx, b.paths.Data, b.vault); err != nil {
		t.Fatal(err)
	}
	good := writeTemp(t, "good.age", sealedFor(t, key, aID.Genesis, keyring, nil, nil, data, offer.Recipient, nil))
	out := b.mustCLI("", "bundle", "restore", "--in", good)
	checkLimits(t, out, "held until erasures from hosted sync are checked", "records                "+strconv.Itoa(len(records)))
	held := func() {
		t.Helper()
		for _, id := range idsOf(records) {
			if e := snapshotOf(t, b, id); e.State == "live" || e.BodyJCS != nil {
				t.Fatalf("hold on %s cleared to %q", id[:8], e.State)
			}
		}
	}
	held()

	refuse := func(name, code string, sealed []byte, args ...string) {
		t.Helper()
		path := writeTemp(t, name+".age", sealed)
		stdin := ""
		if len(args) > 0 {
			stdin = args[0]
			args = args[1:]
		}
		_, err := b.cli(stdin, append([]string{"bundle", "restore", "--in", path}, args...)...)
		if publicCode(err) != code {
			t.Fatalf("%s: got %q want %q", name, publicCode(err), code)
		}
		held()
	}
	goodBytes, _ := os.ReadFile(good)
	tampered := append([]byte(nil), goodBytes...)
	tampered[len(tampered)-20] ^= 1
	refuse("ciphertext-tamper", "bundle_decrypt_failed", tampered)
	changed := append([][]byte(nil), data...)
	changed[0] = bytes.Replace(changed[0], []byte(`"v":3`), []byte(`"v":3 `), 1)
	refuse("noncanonical-item", "bundle_invalid", sealedFor(t, key, aID.Genesis, keyring, nil, nil, changed, offer.Recipient, nil))
	refuse("digest-mismatch", "bundle_invalid", sealedFor(t, key, aID.Genesis, keyring, nil, nil, data, offer.Recipient, func(m *transport.Manifest) { m.ItemsDigest = strings.Repeat("0", 64) }))
	refuse("count-mismatch", "bundle_invalid", sealedFor(t, key, aID.Genesis, keyring, nil, nil, data, offer.Recipient, func(m *transport.Manifest) { m.Data-- }))
	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{44}, 32))
	refuse("unenrolled-exporter", "bundle_exporter_unauthorized", sealedFor(t, other, aID.Genesis, keyring, nil, nil, data, offer.Recipient, nil))
	refuse("forged-signature", "bundle_signature_invalid", sealedFor(t, other, aID.Genesis, keyring, nil, nil, data, offer.Recipient, func(m *transport.Manifest) { m.ExporterKeyID = aID.Device }))
	refuse("foreign-genesis", "bundle_foreign_genesis", sealedFor(t, key, strings.Repeat("ef", 16), keyring, nil, nil, data, offer.Recipient, nil))
	refuse("bad-version", "bundle_invalid", sealedFor(t, key, aID.Genesis, keyring, nil, nil, data, offer.Recipient, func(m *transport.Manifest) { m.Bundle = "mnc/2" }))

	machine := aID.Machine
	// The recalled root is absent: it was never selected or carried.
	absentRoot := "d617feee34a1e14cf67ceed696b707f0800a57cc34d306642342f11ac26ee944"
	affects := append([]string(nil), idsOf(records)...)
	sort.Strings(affects)
	fact := func(boundary string, pending bool) []byte {
		f := `{"affects_ids":["` + strings.Join(affects, `","`) + `"],"boundary":` + boundary + `,"origin_machine":"` + machine + `","pending_attribution":` + map[bool]string{true: "true", false: "false"}[pending] + `,"recalled_id":"` + absentRoot + `","session_key":"sk1:` + strings.Repeat("a", 64) + `","source_call_or_event":{"id":"ev1:` + strings.Repeat("c", 64) + `","kind":"event"}}`
		return []byte(f)
	}
	badTag := fact(`{"event_id":"ev1:`+strings.Repeat("c", 64)+`","kind":"event","ordinal":3,"seq":0}`, false)
	refuse("bad-boundary-tag", "bundle_invalid", sealedFor(t, key, aID.Genesis, keyring, [][]byte{badTag}, nil, data, offer.Recipient, nil))
	unknownTag := fact(`{"kind":"later"}`, true)
	refuse("unknown-boundary-tag", "bundle_invalid", sealedFor(t, key, aID.Genesis, keyring, [][]byte{unknownTag}, nil, data, offer.Recipient, nil))
	falseComplete := fact(`{"event_id":"ev1:`+strings.Repeat("c", 64)+`","kind":"event","seq":0}`, false)
	machine = "6f1d2c3b-4a59-4e6f-8a7b-9c0d1e2f3a4b"
	refuse("unknown-origin", "bundle_exposure_origin_unknown", sealedFor(t, key, aID.Genesis, keyring, [][]byte{fact(`{"event_id":"ev1:`+strings.Repeat("c", 64)+`","kind":"event","seq":0}`, false)}, nil, data, offer.Recipient, nil))

	// False completeness: a valid fact claiming resolved attribution for an
	// absent root admits none of the affected data, persists as a restriction
	// and is not cleared by the hosted reconciliation either.
	path := writeTemp(t, "false-complete.age", sealedFor(t, key, aID.Genesis, keyring, [][]byte{falseComplete}, nil, data, offer.Recipient, nil))
	out = b.mustCLI("", "bundle", "restore", "--in", path, "--json")
	var rep bundleReport
	if err := json.Unmarshal([]byte(out), &rep); err != nil || rep.Data != 0 || rep.Facts != 1 || len(rep.Excluded) != len(records) || rep.Excluded[0].Reason != store.ExcludedLineageIncomplete {
		t.Fatal("facts cleared restriction", out, err)
	}
	held()
	bst, err := store.Open(ctx, store.Options{Dir: b.paths.Data, PinnedGenesisID: bID.Genesis, LocalMachineID: bID.Machine})
	if err != nil {
		t.Fatal(err)
	}
	if err = bst.CompleteRestoreReconciliation(ctx); err != nil {
		t.Fatal(err)
	}
	bst.Close()
	held()
	// The same data restored again without any fact is still held by the
	// persisted restriction.
	b.mustCLI("", "bundle", "restore", "--in", good)
	held()

	// A carried hosted delivery grant refuses the whole bundle.
	var env record.Envelope
	if err := json.Unmarshal(data[0], &env); err != nil {
		t.Fatal(err)
	}
	env.Grant = &record.DeliveryGrant{RecordID: env.ID, Tenant: "tenant-bundle", Generation: 1, Policy: strings.Repeat("a", 64), RecipientGenesis: aID.Genesis}
	granted, err := jcs.MarshalRecord(env)
	if err != nil {
		t.Fatal(err)
	}
	refuse("granted-envelope", "bundle_granted_data", sealedFor(t, key, aID.Genesis, keyring, nil, nil, append([][]byte{granted}, data[1:]...), offer.Recipient, nil))

	// Mixed recipient types and the wrong mode are refused from the encryption.
	recipientB, _ := age.ParseX25519Recipient(offer.Recipient)
	var mixed bytes.Buffer
	w, err := age.Encrypt(&mixed, recipientB, otherStanza{})
	if err != nil {
		t.Fatal(err)
	}
	plain, _, err := bundle.OpenTransfer(goodBytes, mustIdentity(t, b))
	if err != nil {
		t.Fatal(err)
	}
	w.Write(nodesync.RawZstd(plain))
	w.Close()
	refuse("mixed-recipients", "bundle_mode_invalid", mixed.Bytes())
	refuse("transfer-as-backup", "bundle_decrypt_failed", goodBytes, "a long enough passphrase\n", "--backup")

	backup := filepath.Join(t.TempDir(), "backup.age")
	out = a.mustCLI("correct horse battery staple\ncorrect horse battery staple\n", withIDs([]string{"bundle", "backup", "--out", backup}, idsOf(records))...)
	checkLimits(t, out, "Backup written", noSurvivingDeviceLimit, rollbackWarning, unmanagedCopyNotice)
	sealed, _ := os.ReadFile(backup)
	if !bytes.HasPrefix(sealed, []byte("age-encryption.org/v1\n-> scrypt ")) || bytes.Count(sealed[:bytes.Index(sealed, []byte("\n---"))], []byte("\n-> ")) != 1 {
		t.Fatal("backup is not sealed to a sole scrypt recipient")
	}
	if _, err = a.cli("short\nshort\n", withIDs([]string{"bundle", "backup", "--out", backup + "2"}, idsOf(records))...); publicCode(err) != "passphrase_invalid" {
		t.Fatal("short passphrase accepted", err)
	}
	if _, err = a.cli("correct horse battery staple\ncorrect horse battery stapler\n", withIDs([]string{"bundle", "backup", "--out", backup + "3"}, idsOf(records))...); publicCode(err) != "passphrase_invalid" {
		t.Fatal("unconfirmed passphrase accepted", err)
	}
	refuse("wrong-passphrase", "bundle_decrypt_failed", sealed, "wrong horse battery staple\n", "--backup")
	refuse("backup-as-transfer", "bundle_decrypt_failed", sealed)

	// Policy expiry on the receiver denies full bodies on import while the
	// keyring and controls still apply.
	c := newBundleProfile(t)
	joined := joinFresh(t, a, c)
	cst, err := store.Open(ctx, store.Options{Dir: joined.paths.Data, PinnedGenesisID: aID.Genesis, LocalMachineID: joined.identity().Machine})
	if err != nil {
		t.Fatal(err)
	}
	installExpiredPolicy(t, cst)
	cst.Close()
	out = joined.mustCLI("correct horse battery staple\n", "bundle", "restore", "--in", backup, "--backup", "--json")
	if err = json.Unmarshal([]byte(out), &rep); err != nil || rep.Data != 0 || rep.Keyring == 0 || rep.Excluded[0].Reason != store.ExcludedPolicy {
		t.Fatal("expired receiver policy admitted full bodies", out, err)
	}

	// A device without a co-signed device_add: another genesis, and a profile
	// pinned to this genesis whose own key the keyring never added.
	stranger := newGenesisDevice(t)
	if _, err = stranger.cli("correct horse battery staple\n", "bundle", "restore", "--in", backup, "--backup"); publicCode(err) != "bundle_foreign_genesis" {
		t.Fatal("other identity restored a backup", publicCode(err))
	}
	orphan := newBundleProfile(t)
	orphanMachine := "44444444-4444-4444-8444-444444444444"
	ost, err := store.Open(ctx, store.Options{Dir: orphan.paths.Data, PinnedGenesisID: aID.Genesis, LocalMachineID: orphanMachine})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = ost.Append(ctx, sel.Keyring[0]); err != nil {
		t.Fatal(err)
	}
	ost.Close()
	orphanKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{45}, 32))
	manifest, _ := json.Marshal(map[string]any{"version": 1, "owner": aID.Genesis, "machine": orphanMachine, "credential": "55555555-5555-4555-8555-555555555555", "vault_handle": strings.Repeat("ab", 16)})
	join, _ := json.Marshal(map[string]any{"version": 1, "genesis": aID.Genesis, "device": sig.KeyID(orphanKey.Public().(ed25519.PublicKey)), "machine": orphanMachine, "device_add": strings.Repeat("cd", 32)})
	if err = store.WriteInstalledRecord(orphan.paths.Data, manifest); err != nil {
		t.Fatal(err)
	}
	if err = store.WriteProfileRecord(orphan.paths.Data, store.DeviceJoinName, join); err != nil {
		t.Fatal(err)
	}
	if _, err = orphan.cli("correct horse battery staple\n", "bundle", "restore", "--in", backup, "--backup"); publicCode(err) != "device_not_enrolled" {
		t.Fatal("device without device_add restored", publicCode(err))
	}
	// An enrollment whose device_add lacks the co-signature is refused, and the
	// pending device never gains a profile to restore into.
	lone := newBundleProfile(t)
	invite := a.mustCLI("", "bundle", "invite")
	joinedOut := lone.mustCLI(invite, "bundle", "join")
	var q bundle.JoinRequest
	if err = json.Unmarshal([]byte(joinedOut[:strings.IndexByte(joinedOut, '\n')]), &q); err != nil {
		t.Fatal(err)
	}
	enrollment, _ := json.Marshal(bundle.Enrollment{Version: 1, Genesis: aID.Genesis, Keyring: []record.Envelope{nodesync.Envelope(sel.Keyring[0].HeaderJCS, sel.Keyring[0].BodyJCS, sel.Keyring[0].Sigs, sel.Keyring[0].AdvisoryID), q.DeviceAdd}})
	if _, err = lone.cli(string(enrollment), "bundle", "enroll"); publicCode(err) != "enrollment_invalid" {
		t.Fatal("possession-only device_add enrolled", publicCode(err))
	}
	if _, err = lone.cli("correct horse battery staple\n", "bundle", "restore", "--in", backup, "--backup"); publicCode(err) != "profile_invalid" {
		t.Fatal("unenrolled pending device restored", publicCode(err))
	}
}

func mustIdentity(t *testing.T, d *bundleDevice) *age.X25519Identity {
	t.Helper()
	id, err := bundle.LoadExportIdentity(context.Background(), d.paths.Data, d.vault, d.identity())
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// joinFresh enrolls an already created profile.
func joinFresh(t *testing.T, surviving, fresh *bundleDevice) *bundleDevice {
	t.Helper()
	invite := surviving.mustCLI("", "bundle", "invite")
	joined := fresh.mustCLI(invite, "bundle", "join")
	request := joined[:strings.IndexByte(joined, '\n')+1]
	var q bundle.JoinRequest
	if err := json.Unmarshal([]byte(request), &q); err != nil {
		t.Fatal(err)
	}
	fresh.mustCLI(surviving.mustCLI(request, "bundle", "add-device", "--code", q.Code), "bundle", "enroll")
	return fresh
}

func installExpiredPolicy(t *testing.T, st *store.Store) {
	t.Helper()
	ctx := context.Background()
	policyKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{78}, 32))
	pub := policyKey.Public().(ed25519.PublicKey)
	root, err := sig.BuildKeyOp(record.KeyOpBody{Op: record.OpTenantKey, Subject: sig.KeyRefOf(pub, record.RolePolicy, ""), Genesis: "tenant-expired"}, pub, "", time.Now().UnixMilli(), policyKey)
	if err != nil {
		t.Fatal(err)
	}
	if err = st.InstallTenantPolicyContext(ctx, store.TenantPolicyContext{Tenant: "tenant-expired", UserID: "expired-user", Origin: "https://tenant.example", Root: store.SignedRecord{HeaderJCS: root.Rec.HeaderJCS, BodyJCS: root.Rec.BodyJCS, Sigs: root.Sigs, AdvisoryID: root.Rec.ID}}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UnixMilli()
	pb := &record.PolicyBody{Tenant: "tenant-expired", Seq: 1, IssuedAt: now - 7200000, NotAfter: now - 3600000, RefreshAfter: now - 5400000}
	pb.Applies.Users = []string{"expired-user"}
	pr, err := record.Build(record.Header{Type: record.KindPolicy, LID: record.PolicyLID(pb.Tenant), At: now - 7200000, Author: record.Author{KeyID: sig.KeyID(pub)}, Prov: record.ProvUser, Red: record.Redact{Profile: record.ProfileLocal}}, pb)
	if err != nil {
		t.Fatal(err)
	}
	sg, err := sig.SignRecord(policyKey, pr.ID)
	if err != nil {
		t.Fatal(err)
	}
	// An expired policy may be refused for activation; either way the tenant
	// context is installed and governs every bundle data predicate.
	_, _ = st.Append(ctx, store.SignedRecord{HeaderJCS: pr.HeaderJCS, BodyJCS: pr.BodyJCS, Sigs: []record.Signature{sg}, AdvisoryID: pr.ID})
}

// otherStanza is a recipient of a type no bundle mode accepts.
type otherStanza struct{}

func (otherStanza) Wrap([]byte) ([]*age.Stanza, error) {
	return []*age.Stanza{{Type: "other-kind", Args: []string{"x"}, Body: bytes.Repeat([]byte{1}, 32)}}, nil
}
