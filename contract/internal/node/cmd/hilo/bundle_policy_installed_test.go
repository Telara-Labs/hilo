//go:build darwin || linux

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/Telara-Labs/hilo/contract/internal/node/bundle"
	"github.com/Telara-Labs/hilo/contract/internal/node/store"
	nodesync "github.com/Telara-Labs/hilo/contract/internal/node/sync"
	"github.com/Telara-Labs/hilo/contract/internal/node/syncnode"
	"github.com/Telara-Labs/hilo/contract/record"
	"github.com/Telara-Labs/hilo/contract/sig"
	"github.com/Telara-Labs/hilo/contract/transport"
)

// carriedSecrets collects every per-record salt and commitment in a body.
func carriedSecrets(t *testing.T, body []byte) []string {
	t.Helper()
	var v any
	if err := json.Unmarshal(body, &v); err != nil {
		t.Fatal(err)
	}
	var out []string
	var walk func(any)
	walk = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			for k, child := range x {
				if s, ok := child.(string); ok && (k == "salt" || k == "digest" || k == "args_hash" || k == "result_hash") {
					out = append(out, s)
				}
				walk(child)
			}
		case []any:
			for _, child := range x {
				walk(child)
			}
		}
	}
	walk(v)
	return out
}

// physicalState is what a refused restore must leave exactly as it was: the
// profile's file set and the absence of every carried body, salt and
// commitment from every file, including the database, its WAL and FTS
// shadow tables. The node keeps no staging or managed bundle copy, so a new
// file of any other kind is itself a failure.
type physicalState struct {
	t         *testing.T
	d         *bundleDevice
	files     map[string]bool
	forbidden map[string][][]byte
	needles   []string
	ids       []string
}

func profileFiles(t *testing.T, d *bundleDevice) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}
	base := filepath.Dir(d.paths.Data)
	err := filepath.WalkDir(base, func(path string, e fs.DirEntry, err error) error {
		if err != nil || !e.Type().IsRegular() {
			return err
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(base, path)
		out[rel] = b
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func newPhysicalState(t *testing.T, d *bundleDevice, carried []store.SignedRecord, needles ...string) *physicalState {
	t.Helper()
	p := &physicalState{t: t, d: d, files: map[string]bool{}, forbidden: map[string][][]byte{}, needles: needles}
	for name := range profileFiles(t, d) {
		p.files[name] = true
	}
	for _, n := range needles {
		p.forbidden["planted "+n] = [][]byte{[]byte(n)}
	}
	for _, r := range carried {
		p.ids = append(p.ids, r.AdvisoryID)
		p.forbidden["body "+r.AdvisoryID[:8]] = [][]byte{r.BodyJCS}
		for _, s := range carriedSecrets(t, r.BodyJCS) {
			p.forbidden["secret of "+r.AdvisoryID[:8]] = append(p.forbidden["secret of "+r.AdvisoryID[:8]], []byte(s))
		}
	}
	return p
}

func (p *physicalState) assert(stage string) {
	t := p.t
	t.Helper()
	for name, b := range profileFiles(t, p.d) {
		base := strings.TrimSuffix(strings.TrimSuffix(name, "-wal"), "-shm")
		if !p.files[name] && !p.files[base] {
			t.Fatalf("%s: refusal left a new file %s", stage, name)
		}
		scanForbidden(t, stage+" "+name, b, p.forbidden)
	}
	n := &installedNode{t: t, paths: p.d.paths, home: p.d.home}
	for _, needle := range p.needles {
		if hits := n.ftsShadowHits(needle); len(hits) != 0 {
			t.Fatal(stage, "FTS holds refused content", hits)
		}
	}
	memory := filepath.Join(p.d.paths.Data, "memory.sqlite")
	for _, id := range p.ids {
		if got := countIn(t, memory, "SELECT (SELECT count(*) FROM record WHERE id=?)+(SELECT count(*) FROM record_body WHERE id=?)", id, id); got != 0 {
			t.Fatalf("%s: refused record %s stored", stage, id[:8])
		}
	}
}

func restoreReport(t *testing.T, out string) bundleReport {
	t.Helper()
	var r bundleReport
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatal(out, err)
	}
	return r
}

func allExcludedAs(t *testing.T, stage string, r bundleReport, n int, reason string) {
	t.Helper()
	if r.Data != 0 || len(r.Excluded) != n {
		t.Fatalf("%s: %d data, %d excluded, want 0 and %d", stage, r.Data, len(r.Excluded), n)
	}
	for _, e := range r.Excluded {
		if e.Reason != reason {
			t.Fatalf("%s: %s excluded as %q, want %q", stage, e.ID[:8], e.Reason, reason)
		}
	}
}

// signedFromDB reads complete stored envelopes of ids as they sit in a
// profile's database, the bytes an earlier backup or a compromised exporter
// would carry.
func signedFromDB(t *testing.T, dir string, ids []string) []store.SignedRecord {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(dir, "memory.sqlite")+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var out []store.SignedRecord
	for _, id := range ids {
		var header, sigs, body []byte
		if err = db.QueryRow("SELECT r.header,r.sigs,b.body FROM record r JOIN record_body b ON b.id=r.id WHERE r.id=?", id).Scan(&header, &sigs, &body); err != nil {
			t.Fatal("no complete stored envelope for", id[:8], err)
		}
		var signatures []record.Signature
		if err = json.Unmarshal(sigs, &signatures); err != nil {
			t.Fatal(err)
		}
		out = append(out, store.SignedRecord{HeaderJCS: header, BodyJCS: body, Sigs: signatures, AdvisoryID: id})
	}
	return out
}

func offerOf(t *testing.T, d *bundleDevice) bundle.Offer {
	t.Helper()
	var o bundle.Offer
	if err := json.Unmarshal([]byte(d.mustCLI("", "bundle", "key")), &o); err != nil {
		t.Fatal(err)
	}
	return o
}

// TestV20LogoutRetainedPolicyRecordsDenyExportAndImport logs in to a tenant
// through the real login command, captures governed records through MCP and
// logs out through the real logout command. The records stay on the device as
// non-pushable, and they are non-bundleable: every export route refuses them,
// and a bundle that carries their complete signed envelopes anyway, signed by
// the enrolled exporter, is refused on import both by a device that never
// logged in and by the logged-out device itself, leaving no physical copy.
func TestV20LogoutRetainedPolicyRecordsDenyExportAndImport(t *testing.T) {
	useBundleVaults(t)
	old := syncVault
	syncVault = func(dir string) syncnode.SecretVault {
		bundleVaults.Lock()
		defer bundleVaults.Unlock()
		return bundleVaults.m[dir]
	}
	t.Cleanup(func() { syncVault = old })
	d := newGenesisDevice(t)
	n := d.start()
	b := joinDevice(t, d)
	bOffer := trustOffer(t, b, d)
	dOffer := offerOf(t, d)
	login := func(stdin string, args ...string) string {
		t.Helper()
		var out bytes.Buffer
		if err := run(context.Background(), append(args, "--data-dir", d.paths.Data), strings.NewReader(stdin), &out); err != nil {
			t.Fatalf("%v: %s\n%s", args, publicCode(err), out.String())
		}
		return out.String()
	}
	tenant := newLoginTenant(t, 81, "tenant-logout-bundle", "logout-user")
	policy, policyEnv := tenant.policy(1, "logoutbundlerulecanary")
	login("", "login", "--key")
	login(tenant.document(d, policyEnv, "telara_mcp_logout_bundle"), "login")

	canary := "logoutretainedibiscanary"
	plantTask(t, n, canary)
	governed := governedRecords(t, d.paths.Data, policy.ID)
	if len(governed) < 2 {
		t.Fatalf("expected records sealed under the policy, have %d", len(governed))
	}
	envelopes := signedFromDB(t, d.paths.Data, governed)
	for _, e := range envelopes {
		r, err := record.Parse(e.HeaderJCS, e.BodyJCS, e.AdvisoryID)
		if err != nil || r.Header.Pol != policy.ID {
			t.Fatal("governed envelope", err)
		}
	}

	out := login("", "logout")
	if !strings.Contains(out, `"logged_out"`) || !strings.Contains(out, `"physical":"complete"`) {
		t.Fatal("logout", out)
	}
	memory := filepath.Join(d.paths.Data, "memory.sqlite")
	if countIn(t, memory, "SELECT count(*) FROM policy_logout WHERE id=?", policy.ID) != 1 || countIn(t, memory, "SELECT count(*) FROM tenant_context WHERE active=1") != 0 {
		t.Fatal("logout did not retain the per-record fence")
	}
	// The retained records are still on the device, complete.
	if got := signedFromDB(t, d.paths.Data, governed); len(got) != len(governed) {
		t.Fatal("logout dropped retained records")
	}
	n.stop()
	d.node = nil

	// Export: transfer and backup both refuse every retained record, and the
	// written files carry none of them.
	bIdentity := mustIdentity(t, b)
	transfer := filepath.Join(t.TempDir(), "logout-transfer.age")
	rep := restoreReport(t, d.mustCLI("", withIDs([]string{"bundle", "export", "--to", b.identity().Device, "--out", transfer, "--json"}, governed)...))
	allExcludedAs(t, "transfer export after logout", rep, len(governed), store.ExcludedPolicy)
	sealed, err := os.ReadFile(transfer)
	if err != nil {
		t.Fatal(err)
	}
	plain, _, err := bundle.OpenTransfer(sealed, bIdentity)
	if err != nil {
		t.Fatal(err)
	}
	c, err := bundle.Decode(plain, d.identity().Genesis)
	if err != nil || len(c.Data) != 0 || bytes.Contains(plain, []byte(canary)) {
		t.Fatal("transfer file carries logout-retained data", err)
	}
	backup := filepath.Join(t.TempDir(), "logout-backup.age")
	rep = restoreReport(t, d.mustCLI("correct horse battery staple\ncorrect horse battery staple\n", withIDs([]string{"bundle", "backup", "--out", backup, "--json"}, governed)...))
	allExcludedAs(t, "backup export after logout", rep, len(governed), store.ExcludedPolicy)

	// Import: a bundle carrying the complete signed envelopes anyway.
	key := d.deviceKey()
	defer clear(key)
	keyring := envelopeLines(t, selectionOf(t, d, []string{strings.Repeat("0", 64)}).Keyring)
	data := envelopeLines(t, envelopes)
	forged := writeTemp(t, "logout-forged.age", sealedFor(t, key, d.identity().Genesis, keyring, nil, nil, data, bOffer.Recipient, nil))
	// One daemon start first, so the baseline holds its lifecycle files.
	b.start()
	b.stop()
	physical := newPhysicalState(t, b, envelopes, canary, "checkpoint "+canary)
	rep = restoreReport(t, b.mustCLI("", "bundle", "restore", "--in", forged, "--json"))
	allExcludedAs(t, "never-logged-in receiver", rep, len(envelopes), store.ExcludedPolicy)
	physical.assert("never-logged-in receiver")
	b.start()
	b.stop()
	physical.assert("never-logged-in receiver after restart")

	// The logged-out device itself restores the same envelopes: its per-record
	// logout fence refuses them and nothing is added.
	self := writeTemp(t, "logout-self.age", sealedFor(t, key, d.identity().Genesis, keyring, nil, nil, data, dOffer.Recipient, nil))
	counts := func() string {
		return fmt.Sprint(countIn(t, memory, "SELECT count(*) FROM record"), countIn(t, memory, "SELECT count(*) FROM record_body"), countIn(t, memory, "SELECT count(*) FROM passage"), countIn(t, memory, "SELECT count(*) FROM policy_logout"))
	}
	before := counts()
	files := profileFiles(t, d)
	rep = restoreReport(t, d.mustCLI("", "bundle", "restore", "--in", self, "--json"))
	allExcludedAs(t, "logged-out device", rep, len(envelopes), store.ExcludedPolicy)
	if after := counts(); after != before {
		t.Fatal("restore into the logged-out device changed its records", before, after)
	}
	for name := range profileFiles(t, d) {
		base := strings.TrimSuffix(strings.TrimSuffix(name, "-wal"), "-shm")
		if _, ok := files[name]; !ok {
			if _, ok = files[base]; !ok {
				t.Fatal("restore left a new file", name)
			}
		}
	}
	for _, id := range governed {
		if e := snapshotOf(t, d, id); e.BodyJCS != nil {
			t.Fatal("logout-retained body readable after restore")
		}
	}
	rep = restoreReport(t, d.mustCLI("correct horse battery staple\n", "bundle", "restore", "--in", backup, "--backup", "--json"))
	if rep.Data != 0 || counts() != before {
		t.Fatal("backup restore admitted logout-retained data", rep)
	}
}

// policyStates are the receiver and exporter policy conditions under which
// every policy-governed full body is denied (07 section 8.4).
var policyStates = []string{"ceiling-local", "ceiling-push-metadata", "no-push", "kill-sync", "expired", "tampered", "rollback", "clock-rollback"}

// installPolicyState installs a pinned tenant context on a profile and puts
// its policy chain in the named state through the store's own policy
// admission. clock-rollback stores a trusted-time floor ahead of the wall
// clock, as a clock moved backwards after a verified observation leaves it.
func installPolicyState(t *testing.T, d *bundleDevice, state string, seed byte) {
	t.Helper()
	ctx := context.Background()
	ident := d.identity()
	st, err := store.Open(ctx, store.Options{Dir: d.paths.Data, PinnedGenesisID: ident.Genesis, LocalMachineID: ident.Machine})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	tenant := "tenant-" + state
	policyKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, 32))
	pub := policyKey.Public().(ed25519.PublicKey)
	root, err := sig.BuildKeyOp(record.KeyOpBody{Op: record.OpTenantKey, Subject: sig.KeyRefOf(pub, record.RolePolicy, ""), Genesis: tenant}, pub, "", time.Now().UnixMilli(), policyKey)
	if err != nil {
		t.Fatal(err)
	}
	if err = st.InstallTenantPolicyContext(ctx, store.TenantPolicyContext{Tenant: tenant, UserID: "state-user", Origin: "https://tenant.example", Root: store.SignedRecord{HeaderJCS: root.Rec.HeaderJCS, BodyJCS: root.Rec.BodyJCS, Sigs: root.Sigs, AdvisoryID: root.Rec.ID}}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UnixMilli()
	signed := func(seq int64, mutate func(*record.PolicyBody)) store.SignedRecord {
		pb := &record.PolicyBody{Tenant: tenant, Seq: seq, IssuedAt: now - 1000, RefreshAfter: now + 1800000, NotAfter: now + 3600000}
		pb.Applies.Users = []string{"state-user"}
		pb.Push = record.PolicyPush{MaxProfile: record.ProfilePushMetadata, AllowRepos: []string{"*"}}
		if mutate != nil {
			mutate(pb)
		}
		r, err := record.Build(record.Header{Type: record.KindPolicy, LID: record.PolicyLID(tenant), At: pb.IssuedAt, Author: record.Author{KeyID: sig.KeyID(pub)}, Prov: record.ProvUser, Red: record.Redact{Profile: record.ProfileLocal}}, pb)
		if err != nil {
			t.Fatal(err)
		}
		s, err := sig.SignRecord(policyKey, r.ID)
		if err != nil {
			t.Fatal(err)
		}
		return store.SignedRecord{HeaderJCS: r.HeaderJCS, BodyJCS: r.BodyJCS, Sigs: []record.Signature{s}, AdvisoryID: r.ID}
	}
	offer := func(r store.SignedRecord) {
		t.Helper()
		if _, err := st.OfferTenantPolicy(ctx, r); err != nil {
			t.Fatal(state, "policy offer", err)
		}
	}
	switch state {
	case "ceiling-local":
		offer(signed(1, func(b *record.PolicyBody) { b.Push.MaxProfile = record.ProfileLocal }))
	case "ceiling-push-metadata":
		offer(signed(1, nil))
	case "no-push":
		offer(signed(1, func(b *record.PolicyBody) {
			b.BlockedRepos = []record.BlockedRepo{{RemoteGlob: "*", Effect: "no-push"}}
		}))
	case "kill-sync":
		offer(signed(1, func(b *record.PolicyBody) { b.Kill.Sync = true }))
	case "expired":
		// The chain may refuse an already expired head; either way the
		// installed tenant context governs every bundle data predicate.
		_, _ = st.OfferTenantPolicy(ctx, signed(1, func(b *record.PolicyBody) {
			b.IssuedAt, b.RefreshAfter, b.NotAfter = now-7200000, now-5400000, now-3600000
		}))
	case "tampered":
		offer(signed(1, nil))
		offer(signed(1, func(b *record.PolicyBody) { b.Push.AllowRepos = []string{"other.example/*"} }))
	case "rollback":
		offer(signed(2, nil))
		if _, err := st.OfferTenantPolicy(ctx, signed(1, nil)); store.Code(err) != "policy_rollback" {
			t.Fatal("older policy accepted", err)
		}
	case "clock-rollback":
		offer(signed(1, nil))
	default:
		t.Fatal("unknown state", state)
	}
	if state == "clock-rollback" {
		st.Close()
		db, err := sql.Open("sqlite", "file:"+filepath.Join(d.paths.Data, "memory.sqlite"))
		if err != nil {
			t.Fatal(err)
		}
		_, err = db.Exec("UPDATE trusted_time SET floor=? WHERE singleton=1", now+30*24*3600*1000)
		db.Close()
		if err != nil {
			t.Fatal(err)
		}
	}
}

// checkPolicyState asserts the persisted evidence of each state after a
// bundle command evaluated it.
func checkPolicyState(t *testing.T, d *bundleDevice, state string) {
	t.Helper()
	memory := filepath.Join(d.paths.Data, "memory.sqlite")
	if countIn(t, memory, "SELECT count(*) FROM tenant_context WHERE active=1 AND tenant=?", "tenant-"+state) != 1 {
		t.Fatal(state, "tenant context not active")
	}
	switch state {
	case "tampered":
		if countIn(t, memory, "SELECT count(*) FROM tenant_context WHERE tampered=1") != 1 || countIn(t, memory, "SELECT count(*) FROM policy_equivocation") < 2 {
			t.Fatal("equal-sequence policies did not mark the chain tampered")
		}
	case "rollback":
		if countIn(t, memory, "SELECT count(*) FROM tenant_context WHERE highest_seq=2") != 1 {
			t.Fatal("rollback replaced the newer head")
		}
	case "clock-rollback":
		if countIn(t, memory, "SELECT count(*) FROM trusted_time WHERE rollback=1") != 1 {
			t.Fatal("clock rollback not latched")
		}
	}
}

// TestV20PolicyStatesDenyFullBodiesOnExportAndImport puts an exporting and a
// receiving device of one identity into each policy state, both max_profile
// ceilings, no-push, kill-sync, expiry, equal-sequence tamper, a refused
// rollback and a clock rollback, and requires every full body to be denied
// on export and on import, with nothing written or left behind.
func TestV20PolicyStatesDenyFullBodiesOnExportAndImport(t *testing.T) {
	useBundleVaults(t)
	a := newGenesisDevice(t)
	an := a.start()
	canary := "policystatecormorantcanary"
	plantTask(t, an, canary)
	records := dataRecords(t, a.paths.Data)
	an.stop()
	a.node = nil
	carried := signedFromDB(t, a.paths.Data, idsOf(records))
	offerOf(t, a)
	aIdentity := mustIdentity(t, a)
	for i, state := range policyStates {
		t.Run(state, func(t *testing.T) {
			// Export side: a device holding restored ungoverned data enters
			// the state and can no longer write any of it.
			exp := joinDevice(t, a)
			trustOffer(t, exp, a)
			trustOffer(t, a, exp)
			in := filepath.Join(t.TempDir(), "in.age")
			a.mustCLI("", withIDs([]string{"bundle", "export", "--to", exp.identity().Device, "--out", in}, idsOf(records))...)
			if rep := restoreReport(t, exp.mustCLI("", "bundle", "restore", "--in", in, "--json")); rep.Data != len(records) {
				t.Fatal("ungoverned restore before the policy", rep)
			}
			installPolicyState(t, exp, state, byte(120+i))
			out := filepath.Join(t.TempDir(), "out.age")
			rep := restoreReport(t, exp.mustCLI("", withIDs([]string{"bundle", "export", "--to", a.identity().Device, "--out", out, "--json"}, idsOf(records))...))
			allExcludedAs(t, state+" export", rep, len(records), store.ExcludedPolicy)
			checkPolicyState(t, exp, state)
			sealed, err := os.ReadFile(out)
			if err != nil {
				t.Fatal(err)
			}
			plain, _, err := bundle.OpenTransfer(sealed, aIdentity)
			if err != nil {
				t.Fatal(err)
			}
			c, err := bundle.Decode(plain, a.identity().Genesis)
			if err != nil || len(c.Data) != 0 || bytes.Contains(plain, []byte(canary)) {
				t.Fatal(state, "export wrote governed data", err)
			}
			for _, r := range carried {
				if bytes.Contains(plain, r.BodyJCS) {
					t.Fatal(state, "export carries a full body")
				}
			}

			// Import side: a device in the state refuses the same bodies.
			imp := joinDevice(t, a)
			trustOffer(t, imp, a)
			installPolicyState(t, imp, state, byte(160+i))
			physical := newPhysicalState(t, imp, carried, canary, "checkpoint "+canary)
			file := filepath.Join(t.TempDir(), "import.age")
			a.mustCLI("", withIDs([]string{"bundle", "export", "--to", imp.identity().Device, "--out", file}, idsOf(records))...)
			rep = restoreReport(t, imp.mustCLI("", "bundle", "restore", "--in", file, "--json"))
			allExcludedAs(t, state+" import", rep, len(records), store.ExcludedPolicy)
			if rep.Keyring == 0 {
				t.Fatal(state, "keyring did not apply while data was denied")
			}
			checkPolicyState(t, imp, state)
			physical.assert(state + " import")
		})
	}
}

// fixtureFact is one §8.4.1 fact line from origin machine about recalled,
// affecting affects.
func fixtureFact(machine, recalled, boundary string, pending bool, affects []string) []byte {
	sorted := append([]string(nil), affects...)
	sort.Strings(sorted)
	p := "false"
	if pending {
		p = "true"
	}
	return []byte(`{"affects_ids":["` + strings.Join(sorted, `","`) + `"],"boundary":` + boundary + `,"origin_machine":"` + machine + `","pending_attribution":` + p + `,"recalled_id":"` + recalled + `","session_key":"sk1:` + strings.Repeat("a", 64) + `","source_call_or_event":{"id":"ev1:` + strings.Repeat("c", 64) + `","kind":"event"}}`)
}

// TestV20FixtureRefusalsLeaveNoPhysicalCopy sends hostile bundles to a device
// that has never received this data: tamper, digest and count mismatch, bad
// and unknown Boundary tags, every fact and size ceiling, then valid facts
// claiming false completeness or unknown order for an absent root. After each
// refusal the receiver's database, WAL, FTS shadow tables and profile files
// hold no carried body, salt or commitment, and the persisted restrictions
// keep refusing the same data when it arrives again without any fact.
func TestV20FixtureRefusalsLeaveNoPhysicalCopy(t *testing.T) {
	useBundleVaults(t)
	a := newGenesisDevice(t)
	an := a.start()
	canary := "fixturerefusalpangolincanary"
	plantTask(t, an, canary)
	records := dataRecords(t, a.paths.Data)
	an.stop()
	a.node = nil
	aID := a.identity()
	key := a.deviceKey()
	defer clear(key)
	sel := selectionOf(t, a, idsOf(records))
	if len(sel.Data) != len(records) {
		t.Fatal(sel.Excluded)
	}
	keyring, data := envelopeLines(t, sel.Keyring), envelopeLines(t, sel.Data)
	b := joinDevice(t, a)
	offer := offerOf(t, b)
	b.start()
	b.stop()
	physical := newPhysicalState(t, b, sel.Data, canary, "checkpoint "+canary)
	seal := func(facts, d [][]byte, mutate func(*transport.Manifest)) []byte {
		return sealedFor(t, key, aID.Genesis, keyring, facts, nil, d, offer.Recipient, mutate)
	}
	refuse := func(name, code string, sealed []byte) {
		t.Helper()
		_, err := b.cli("", "bundle", "restore", "--in", writeTemp(t, name+".age", sealed))
		if publicCode(err) != code {
			t.Fatalf("%s: got %q want %q", name, publicCode(err), code)
		}
		physical.assert(name)
	}

	good := seal(nil, data, nil)
	tampered := append([]byte(nil), good...)
	tampered[len(tampered)-20] ^= 1
	refuse("ciphertext-tamper", "bundle_decrypt_failed", tampered)
	refuse("digest-mismatch", "bundle_invalid", seal(nil, data, func(m *transport.Manifest) { m.ItemsDigest = strings.Repeat("0", 64) }))
	refuse("count-mismatch", "bundle_invalid", seal(nil, data, func(m *transport.Manifest) { m.Data++ }))
	refuse("foreign-genesis", "bundle_foreign_genesis", sealedFor(t, key, strings.Repeat("ef", 16), keyring, nil, nil, data, offer.Recipient, nil))
	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{46}, 32))
	refuse("unenrolled-exporter", "bundle_exporter_unauthorized", sealedFor(t, other, aID.Genesis, keyring, nil, nil, data, offer.Recipient, nil))

	absent := "d617feee34a1e14cf67ceed696b707f0800a57cc34d306642342f11ac26ee944"
	ids := idsOf(records)
	event := `{"event_id":"ev1:` + strings.Repeat("c", 64) + `","kind":"event","seq":0}`
	refuse("bad-boundary-tag", "bundle_invalid", seal([][]byte{fixtureFact(aID.Machine, absent, `{"event_id":"ev1:`+strings.Repeat("c", 64)+`","kind":"event","ordinal":3,"seq":0}`, false, ids)}, data, nil))
	refuse("unknown-boundary-tag", "bundle_invalid", seal([][]byte{fixtureFact(aID.Machine, absent, `{"kind":"later"}`, true, ids)}, data, nil))
	refuse("unknown-order-not-pending", "bundle_invalid", seal([][]byte{fixtureFact(aID.Machine, absent, `{"kind":"unknown"}`, false, ids)}, data, nil))
	refuse("unknown-origin", "bundle_exposure_origin_unknown", seal([][]byte{fixtureFact("6f1d2c3b-4a59-4e6f-8a7b-9c0d1e2f3a4b", absent, event, false, ids)}, data, nil))

	// Ceilings: a fact over 16 KiB, more than 8192 facts, more than 8192 array
	// entries across facts that are each within bounds, and a plaintext over
	// 64 MiB, which is refused before it is decompressed into the store.
	many := func(n, offset int) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = fmt.Sprintf("%064x", offset+i)
		}
		return out
	}
	big := fixtureFact(aID.Machine, absent, event, false, many(260, 0))
	if len(big) <= 16<<10 {
		t.Fatal("oversize fact fixture too small", len(big))
	}
	refuse("fact-over-16KiB", "bundle_invalid", seal([][]byte{big}, data, nil))
	small := fixtureFact(aID.Machine, absent, event, false, ids)
	tooMany := make([][]byte, 8193)
	for i := range tooMany {
		tooMany[i] = small
	}
	refuse("over-8192-facts", "bundle_invalid", seal(tooMany, data, nil))
	var entries [][]byte
	for i := 0; i < 36; i++ {
		f := fixtureFact(aID.Machine, absent, event, false, many(230, i*230))
		if len(f) > 16<<10 {
			t.Fatal("entry fixture over the per-fact bound")
		}
		entries = append(entries, f)
	}
	refuse("over-8192-entries", "bundle_invalid", seal(entries, data, nil))
	recipient, err := age.ParseX25519Recipient(offer.Recipient)
	if err != nil {
		t.Fatal(err)
	}
	huge := append(bytes.Repeat([]byte{'x'}, bundle.MaxBytes+256<<10), '\n')
	var over bytes.Buffer
	w, err := age.Encrypt(&over, recipient)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = w.Write(nodesync.RawZstd(huge)); err != nil || w.Close() != nil {
		t.Fatal(err)
	}
	refuse("plaintext-over-64MiB", "bundle_too_large", over.Bytes())

	// False completeness and unknown order: valid facts for an absent root
	// admit no affected data and persist as restrictions.
	for _, c := range []struct {
		name string
		fact []byte
	}{
		{"false-completeness", fixtureFact(aID.Machine, absent, event, false, ids)},
		{"unknown-order", fixtureFact(aID.Machine, absent, `{"kind":"unknown"}`, true, ids)},
	} {
		out := b.mustCLI("", "bundle", "restore", "--in", writeTemp(t, c.name+".age", seal([][]byte{c.fact}, data, nil)), "--json")
		rep := restoreReport(t, out)
		if rep.Facts != 1 {
			t.Fatal(c.name, "fact not admitted", out)
		}
		allExcludedAs(t, c.name, rep, len(records), store.ExcludedLineageIncomplete)
		physical.assert(c.name)
	}
	memory := filepath.Join(b.paths.Data, "memory.sqlite")
	if countIn(t, memory, "SELECT count(*) FROM imported_exposure") != 2 {
		t.Fatal("restrictions not persisted")
	}
	// The same data without any fact, after a restart, is still refused.
	b.start()
	b.stop()
	rep := restoreReport(t, b.mustCLI("", "bundle", "restore", "--in", writeTemp(t, "factless.age", good), "--json"))
	allExcludedAs(t, "factless re-restore", rep, len(records), store.ExcludedLineageIncomplete)
	physical.assert("factless re-restore")
}

// eraseSigner signs a device's own erasure control.
type eraseSigner struct{ key ed25519.PrivateKey }

func (s eraseSigner) KeyID() string { return sig.KeyID(s.key.Public().(ed25519.PublicKey)) }
func (s eraseSigner) SignRecordID(id string) (record.Signature, error) {
	return sig.SignRecord(s.key, id)
}

// TestV20UnknownOrderFactHoldsCarriedDependentsOnRootErasure carries two
// independent tasks. An unknown-order fact says the first task's records may
// follow exposure of the later second task's record. With the fact, exact erasure of
// that root holds every potentially downstream record; without it, the same
// erasure leaves them live. Facts only add holds.
func TestV20UnknownOrderFactHoldsCarriedDependentsOnRootErasure(t *testing.T) {
	useBundleVaults(t)
	ctx := context.Background()
	a := newGenesisDevice(t)
	an := a.start()
	// The dependents are captured before the root, so nothing the node
	// itself records ties them to it; only the fact's unknown order does.
	plantTask(t, an, "unknownorderdependentcanary")
	first := dataRecords(t, a.paths.Data)
	plantTask(t, an, "unknownorderrootcanary")
	all := dataRecords(t, a.paths.Data)
	an.stop()
	a.node = nil
	var root string
	for _, r := range all[len(first):] {
		if r.kind == "task" {
			root = r.id
		}
	}
	dependents := idsOf(first)
	if root == "" || len(dependents) < 2 {
		t.Fatal("fixture", root, dependents)
	}
	aID := a.identity()
	key := a.deviceKey()
	defer clear(key)
	sel := selectionOf(t, a, idsOf(all))
	if len(sel.Data) != len(all) {
		t.Fatal(sel.Excluded)
	}
	keyring, data := envelopeLines(t, sel.Keyring), envelopeLines(t, sel.Data)
	fact := fixtureFact(aID.Machine, root, `{"kind":"unknown"}`, true, dependents)
	for _, withFact := range []bool{true, false} {
		recv := joinDevice(t, a)
		offer := offerOf(t, recv)
		var facts [][]byte
		if withFact {
			facts = [][]byte{fact}
		}
		rep := restoreReport(t, recv.mustCLI("", "bundle", "restore", "--in", writeTemp(t, "order.age", sealedFor(t, key, aID.Genesis, keyring, facts, nil, data, offer.Recipient, nil)), "--json"))
		if rep.Data != len(all) || len(rep.Excluded) != 0 {
			t.Fatal("carried root and dependents not admitted", rep)
		}
		ident := recv.identity()
		st, err := store.Open(ctx, store.Options{Dir: recv.paths.Data, PinnedGenesisID: ident.Genesis, LocalMachineID: ident.Machine})
		if err != nil {
			t.Fatal(err)
		}
		receipt, err := st.EraseExact(ctx, store.EraseRequest{IDs: []string{root}}, eraseSigner{recv.deviceKey()})
		if err != nil {
			st.Close()
			t.Fatal(err)
		}
		if res, err := st.Scrub(ctx, receipt.Control); err != nil || res.State != "complete" {
			st.Close()
			t.Fatal(res, err)
		}
		st.Close()
		// Restart before reading.
		recv.start()
		recv.stop()
		for _, id := range dependents {
			e := snapshotOf(t, recv, id)
			if withFact && (e.State == "live" || e.BodyJCS != nil) {
				t.Fatalf("unknown order released %s as %q after root erasure", id[:8], e.State)
			}
			if !withFact && e.State != "live" {
				t.Fatalf("independent %s held as %q without any fact", id[:8], e.State)
			}
		}
		if e := snapshotOf(t, recv, root); e.BodyJCS != nil {
			t.Fatal("erased root served")
		}
	}
}
