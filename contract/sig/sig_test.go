package sig

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/rand"
	"testing"

	"github.com/Telara-Labs/hilo/contract/record"
)

const (
	mA = "11111111-1111-4111-8111-111111111111"
	mB = "22222222-2222-4222-8222-222222222222"
	mC = "33333333-3333-4333-8333-333333333333"
	mD = "44444444-4444-4444-8444-444444444444"
)

func key(name string) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("mnc-test-key/" + name))
	return ed25519.NewKeyFromSeed(seed[:])
}

func pub(k ed25519.PrivateKey) ed25519.PublicKey { return k.Public().(ed25519.PublicKey) }

func hx(s string) string { sum := sha256.Sum256([]byte(s)); return hex.EncodeToString(sum[:]) }

type world struct {
	t       *testing.T
	genesis ed25519.PrivateKey
	ops     map[string]*KeyOp
	at      int64
}

func newWorld(t *testing.T) *world {
	w := &world{t: t, genesis: key("A"), ops: map[string]*KeyOp{}, at: 1761150000000}
	w.op("genesis", record.KeyOpBody{Op: record.OpGenesis, Subject: KeyRefOf(pub(w.genesis), record.RoleDevice, mA),
		Genesis: KeyID(pub(w.genesis))}, w.genesis, mA, w.genesis)
	return w
}

func (w *world) gid() string { return KeyID(pub(w.genesis)) }

func (w *world) op(name string, b record.KeyOpBody, author ed25519.PrivateKey, machine string, signers ...ed25519.PrivateKey) *KeyOp {
	w.t.Helper()
	w.at++
	op, err := BuildKeyOp(b, pub(author), machine, w.at, signers...)
	if err != nil {
		w.t.Fatalf("%s: %v", name, err)
	}
	if b.Subject.Role != record.RoleDevice {
		op.Issuer = TrustedIssuer{Tenant: b.Genesis, Role: b.Subject.Role, Provenance: PinnedTLSLogin}
	}
	w.ops[name] = op
	return op
}

func (w *world) id(name string) string { return w.ops[name].Rec.ID }

func (w *world) add(name string, sub ed25519.PrivateKey, machine string, by ed25519.PrivateKey, byMachine string, parents ...string) {
	w.op(name, record.KeyOpBody{Op: record.OpDeviceAdd, Subject: KeyRefOf(pub(sub), record.RoleDevice, machine),
		Genesis: w.gid(), Parents: parents}, by, byMachine, sub, by)
}

func (w *world) revoke(name string, target ed25519.PrivateKey, targetMachine, reason string, by ed25519.PrivateKey, byMachine string, parents ...string) {
	w.op(name, record.KeyOpBody{Op: record.OpDeviceRevoke, Subject: KeyRefOf(pub(target), record.RoleDevice, targetMachine),
		Genesis: w.gid(), Reason: reason, Parents: parents}, by, byMachine, by)
}

func (w *world) rotate(name string, prev, next ed25519.PrivateKey, machine string, parents ...string) {
	w.op(name, record.KeyOpBody{Op: record.OpDeviceRotate, Subject: KeyRefOf(pub(next), record.RoleDevice, machine),
		Genesis: w.gid(), Previous: KeyID(pub(prev)), Parents: parents}, prev, machine, prev, next)
}

// fold adds the named ops in the given order and returns the state.
func (w *world) fold(order []string) *State {
	kr := NewKeyring(w.gid())
	for _, n := range order {
		if err := kr.Add(w.ops[n]); err != nil {
			w.t.Fatalf("add %s: %v", n, err)
		}
	}
	return kr.State()
}

func names(w *world) []string {
	var n []string
	for k := range w.ops {
		n = append(n, k)
	}
	return n
}

// allOrders asserts that every permutation (or a sample of them) folds to
// the same key statuses.
func allOrders(t *testing.T, w *world, check func(*State)) {
	base := names(w)
	r := rand.New(rand.NewSource(1))
	var ref string
	for i := 0; i < 200; i++ {
		order := append([]string(nil), base...)
		r.Shuffle(len(order), func(a, b int) { order[a], order[b] = order[b], order[a] })
		st := w.fold(order)
		check(st)
		sig := fmt.Sprint(summary(st))
		if ref == "" {
			ref = sig
		} else if sig != ref {
			t.Fatalf("order dependence:\n%s\n%s", ref, sig)
		}
	}
}

func summary(st *State) map[string]string {
	m := map[string]string{}
	for id, k := range st.Keys {
		m[id] = string(k.Status) + "/" + k.RevokedReason
	}
	for id, s := range st.Status {
		m["op:"+id] = string(s)
	}
	return m
}

func status(st *State, k ed25519.PrivateKey) KeyStatus {
	if x := st.Key(KeyID(pub(k))); x != nil {
		return x.Status
	}
	return ""
}

func TestKeyringEnrollRotateRevoke(t *testing.T) {
	w := newWorld(t)
	B, C, D := key("B"), key("C"), key("D")
	w.add("addB", B, mB, w.genesis, mA, w.id("genesis"))
	w.rotate("rotB", B, C, mB, w.id("addB"))
	w.add("addD", D, mD, C, mB, w.id("rotB"))
	allOrders(t, w, func(st *State) {
		if status(st, w.genesis) != KeyActive || status(st, B) != KeyRetired || status(st, C) != KeyActive || status(st, D) != KeyActive {
			t.Fatalf("statuses %v", summary(st))
		}
	})
	w.revoke("revD", D, mD, "lost", w.genesis, mA, w.id("addD"))
	allOrders(t, w, func(st *State) {
		if status(st, D) != KeyRevoked || status(st, C) != KeyActive {
			t.Fatalf("statuses %v", summary(st))
		}
	})
}

func TestKeyringDeviceAddNeedsAuthorizer(t *testing.T) {
	w := newWorld(t)
	B := key("B")
	// possession only: rejected at Add (one signature where two are needed)
	op, err := BuildKeyOp(record.KeyOpBody{Op: record.OpDeviceAdd, Subject: KeyRefOf(pub(B), record.RoleDevice, mB),
		Genesis: w.gid(), Parents: []string{w.id("genesis")}}, pub(B), mB, w.at+1, B)
	if err != nil {
		t.Fatal(err)
	}
	if r := VerifyKeyOp(NewKeyring(w.gid()), op); r.Status != OpInvalid {
		t.Fatalf("got %v", r)
	}
	// authorizer that is not in the keyring: unauthorized
	X := key("X")
	w.add("addB", B, mB, X, mC, w.id("genesis"))
	st := w.fold([]string{"genesis", "addB"})
	if st.Status[w.id("addB")] != OpUnauthorized || status(st, B) != "" {
		t.Fatalf("%v", summary(st))
	}
	// header author machine must be the authorizer's machine
	w.add("addB2", B, mB, w.genesis, mC, w.id("genesis"))
	st = w.fold([]string{"genesis", "addB2"})
	if st.Status[w.id("addB2")] != OpInvalid {
		t.Fatalf("%v", summary(st))
	}
}

func TestKeyringHeldParentsFillLater(t *testing.T) {
	w := newWorld(t)
	B := key("B")
	w.add("addB", B, mB, w.genesis, mA, w.id("genesis"))
	kr := NewKeyring(w.gid())
	if r := VerifyKeyOp(kr, w.ops["addB"]); r.Status != OpHeldParents {
		t.Fatalf("got %v", r)
	}
	if r := VerifyKeyOp(kr, w.ops["genesis"]); r.Status != OpAuthorized {
		t.Fatalf("got %v", r)
	}
	if kr.State().Status[w.id("addB")] != OpAuthorized {
		t.Fatal("held op not filled")
	}
}

func TestKeyringSecondGenesisRefused(t *testing.T) {
	w := newWorld(t)
	Z := key("Z")
	w.op("genesis2", record.KeyOpBody{Op: record.OpGenesis, Subject: KeyRefOf(pub(Z), record.RoleDevice, mC), Genesis: KeyID(pub(Z))}, Z, mC, Z)
	st := w.fold([]string{"genesis", "genesis2"})
	if st.Status[w.id("genesis2")] != OpUnauthorized || status(st, Z) != "" {
		t.Fatalf("%v", summary(st))
	}
}

func TestKeyringMutualRevokeRevokesBoth(t *testing.T) {
	w := newWorld(t)
	B := key("B")
	w.add("addB", B, mB, w.genesis, mA, w.id("genesis"))
	w.revoke("AxB", B, mB, "lost", w.genesis, mA, w.id("addB"))
	w.revoke("BxA", w.genesis, mA, "lost", B, mB, w.id("addB"))
	allOrders(t, w, func(st *State) {
		if status(st, w.genesis) != KeyRevoked || status(st, B) != KeyRevoked {
			t.Fatalf("%v", summary(st))
		}
	})
}

func TestKeyringConcurrentRotationLowestIDWins(t *testing.T) {
	w := newWorld(t)
	B, C1, C2 := key("B"), key("C1"), key("C2")
	w.add("addB", B, mB, w.genesis, mA, w.id("genesis"))
	w.rotate("r1", B, C1, mB, w.id("addB"))
	w.rotate("r2", B, C2, mB, w.id("addB"))
	win, lose := C1, C2
	if w.id("r2") < w.id("r1") {
		win, lose = C2, C1
	}
	allOrders(t, w, func(st *State) {
		if status(st, B) != KeyRetired || status(st, win) != KeyActive || status(st, lose) != KeyRevoked {
			t.Fatalf("%v", summary(st))
		}
		if st.Key(KeyID(pub(lose))).RevokedReason != "conflict" {
			t.Fatal("loser reason")
		}
	})
}

func TestKeyringCompromiseCascades(t *testing.T) {
	w := newWorld(t)
	B, C, D := key("B"), key("C"), key("D")
	w.add("addB", B, mB, w.genesis, mA, w.id("genesis"))
	w.add("addC", C, mC, B, mB, w.id("addB"))          // authorized only by B
	w.add("addD", D, mD, B, mB, w.id("addB"))          // by B ...
	w.add("addD2", D, mD, w.genesis, mA, w.id("addB")) // ... and by A
	w.revoke("revB", B, mB, "compromised", w.genesis, mA, w.id("addC"), w.id("addD"), w.id("addD2"))
	allOrders(t, w, func(st *State) {
		if status(st, B) != KeyRevoked || status(st, C) != KeyRevoked || status(st, D) != KeyRevoked {
			t.Fatalf("%v", summary(st))
		}
		if st.Key(KeyID(pub(C))).RevokedReason != "cascade" {
			t.Fatal("cascade reason")
		}
	})
}

func TestKeyringRevokedAuthorizerCannotAddAfterRevocation(t *testing.T) {
	w := newWorld(t)
	B, E := key("B"), key("E")
	w.add("addB", B, mB, w.genesis, mA, w.id("genesis"))
	w.revoke("revB", B, mB, "lost", w.genesis, mA, w.id("addB"))
	// B signs an add whose history includes its own revocation: unauthorized
	w.add("addE", E, mC, B, mB, w.id("revB"))
	allOrders(t, w, func(st *State) {
		if st.Status[w.id("addE")] != OpUnauthorized || status(st, E) != "" {
			t.Fatalf("%v", summary(st))
		}
	})
}

func TestTenantKeys(t *testing.T) {
	w := newWorld(t)
	T1, T2 := key("TSK1"), key("TSK2")
	tk := w.op("tsk", record.KeyOpBody{Op: record.OpTenantKey, Subject: KeyRefOf(pub(T1), record.RoleService, ""), Genesis: "acme"}, T1, "", T1)
	kr := NewKeyring(w.gid())
	_ = kr.Add(w.ops["genesis"])
	if r := VerifyKeyOp(kr, tk); r.Status != OpIgnored {
		t.Fatalf("tenant key from sync must be ignored, got %v", r)
	}
	tk.FromLogin = true
	if r := VerifyKeyOp(kr, tk); r.Status != OpAuthorized {
		t.Fatalf("got %v", r)
	}
	rot := w.op("tskrot", record.KeyOpBody{Op: record.OpTenantKeyRotate, Subject: KeyRefOf(pub(T2), record.RoleService, ""),
		Genesis: "acme", Previous: KeyID(pub(T1)), Parents: []string{tk.Rec.ID}}, T1, "", T1)
	if r := VerifyKeyOp(kr, rot); r.Status != OpAuthorized {
		t.Fatalf("got %v", r)
	}
	st := kr.State()
	if status(st, T1) != KeyRetired || status(st, T2) != KeyActive || st.Key(KeyID(pub(T2))).Owner() != "tenant:acme" {
		t.Fatalf("%v", summary(st))
	}
}

func TestKeyOpShapeRejects(t *testing.T) {
	w := newWorld(t)
	g := w.ops["genesis"]
	bad := *g
	bad.Sigs = append([]record.Signature(nil), g.Sigs...)
	bad.Sigs[0].Value = bad.Sigs[0].Value[:len(bad.Sigs[0].Value)-2] + "AA"
	if err := NewKeyring("").Add(&bad); err == nil {
		t.Fatal("bad possession signature accepted")
	}
	wrongID := *g
	b := *g.Body
	b.Subject.KeyID = hx("x")[:32]
	wrongID.Body = &b
	if err := NewKeyring("").Add(&wrongID); err == nil {
		t.Fatal("subject key id not derived from pub accepted")
	}
}

func TestCompromiseAndLosingRotationDescendants(t *testing.T) {
	w := newWorld(t)
	b, c, d, e := key("B"), key("C"), key("D"), key("E")
	w.add("b", b, mB, w.genesis, mA, w.id("genesis"))
	w.rotate("c", b, c, mB, w.id("b"))
	w.rotate("d", b, d, mB, w.id("b"))
	loser := c
	loserOp := "c"
	if w.id("c") < w.id("d") {
		loser = d
		loserOp = "d"
	}
	w.add("e", e, mEForTest, loser, mB, w.id(loserOp))
	allOrders(t, w, func(st *State) {
		if status(st, loser) != KeyRevoked || status(st, e) != KeyRevoked {
			t.Fatalf("losing branch escaped %v", summary(st))
		}
	})
	w.revoke("compromise", b, mB, "compromised", w.genesis, mA, w.id("b"))
	allOrders(t, w, func(st *State) {
		if status(st, c) != KeyRevoked || status(st, d) != KeyRevoked || status(st, e) != KeyRevoked {
			t.Fatalf("rotation compromise closure escaped %v", summary(st))
		}
	})
}

const mEForTest = "55555555-5555-4555-8555-555555555555"

func TestDeliveryGrantBindings(t *testing.T) {
	w := newWorld(t)
	tsk := key("TSK")
	op := w.op("tsk", record.KeyOpBody{Op: record.OpTenantKey, Subject: KeyRefOf(pub(tsk), record.RoleService, ""), Genesis: "acme"}, tsk, "", tsk)
	op.FromLogin = true
	kr := NewKeyring(w.gid())
	kr.Add(w.ops["genesis"])
	kr.Add(op)
	st := kr.State()
	id, policy := hx("record"), hx("policy")
	grant, err := SignGrant(tsk, record.DeliveryGrant{RecordID: id, Tenant: "acme", Generation: 4, Policy: policy, RecipientGenesis: w.gid()})
	if err != nil {
		t.Fatal(err)
	}
	verify := func(g record.DeliveryGrant, cutoff int64) error {
		return VerifyGrant(g, st, id, TrustedIssuer{Tenant: "acme", Role: record.RoleService, Provenance: AuthenticatedAdmission}, w.gid(), policy, 4, cutoff)
	}
	if verify(grant, 3) != nil {
		t.Fatal("valid grant refused")
	}
	if verify(grant, 4) == nil {
		t.Fatal("withdrawal cutoff bypass")
	}
	bad := grant
	bad.RecordID = hx("other")
	if verify(bad, 0) == nil {
		t.Fatal("grant transplanted")
	}
	bad = grant
	bad.RecipientGenesis = KeyID(pub(key("foreign")))
	if verify(bad, 0) == nil {
		t.Fatal("foreign recipient accepted")
	}
	bad = grant
	bad.Generation = 5
	if verify(bad, 0) == nil {
		t.Fatal("generation forged")
	}
	deviceGrant, _ := SignGrant(w.genesis, record.DeliveryGrant{RecordID: id, Tenant: "acme", Generation: 4, Policy: policy, RecipientGenesis: w.gid()})
	if verify(deviceGrant, 0) == nil {
		t.Fatal("device minted tenant grant")
	}
}

func TestTenantRotationCannotPoisonDeviceBinding(t *testing.T) {
	w := newWorld(t)
	b := key("B")
	w.add("b", b, mB, w.genesis, mA, w.id("genesis"))
	tsk := key("TSK")
	tk := w.op("tsk", record.KeyOpBody{Op: record.OpTenantKey, Subject: KeyRefOf(pub(tsk), record.RoleService, ""), Genesis: "acme"}, tsk, "", tsk)
	tk.FromLogin = true
	// The tenant knows the public DRK, without possession of its private key.
	w.op("malicious", record.KeyOpBody{Op: record.OpTenantKeyRotate, Subject: KeyRefOf(pub(w.genesis), record.RoleService, ""), Genesis: "acme", Previous: KeyID(pub(tsk)), Parents: []string{w.id("tsk")}}, tsk, "", tsk)
	allOrders(t, w, func(st *State) {
		if st.Status[w.id("malicious")] != OpAuthorized || status(st, w.genesis) != KeyActive || status(st, b) != KeyActive {
			t.Fatalf("TSK crossed authority domain: %+v %v", st.Status, summary(st))
		}
	})
}
func TestStateOperationSnapshotsDetached(t *testing.T) {
	w := newWorld(t)
	b, c := key("B"), key("C")
	w.add("b", b, mB, w.genesis, mA, w.id("genesis"))
	w.add("c", c, mC, b, mB, w.id("b"))
	w.revoke("revoke", b, mB, "compromised", w.genesis, mA, w.id("c"))
	kr := NewKeyring(w.gid())
	for _, op := range w.ops {
		kr.Add(op)
	}
	st := kr.State()
	st.Ops[w.id("revoke")].Body.Reason = "lost"
	st.Ops[w.id("revoke")].Rec.HeaderJCS[0] = 'X'
	if status(kr.State(), c) != KeyRevoked {
		t.Fatal("mutable snapshot changed signed authority semantics")
	}
}
func TestConflictRetirementNeverRevivesLosingRotator(t *testing.T) {
	w := newWorld(t)
	b, c, d := key("B"), key("C"), key("D")
	w.rotate("b", w.genesis, b, mA, w.id("genesis"))
	w.rotate("c", w.genesis, c, mA, w.id("genesis"))
	loser := b
	loserOp := "b"
	if w.id("b") < w.id("c") {
		loser = c
		loserOp = "c"
	}
	w.rotate("d", loser, d, mA, w.id(loserOp))
	for i := 0; i < 100; i++ {
		st := w.fold(names(w))
		if status(st, loser) != KeyRevoked || status(st, d) != KeyRevoked {
			t.Fatalf("retirement revived conflict branch: %v", summary(st))
		}
	}
}

func TestOpsAccessorDetached(t *testing.T) {
	w := newWorld(t)
	kr := NewKeyring(w.gid())
	kr.Add(w.ops["genesis"])
	snapshot := kr.Ops()
	snapshot[w.id("genesis")].Rec.HeaderJCS[0] = 'X'
	snapshot[w.id("genesis")].Body.Subject.MachineID = "bad"
	again := kr.Ops()
	if again[w.id("genesis")].Rec.HeaderJCS[0] != '{' || again[w.id("genesis")].Body.Subject.MachineID != mA || status(kr.State(), w.genesis) != KeyActive {
		t.Fatal("Ops accessor leaked stored slices")
	}
}

func TestTenantSharedSuccessorConflictIsolation(t *testing.T) {
	w := newWorld(t)
	a, b, shared, alternate, next := key("tenantA"), key("tenantB"), key("shared-service"), key("alternate-service"), key("next-A")
	for _, x := range []struct {
		name, tenant string
		key          ed25519.PrivateKey
	}{{"rootA", "tenant-a", a}, {"rootB", "tenant-b", b}} {
		op := w.op(x.name, record.KeyOpBody{Op: record.OpTenantKey, Subject: KeyRefOf(pub(x.key), record.RoleService, ""), Genesis: x.tenant}, x.key, "", x.key)
		op.FromLogin = true
	}
	rotate := func(name, tenant string, prev, subject ed25519.PrivateKey, parent string) {
		w.op(name, record.KeyOpBody{Op: record.OpTenantKeyRotate, Subject: KeyRefOf(pub(subject), record.RoleService, ""), Genesis: tenant, Previous: KeyID(pub(prev)), Parents: []string{w.id(parent)}}, prev, "", prev)
	}
	rotate("aShared", "tenant-a", a, shared, "rootA")
	rotate("aNext", "tenant-a", shared, next, "aShared")
	rotate("bShared", "tenant-b", b, shared, "rootB")
	rotate("bOther", "tenant-b", b, alternate, "rootB")
	allOrders(t, w, func(st *State) {
		ka := st.KeyFor(KeyID(pub(shared)), record.RoleService, "tenant-a")
		kn := st.KeyFor(KeyID(pub(next)), record.RoleService, "tenant-a")
		if ka == nil || ka.Status != KeyRetired || kn == nil || kn.Status != KeyActive {
			t.Fatalf("B conflict poisoned A %+v", st.Keys)
		}
		expectedB := KeyActive
		if w.id("bOther") < w.id("bShared") {
			expectedB = KeyRevoked
		}
		if kb := st.KeyFor(KeyID(pub(shared)), record.RoleService, "tenant-b"); kb == nil || kb.Status != expectedB {
			t.Fatal("B conflict not isolated")
		}
		if st.KeyFor(w.gid(), record.RoleDevice, "").Status != KeyActive {
			t.Fatal("tenant conflict crossed DRK domain")
		}
	})
}
func TestTenantRootRoleAndDRKDomainsIsolated(t *testing.T) {
	w := newWorld(t)
	shared := w.genesis
	tsk := w.op("service", record.KeyOpBody{Op: record.OpTenantKey, Subject: KeyRefOf(pub(shared), record.RoleService, ""), Genesis: "tenant-a"}, shared, "", shared)
	tsk.FromLogin = true
	tpk := w.op("policy", record.KeyOpBody{Op: record.OpTenantKey, Subject: KeyRefOf(pub(shared), record.RolePolicy, ""), Genesis: "tenant-a"}, shared, "", shared)
	tpk.FromLogin = true
	rootB := key("root-B")
	rb := w.op("b", record.KeyOpBody{Op: record.OpTenantKey, Subject: KeyRefOf(pub(rootB), record.RoleService, ""), Genesis: "tenant-b"}, rootB, "", rootB)
	rb.FromLogin = true
	w.op("rotateB", record.KeyOpBody{Op: record.OpTenantKeyRotate, Subject: KeyRefOf(pub(shared), record.RoleService, ""), Genesis: "tenant-b", Previous: KeyID(pub(rootB)), Parents: []string{w.id("b")}}, rootB, "", rootB)
	st := w.fold(names(w))
	for _, domain := range []struct {
		role   record.Role
		tenant string
	}{{record.RoleDevice, ""}, {record.RoleService, "tenant-a"}, {record.RolePolicy, "tenant-a"}, {record.RoleService, "tenant-b"}} {
		k := st.KeyFor(w.gid(), domain.role, domain.tenant)
		if k == nil || k.Status != KeyActive {
			t.Fatal("root/role/DRK domain overwritten")
		}
	}
	r := taskRecord(t, "tenant:tenant-a", pub(shared), "", record.ProvGateway)
	signatures := signed(t, r, shared)
	if got := VerifyRecord(r, signatures, st, Context{SignerRole: record.RoleService}); got.Status == StatusVerified {
		t.Fatal("missing authenticated issuer accepted")
	}
	if got := VerifyRecord(r, signatures, st, Context{SignerRole: record.RoleService, Issuer: TrustedIssuer{Tenant: "tenant-a", Role: record.RoleService, Provenance: PinnedTLSLogin}}); got.Status != StatusVerified || got.Owner != "tenant:tenant-a" {
		t.Fatal("trusted issuer not selected", got)
	}
	if got := VerifyRecord(r, signatures, st, Context{SignerRole: record.RoleService, Issuer: TrustedIssuer{Tenant: "tenant-b", Role: record.RoleService, Provenance: AuthenticatedAdmission}}); got.Status == StatusVerified {
		t.Fatal("untrusted record task namespace chose issuer")
	}
}
func TestDuplicateKeyOpCannotDowngradeIssuer(t *testing.T) {
	w := newWorld(t)
	tsk := key("root")
	op := w.op("root", record.KeyOpBody{Op: record.OpTenantKey, Subject: KeyRefOf(pub(tsk), record.RoleService, ""), Genesis: "tenant-a"}, tsk, "", tsk)
	op.FromLogin = true
	kr := NewKeyring(w.gid())
	kr.Add(w.ops["genesis"])
	kr.Add(op)
	duplicate := cloneOp(op)
	duplicate.FromLogin = false
	duplicate.Issuer = TrustedIssuer{}
	kr.Add(duplicate)
	if kr.State().KeyFor(KeyID(pub(tsk)), record.RoleService, "tenant-a").Status != KeyActive {
		t.Fatal("dedup downgraded trusted login")
	}
}

func TestLaterLoginUpgradesEarlierUnpinnedRoot(t *testing.T) {
	w := newWorld(t)
	tsk := key("upgrade-root")
	op := w.op("root", record.KeyOpBody{Op: record.OpTenantKey, Subject: KeyRefOf(pub(tsk), record.RoleService, ""), Genesis: "tenant-a"}, tsk, "", tsk)
	op.FromLogin = false
	op.Issuer.Provenance = AuthenticatedAdmission
	kr := NewKeyring(w.gid())
	kr.Add(w.ops["genesis"])
	kr.Add(op)
	if kr.State().Status[op.Rec.ID] != OpIgnored {
		t.Fatal("untrusted sync root bootstrapped pin")
	}
	login := cloneOp(op)
	login.FromLogin = true
	login.Issuer.Provenance = PinnedTLSLogin
	kr.Add(login)
	if kr.State().Status[op.Rec.ID] != OpAuthorized {
		t.Fatal("fresh TLS login could not upgrade earlier ignored root")
	}
	kr.Add(op)
	kr.Add(login)
	if kr.State().Status[op.Rec.ID] != OpAuthorized {
		t.Fatal("repeat admission downgraded established login pin")
	}
}
