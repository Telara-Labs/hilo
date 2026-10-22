package sig

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/rand"
	"testing"

	"github.com/Telara-Labs/telara-memory/contract/record"
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
	w.op("genesis", record.KeyOpBody{Op: record.OpGenesis, Subject: KeyRefOf(pub(w.genesis), record.RoleDevice, mA, "laptop"),
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
	w.ops[name] = op
	return op
}

func (w *world) id(name string) string { return w.ops[name].Rec.ID }

func (w *world) add(name string, sub ed25519.PrivateKey, machine string, by ed25519.PrivateKey, byMachine string, parents ...string) {
	w.op(name, record.KeyOpBody{Op: record.OpDeviceAdd, Subject: KeyRefOf(pub(sub), record.RoleDevice, machine, ""),
		Genesis: w.gid(), Parents: parents}, by, byMachine, sub, by)
}

func (w *world) revoke(name string, target ed25519.PrivateKey, targetMachine, reason string, by ed25519.PrivateKey, byMachine string, parents ...string) {
	w.op(name, record.KeyOpBody{Op: record.OpDeviceRevoke, Subject: KeyRefOf(pub(target), record.RoleDevice, targetMachine, ""),
		Genesis: w.gid(), Reason: reason, Parents: parents}, by, byMachine, by)
}

func (w *world) rotate(name string, prev, next ed25519.PrivateKey, machine string, parents ...string) {
	w.op(name, record.KeyOpBody{Op: record.OpDeviceRotate, Subject: KeyRefOf(pub(next), record.RoleDevice, machine, ""),
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
	op, err := BuildKeyOp(record.KeyOpBody{Op: record.OpDeviceAdd, Subject: KeyRefOf(pub(B), record.RoleDevice, mB, ""),
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

func TestKeyringSecondGenesisHeld(t *testing.T) {
	w := newWorld(t)
	Z := key("Z")
	w.op("genesis2", record.KeyOpBody{Op: record.OpGenesis, Subject: KeyRefOf(pub(Z), record.RoleDevice, mC, ""), Genesis: KeyID(pub(Z))}, Z, mC, Z)
	st := w.fold([]string{"genesis", "genesis2"})
	if st.Status[w.id("genesis2")] != OpHeldGenesis || status(st, Z) != "" {
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
		if status(st, B) != KeyRevoked || status(st, C) != KeyRevoked || status(st, D) != KeyActive {
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
	tk := w.op("tsk", record.KeyOpBody{Op: record.OpTenantKey, Subject: KeyRefOf(pub(T1), record.RoleService, "", ""), Genesis: "acme"}, T1, "", T1)
	kr := NewKeyring(w.gid())
	_ = kr.Add(w.ops["genesis"])
	if r := VerifyKeyOp(kr, tk); r.Status != OpIgnored {
		t.Fatalf("tenant key from sync must be ignored, got %v", r)
	}
	tk.FromLogin = true
	if r := VerifyKeyOp(kr, tk); r.Status != OpAuthorized {
		t.Fatalf("got %v", r)
	}
	rot := w.op("tskrot", record.KeyOpBody{Op: record.OpTenantKeyRotate, Subject: KeyRefOf(pub(T2), record.RoleService, "", ""),
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
