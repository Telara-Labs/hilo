package sig_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"sort"
	"testing"
	"time"

	"github.com/Telara-Labs/hilo/contract/record"
	"github.com/Telara-Labs/hilo/contract/sig"
)

const (
	fuzzMachineA = "11111111-1111-4111-8111-111111111111"
	fuzzMachineB = "22222222-2222-4222-8222-222222222222"
	fuzzAt       = int64(1761150000000)
)

func fuzzKey(name string) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("mnc-fuzz-key/" + name))
	return ed25519.NewKeyFromSeed(seed[:])
}

func fuzzPub(k ed25519.PrivateKey) ed25519.PublicKey { return k.Public().(ed25519.PublicKey) }

type signedFixture struct {
	header, body []byte
	id           string
	sigs         []record.Signature
}

// v05Fixture loads the signed conclusion fixture and a keyring whose genesis
// is the fixture's device key, so the unmodified record verifies.
func v05Fixture(tb testing.TB) (signedFixture, *sig.State) {
	tb.Helper()
	raw, err := os.ReadFile("../testdata/v05-signature.json")
	if err != nil {
		tb.Fatal(err)
	}
	var f struct {
		HeaderJCS string           `json:"header_jcs"`
		BodyJCS   string           `json:"body_jcs"`
		RecordID  string           `json:"record_id"`
		Seed      string           `json:"test_seed_hex"`
		Signature record.Signature `json:"signature"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		tb.Fatal(err)
	}
	seed, _ := hex.DecodeString(f.Seed)
	priv := ed25519.NewKeyFromSeed(seed)
	var h record.Header
	if err := json.Unmarshal([]byte(f.HeaderJCS), &h); err != nil {
		tb.Fatal(err)
	}
	op, err := sig.BuildKeyOp(record.KeyOpBody{Op: record.OpGenesis, Subject: sig.KeyRefOf(fuzzPub(priv), record.RoleDevice, h.Author.MachineID),
		Genesis: sig.KeyID(fuzzPub(priv))}, fuzzPub(priv), h.Author.MachineID, fuzzAt, priv)
	if err != nil {
		tb.Fatal(err)
	}
	kr := sig.NewKeyring(sig.KeyID(fuzzPub(priv)))
	if r := sig.VerifyKeyOp(kr, op); r.Status != sig.OpAuthorized {
		tb.Fatalf("genesis %+v", r)
	}
	return signedFixture{[]byte(f.HeaderJCS), []byte(f.BodyJCS), f.RecordID, []record.Signature{f.Signature}}, kr.State()
}

// mutate applies one deterministic edit: 0 flip, 1 truncate, 2 append, 3 insert.
func mutate(b []byte, mode uint8, offset uint32, x byte) []byte {
	out := append([]byte(nil), b...)
	if x == 0 {
		x = 1
	}
	if len(out) == 0 {
		return append(out, x)
	}
	at := int(offset % uint32(len(out)))
	switch mode % 4 {
	case 0:
		out[at] ^= x
	case 1:
		out = out[:at]
	case 2:
		out = append(out, x)
	default:
		out = append(out[:at], append([]byte{x}, out[at:]...)...)
	}
	return out
}

// FuzzVerifyRecordRejectsMutation checks that VerifyRecord never reports a
// changed signed record as verified, whichever id the sender claims.
func FuzzVerifyRecordRejectsMutation(f *testing.F) {
	fx, st := v05Fixture(f)
	if res := sig.VerifyRecord(&record.Record{ID: fx.id, HeaderJCS: fx.header, BodyJCS: fx.body}, fx.sigs, st, sig.Context{}); res.Status != sig.StatusVerified {
		f.Fatalf("unmodified fixture %+v", res)
	}
	for part := uint8(0); part < 6; part++ {
		for mode := uint8(0); mode < 4; mode++ {
			f.Add(part, mode, uint32(17), byte(0x01))
		}
	}
	f.Add(uint8(2), uint8(0), uint32(85), byte(0x80))
	f.Fuzz(func(t *testing.T, part, mode uint8, offset uint32, x byte) {
		header, body := fx.header, fx.body
		sigs := append([]record.Signature(nil), fx.sigs...)
		switch part % 6 {
		case 0:
			header = mutate(header, mode, offset, x)
		case 1:
			body = mutate(body, mode, offset, x)
		case 2:
			sigs[0].Value = string(mutate([]byte(sigs[0].Value), mode, offset, x))
		case 3:
			sigs[0].KeyID = string(mutate([]byte(sigs[0].KeyID), mode, offset, x))
		case 4:
			sigs[0].Ctx = string(mutate([]byte(sigs[0].Ctx), mode, offset, x))
		default:
			sigs[0].Alg = string(mutate([]byte(sigs[0].Alg), mode, offset, x))
		}
		if bytes.Equal(header, fx.header) && bytes.Equal(body, fx.body) && sigs[0] == fx.sigs[0] {
			return
		}
		for _, id := range []string{fx.id, record.ContentID(header)} {
			res := sig.VerifyRecord(&record.Record{ID: id, HeaderJCS: header, BodyJCS: body}, sigs, st, sig.Context{})
			if res.Status == sig.StatusVerified {
				t.Fatalf("mutated record verified (part %d)", part%6)
			}
		}
		// A second signature never rescues or extends a record.
		res := sig.VerifyRecord(&record.Record{ID: fx.id, HeaderJCS: fx.header, BodyJCS: fx.body}, append(append([]record.Signature(nil), fx.sigs...), sigs[0]), st, sig.Context{})
		if res.Status == sig.StatusVerified {
			t.Fatal("two signatures verified")
		}
	})
}

type keyOpWorld struct {
	genesis ed25519.PrivateKey
	ops     []*sig.KeyOp
}

// newKeyOpWorld builds a small valid keyring: genesis, a second device,
// a rotation, a revocation, and a TLS-pinned tenant key with a rotation.
func newKeyOpWorld(tb testing.TB) keyOpWorld {
	tb.Helper()
	A, B, C, D, T1, T2 := fuzzKey("A"), fuzzKey("B"), fuzzKey("C"), fuzzKey("D"), fuzzKey("T1"), fuzzKey("T2")
	gid := sig.KeyID(fuzzPub(A))
	w := keyOpWorld{genesis: A}
	build := func(b record.KeyOpBody, author ed25519.PrivateKey, machine string, signers ...ed25519.PrivateKey) *sig.KeyOp {
		op, err := sig.BuildKeyOp(b, fuzzPub(author), machine, fuzzAt+int64(len(w.ops)), signers...)
		if err != nil {
			tb.Fatal(err)
		}
		if b.Subject.Role != record.RoleDevice {
			op.Issuer = sig.TrustedIssuer{Tenant: b.Genesis, Role: b.Subject.Role, Provenance: sig.PinnedTLSLogin}
			op.FromLogin = b.Op == record.OpTenantKey
		}
		w.ops = append(w.ops, op)
		return op
	}
	g := build(record.KeyOpBody{Op: record.OpGenesis, Subject: sig.KeyRefOf(fuzzPub(A), record.RoleDevice, fuzzMachineA), Genesis: gid}, A, fuzzMachineA, A)
	add := build(record.KeyOpBody{Op: record.OpDeviceAdd, Subject: sig.KeyRefOf(fuzzPub(B), record.RoleDevice, fuzzMachineB), Genesis: gid, Parents: []string{g.Rec.ID}}, A, fuzzMachineA, B, A)
	rot := build(record.KeyOpBody{Op: record.OpDeviceRotate, Subject: sig.KeyRefOf(fuzzPub(C), record.RoleDevice, fuzzMachineB), Genesis: gid, Previous: sig.KeyID(fuzzPub(B)), Parents: []string{add.Rec.ID}}, B, fuzzMachineB, B, C)
	addD := build(record.KeyOpBody{Op: record.OpDeviceAdd, Subject: sig.KeyRefOf(fuzzPub(D), record.RoleDevice, fuzzMachineB), Genesis: gid, Parents: []string{rot.Rec.ID}}, C, fuzzMachineB, D, C)
	build(record.KeyOpBody{Op: record.OpDeviceRevoke, Subject: sig.KeyRefOf(fuzzPub(D), record.RoleDevice, fuzzMachineB), Genesis: gid, Reason: "lost", Parents: []string{addD.Rec.ID}}, A, fuzzMachineA, A)
	tk := build(record.KeyOpBody{Op: record.OpTenantKey, Subject: sig.KeyRefOf(fuzzPub(T1), record.RoleService, ""), Genesis: "acme"}, T1, "", T1)
	build(record.KeyOpBody{Op: record.OpTenantKeyRotate, Subject: sig.KeyRefOf(fuzzPub(T2), record.RoleService, ""), Genesis: "acme", Previous: sig.KeyID(fuzzPub(T1)), Parents: []string{tk.Rec.ID}}, T1, "", T1)
	kr := sig.NewKeyring(gid)
	for _, op := range w.ops {
		if err := kr.Add(op); err != nil {
			tb.Fatal(err)
		}
	}
	for id, s := range kr.State().Status {
		if s != sig.OpAuthorized {
			tb.Fatalf("seed op %s is %s", id, s)
		}
	}
	return w
}

func encodeSigs(tb testing.TB, s []record.Signature) []byte {
	b, err := json.Marshal(s)
	if err != nil {
		tb.Fatal(err)
	}
	return b
}

func stateSummary(st *sig.State) string {
	type k struct {
		Binding, Status, Reason string
		Causes                 []string
		Seq                    int64
	}
	var out []any
	for b, key := range st.Keys {
		out = append(out, k{b, string(key.Status), key.RevokedReason, key.RevocationCauses, key.RevokedSeq})
	}
	for id, s := range st.Status {
		out = append(out, [2]string{id, string(s)})
	}
	sort.Slice(out, func(i, j int) bool {
		a, _ := json.Marshal(out[i])
		b, _ := json.Marshal(out[j])
		return string(a) < string(b)
	})
	raw, _ := json.Marshal(out)
	return string(raw)
}

// FuzzKeyOpDecode feeds arbitrary key operation bytes and signatures into a
// keyring holding a valid history. It must never panic, never authorize a
// genesis other than the pinned one or an unpinned tenant key, and keep the
// folded state independent of insertion order.
func FuzzKeyOpDecode(f *testing.F) {
	w := newKeyOpWorld(f)
	for _, op := range w.ops {
		f.Add(op.Rec.HeaderJCS, op.Rec.BodyJCS, encodeSigs(f, op.Sigs), uint8(0))
		f.Add(op.Rec.HeaderJCS, op.Rec.BodyJCS, encodeSigs(f, op.Sigs), uint8(3))
		f.Add(op.Rec.HeaderJCS, op.Rec.BodyJCS, []byte(`[]`), uint8(1))
	}
	f.Add([]byte(`{}`), []byte(`{}`), []byte(`null`), uint8(0))
	f.Fuzz(func(t *testing.T, header, body, rawSigs []byte, flags uint8) {
		var sigs []record.Signature
		if json.Unmarshal(rawSigs, &sigs) != nil || len(sigs) > 8 {
			return
		}
		op := &sig.KeyOp{Rec: &record.Record{ID: record.ContentID(header), HeaderJCS: header, BodyJCS: body}, Sigs: sigs, AdmittedSeq: int64(flags >> 4)}
		if parsed, err := record.Parse(header, body, ""); err == nil {
			op.Rec = parsed
			op.Body, _ = parsed.Body.(*record.KeyOpBody)
		}
		if flags&1 != 0 {
			op.FromLogin = true
		}
		if flags&2 != 0 && op.Body != nil {
			op.Issuer = sig.TrustedIssuer{Tenant: op.Body.Genesis, Role: op.Body.Subject.Role, Provenance: sig.PinnedTLSLogin}
		}
		start := time.Now()
		kr := sig.NewKeyring(sig.KeyID(fuzzPub(w.genesis)))
		for _, x := range w.ops {
			if err := kr.Add(x); err != nil {
				t.Fatal(err)
			}
		}
		res := sig.VerifyKeyOp(kr, op)
		if d := time.Since(start); d > 5*time.Second {
			t.Fatalf("key op verification took %v", d)
		}
		if res.Status == sig.OpInvalid {
			return
		}
		if op.Body == nil {
			t.Fatal("op without a decoded key body was stored")
		}
		if res.Status == sig.OpAuthorized {
			// Content dedup keeps receiver facts of an earlier identical op,
			// so the stored op, not the offered one, carries the login pin.
			stored := kr.Ops()[op.Rec.ID]
			b := stored.Body
			if b.Op == record.OpGenesis && b.Subject.KeyID != sig.KeyID(fuzzPub(w.genesis)) {
				t.Fatal("foreign genesis authorized")
			}
			if b.Op == record.OpTenantKey && !(stored.FromLogin && stored.Issuer.Provenance == sig.PinnedTLSLogin) {
				t.Fatal("tenant key authorized without a pinned login")
			}
			if b.Op == record.OpTenantKey && (len(b.Parents) != 0 || len(stored.Sigs) != 1) {
				t.Fatal("tenant key authorized with parents or extra signatures")
			}
			pub, err := sig.DecodePub(b.Subject.Pub)
			if err != nil || sig.KeyID(pub) != b.Subject.KeyID {
				t.Fatal("authorized subject key id is not derived from its key")
			}
		}
		// Order independence: the same set added in reverse folds identically.
		rev := sig.NewKeyring(sig.KeyID(fuzzPub(w.genesis)))
		if err := rev.Add(op); err != nil {
			t.Fatalf("stored op refused on re-add: %v", err)
		}
		for i := len(w.ops) - 1; i >= 0; i-- {
			if err := rev.Add(w.ops[i]); err != nil {
				t.Fatal(err)
			}
		}
		if a, b := stateSummary(kr.State()), stateSummary(rev.State()); a != b {
			t.Fatalf("order dependence\n%s\n%s", a, b)
		}
	})
}

// FuzzKeyOpRejectsMutation changes one byte region of one valid key
// operation; the changed operation is never authorized.
func FuzzKeyOpRejectsMutation(f *testing.F) {
	w := newKeyOpWorld(f)
	for i := range w.ops {
		for part := uint8(0); part < 4; part++ {
			f.Add(uint8(i), part, uint8(0), uint32(31), byte(1))
		}
	}
	f.Fuzz(func(t *testing.T, index, part, mode uint8, offset uint32, x byte) {
		i := int(index) % len(w.ops)
		orig := w.ops[i]
		header, body := orig.Rec.HeaderJCS, orig.Rec.BodyJCS
		sigs := append([]record.Signature(nil), orig.Sigs...)
		s := int(offset) % len(sigs)
		switch part % 4 {
		case 0:
			header = mutate(header, mode, offset, x)
		case 1:
			body = mutate(body, mode, offset, x)
		case 2:
			sigs[s].Value = string(mutate([]byte(sigs[s].Value), mode, offset/7, x))
		default:
			sigs[s].KeyID = string(mutate([]byte(sigs[s].KeyID), mode, offset/7, x))
		}
		changed := !bytes.Equal(header, orig.Rec.HeaderJCS) || !bytes.Equal(body, orig.Rec.BodyJCS)
		for j := range sigs {
			changed = changed || sigs[j] != orig.Sigs[j]
		}
		if !changed {
			return
		}
		op := &sig.KeyOp{Rec: &record.Record{ID: orig.Rec.ID, HeaderJCS: header, BodyJCS: body}, Body: orig.Body, Sigs: sigs, FromLogin: orig.FromLogin, Issuer: orig.Issuer}
		if parsed, err := record.Parse(header, body, ""); err == nil {
			op.Rec = parsed
			if kb, ok := parsed.Body.(*record.KeyOpBody); ok {
				op.Body = kb
			}
		}
		kr := sig.NewKeyring(sig.KeyID(fuzzPub(w.genesis)))
		for j, other := range w.ops {
			if j != i {
				if err := kr.Add(other); err != nil {
					t.Fatal(err)
				}
			}
		}
		res := sig.VerifyKeyOp(kr, op)
		if res.Status == sig.OpAuthorized && op.Rec.ID != orig.Rec.ID {
			t.Fatalf("mutated key operation authorized (op %d part %d)", i, part%4)
		}
		if res.Status == sig.OpAuthorized && op.Rec.ID == orig.Rec.ID {
			// Same signed id: only an unsigned list edit could be accepted,
			// and the stored signatures must still all verify.
			msg, _ := sig.RecordMessage(op.Rec.ID)
			for _, s := range kr.Ops()[op.Rec.ID].Sigs {
				ok := false
				for _, k := range kr.State().Keys {
					if s.KeyID == k.KeyID && sig.Verify(k.Pub, sig.CtxRecord, msg, s) == nil {
						ok = true
					}
				}
				if !ok {
					t.Fatalf("authorized operation keeps an unverifiable signature (op %d part %d)", i, part%4)
				}
			}
		}
	})
}
