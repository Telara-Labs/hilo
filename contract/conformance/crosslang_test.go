// Package conformance_test pins the V6 and V7 cross-language vectors. The Go
// verifier computes the expected key state and record statuses from the
// committed inputs, and the independent Python runner must produce the
// same canonical result bytes.
//
// Regenerate the fixture with:
//
//	GOWORK=off go test ./conformance -run TestKeyringVectors -args -update
//
// Run the Python comparison with an isolated dependency directory:
//
//	GOWORK=off go test ./conformance -run TestPythonCrossLanguage -args -pydeps=/path/to/deps
package conformance_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/Telara-Labs/telara-memory/contract/jcs"
	"github.com/Telara-Labs/telara-memory/contract/record"
	"github.com/Telara-Labs/telara-memory/contract/sig"
)

var (
	update = flag.Bool("update", false, "regenerate the V6/V7 cross-language fixture")
	pyDeps = flag.String("pydeps", "", "pip --target directory holding the Python runner's requirements")
)

const fixtureName = "v06-v07-keyring.json"

type xIssuer struct {
	Tenant     string `json:"tenant"`
	Role       string `json:"role"`
	Provenance string `json:"provenance"`
}

type xOp struct {
	Name          string             `json:"name"`
	HeaderJCS     string             `json:"header_jcs"`
	BodyJCS       string             `json:"body_jcs"`
	ID            string             `json:"id"`
	Sigs          []record.Signature `json:"sigs"`
	FromLogin     bool               `json:"from_login"`
	Issuer        *xIssuer           `json:"issuer,omitempty"`
	AdmittedSeq   int64              `json:"admitted_seq"`
	Receipt       *record.Receipt    `json:"receipt,omitempty"`
	ReceiptIssuer *xIssuer           `json:"receipt_issuer,omitempty"`
}

type xScenario struct {
	Name   string     `json:"name"`
	Pinned string     `json:"pinned"`
	Ops    []string   `json:"ops"`
	Orders [][]string `json:"orders"`
}

type xAdd struct {
	Name   string   `json:"name"`
	Pinned string   `json:"pinned"`
	Prior  []string `json:"prior"`
	Op     xOp      `json:"op"`
}

type xRecord struct {
	Name          string             `json:"name"`
	Scenario      string             `json:"scenario"`
	HeaderJCS     string             `json:"header_jcs"`
	BodyJCS       string             `json:"body_jcs"`
	ID            string             `json:"id"`
	Sigs          []record.Signature `json:"sigs"`
	SignerRole    string             `json:"signer_role,omitempty"`
	Issuer        *xIssuer           `json:"issuer,omitempty"`
	ReceiptIssuer *xIssuer           `json:"receipt_issuer,omitempty"`
	AdmittedSeq   int64              `json:"admitted_seq"`
	Receipt       *record.Receipt    `json:"receipt,omitempty"`
}

type xFixture struct {
	Contract    string      `json:"contract"`
	Description string      `json:"description"`
	Ops         []xOp       `json:"ops"`
	V6          []xScenario `json:"v6"`
	V6Add       []xAdd      `json:"v6_add"`
	V7          []xRecord   `json:"v7"`
	Expected    string      `json:"expected_jcs"`
}

func issuerOf(x *xIssuer) sig.TrustedIssuer {
	if x == nil {
		return sig.TrustedIssuer{}
	}
	return sig.TrustedIssuer{Tenant: x.Tenant, Role: record.Role(x.Role), Provenance: sig.IssuerProvenance(x.Provenance)}
}

func toKeyOp(x xOp) *sig.KeyOp {
	op := &sig.KeyOp{Rec: &record.Record{ID: record.ContentID([]byte(x.HeaderJCS)), HeaderJCS: []byte(x.HeaderJCS), BodyJCS: []byte(x.BodyJCS)},
		Sigs: append([]record.Signature(nil), x.Sigs...), FromLogin: x.FromLogin, Issuer: issuerOf(x.Issuer), AdmittedSeq: x.AdmittedSeq,
		ReceiptIssuer: issuerOf(x.ReceiptIssuer)}
	if x.Receipt != nil {
		r := *x.Receipt
		op.Receipt = &r
	}
	if r, err := record.Parse([]byte(x.HeaderJCS), []byte(x.BodyJCS), ""); err == nil {
		op.Rec = r
		op.Body, _ = r.Body.(*record.KeyOpBody)
	}
	return op
}

func stateResult(st *sig.State, names map[string]string, scenarioOps []string) map[string]any {
	ops := map[string]any{}
	for _, n := range scenarioOps {
		ops[n] = string(st.Status[names[n]])
	}
	keys := map[string]any{}
	for binding, k := range st.Keys {
		causes := append([]string{}, k.RevocationCauses...)
		sort.Strings(causes)
		keys[binding] = map[string]any{"status": string(k.Status), "reason": k.RevokedReason, "causes": causes, "revoked_seq": k.RevokedSeq}
	}
	return map[string]any{"ops": ops, "keys": keys}
}

func foldOrder(t *testing.T, fx *xFixture, pinned string, order []string) (*sig.State, map[string]string) {
	t.Helper()
	byName := map[string]xOp{}
	ids := map[string]string{}
	for _, o := range fx.Ops {
		byName[o.Name] = o
		ids[o.Name] = record.ContentID([]byte(o.HeaderJCS))
	}
	kr := sig.NewKeyring(pinned)
	for _, n := range order {
		o, ok := byName[n]
		if !ok {
			t.Fatalf("unknown op %s", n)
		}
		if err := kr.Add(toKeyOp(o)); err != nil {
			t.Fatalf("scenario op %s refused: %v", n, err)
		}
	}
	return kr.State(), ids
}

// goResults computes the canonical results document with the Go verifier.
func goResults(t *testing.T, fx *xFixture) []byte {
	t.Helper()
	v6 := map[string]any{}
	states := map[string]*sig.State{}
	for _, s := range fx.V6 {
		var ref []byte
		for i, order := range s.Orders {
			st, ids := foldOrder(t, fx, s.Pinned, order)
			res, err := jcs.Marshal(stateResult(st, ids, s.Ops))
			if err != nil {
				t.Fatal(err)
			}
			if i == 0 {
				ref = res
				states[s.Name] = st
				v6[s.Name] = json.RawMessage(res)
			} else if !bytes.Equal(ref, res) {
				t.Fatalf("%s: arrival order changes key state\n%s\n%s", s.Name, ref, res)
			}
		}
	}
	add := map[string]any{}
	for _, a := range fx.V6Add {
		kr := sig.NewKeyring(a.Pinned)
		for _, n := range a.Prior {
			for _, o := range fx.Ops {
				if o.Name == n {
					if err := kr.Add(toKeyOp(o)); err != nil {
						t.Fatalf("%s prior %s: %v", a.Name, n, err)
					}
				}
			}
		}
		add[a.Name] = string(sig.VerifyKeyOp(kr, toKeyOp(a.Op)).Status)
	}
	v7 := map[string]any{}
	for _, r := range fx.V7 {
		st := states[r.Scenario]
		if st == nil {
			t.Fatalf("%s: unknown scenario %s", r.Name, r.Scenario)
		}
		c := sig.Context{SignerRole: record.Role(r.SignerRole), Issuer: issuerOf(r.Issuer), ReceiptIssuer: issuerOf(r.ReceiptIssuer), AdmittedSeq: r.AdmittedSeq}
		if r.Receipt != nil {
			rc := *r.Receipt
			c.Receipt = &rc
		}
		res := sig.VerifyRecord(&record.Record{ID: r.ID, HeaderJCS: []byte(r.HeaderJCS), BodyJCS: []byte(r.BodyJCS)}, r.Sigs, st, c)
		v7[r.Name] = string(res.Status)
	}
	out, err := jcs.Marshal(map[string]any{"v6": v6, "v6_add": add, "v7": v7})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func loadFixture(t *testing.T) *xFixture {
	t.Helper()
	raw, err := os.ReadFile(fixtureName)
	if err != nil {
		t.Fatal(err)
	}
	var fx xFixture
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatal(err)
	}
	return &fx
}

// TestKeyringVectors recomputes V6/V7 with the Go verifier and requires the
// committed expected document byte for byte.
func TestKeyringVectors(t *testing.T) {
	if *update {
		fx := generate(t)
		fx.Expected = string(goResults(t, fx))
		raw, err := json.MarshalIndent(fx, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(fixtureName, append(raw, '\n'), 0644); err != nil {
			t.Fatal(err)
		}
	}
	fx := loadFixture(t)
	if fx.Contract != record.ContractVersion {
		t.Fatalf("fixture contract %s, module %s", fx.Contract, record.ContractVersion)
	}
	got := goResults(t, fx)
	if string(got) != fx.Expected {
		t.Fatalf("Go results differ from the committed expected document\n%s\n%s", got, fx.Expected)
	}
	for _, o := range fx.Ops {
		if o.ID != record.ContentID([]byte(o.HeaderJCS)) {
			t.Fatalf("op %s advisory id differs", o.Name)
		}
	}
	coverage := map[string]bool{}
	for _, s := range fx.V6 {
		coverage[s.Name] = true
	}
	for _, need := range []string{"enroll_rotate_revoke", "held_parent", "mutual_revoke", "double_rotation", "compromise_backdated_rotation", "second_genesis", "tenant_activation_rotation", "tenant_wrong_issuer", "device_add_wrong_machine", "tsk_cannot_revoke_device", "validity"} {
		if !coverage[need] {
			t.Fatalf("V6 scenario %s missing", need)
		}
	}
}

// TestPythonCrossLanguage runs the independent Python runner and requires
// its canonical V6/V7 results to equal the Go results byte for byte.
func TestPythonCrossLanguage(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("UNVERIFIED: python3 is not installed")
	}
	fx := loadFixture(t)
	want := goResults(t, fx)
	out := filepath.Join(t.TempDir(), "results.json")
	args := []string{"-I", "python_vectors.py", "--results", out}
	if *pyDeps != "" {
		args = append(args, "--deps", *pyDeps)
	}
	cmd := exec.Command(python, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		if strings.Contains(string(output), "ModuleNotFoundError") && *pyDeps == "" {
			t.Skipf("UNVERIFIED: Python requirements not installed; pass -pydeps (%s)", strings.TrimSpace(string(output)))
		}
		t.Fatalf("python runner failed: %v\n%s", err, output)
	}
	for _, line := range []string{"V1 PASS", "V2 PASS", "V3 PASS", "V4 PASS", "V5 PASS", "V6 PASS", "V7 PASS"} {
		if !strings.Contains(string(output), line) {
			t.Fatalf("python runner did not report %s\n%s", line, output)
		}
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("Python and Go V6/V7 results differ\npython %s\ngo     %s", got, want)
	}
	t.Logf("%s", output)
}

// ---- generation (only with -update) ----

const (
	mA = "11111111-1111-4111-8111-111111111111"
	mB = "22222222-2222-4222-8222-222222222222"
	mC = "33333333-3333-4333-8333-333333333333"
	mD = "44444444-4444-4444-8444-444444444444"
	mE = "55555555-5555-4555-8555-555555555555"
	t0 = int64(1761150000000)
)

func xkey(name string) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("mnc-xlang-test-key/" + name))
	return ed25519.NewKeyFromSeed(seed[:])
}
func xpub(k ed25519.PrivateKey) ed25519.PublicKey { return k.Public().(ed25519.PublicKey) }
func hx(s string) string                          { return record.ContentID([]byte(s)) }

type gen struct {
	t    *testing.T
	fx   *xFixture
	ops  map[string]*xOp
	list []*xOp
	at   int64
}

func (g *gen) put(name string, op *sig.KeyOp) *xOp {
	x := xOp{Name: name, HeaderJCS: string(op.Rec.HeaderJCS), BodyJCS: string(op.Rec.BodyJCS), ID: op.Rec.ID, Sigs: op.Sigs, FromLogin: op.FromLogin}
	if op.Issuer.Tenant != "" {
		x.Issuer = &xIssuer{op.Issuer.Tenant, string(op.Issuer.Role), string(op.Issuer.Provenance)}
	}
	p := &x
	g.list = append(g.list, p)
	g.ops[name] = p
	return p
}

func (g *gen) op(name string, b record.KeyOpBody, author ed25519.PrivateKey, machine string, signers ...ed25519.PrivateKey) *xOp {
	g.t.Helper()
	g.at++
	op, err := sig.BuildKeyOp(b, xpub(author), machine, g.at, signers...)
	if err != nil {
		g.t.Fatalf("%s: %v", name, err)
	}
	if b.Subject.Role != record.RoleDevice {
		op.Issuer = sig.TrustedIssuer{Tenant: b.Genesis, Role: b.Subject.Role, Provenance: sig.PinnedTLSLogin}
		op.FromLogin = b.Op == record.OpTenantKey
	}
	return g.put(name, op)
}

// raw builds a key op without record.Build validation, for rejection cases.
func (g *gen) raw(name string, b record.KeyOpBody, author ed25519.PrivateKey, machine string, signers ...ed25519.PrivateKey) xOp {
	g.t.Helper()
	g.at++
	body, err := jcs.MarshalRecord(&b)
	if err != nil {
		g.t.Fatal(err)
	}
	h := record.Header{V: record.Version, Type: record.KindKeyOp, LID: record.KeyLID(b.Subject.KeyID), Author: record.Author{MachineID: machine, KeyID: sig.KeyID(xpub(author))},
		At: g.at, Prov: record.ProvUser, Red: record.Redact{Profile: record.ProfileLocal}, Body: &record.BodyRef{Digest: record.BodyDigest(body), Size: int64(len(body))}}
	header, err := jcs.MarshalRecord(&h)
	if err != nil {
		g.t.Fatal(err)
	}
	id := record.ContentID(header)
	x := xOp{Name: name, HeaderJCS: string(header), BodyJCS: string(body), ID: id, Sigs: []record.Signature{}}
	for _, s := range signers {
		sg, err := sig.SignRecord(s, id)
		if err != nil {
			g.t.Fatal(err)
		}
		x.Sigs = append(x.Sigs, sg)
	}
	return x
}

func (g *gen) id(name string) string { return g.ops[name].ID }

func ref(k ed25519.PrivateKey, role record.Role, machine string) record.KeyRef {
	return sig.KeyRefOf(xpub(k), role, machine)
}

func permutations(names []string, limit int) [][]string {
	var out [][]string
	var rec func(prefix, rest []string)
	rec = func(prefix, rest []string) {
		if len(out) >= limit {
			return
		}
		if len(rest) == 0 {
			out = append(out, append([]string(nil), prefix...))
			return
		}
		for i := range rest {
			next := append(append([]string(nil), rest[:i]...), rest[i+1:]...)
			rec(append(prefix, rest[i]), next)
		}
	}
	rec(nil, names)
	// Always include the reverse order.
	rev := append([]string(nil), names...)
	for i, j := 0, len(rev)-1; i < j; i, j = i+1, j-1 {
		rev[i], rev[j] = rev[j], rev[i]
	}
	return append(out, rev)
}

func (g *gen) scenario(name, pinned string, ops ...string) {
	g.fx.V6 = append(g.fx.V6, xScenario{Name: name, Pinned: pinned, Ops: ops, Orders: permutations(ops, 24)})
}

func (g *gen) task(name string, signer ed25519.PrivateKey, owner, machine string, prov record.Prov) (*record.Record, []record.Signature) {
	g.t.Helper()
	const taskID = "3f2a91c0-1111-4222-8333-444455556666"
	h := record.Header{Type: record.KindTask, LID: record.TaskLID(owner, taskID), Author: record.Author{MachineID: machine, KeyID: sig.KeyID(xpub(signer))},
		At: t0 + 5000, Prov: prov, Subj: record.Subject{TaskID: taskID}, Red: record.Redact{Profile: record.ProfileLocal}}
	if prov == record.ProvMCPExplicit {
		h.Op = hx("op/" + name)
	}
	r, err := record.Build(h, &record.TaskBody{Name: "cross-language " + name, Status: "active"})
	if err != nil {
		g.t.Fatalf("%s: %v", name, err)
	}
	s, err := sig.SignRecord(signer, r.ID)
	if err != nil {
		g.t.Fatal(err)
	}
	return r, []record.Signature{s}
}

func (g *gen) record(name, scenario string, r *record.Record, sigs []record.Signature, edit func(*xRecord)) {
	x := xRecord{Name: name, Scenario: scenario, HeaderJCS: string(r.HeaderJCS), BodyJCS: string(r.BodyJCS), ID: r.ID, Sigs: sigs}
	if edit != nil {
		edit(&x)
	}
	g.fx.V7 = append(g.fx.V7, x)
}

func receipt(t *testing.T, k ed25519.PrivateKey, id, device string, at int64) *record.Receipt {
	r, err := sig.SignReceipt(k, record.Receipt{ID: id, Tenant: "acme", DeviceID: device, AcceptedAt: at, HSeq: 9, Policy: hx("policy")})
	if err != nil {
		t.Fatal(err)
	}
	return &r
}

func generate(t *testing.T) *xFixture {
	fx := &xFixture{Contract: record.ContractVersion,
		Description: "V6 VerifyKeyOp key state and possession bootstrap, V7 validity across rotation and revocation. Inputs are signed key operations and records with receiver context; expected is the canonical result document both implementations must produce."}
	g := &gen{t: t, fx: fx, ops: map[string]*xOp{}, at: t0}
	A, B, C, D, E, F, X := xkey("A"), xkey("B"), xkey("C"), xkey("D"), xkey("E"), xkey("F"), xkey("X")
	T1, T2, T3, P1 := xkey("T1"), xkey("T2"), xkey("T3"), xkey("P1")
	gid := sig.KeyID(xpub(A))
	dev := record.RoleDevice

	g.op("genesis", record.KeyOpBody{Op: record.OpGenesis, Subject: ref(A, dev, mA), Genesis: gid}, A, mA, A)
	g.op("addB", record.KeyOpBody{Op: record.OpDeviceAdd, Subject: ref(B, dev, mB), Genesis: gid, Parents: []string{g.id("genesis")}}, A, mA, B, A)
	g.op("rotB", record.KeyOpBody{Op: record.OpDeviceRotate, Subject: ref(C, dev, mB), Genesis: gid, Previous: sig.KeyID(xpub(B)), Parents: []string{g.id("addB")}}, B, mB, B, C)
	g.op("addDbyC", record.KeyOpBody{Op: record.OpDeviceAdd, Subject: ref(D, dev, mD), Genesis: gid, Parents: []string{g.id("rotB")}}, C, mB, D, C)
	g.op("revDlost", record.KeyOpBody{Op: record.OpDeviceRevoke, Subject: ref(D, dev, mD), Genesis: gid, Reason: "lost", Parents: []string{g.id("addDbyC")}}, A, mA, A)
	g.scenario("enroll_rotate_revoke", gid, "genesis", "addB", "rotB", "addDbyC", "revDlost")
	g.scenario("held_parent", gid, "addB", "rotB")

	g.op("revAbyB", record.KeyOpBody{Op: record.OpDeviceRevoke, Subject: ref(A, dev, mA), Genesis: gid, Reason: "user_request", Parents: []string{g.id("addB")}}, B, mB, B)
	g.op("revBbyA", record.KeyOpBody{Op: record.OpDeviceRevoke, Subject: ref(B, dev, mB), Genesis: gid, Reason: "user_request", Parents: []string{g.id("addB")}}, A, mA, A)
	g.scenario("mutual_revoke", gid, "genesis", "addB", "revAbyB", "revBbyA")

	g.op("rotB2C", record.KeyOpBody{Op: record.OpDeviceRotate, Subject: ref(C, dev, mB), Genesis: gid, Previous: sig.KeyID(xpub(B)), Parents: []string{g.id("addB")}}, B, mB, B, C)
	g.op("rotB2D", record.KeyOpBody{Op: record.OpDeviceRotate, Subject: ref(D, dev, mB), Genesis: gid, Previous: sig.KeyID(xpub(B)), Parents: []string{g.id("addB")}}, B, mB, B, D)
	loserOp, loserKey := "rotB2C", C
	if g.id("rotB2C") < g.id("rotB2D") {
		loserOp, loserKey = "rotB2D", D
	}
	g.op("addEbyLoser", record.KeyOpBody{Op: record.OpDeviceAdd, Subject: ref(E, dev, mE), Genesis: gid, Parents: []string{g.id(loserOp)}}, loserKey, mB, E, loserKey)
	g.scenario("double_rotation", gid, "genesis", "addB", "rotB2C", "rotB2D", "addEbyLoser")

	g.op("addCbyB", record.KeyOpBody{Op: record.OpDeviceAdd, Subject: ref(C, dev, mC), Genesis: gid, Parents: []string{g.id("addB")}}, B, mB, C, B)
	g.op("revBcomp", record.KeyOpBody{Op: record.OpDeviceRevoke, Subject: ref(B, dev, mB), Genesis: gid, Reason: "compromised", Parents: []string{g.id("addCbyB")}}, A, mA, A)
	g.op("rotBbackdated", record.KeyOpBody{Op: record.OpDeviceRotate, Subject: ref(E, dev, mB), Genesis: gid, Previous: sig.KeyID(xpub(B)), Parents: []string{g.id("addB")}}, B, mB, B, E)
	g.scenario("compromise_backdated_rotation", gid, "genesis", "addB", "addCbyB", "revBcomp", "rotBbackdated")

	g.op("genesisF", record.KeyOpBody{Op: record.OpGenesis, Subject: ref(F, dev, mC), Genesis: sig.KeyID(xpub(F))}, F, mC, F)
	g.scenario("second_genesis", gid, "genesis", "genesisF")

	g.op("tskT1", record.KeyOpBody{Op: record.OpTenantKey, Subject: ref(T1, record.RoleService, ""), Genesis: "acme"}, T1, "", T1)
	g.op("rotT1T2", record.KeyOpBody{Op: record.OpTenantKeyRotate, Subject: ref(T2, record.RoleService, ""), Genesis: "acme", Previous: sig.KeyID(xpub(T1)), Parents: []string{g.id("tskT1")}}, T1, "", T1)
	synced := g.op("tskT3sync", record.KeyOpBody{Op: record.OpTenantKey, Subject: ref(T3, record.RoleService, ""), Genesis: "acme"}, T3, "", T3)
	synced.FromLogin = false
	synced.Issuer.Provenance = string(sig.AuthenticatedAdmission)
	g.op("tpkP1", record.KeyOpBody{Op: record.OpTenantKey, Subject: ref(P1, record.RolePolicy, ""), Genesis: "acme"}, P1, "", P1)
	g.scenario("tenant_activation_rotation", gid, "genesis", "tskT1", "rotT1T2", "tskT3sync", "tpkP1")

	wrong := g.op("tskGlobexAsAcme", record.KeyOpBody{Op: record.OpTenantKey, Subject: ref(T3, record.RoleService, ""), Genesis: "globex"}, T3, "", T3)
	wrong.Issuer.Tenant = "acme"
	g.scenario("tenant_wrong_issuer", gid, "genesis", "tskGlobexAsAcme")

	g.op("addBwrongMachine", record.KeyOpBody{Op: record.OpDeviceAdd, Subject: ref(B, dev, mB), Genesis: gid, Parents: []string{g.id("genesis")}}, A, mC, B, A)
	g.scenario("device_add_wrong_machine", gid, "genesis", "addBwrongMachine")

	g.op("revBbyTSK", record.KeyOpBody{Op: record.OpDeviceRevoke, Subject: ref(B, dev, mB), Genesis: gid, Reason: "compromised", Parents: []string{g.id("addB")}}, T1, "", T1)
	g.scenario("tsk_cannot_revoke_device", gid, "genesis", "addB", "tskT1", "revBbyTSK")

	// Possession bootstrap and signature-count rejections.
	addCase := func(name string, op xOp, prior ...string) {
		fx.V6Add = append(fx.V6Add, xAdd{Name: name, Pinned: gid, Prior: prior, Op: op})
	}
	tk := record.KeyOpBody{Op: record.OpTenantKey, Subject: ref(T2, record.RoleService, ""), Genesis: "acme"}
	login := func(x xOp) xOp {
		x.FromLogin = true
		x.Issuer = &xIssuer{"acme", "service", string(sig.PinnedTLSLogin)}
		return x
	}
	addCase("tenant_key_login_exactly_one_possession", login(g.raw("tk1", tk, T2, "", T2)), "genesis")
	addCase("tenant_key_without_login_ignored", g.raw("tk1b", tk, T2, "", T2), "genesis")
	addCase("tenant_key_two_signatures", login(g.raw("tk2", tk, T2, "", T2, A)), "genesis")
	addCase("tenant_key_no_signature", login(g.raw("tk0", tk, T2, "")), "genesis")
	addCase("tenant_key_foreign_signature", login(g.raw("tkX", tk, T2, "", X)), "genesis")
	forged := login(g.raw("tkForged", tk, T2, "", X))
	forged.Sigs[0].KeyID = sig.KeyID(xpub(T2))
	addCase("tenant_key_forged_possession", forged, "genesis")
	tkParents := tk
	tkParents.Parents = []string{g.id("genesis")}
	addCase("tenant_key_nonempty_parents", login(g.raw("tkP", tkParents, T2, "", T2)), "genesis")
	gParents := record.KeyOpBody{Op: record.OpGenesis, Subject: ref(A, dev, mA), Genesis: gid, Parents: []string{hx("x")}}
	addCase("genesis_nonempty_parents", g.raw("gP", gParents, A, mA, A))
	addCase("genesis_possession", g.raw("gOK", record.KeyOpBody{Op: record.OpGenesis, Subject: ref(A, dev, mA), Genesis: gid}, A, mA, A))
	addCase("genesis_foreign_signature", g.raw("gX", record.KeyOpBody{Op: record.OpGenesis, Subject: ref(A, dev, mA), Genesis: gid}, A, mA, X))
	add := record.KeyOpBody{Op: record.OpDeviceAdd, Subject: ref(B, dev, mB), Genesis: gid, Parents: []string{g.id("genesis")}}
	addCase("device_add_possession_only", g.raw("aP", add, B, mB, B), "genesis")
	addCase("device_add_authorizer_only", g.raw("aA", add, A, mA, A), "genesis")
	addCase("device_add_wrong_possession", g.raw("aW", add, A, mA, X, A), "genesis")
	addCase("device_add_unknown_authorizer", g.raw("aU", add, X, mC, B, X), "genesis")
	addCase("device_add_duplicate_signer", g.raw("aD", add, A, mA, B, B), "genesis")
	mismatch := add
	mismatch.Subject.KeyID = sig.KeyID(xpub(A))
	addCase("subject_key_id_mismatch", g.raw("aM", mismatch, A, mA, B, A), "genesis")
	rot := record.KeyOpBody{Op: record.OpDeviceRotate, Subject: ref(C, dev, mB), Genesis: gid, Previous: sig.KeyID(xpub(B)), Parents: []string{g.id("addB")}}
	addCase("device_rotate_missing_new_key", g.raw("rM", rot, B, mB, B), "genesis", "addB")
	addCase("device_rotate_both", g.raw("rOK", rot, B, mB, B, C), "genesis", "addB")
	badReason := record.KeyOpBody{Op: record.OpDeviceRevoke, Subject: ref(B, dev, mB), Genesis: gid, Reason: "because", Parents: []string{g.id("addB")}}
	addCase("revoke_unknown_reason", g.raw("vR", badReason, A, mA, A), "genesis", "addB")
	ctxWrong := g.raw("gCtx", record.KeyOpBody{Op: record.OpGenesis, Subject: ref(A, dev, mA), Genesis: gid}, A, mA, A)
	ctxWrong.Sigs[0].Ctx = sig.CtxBundle
	addCase("genesis_wrong_context", ctxWrong)

	// V7: validity across rotation and revocation.
	g.op("addDbyA", record.KeyOpBody{Op: record.OpDeviceAdd, Subject: ref(D, dev, mD), Genesis: gid, Parents: []string{g.id("rotB")}}, A, mA, D, A)
	revD := g.op("revD", record.KeyOpBody{Op: record.OpDeviceRevoke, Subject: ref(D, dev, mD), Genesis: gid, Reason: "lost", Parents: []string{g.id("addDbyA")}}, A, mA, A)
	revD.AdmittedSeq = 50
	revD.Receipt = receipt(t, T1, revD.ID, mA, 1000)
	revD.ReceiptIssuer = &xIssuer{"acme", "service", string(sig.AuthenticatedAdmission)}
	g.op("addE", record.KeyOpBody{Op: record.OpDeviceAdd, Subject: ref(E, dev, mE), Genesis: gid, Parents: []string{g.id("revD")}}, A, mA, E, A)
	revE := g.op("revEcomp", record.KeyOpBody{Op: record.OpDeviceRevoke, Subject: ref(E, dev, mE), Genesis: gid, Reason: "compromised", Parents: []string{g.id("addE")}}, A, mA, A)
	revE.AdmittedSeq = 70
	g.scenario("validity", gid, "genesis", "addB", "rotB", "tskT1", "addDbyA", "revD", "addE", "revEcomp")

	svc := &xIssuer{"acme", "service", string(sig.AuthenticatedAdmission)}
	ra, sa := g.task("active", A, gid, mA, record.ProvMCPExplicit)
	g.record("active_key_verified", "validity", ra, sa, nil)
	rb, sb := g.task("retired", B, gid, mB, record.ProvMCPExplicit)
	g.record("retired_key_backlog_verified", "validity", rb, sb, nil)
	rc, sc := g.task("rotated", C, gid, mB, record.ProvMCPExplicit)
	g.record("rotated_successor_verified", "validity", rc, sc, nil)
	rd, sd := g.task("revoked", D, gid, mD, record.ProvMCPExplicit)
	g.record("revoked_admitted_after", "validity", rd, sd, func(x *xRecord) { x.AdmittedSeq = 60 })
	g.record("revoked_admitted_before", "validity", rd, sd, func(x *xRecord) { x.AdmittedSeq = 40 })
	g.record("revoked_unadmitted_no_receipt", "validity", rd, sd, nil)
	withReceipt := func(at int64, edit func(*record.Receipt)) func(*xRecord) {
		return func(x *xRecord) {
			x.AdmittedSeq = 60
			x.Receipt = receipt(t, T1, rd.ID, mD, at)
			if edit != nil {
				edit(x.Receipt)
			}
			x.ReceiptIssuer = svc
		}
	}
	g.record("receipt_before_cutoff", "validity", rd, sd, withReceipt(999, nil))
	g.record("receipt_at_cutoff", "validity", rd, sd, withReceipt(1000, nil))
	g.record("receipt_after_cutoff", "validity", rd, sd, withReceipt(1001, nil))
	g.record("receipt_altered_after_signing", "validity", rd, sd, withReceipt(999, func(r *record.Receipt) { r.AcceptedAt = 998 }))
	g.record("receipt_for_other_record", "validity", rd, sd, func(x *xRecord) {
		x.AdmittedSeq = 60
		x.Receipt = receipt(t, T1, ra.ID, mD, 999)
		x.ReceiptIssuer = svc
	})
	g.record("receipt_wrong_device", "validity", rd, sd, func(x *xRecord) {
		x.AdmittedSeq = 60
		x.Receipt = receipt(t, T1, rd.ID, mA, 999)
		x.ReceiptIssuer = svc
	})
	g.record("receipt_without_trusted_issuer", "validity", rd, sd, func(x *xRecord) {
		x.AdmittedSeq = 60
		x.Receipt = receipt(t, T1, rd.ID, mD, 999)
	})
	g.record("receipt_by_unknown_key", "validity", rd, sd, func(x *xRecord) {
		x.AdmittedSeq = 60
		x.Receipt = receipt(t, X, rd.ID, mD, 999)
		x.ReceiptIssuer = svc
	})
	re, se := g.task("compromised", E, gid, mE, record.ProvMCPExplicit)
	g.record("compromised_cutoff_unknown", "validity", re, se, func(x *xRecord) {
		x.AdmittedSeq = 80
		x.Receipt = receipt(t, T1, re.ID, mE, 1)
		x.ReceiptIssuer = svc
	})
	g.record("compromised_admitted_before", "validity", re, se, func(x *xRecord) { x.AdmittedSeq = 60 })
	g.record("wrong_signature_context", "validity", ra, sa, func(x *xRecord) {
		x.Sigs = []record.Signature{sig.Sign(A, sig.CtxBundle, mustMsg(t, ra.ID))}
	})
	g.record("relabelled_context", "validity", ra, sa, func(x *xRecord) {
		s := x.Sigs[0]
		s.Ctx = sig.CtxReceipt
		x.Sigs = []record.Signature{s}
	})
	mal := sa[0]
	v, _ := base64.RawURLEncoding.DecodeString(mal.Value)
	v[63] |= 0x80
	mal.Value = base64.RawURLEncoding.EncodeToString(v)
	g.record("malleated_signature", "validity", ra, []record.Signature{mal}, nil)
	g.record("two_signatures", "validity", ra, []record.Signature{sa[0], sa[0]}, nil)
	g.record("no_signature", "validity", ra, []record.Signature{}, nil)
	rx, sx := g.task("unknown", X, gid, mA, record.ProvMCPExplicit)
	g.record("unknown_signer", "validity", rx, sx, nil)
	rm, sm := g.task("machine", A, gid, mB, record.ProvMCPExplicit)
	g.record("machine_mismatch", "validity", rm, sm, nil)
	rs, ss := g.task("service", T1, "tenant:acme", "", record.ProvGateway)
	g.record("service_record_verified", "validity", rs, ss, func(x *xRecord) { x.SignerRole = "service"; x.Issuer = svc })
	g.record("service_record_without_issuer", "validity", rs, ss, func(x *xRecord) { x.SignerRole = "service" })
	g.record("service_key_as_policy_role", "validity", rs, ss, func(x *xRecord) {
		x.SignerRole = "policy"
		x.Issuer = &xIssuer{"acme", "policy", string(sig.PinnedTLSLogin)}
	})
	g.record("service_key_as_device_role", "validity", rs, ss, nil)
	rg, sg := g.task("device-gateway", A, gid, mA, record.ProvGateway)
	g.record("wrong_role_for_provenance", "validity", rg, sg, nil)
	g.record("advisory_id_mismatch", "validity", ra, sa, func(x *xRecord) { x.ID = rb.ID })
	for _, p := range g.list {
		fx.Ops = append(fx.Ops, *p)
	}
	return fx
}

func mustMsg(t *testing.T, id string) []byte {
	m, err := sig.RecordMessage(id)
	if err != nil {
		t.Fatal(err)
	}
	return m
}
