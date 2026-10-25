package sig

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"sort"
	"testing"

	"github.com/Telara-Labs/telara-memory/contract/jcs"
	"github.com/Telara-Labs/telara-memory/contract/record"
)

// The possession-bootstrap vector pins how a node acquires its first keys:
// the self-signed genesis, a co-signed device_add and the tenant root keys
// taken from the TLS login response. Every op carries exact signed bytes so
// an implementation in another language can recompute every status.
//
// Regenerate with:
//
//	GOWORK=off go test ./sig -run TestV6PossessionBootstrapVector -args -update-possession
var updatePossession = flag.Bool("update-possession", false, "regenerate testdata/v06-possession-bootstrap.json")

const possessionFixture = "../testdata/v06-possession-bootstrap.json"

type pbKey struct {
	Name        string `json:"name"`
	TestSeedHex string `json:"test_seed_hex"`
	Pub         string `json:"pub"`
	KeyID       string `json:"key_id"`
}

type pbIssuer struct {
	Tenant     string `json:"tenant"`
	Role       string `json:"role"`
	Provenance string `json:"provenance"`
}

type pbOp struct {
	Name      string             `json:"name"`
	HeaderJCS string             `json:"header_jcs"`
	BodyJCS   string             `json:"body_jcs"`
	ID        string             `json:"id"`
	Sigs      []record.Signature `json:"sigs"`
	FromLogin bool               `json:"from_login"`
	Issuer    *pbIssuer          `json:"issuer,omitempty"`
}

type pbKeyState struct {
	Role      string `json:"role"`
	Domain    string `json:"domain"`
	KeyID     string `json:"key_id"`
	MachineID string `json:"machine_id"`
	Status    string `json:"status"`
}

type pbBootstrap struct {
	Ops      []string          `json:"ops"`
	Expected map[string]string `json:"expected"`
	Keys     []pbKeyState      `json:"keys"`
}

type pbCase struct {
	Name     string   `json:"name"`
	Rule     string   `json:"rule"`
	Prior    []string `json:"prior"`
	Op       string   `json:"op"`
	Expected string   `json:"expected"`
}

type pbFixture struct {
	Contract    string      `json:"contract"`
	Description string      `json:"description"`
	Pinned      string      `json:"pinned_genesis"`
	Keys        []pbKey     `json:"keys"`
	Ops         []pbOp      `json:"ops"`
	Bootstrap   pbBootstrap `json:"bootstrap"`
	Cases       []pbCase    `json:"cases"`
}

func pbSeed(name string) []byte {
	seed := sha256.Sum256([]byte("mnc-possession-bootstrap-test-key/" + name))
	return seed[:]
}

type pbGen struct {
	t    *testing.T
	fx   *pbFixture
	keys map[string]ed25519.PrivateKey
	ops  map[string]*pbOp
	list []*pbOp
	at   int64
}

func (g *pbGen) key(name string) ed25519.PrivateKey {
	if k, ok := g.keys[name]; ok {
		return k
	}
	seed := pbSeed(name)
	k := ed25519.NewKeyFromSeed(seed)
	g.keys[name] = k
	p := k.Public().(ed25519.PublicKey)
	g.fx.Keys = append(g.fx.Keys, pbKey{Name: name, TestSeedHex: hex.EncodeToString(seed), Pub: EncodePub(p), KeyID: KeyID(p)})
	return k
}

func (g *pbGen) ref(name string, role record.Role, machine string) record.KeyRef {
	return KeyRefOf(g.key(name).Public().(ed25519.PublicKey), role, machine)
}

func (g *pbGen) put(x pbOp) *pbOp {
	if g.ops[x.Name] != nil {
		g.t.Fatalf("duplicate op %s", x.Name)
	}
	p := &x
	g.ops[x.Name] = p
	g.list = append(g.list, p)
	return p
}

// build uses the production builder; raw serializes without validation so
// shapes the builder refuses can still be signed and presented.
func (g *pbGen) build(name string, b record.KeyOpBody, author, machine string, signers ...string) *pbOp {
	g.t.Helper()
	g.at++
	keys := []ed25519.PrivateKey{}
	for _, s := range signers {
		keys = append(keys, g.key(s))
	}
	op, err := BuildKeyOp(b, g.key(author).Public().(ed25519.PublicKey), machine, g.at, keys...)
	if err != nil {
		g.t.Fatalf("%s: %v", name, err)
	}
	sigs := op.Sigs
	if sigs == nil {
		sigs = []record.Signature{}
	}
	return g.put(pbOp{Name: name, HeaderJCS: string(op.Rec.HeaderJCS), BodyJCS: string(op.Rec.BodyJCS), ID: op.Rec.ID, Sigs: sigs})
}

func (g *pbGen) raw(name string, b record.KeyOpBody, author, machine string, signers ...string) *pbOp {
	g.t.Helper()
	g.at++
	body, err := jcs.MarshalRecord(&b)
	if err != nil {
		g.t.Fatal(err)
	}
	h := record.Header{V: record.Version, Type: record.KindKeyOp, LID: record.KeyLID(b.Subject.KeyID),
		Author: record.Author{MachineID: machine, KeyID: KeyID(g.key(author).Public().(ed25519.PublicKey))},
		At:     g.at, Prov: record.ProvUser, Red: record.Redact{Profile: record.ProfileLocal},
		Body: &record.BodyRef{Digest: record.BodyDigest(body), Size: int64(len(body))}}
	header, err := jcs.MarshalRecord(&h)
	if err != nil {
		g.t.Fatal(err)
	}
	x := pbOp{Name: name, HeaderJCS: string(header), BodyJCS: string(body), ID: record.ContentID(header), Sigs: []record.Signature{}}
	for _, s := range signers {
		sg, err := SignRecord(g.key(s), x.ID)
		if err != nil {
			g.t.Fatal(err)
		}
		x.Sigs = append(x.Sigs, sg)
	}
	return g.put(x)
}

func pbLogin(x *pbOp, tenant, role string) *pbOp {
	x.FromLogin = true
	x.Issuer = &pbIssuer{Tenant: tenant, Role: role, Provenance: string(PinnedTLSLogin)}
	return x
}

func generatePossessionFixture(t *testing.T) *pbFixture {
	fx := &pbFixture{Contract: record.ContractVersion,
		Description: "V6 possession bootstrap. Genesis is self-signed by its subject; device_add carries the new key's possession signature and one active co-signer of the same genesis in the op's history; a tenant root key needs exactly one subject possession signature, empty parents and a matching pinned TLS login, and neither the signature nor the login alone suffices. Seeds are public TEST-ONLY inputs. Statuses are what VerifyKeyOp reports for op after the prior ops are added to a keyring pinned to pinned_genesis; bootstrap must fold to the same key state in every arrival order."}
	g := &pbGen{t: t, fx: fx, keys: map[string]ed25519.PrivateKey{}, ops: map[string]*pbOp{}, at: 1761160000000}
	dev, svc, pol := record.RoleDevice, record.RoleService, record.RolePolicy
	const mA, mB, mC = "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222", "33333333-3333-4333-8333-333333333333"
	A := g.key("A")
	gid := KeyID(A.Public().(ed25519.PublicKey))
	fx.Pinned = gid
	for _, n := range []string{"B", "C", "T", "T2", "P", "X"} {
		g.key(n)
	}
	kid := func(n string) string { return KeyID(g.key(n).Public().(ed25519.PublicKey)) }

	genesis := record.KeyOpBody{Op: record.OpGenesis, Subject: g.ref("A", dev, mA), Genesis: gid}
	g.build("genesis", genesis, "A", mA, "A")
	add := record.KeyOpBody{Op: record.OpDeviceAdd, Subject: g.ref("B", dev, mB), Genesis: gid, Parents: []string{g.ops["genesis"].ID}}
	g.build("addB", add, "A", mA, "B", "A")
	tsk := record.KeyOpBody{Op: record.OpTenantKey, Subject: g.ref("T", svc, ""), Genesis: "acme"}
	pbLogin(g.build("tskT", tsk, "T", "", "T"), "acme", "service")
	tpk := record.KeyOpBody{Op: record.OpTenantKey, Subject: g.ref("P", pol, ""), Genesis: "acme"}
	pbLogin(g.build("tpkP", tpk, "P", "", "P"), "acme", "policy")
	sync := record.KeyOpBody{Op: record.OpTenantKey, Subject: g.ref("T2", svc, ""), Genesis: "acme"}
	synced := g.build("tskT2sync", sync, "T2", "", "T2")
	synced.Issuer = &pbIssuer{Tenant: "acme", Role: "service", Provenance: string(AuthenticatedAdmission)}

	// Genesis possession.
	g.raw("gNoSig", genesis, "A", mA)
	g.raw("gForeign", genesis, "A", mA, "X")
	forged := g.raw("gForged", genesis, "A", mA, "X")
	forged.Sigs[0].KeyID = gid
	ctx := g.raw("gBundleCtx", genesis, "A", mA)
	ctx.Sigs = []record.Signature{pbCrossContext(t, A, ctx.ID)}
	gp := genesis
	gp.Parents = []string{record.ContentID([]byte("absent"))}
	g.raw("gParents", gp, "A", mA, "A")

	// device_add possession and co-signature.
	g.raw("addBpossOnly", add, "B", mB, "B")
	g.raw("addBauthOnly", add, "A", mA, "A")
	g.raw("addBforeignPoss", add, "A", mA, "X", "A")
	fp := g.raw("addBforgedPoss", add, "A", mA, "X", "A")
	fp.Sigs[0].KeyID = kid("B")
	bc := g.raw("addBbundleCtx", add, "A", mA, "A")
	bc.Sigs = []record.Signature{pbCrossContext(t, g.key("B"), bc.ID), bc.Sigs[0]}
	g.raw("addBwrongMachine", add, "A", mC, "B", "A")
	addC := record.KeyOpBody{Op: record.OpDeviceAdd, Subject: g.ref("C", dev, mC), Genesis: gid, Parents: []string{g.ops["genesis"].ID}}
	g.raw("addCbyBoutsideHistory", addC, "B", mB, "C", "B")
	g.raw("addCbyTenantKey", addC, "T", "", "C", "T")

	// Tenant root possession and login pin.
	g.raw("tskNoSig", tsk, "T", "")
	g.raw("tskTwoSigs", tsk, "T", "", "T", "A")
	g.raw("tskForeign", tsk, "T", "", "X")
	tf := g.raw("tskForged", tsk, "T", "", "X")
	tf.Sigs[0].KeyID = kid("T")
	tc := g.raw("tskBundleCtx", tsk, "T", "")
	tc.Sigs = []record.Signature{pbCrossContext(t, g.key("T"), tc.ID)}
	tp := tsk
	tp.Parents = []string{g.ops["genesis"].ID}
	g.raw("tskParents", tp, "T", "", "T")
	g.raw("tskAuthorMachine", tsk, "T", mA, "T")
	td := tsk
	td.Subject = g.ref("T", dev, mA)
	g.raw("tskDeviceRole", td, "T", mA, "T")
	for _, x := range []string{"tskNoSig", "tskTwoSigs", "tskForeign", "tskForged", "tskBundleCtx", "tskParents", "tskAuthorMachine", "tskDeviceRole"} {
		pbLogin(g.ops[x], "acme", "service")
	}
	g.raw("tskBundleNoIssuer", tsk, "T", "", "T")
	pbLogin(g.raw("tskPinOtherTenant", tsk, "T", "", "T"), "globex", "service")
	pbLogin(g.raw("tskPinOtherRole", tsk, "T", "", "T"), "acme", "policy")
	ap := pbLogin(g.raw("tskLoginFlagAdmission", tsk, "T", "", "T"), "acme", "service")
	ap.Issuer.Provenance = string(AuthenticatedAdmission)

	c := func(name, rule, op, want string, prior ...string) {
		if prior == nil {
			prior = []string{}
		}
		fx.Cases = append(fx.Cases, pbCase{Name: name, Rule: rule, Prior: prior, Op: op, Expected: want})
	}
	c("genesis_self_possession", "genesis needs one signature by its subject", "genesis", "authorized")
	c("genesis_missing_possession", "genesis needs one signature by its subject", "gNoSig", "invalid")
	c("genesis_foreign_possession", "the possession signature verifies under the body's subject pub", "gForeign", "invalid")
	c("genesis_forged_possession_label", "a key_id label does not make a foreign signature verify", "gForged", "invalid")
	c("genesis_signed_under_bundle_context", "possession is signed over the record context", "gBundleCtx", "invalid")
	c("genesis_nonempty_parents", "genesis has empty parents", "gParents", "invalid")
	c("device_add_possession_and_cosigner", "device_add needs subject possession and an active device of the genesis", "addB", "authorized", "genesis")
	c("device_add_before_parent_held", "missing parents hold the op", "addB", "held-parents")
	c("device_add_possession_only", "device_add needs a co-signer", "addBpossOnly", "invalid", "genesis")
	c("device_add_cosigner_only", "device_add needs subject possession", "addBauthOnly", "invalid", "genesis")
	c("device_add_foreign_possession", "the possession signature verifies under the body's subject pub", "addBforeignPoss", "invalid", "genesis")
	c("device_add_forged_possession_label", "a key_id label does not make a foreign signature verify", "addBforgedPoss", "invalid", "genesis")
	c("device_add_possession_under_bundle_context", "possession is signed over the record context", "addBbundleCtx", "invalid", "genesis")
	c("device_add_author_machine_mismatch", "the author's machine must match its enrolled machine", "addBwrongMachine", "invalid", "genesis")
	c("device_add_cosigner_outside_history", "the co-signer must be active in the state of the op's own history", "addCbyBoutsideHistory", "unauthorized", "genesis", "addB")
	c("device_add_cosigned_by_tenant_key", "a tenant key cannot enroll a device", "addCbyTenantKey", "unauthorized", "genesis", "tskT")
	c("tenant_key_login_possession", "tenant_key: one subject signature, empty parents, matching pinned TLS login", "tskT", "authorized", "genesis")
	c("tenant_policy_key_login_possession", "tenant_key for the policy role", "tpkP", "authorized", "genesis")
	c("tenant_key_signature_without_login", "a valid signature from sync does not pin a tenant key", "tskT2sync", "ignored", "genesis")
	c("tenant_key_from_bundle_without_issuer", "a bundle carries no trusted issuer context", "tskBundleNoIssuer", "unauthorized", "genesis")
	c("tenant_key_login_without_signature", "the TLS login alone does not pin a tenant key", "tskNoSig", "invalid", "genesis")
	c("tenant_key_two_signatures", "tenant_key has exactly one signature", "tskTwoSigs", "invalid", "genesis")
	c("tenant_key_foreign_signature", "the signature verifies under the body's subject pub", "tskForeign", "invalid", "genesis")
	c("tenant_key_forged_label", "a key_id label does not make a foreign signature verify", "tskForged", "invalid", "genesis")
	c("tenant_key_signed_under_bundle_context", "possession is signed over the record context", "tskBundleCtx", "invalid", "genesis")
	c("tenant_key_nonempty_parents", "tenant_key has empty parents", "tskParents", "invalid", "genesis")
	c("tenant_key_author_machine", "tenant keys carry no author machine", "tskAuthorMachine", "invalid", "genesis")
	c("tenant_key_device_role", "tenant keys are service or policy keys", "tskDeviceRole", "invalid", "genesis")
	c("tenant_key_pin_other_tenant", "the login pin must name the body's tenant", "tskPinOtherTenant", "unauthorized", "genesis")
	c("tenant_key_pin_other_role", "the login pin must name the subject's role", "tskPinOtherRole", "unauthorized", "genesis")
	c("tenant_key_login_flag_with_admission_provenance", "only a pinned TLS login activates a tenant root", "tskLoginFlagAdmission", "ignored", "genesis")

	for _, p := range g.list {
		fx.Ops = append(fx.Ops, *p)
	}
	fx.Bootstrap = pbBootstrap{
		Ops:      []string{"genesis", "addB", "tskT", "tpkP", "tskT2sync"},
		Expected: map[string]string{"genesis": "authorized", "addB": "authorized", "tskT": "authorized", "tpkP": "authorized", "tskT2sync": "ignored"},
		Keys: []pbKeyState{
			{Role: "device", Domain: gid, KeyID: gid, MachineID: mA, Status: "active"},
			{Role: "device", Domain: gid, KeyID: kid("B"), MachineID: mB, Status: "active"},
			{Role: "policy", Domain: "acme", KeyID: kid("P"), Status: "active"},
			{Role: "service", Domain: "acme", KeyID: kid("T"), Status: "active"},
		},
	}
	return fx
}

// pbCrossContext signs the record id under the bundle context but labels the
// signature as a record signature, so only the signed bytes are wrong.
func pbCrossContext(t *testing.T, k ed25519.PrivateKey, id string) record.Signature {
	raw, err := hex.DecodeString(id)
	if err != nil {
		t.Fatal(err)
	}
	m := append([]byte(CtxBundle+"\x00"), raw...)
	return record.Signature{Alg: AlgEd25519, KeyID: KeyID(k.Public().(ed25519.PublicKey)), Ctx: CtxRecord, Value: base64.RawURLEncoding.EncodeToString(ed25519.Sign(k, m))}
}

func marshalPossession(t *testing.T, fx *pbFixture) []byte {
	raw, err := json.MarshalIndent(fx, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return append(raw, '\n')
}

func pbKeyOp(x pbOp) *KeyOp {
	op := &KeyOp{Rec: &record.Record{ID: x.ID, HeaderJCS: []byte(x.HeaderJCS), BodyJCS: []byte(x.BodyJCS)},
		Sigs: append([]record.Signature(nil), x.Sigs...), FromLogin: x.FromLogin}
	if x.Issuer != nil {
		op.Issuer = TrustedIssuer{Tenant: x.Issuer.Tenant, Role: record.Role(x.Issuer.Role), Provenance: IssuerProvenance(x.Issuer.Provenance)}
	}
	if r, err := record.Parse([]byte(x.HeaderJCS), []byte(x.BodyJCS), x.ID); err == nil {
		op.Rec = r
		op.Body, _ = r.Body.(*record.KeyOpBody)
	}
	return op
}

func pbPermutations(names []string) [][]string {
	var out [][]string
	var rec func(prefix, rest []string)
	rec = func(prefix, rest []string) {
		if len(rest) == 0 {
			out = append(out, append([]string(nil), prefix...))
			return
		}
		for i := range rest {
			next := append(append([]string(nil), rest[:i]...), rest[i+1:]...)
			rec(append(append([]string(nil), prefix...), rest[i]), next)
		}
	}
	rec(nil, names)
	return out
}

// TestV6PossessionBootstrapVector requires the committed fixture to equal
// what the production builder and signer produce, then requires every case
// and every arrival order of the bootstrap to give the committed statuses.
func TestV6PossessionBootstrapVector(t *testing.T) {
	want := marshalPossession(t, generatePossessionFixture(t))
	if *updatePossession {
		if err := os.WriteFile(possessionFixture, want, 0644); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(possessionFixture)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, want) {
		t.Fatal("committed possession-bootstrap fixture differs from the production builder's bytes")
	}
	var fx pbFixture
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatal(err)
	}
	if fx.Contract != record.ContractVersion {
		t.Fatalf("fixture contract %s, module %s", fx.Contract, record.ContractVersion)
	}
	byName := map[string]pbOp{}
	for _, o := range fx.Ops {
		if o.ID != record.ContentID([]byte(o.HeaderJCS)) {
			t.Fatalf("%s: advisory id differs from sha256(header)", o.Name)
		}
		byName[o.Name] = o
	}
	used := map[string]bool{}
	for _, c := range fx.Cases {
		kr := NewKeyring(fx.Pinned)
		for _, p := range c.Prior {
			if err := kr.Add(pbKeyOp(byName[p])); err != nil {
				t.Fatalf("%s prior %s: %v", c.Name, p, err)
			}
			if s := kr.State().Status[byName[p].ID]; s != OpAuthorized {
				t.Fatalf("%s prior %s: %s", c.Name, p, s)
			}
		}
		x, ok := byName[c.Op]
		if !ok {
			t.Fatalf("%s: unknown op %s", c.Name, c.Op)
		}
		used[c.Op] = true
		got := VerifyKeyOp(kr, pbKeyOp(x))
		if string(got.Status) != c.Expected {
			t.Errorf("%s: got %s (%v), want %s", c.Name, got.Status, got.Err, c.Expected)
		}
	}
	for _, o := range fx.Ops {
		if !used[o.Name] {
			t.Errorf("op %s is not exercised by any case", o.Name)
		}
	}
	for _, order := range pbPermutations(fx.Bootstrap.Ops) {
		kr := NewKeyring(fx.Pinned)
		for _, n := range order {
			if err := kr.Add(pbKeyOp(byName[n])); err != nil {
				t.Fatalf("bootstrap %v: %s: %v", order, n, err)
			}
		}
		st := kr.State()
		for n, w := range fx.Bootstrap.Expected {
			if s := string(st.Status[byName[n].ID]); s != w {
				t.Fatalf("bootstrap %v: %s is %s, want %s", order, n, s, w)
			}
		}
		if len(st.Keys) != len(fx.Bootstrap.Keys) {
			t.Fatalf("bootstrap %v: %d keys, want %d", order, len(st.Keys), len(fx.Bootstrap.Keys))
		}
		for _, k := range fx.Bootstrap.Keys {
			got := st.KeyFor(k.KeyID, record.Role(k.Role), k.Domain)
			if got == nil || string(got.Status) != k.Status || got.MachineID != k.MachineID {
				t.Fatalf("bootstrap %v: key %s/%s/%s is %+v", order, k.Role, k.Domain, k.KeyID, got)
			}
		}
	}
	names := []string{}
	for _, c := range fx.Cases {
		names = append(names, c.Name)
	}
	sort.Strings(names)
	for _, need := range []string{"genesis_self_possession", "device_add_possession_and_cosigner", "tenant_key_login_possession",
		"tenant_key_signature_without_login", "tenant_key_login_without_signature", "tenant_key_two_signatures", "tenant_key_nonempty_parents",
		"tenant_key_pin_other_tenant", "device_add_possession_only", "device_add_cosigner_only"} {
		if i := sort.SearchStrings(names, need); i == len(names) || names[i] != need {
			t.Fatalf("possession case %s missing", need)
		}
	}
}
