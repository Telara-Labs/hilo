package sig

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/Telara-Labs/telara-memory/contract/record"
)

// KeyStatus is the state of a key in the folded keyring.
type KeyStatus string

const (
	KeyActive  KeyStatus = "active"
	KeyRetired KeyStatus = "retired" // rotated away; not a compromise statement
	KeyRevoked KeyStatus = "revoked"
)

// Key is one key of the folded keyring.
type Key struct {
	KeyID     string
	Pub       ed25519.PublicKey
	Role      record.Role
	MachineID string
	// Genesis is the genesis key id for a device key; Tenant the tenant id
	// for a service or policy key.
	Genesis string
	Tenant  string
	Status  KeyStatus
	// Verified cause ids and the first local sequence at which revocation
	// became effective. Author timestamps are never authorization cutoffs.
	RevocationCauses []string
	RevokedSeq       int64
	RevokedReason    string // compromised | lost | user_request | conflict | cascade
}

// Owner returns the owner namespace of records signed by this key (§1.3).
func (k *Key) Owner() string { return record.Owner(k.Role, k.Genesis, k.Tenant) }

// KeyOp is one key operation as stored: the admitted record, its body, its
// signatures, and local facts the fold needs.
type KeyOp struct {
	Rec  *record.Record
	Body *record.KeyOpBody
	Sigs []record.Signature
	// AdmittedSeq is the local admission order (§2.3). Only §4.4 reads it.
	AdmittedSeq int64
	// FromLogin marks a tenant_key op taken from the TLS response of login.
	// A tenant_key op without it is never authorized.
	FromLogin bool            `json:"-"`
	Receipt   *record.Receipt // authenticated acceptance of this key operation
	// Trusted receiver context from pinned TLS login/admission, never wire metadata.
	Issuer        TrustedIssuer `json:"-"`
	ReceiptIssuer TrustedIssuer `json:"-"`
}

// OpStatus is the disposition of one key operation in a keyring.
type OpStatus string

const (
	OpAuthorized   OpStatus = "authorized"
	OpHeldParents  OpStatus = "held-parents"  // some parent is not present yet
	OpHeldGenesis  OpStatus = "held-genesis"  // a second genesis, held for local confirmation
	OpUnauthorized OpStatus = "unauthorized"  // parents present, authorizer not active in History(op)
	OpInvalid      OpStatus = "invalid"       // shape or signature failure, never folded
	OpIgnored      OpStatus = "ignored"       // tenant_key not taken from login
	OpConflictLost OpStatus = "conflict-lost" // authorized rotation that lost to a lower id
)

// Keyring is the set of key operations a node holds for its one pinned
// genesis and its tenants. Its state is a pure function of that set.
type Keyring struct {
	pinned string
	ops    map[string]*KeyOp
}

// NewKeyring returns a keyring. pinnedGenesis may be empty, in which case
// the first genesis op added pins itself.
func NewKeyring(pinnedGenesis string) *Keyring {
	return &Keyring{pinned: pinnedGenesis, ops: map[string]*KeyOp{}}
}

// Pinned returns the pinned genesis key id.
func (k *Keyring) Pinned() string { return k.pinned }

// ConfirmGenesis replaces the pinned genesis after local confirmation.
func (k *Keyring) ConfirmGenesis(keyID string) error {
	if keyID != k.pinned {
		return fmt.Errorf("foreign genesis is not supported")
	}
	return nil
}

// Add checks an op's shape and possession signature and stores it. Ops that
// fail are not stored. A stored op may still be held or unauthorized; read
// its status from State.
func (k *Keyring) Add(op *KeyOp) error {
	if op == nil || op.Rec == nil {
		return fmt.Errorf("key op: incomplete")
	}
	parsed, err := record.Parse(op.Rec.HeaderJCS, op.Rec.BodyJCS, op.Rec.ID)
	if err != nil {
		return err
	}
	body, ok := parsed.Body.(*record.KeyOpBody)
	if !ok {
		return fmt.Errorf("key op: body absent")
	}
	a, _ := json.Marshal(body)
	b, _ := json.Marshal(op.Body)
	if !bytes.Equal(a, b) {
		return fmt.Errorf("key op: body differs from signed bytes")
	}
	copyOp := *op
	copyOp.Rec = parsed
	copyOp.Body = body
	copyOp.Sigs = append([]record.Signature(nil), op.Sigs...)
	copyOp.Rec.HeaderJCS = append([]byte(nil), parsed.HeaderJCS...)
	copyOp.Rec.BodyJCS = append([]byte(nil), parsed.BodyJCS...)
	if op.Receipt != nil {
		raw, _ := json.Marshal(op.Receipt)
		var receipt record.Receipt
		json.Unmarshal(raw, &receipt)
		copyOp.Receipt = &receipt
	}
	op = &copyOp
	if err := checkOpShape(op); err != nil {
		return err
	}
	if old := k.ops[op.Rec.ID]; old != nil {
		// Content dedup cannot remove previously authenticated receiver facts.
		prior := k.State().Status[op.Rec.ID]
		if prior == OpAuthorized || prior == OpConflictLost {
			op.Sigs = append([]record.Signature(nil), old.Sigs...)
		}
		if old.Issuer.ValidFor(op.Body.Subject.Role) && old.Issuer.Tenant == op.Body.Genesis && !(op.Issuer.ValidFor(op.Body.Subject.Role) && op.Issuer.Tenant == op.Body.Genesis && op.Issuer.Provenance == PinnedTLSLogin && op.FromLogin) {
			op.Issuer = old.Issuer
		}
		op.FromLogin = old.FromLogin || op.FromLogin
		if old.AdmittedSeq > 0 && (op.AdmittedSeq == 0 || old.AdmittedSeq < op.AdmittedSeq) {
			op.AdmittedSeq = old.AdmittedSeq
		}
		if old.Receipt != nil && old.ReceiptIssuer.ValidFor(record.RoleService) {
			op.Receipt = cloneOp(old).Receipt
			op.ReceiptIssuer = old.ReceiptIssuer
		}
	}
	if op.Body.Op == record.OpGenesis && k.pinned == "" {
		k.pinned = op.Body.Subject.KeyID
	}
	k.ops[op.Rec.ID] = op
	return nil
}

// Ops returns the stored ops keyed by id.
func (k *Keyring) Ops() map[string]*KeyOp {
	out := map[string]*KeyOp{}
	for id, op := range k.ops {
		out[id] = cloneOp(op)
	}
	return out
}

// possessionOps need a signature by the subject key.
func possession(op string) bool {
	return op == record.OpGenesis || op == record.OpDeviceAdd || op == record.OpDeviceRotate
}

// needsAuthorizer reports ops whose second (or only) signature comes from an
// existing key.
func needsAuthorizer(op string) bool {
	switch op {
	case record.OpDeviceAdd, record.OpDeviceRotate, record.OpDeviceRevoke, record.OpTenantKeyRotate:
		return true
	}
	return false
}

// checkOpShape verifies what does not depend on other ops: the record kind,
// the subject key id, the signature list shape and the possession
// signature.
func checkOpShape(op *KeyOp) error {
	if op == nil || op.Rec == nil || op.Body == nil {
		return fmt.Errorf("key op: incomplete")
	}
	if op.Rec.Header.Type != record.KindKeyOp {
		return fmt.Errorf("key op: record is a %s", op.Rec.Header.Type)
	}
	b := op.Body
	pub, err := DecodePub(b.Subject.Pub)
	if err != nil {
		return fmt.Errorf("key op: subject: %w", err)
	}
	if b.Subject.Alg != AlgEd25519 || b.Subject.KeyID != KeyID(pub) {
		return fmt.Errorf("key op: subject key id is not hex(sha256(pub))[:32]")
	}
	want := 0
	if possession(b.Op) {
		want++
	}
	if needsAuthorizer(b.Op) {
		want++
	}
	if b.Op == record.OpTenantKey {
		want = 1
	}
	if len(op.Sigs) != want {
		return fmt.Errorf("key op: %s needs exactly %d signature(s), has %d", b.Op, want, len(op.Sigs))
	}
	msg, err := RecordMessage(op.Rec.ID)
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, s := range op.Sigs {
		if s.Alg != AlgEd25519 || s.Ctx != CtxRecord || seen[s.KeyID] {
			return fmt.Errorf("key op: signatures must be distinct ed25519 %s signatures", CtxRecord)
		}
		seen[s.KeyID] = true
	}
	if possession(b.Op) || b.Op == record.OpTenantKey {
		s, ok := sigBy(op.Sigs, b.Subject.KeyID)
		if !ok {
			return fmt.Errorf("key op: no signature by the subject key")
		}
		if err := Verify(pub, CtxRecord, msg, s); err != nil {
			return fmt.Errorf("key op: possession: %w", err)
		}
	}
	return nil
}

func sigBy(sigs []record.Signature, keyID string) (record.Signature, bool) {
	for _, s := range sigs {
		if s.KeyID == keyID {
			return s, true
		}
	}
	return record.Signature{}, false
}

// authorizerOf returns the key id that must authorize op, or "" when none.
func authorizerOf(op *KeyOp) string {
	b := op.Body
	switch b.Op {
	case record.OpDeviceRotate, record.OpTenantKeyRotate:
		return b.Previous
	case record.OpDeviceAdd, record.OpDeviceRevoke:
		for _, s := range op.Sigs {
			if s.KeyID != b.Subject.KeyID || b.Op == record.OpDeviceRevoke {
				return s.KeyID
			}
		}
	}
	return ""
}

// State is the folded keyring.
type State struct {
	Genesis string
	Keys    map[string]*Key
	Status  map[string]OpStatus // per op id
	Ops     map[string]*KeyOp   // verified immutable operation snapshots
}

// Key is an inspection convenience: prefer the DRK binding, otherwise return
// the sole matching tenant binding. Admission MUST use KeyFor with trusted context.
func (s *State) Key(id string) *Key {
	if k := s.KeyFor(id, record.RoleDevice, ""); k != nil {
		return k
	}
	var found *Key
	for _, k := range s.Keys {
		if k.KeyID == id {
			if found != nil {
				return nil
			}
			found = k
		}
	}
	return found
}

// KeyFor selects an authority binding using authenticated receiver context.
func (s *State) KeyFor(id string, role record.Role, tenant string) *Key {
	if s == nil {
		return nil
	}
	domain := tenant
	if role == record.RoleDevice {
		domain = s.Genesis
	} else if tenant == "" {
		return nil
	}
	return s.Keys[bindingKey(role, domain, id)]
}
func bindingKey(role record.Role, domain, id string) string {
	return record.H("authority", string(role), domain, id)
}
func subjectBinding(b *record.KeyOpBody) string {
	return bindingKey(b.Subject.Role, b.Genesis, b.Subject.KeyID)
}
func authorizerBinding(op *KeyOp) string {
	b := op.Body
	return bindingKey(b.Subject.Role, b.Genesis, authorizerOf(op))
}

// State folds the keyring. The result depends only on the set of stored ops
// and the pinned genesis, never on the order they were added.
func (k *Keyring) State() *State {
	st := &State{Genesis: k.pinned, Keys: map[string]*Key{}, Status: map[string]OpStatus{}, Ops: map[string]*KeyOp{}}
	for id, op := range k.ops {
		st.Ops[id] = cloneOp(op)
	}
	// Ops whose ancestry is incomplete are held.
	complete := map[string]bool{}
	var isComplete func(id string, seen map[string]bool) bool
	isComplete = func(id string, seen map[string]bool) bool {
		if v, ok := complete[id]; ok {
			return v
		}
		op, ok := k.ops[id]
		if !ok || seen[id] {
			return false
		}
		seen[id] = true
		defer delete(seen, id)
		res := true
		for _, p := range op.Body.Parents {
			if !isComplete(p, seen) {
				res = false
			}
		}
		complete[id] = res
		return res
	}
	ids := make([]string, 0, len(k.ops))
	for id := range k.ops {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	anc := map[string]map[string]bool{}
	var ancestors func(id string) map[string]bool
	ancestors = func(id string) map[string]bool {
		if a, ok := anc[id]; ok {
			return a
		}
		a := map[string]bool{}
		for _, p := range k.ops[id].Body.Parents {
			a[p] = true
			for q := range ancestors(p) {
				a[q] = true
			}
		}
		anc[id] = a
		return a
	}
	authorized := map[string]bool{}
	var decide func(id string) OpStatus
	decide = func(id string) OpStatus {
		if s, ok := st.Status[id]; ok {
			return s
		}
		op := k.ops[id]
		hist := ancestors(id)
		for p := range hist {
			decide(p)
		}
		var histOps []*KeyOp
		for p := range hist {
			if authorized[p] {
				histOps = append(histOps, k.ops[p])
			}
		}
		s := k.authorize(op, fold(histOps, k.pinned))
		st.Status[id] = s
		if s == OpAuthorized {
			authorized[id] = true
		}
		return s
	}
	for _, id := range ids {
		if !isComplete(id, map[string]bool{}) {
			st.Status[id] = OpHeldParents
			continue
		}
		decide(id)
	}
	var all []*KeyOp
	for _, id := range ids {
		if authorized[id] {
			all = append(all, k.ops[id])
		}
	}
	st.Keys = fold(all, k.pinned)
	for _, id := range ids {
		if st.Status[id] != OpAuthorized {
			continue
		}
		b := k.ops[id].Body
		if (b.Op == record.OpDeviceRotate || b.Op == record.OpTenantKeyRotate) &&
			st.Keys[subjectBinding(b)] != nil && st.Keys[subjectBinding(b)].RevokedReason == "conflict" {
			st.Status[id] = OpConflictLost
		}
	}
	return st
}

// authorize decides one op against the key state of its history.
func (k *Keyring) authorize(op *KeyOp, hist map[string]*Key) OpStatus {
	b := op.Body
	h := op.Rec.Header
	// Tenant authority comes from authenticated receiver context. A signed field
	// naming a tenant does not select a trusted issuer domain.
	if b.Subject.Role != record.RoleDevice && (!op.Issuer.ValidFor(b.Subject.Role) || op.Issuer.Tenant != b.Genesis) {
		return OpUnauthorized
	}
	subjectKey := subjectBinding(b)
	if existing := hist[subjectKey]; existing != nil && existing.MachineID != b.Subject.MachineID {
		return OpUnauthorized
	}
	msg, _ := RecordMessage(op.Rec.ID)
	// author and machine checks: the author is the authorizer when one is
	// required, else the subject
	authorID := authorizerOf(op)
	if authorID == "" {
		authorID = b.Subject.KeyID
	}
	if h.Author.KeyID != authorID {
		return OpInvalid
	}
	switch b.Op {
	case record.OpGenesis:
		if b.Subject.KeyID != k.pinned {
			return OpUnauthorized
		}
		if h.Author.MachineID != b.Subject.MachineID {
			return OpInvalid
		}
		return OpAuthorized
	case record.OpTenantKey:
		if !op.FromLogin || op.Issuer.Provenance != PinnedTLSLogin {
			return OpIgnored
		}
		if h.Author.MachineID != "" {
			return OpInvalid
		}
		return OpAuthorized
	}
	a := hist[authorizerBinding(op)]
	if a == nil || a.Status != KeyActive {
		return OpUnauthorized
	}
	s, ok := sigBy(op.Sigs, authorID)
	if !ok || Verify(a.Pub, CtxRecord, msg, s) != nil {
		return OpInvalid
	}
	if a.Role == record.RoleDevice && h.Author.MachineID != a.MachineID {
		return OpInvalid
	}
	if a.Role != record.RoleDevice && h.Author.MachineID != "" {
		return OpInvalid
	}
	switch b.Op {
	case record.OpDeviceAdd, record.OpDeviceRotate:
		if a.Role != record.RoleDevice || a.Genesis != b.Genesis || b.Genesis != k.pinned {
			return OpUnauthorized
		}
	case record.OpDeviceRevoke:
		target := hist[subjectKey]
		deviceOK := a.Role == record.RoleDevice && a.Genesis == b.Genesis && b.Genesis == k.pinned
		if !deviceOK || target == nil || target.Role != record.RoleDevice || target.Genesis != b.Genesis {
			return OpUnauthorized
		}
	case record.OpTenantKeyRotate:
		if a.Role != b.Subject.Role || a.Tenant != b.Genesis {
			return OpUnauthorized
		}
	}
	return OpAuthorized
}

// fold computes key state from a set of authorized ops (§4.3). It is
// set-based: the order of ops does not matter.
func fold(ops []*KeyOp, pinned string) map[string]*Key {
	keys := map[string]*Key{}
	sort.Slice(ops, func(i, j int) bool { return ops[i].Rec.ID < ops[j].Rec.ID })
	for _, op := range ops {
		b := op.Body
		switch b.Op {
		case record.OpGenesis, record.OpDeviceAdd, record.OpDeviceRotate, record.OpTenantKey, record.OpTenantKeyRotate:
			if keys[subjectBinding(b)] == nil {
				pub, _ := DecodePub(b.Subject.Pub)
				key := &Key{KeyID: b.Subject.KeyID, Pub: pub, Role: b.Subject.Role, MachineID: b.Subject.MachineID, Status: KeyActive}
				if key.Role == record.RoleDevice {
					key.Genesis = b.Genesis
				} else {
					key.Tenant = b.Genesis
				}
				keys[subjectBinding(b)] = key
			}
		}
	}
	revoke := func(id, cause string, seq int64, reason string) {
		key := keys[id]
		if key == nil {
			return
		}
		if key.Status != KeyRevoked || reason == "compromised" {
			key.RevokedReason = reason
		}
		if seq > 0 && (key.RevokedSeq == 0 || seq < key.RevokedSeq) {
			key.RevokedSeq = seq
		}
		for _, c := range key.RevocationCauses {
			if c == cause {
				key.Status = KeyRevoked
				return
			}
		}
		key.RevocationCauses = append(key.RevocationCauses, cause)
		sort.Strings(key.RevocationCauses)
		key.Status = KeyRevoked
	}
	rotations := map[string][]*KeyOp{}
	edges := map[string][]string{}
	for _, op := range ops {
		b := op.Body
		if b.Op == record.OpDeviceAdd || b.Op == record.OpDeviceRotate || b.Op == record.OpTenantKeyRotate {
			edges[authorizerBinding(op)] = append(edges[authorizerBinding(op)], subjectBinding(b))
		}
		if b.Op == record.OpDeviceRotate || b.Op == record.OpTenantKeyRotate {
			previousBinding := bindingKey(b.Subject.Role, b.Genesis, b.Previous)
			rotations[previousBinding] = append(rotations[previousBinding], op)
		}
	}
	type poison struct {
		id, cause string
		seq       int64
	}
	var todo []poison
	for prev := range rotations {
		if keys[prev] != nil {
			keys[prev].Status = KeyRetired
		}
	}
	for _, rs := range rotations {
		for _, loser := range rs[1:] {
			seq := loser.AdmittedSeq
			if rs[0].AdmittedSeq > seq {
				seq = rs[0].AdmittedSeq
			}
			revoke(subjectBinding(loser.Body), loser.Rec.ID, seq, "conflict")
			todo = append(todo, poison{subjectBinding(loser.Body), loser.Rec.ID, seq})
		}
	}
	for _, op := range ops {
		if op.Body.Op == record.OpDeviceRevoke {
			revoke(subjectBinding(op.Body), op.Rec.ID, op.AdmittedSeq, op.Body.Reason)
			if op.Body.Reason == "compromised" {
				todo = append(todo, poison{subjectBinding(op.Body), op.Rec.ID, op.AdmittedSeq})
			}
		}
	}
	seen := map[string]bool{}
	for len(todo) > 0 {
		p := todo[0]
		todo = todo[1:]
		token := p.id + "/" + p.cause
		if seen[token] {
			continue
		}
		seen[token] = true
		for _, child := range edges[p.id] {
			revoke(child, p.cause, p.seq, "cascade")
			todo = append(todo, poison{child, p.cause, p.seq})
		}
	}
	return keys
}

func cloneOp(op *KeyOp) *KeyOp {
	if op == nil {
		return nil
	}
	c := *op
	c.Sigs = append([]record.Signature(nil), op.Sigs...)
	if op.Rec != nil {
		c.Rec, _ = record.Parse(append([]byte(nil), op.Rec.HeaderJCS...), append([]byte(nil), op.Rec.BodyJCS...), op.Rec.ID)
		if c.Rec != nil {
			c.Body, _ = c.Rec.Body.(*record.KeyOpBody)
		}
	}
	if op.Receipt != nil {
		raw, _ := json.Marshal(op.Receipt)
		var r record.Receipt
		json.Unmarshal(raw, &r)
		c.Receipt = &r
	}
	return &c
}
