package sig

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"sort"
	"sync"

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

// Owner returns the owner namespace of records signed by this key.
func (k *Key) Owner() string { return record.Owner(k.Role, k.Genesis, k.Tenant) }

// KeyOp is one key operation as stored: the admitted record, its body, its
// signatures, and local facts the fold needs.
type KeyOp struct {
	Rec  *record.Record
	Body *record.KeyOpBody
	Sigs []record.Signature
	// AdmittedSeq is the local admission order. Used only for revocation grandfathering.
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
	pinned      string
	ops         map[string]*KeyOp
	cached      *State
	causal      map[string]*causalNode
	work        HistoryWork
	causalBytes int
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
func (k *Keyring) Add(op *KeyOp) error { return k.AddContext(context.Background(), op) }

func (k *Keyring) AddContext(ctx context.Context, op *KeyOp) error {
	if err := ctx.Err(); err != nil {
		return err
	}
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
		priorState, err := k.stateContext(ctx)
		if err != nil {
			return err
		}
		prior := priorState.Status[op.Rec.ID]
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
	pinnedChanged := false
	if op.Body.Op == record.OpGenesis && k.pinned == "" {
		k.pinned = op.Body.Subject.KeyID
		pinnedChanged = true
	}
	// Cached causal decisions depend on the pinned genesis and on duplicate
	// receiver facts; either change discards them.
	if pinnedChanged || k.ops[op.Rec.ID] != nil {
		k.causal = nil
		k.causalBytes = 0
	}
	k.cached = nil
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
	err      error
	cutoffMu sync.Mutex
	cutoffs  map[string]cutoffResult
	Genesis  string
	Keys     map[string]*Key
	Status   map[string]OpStatus // per op id
	Ops      map[string]*KeyOp   // verified immutable operation snapshots
}

// Key is an inspection convenience: prefer the DRK binding, otherwise return
// the sole matching tenant binding. Admission MUST use KeyFor with trusted context.
func (s *State) Key(id string) *Key {
	if s == nil || s.err != nil {
		return nil
	}
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
	if s == nil || s.err != nil {
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
	return bindingKey(b.Subject.Role, genesisOf(b), b.Subject.KeyID)
}
func authorizerBinding(op *KeyOp) string {
	b := op.Body
	return bindingKey(b.Subject.Role, genesisOf(b), authorizerOf(op))
}

// State folds the keyring. The result depends only on the set of stored ops
// and the pinned genesis, never on the order they were added.
func (k *Keyring) State() *State {
	st, err := k.StateContext(context.Background())
	if err != nil {
		return &State{err: err, Genesis: k.pinned, Keys: map[string]*Key{}, Status: map[string]OpStatus{}, Ops: map[string]*KeyOp{}}
	}
	return st
}

// authorize decides one op against the key state of its history.
func (k *Keyring) authorize(op *KeyOp, hist map[string]*Key) OpStatus {
	return k.authorizeLookup(op, func(id string) *Key { return hist[id] })
}

func (k *Keyring) authorizeLookup(op *KeyOp, lookup func(string) *Key) OpStatus {
	b := op.Body
	h := op.Rec.Header
	// Tenant authority comes from authenticated receiver context. A signed field
	// naming a tenant does not select a trusted issuer domain.
	if b.Subject.Role != record.RoleDevice && (!op.Issuer.ValidFor(b.Subject.Role) || op.Issuer.Tenant != genesisOf(b)) {
		return OpUnauthorized
	}
	subjectKey := subjectBinding(b)
	if existing := lookup(subjectKey); existing != nil && existing.MachineID != b.Subject.MachineID {
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
	a := lookup(authorizerBinding(op))
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
		if a.Role != record.RoleDevice || a.Genesis != genesisOf(b) || genesisOf(b) != k.pinned {
			return OpUnauthorized
		}
	case record.OpDeviceRevoke:
		target := lookup(subjectKey)
		deviceOK := a.Role == record.RoleDevice && a.Genesis == genesisOf(b) && genesisOf(b) == k.pinned
		if !deviceOK || target == nil || target.Role != record.RoleDevice || target.Genesis != genesisOf(b) {
			return OpUnauthorized
		}
	case record.OpTenantKeyRotate:
		if a.Role != b.Subject.Role || a.Tenant != genesisOf(b) {
			return OpUnauthorized
		}
	}
	return OpAuthorized
}

// fold computes key state from a set of authorized ops. It is
// set-based: the order of ops does not matter.
func fold(ops []*KeyOp, pinned string) map[string]*Key {
	keys, _ := foldContext(context.Background(), ops, pinned)
	return keys
}

func foldContext(ctx context.Context, ops []*KeyOp, pinned string) (map[string]*Key, error) {
	keys := map[string]*Key{}
	sort.Slice(ops, func(i, j int) bool { return ops[i].Rec.ID < ops[j].Rec.ID })
	for _, op := range ops {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		b := op.Body
		switch b.Op {
		case record.OpGenesis, record.OpDeviceAdd, record.OpDeviceRotate, record.OpTenantKey, record.OpTenantKeyRotate:
			if keys[subjectBinding(b)] == nil {
				pub, _ := DecodePub(b.Subject.Pub)
				key := &Key{KeyID: b.Subject.KeyID, Pub: pub, Role: b.Subject.Role, MachineID: b.Subject.MachineID, Status: KeyActive}
				if key.Role == record.RoleDevice {
					key.Genesis = genesisOf(b)
				} else {
					key.Tenant = genesisOf(b)
				}
				keys[subjectBinding(b)] = key
			}
		}
	}
	causes := map[string]map[string]bool{}
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
		if causes[id] == nil {
			causes[id] = map[string]bool{}
		}
		if !causes[id][cause] {
			if err := reserveHistory(ctx, 128); err != nil {
				return
			}
			causes[id][cause] = true
			key.RevocationCauses = append(key.RevocationCauses, cause)
		}
		key.Status = KeyRevoked
	}
	rotations := map[string][]*KeyOp{}
	edges := map[string][]string{}
	for _, op := range ops {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		b := op.Body
		if b.Op == record.OpDeviceAdd || b.Op == record.OpDeviceRotate || b.Op == record.OpTenantKeyRotate {
			edges[authorizerBinding(op)] = append(edges[authorizerBinding(op)], subjectBinding(b))
		}
		if b.Op == record.OpDeviceRotate || b.Op == record.OpTenantKeyRotate {
			previousBinding := bindingKey(b.Subject.Role, genesisOf(b), b.Previous)
			rotations[previousBinding] = append(rotations[previousBinding], op)
		}
	}
	type poison struct {
		id, cause string
		seq       int64
	}
	var todo []poison
	for prev := range rotations {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if keys[prev] != nil {
			keys[prev].Status = KeyRetired
		}
	}
	for _, rs := range rotations {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		for _, loser := range rs[1:] {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			seq := loser.AdmittedSeq
			if rs[0].AdmittedSeq > seq {
				seq = rs[0].AdmittedSeq
			}
			revoke(subjectBinding(loser.Body), loser.Rec.ID, seq, "conflict")
			todo = append(todo, poison{subjectBinding(loser.Body), loser.Rec.ID, seq})
		}
	}
	for _, op := range ops {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if op.Body.Op == record.OpDeviceRevoke {
			revoke(subjectBinding(op.Body), op.Rec.ID, op.AdmittedSeq, op.Body.Reason)
			if op.Body.Reason == "compromised" {
				todo = append(todo, poison{subjectBinding(op.Body), op.Rec.ID, op.AdmittedSeq})
			}
		}
	}
	seen := map[string]bool{}
	for len(todo) > 0 {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		p := todo[0]
		todo = todo[1:]
		token := p.id + "/" + p.cause
		if seen[token] {
			continue
		}
		seen[token] = true
		for _, child := range edges[p.id] {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			revoke(child, p.cause, p.seq, "cascade")
			todo = append(todo, poison{child, p.cause, p.seq})
		}
	}
	for _, key := range keys {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		sort.Strings(key.RevocationCauses)
	}
	return keys, ctx.Err()
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

// Genesis may omit its redundant authority field. AddContext checks the original
// signed bytes and subject possession before this internal binding is used; an
// explicit Genesis must already match the subject. Never fill the signed body.
func genesisOf(b *record.KeyOpBody) string {
	if b.Op == record.OpGenesis {
		return b.Subject.KeyID
	}
	return b.Genesis
}
