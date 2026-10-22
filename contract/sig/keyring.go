package sig

import (
	"crypto/ed25519"
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
	Label     string
	// Genesis is the genesis key id for a device key; Tenant the tenant id
	// for a service or policy key.
	Genesis string
	Tenant  string
	Status  KeyStatus
	// Revocation facts used by §4.4: the earliest authoring time and the
	// earliest local admission sequence among the ops that revoked the key.
	RevokedAt     int64
	RevokedSeq    int64
	RevokedReason string // compromised | lost | user_request | conflict | cascade
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
	FromLogin bool
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
func (k *Keyring) ConfirmGenesis(keyID string) { k.pinned = keyID }

// Add checks an op's shape and possession signature and stores it. Ops that
// fail are not stored. A stored op may still be held or unauthorized; read
// its status from State.
func (k *Keyring) Add(op *KeyOp) error {
	if err := checkOpShape(op); err != nil {
		return err
	}
	if op.Body.Op == record.OpGenesis && k.pinned == "" {
		k.pinned = op.Body.Subject.KeyID
	}
	k.ops[op.Rec.ID] = op
	return nil
}

// Ops returns the stored ops keyed by id.
func (k *Keyring) Ops() map[string]*KeyOp { return k.ops }

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
	Keys   map[string]*Key
	Status map[string]OpStatus // per op id
}

// Key returns the key with the given id, or nil.
func (s *State) Key(id string) *Key { return s.Keys[id] }

// State folds the keyring. The result depends only on the set of stored ops
// and the pinned genesis, never on the order they were added.
func (k *Keyring) State() *State {
	st := &State{Keys: map[string]*Key{}, Status: map[string]OpStatus{}}
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
			st.Keys[b.Subject.KeyID] != nil && st.Keys[b.Subject.KeyID].RevokedReason == "conflict" {
			st.Status[id] = OpConflictLost
		}
	}
	return st
}

// authorize decides one op against the key state of its history.
func (k *Keyring) authorize(op *KeyOp, hist map[string]*Key) OpStatus {
	b := op.Body
	h := op.Rec.Header
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
			return OpHeldGenesis
		}
		if h.Author.MachineID != b.Subject.MachineID {
			return OpInvalid
		}
		return OpAuthorized
	case record.OpTenantKey:
		if !op.FromLogin {
			return OpIgnored
		}
		if h.Author.MachineID != "" {
			return OpInvalid
		}
		return OpAuthorized
	}
	a := hist[authorID]
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
		target := hist[b.Subject.KeyID]
		deviceOK := a.Role == record.RoleDevice && a.Genesis == b.Genesis && b.Genesis == k.pinned
		serviceOK := a.Role == record.RoleService
		if !(deviceOK || serviceOK) || target == nil || target.Role != record.RoleDevice || target.Genesis != b.Genesis {
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
	addedBy := map[string][]string{} // subject -> authorizers of its device_add ops
	revoke := func(id string, at, seq int64, reason string) {
		k := keys[id]
		if k == nil {
			return
		}
		if k.Status != KeyRevoked || at < k.RevokedAt {
			k.RevokedAt = at
		}
		if k.Status != KeyRevoked || seq < k.RevokedSeq {
			k.RevokedSeq = seq
		}
		if k.Status != KeyRevoked || reason == "compromised" {
			k.RevokedReason = reason
		}
		k.Status = KeyRevoked
	}
	// 1. every key some op made active
	for _, op := range ops {
		b := op.Body
		switch b.Op {
		case record.OpGenesis, record.OpDeviceAdd, record.OpDeviceRotate, record.OpTenantKey, record.OpTenantKeyRotate:
			if _, ok := keys[b.Subject.KeyID]; !ok {
				pub, _ := DecodePub(b.Subject.Pub)
				k := &Key{KeyID: b.Subject.KeyID, Pub: pub, Role: b.Subject.Role, MachineID: b.Subject.MachineID,
					Label: b.Subject.Label, Status: KeyActive}
				if b.Subject.Role == record.RoleDevice {
					k.Genesis = b.Genesis
				} else {
					k.Tenant = b.Genesis
				}
				keys[b.Subject.KeyID] = k
			}
			if b.Op == record.OpDeviceAdd {
				addedBy[b.Subject.KeyID] = append(addedBy[b.Subject.KeyID], authorizerOf(op))
			}
		}
	}
	// 2. rotations retire the previous key; concurrent rotations of one key:
	// the lowest op id wins and every other subject is revoked (conflict)
	rotations := map[string][]*KeyOp{}
	for _, op := range ops {
		if op.Body.Op == record.OpDeviceRotate || op.Body.Op == record.OpTenantKeyRotate {
			rotations[op.Body.Previous] = append(rotations[op.Body.Previous], op)
		}
	}
	for prev, rs := range rotations {
		if k := keys[prev]; k != nil && k.Status == KeyActive {
			k.Status = KeyRetired
		}
		for _, loser := range rs[1:] { // rs is in id order
			revoke(loser.Body.Subject.KeyID, loser.Rec.Header.At, loser.AdmittedSeq, "conflict")
		}
	}
	// 3. revocation is monotone
	var compromised []string
	for _, op := range ops {
		if op.Body.Op == record.OpDeviceRevoke {
			revoke(op.Body.Subject.KeyID, op.Rec.Header.At, op.AdmittedSeq, op.Body.Reason)
			if op.Body.Reason == "compromised" {
				compromised = append(compromised, op.Body.Subject.KeyID)
			}
		}
	}
	// 4. a compromised key takes with it every key whose device_add ops were
	// all authorized by it; applied transitively (fail closed)
	for len(compromised) > 0 {
		bad := compromised[0]
		compromised = compromised[1:]
		src := keys[bad]
		subjects := make([]string, 0, len(addedBy))
		for s := range addedBy {
			subjects = append(subjects, s)
		}
		sort.Strings(subjects)
		for _, subj := range subjects {
			only := true
			for _, a := range addedBy[subj] {
				if a != bad {
					only = false
				}
			}
			if only && keys[subj] != nil && keys[subj].Status != KeyRevoked {
				revoke(subj, src.RevokedAt, src.RevokedSeq, "cascade")
				compromised = append(compromised, subj)
			}
		}
	}
	return keys
}
