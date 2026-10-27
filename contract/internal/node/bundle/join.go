package bundle

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"

	"filippo.io/age"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/custodyguard"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/ipc"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/store"
	nodesync "github.com/Telara-Labs/telara-memory/contract/internal/node/sync"
	"github.com/Telara-Labs/telara-memory/contract/record"
	"github.com/Telara-Labs/telara-memory/contract/sig"
)

// A fresh machine joins an identity in four steps, and only then restores:
// the surviving device issues an Invite, the fresh machine answers with a
// JoinRequest carrying its possession-signed device_add, the surviving device
// co-signs it after the owner compares the code and returns an Enrollment,
// and the fresh machine verifies that and provisions its profile.

// Invite names the surviving device that will co-sign and the keyring heads
// the device_add must descend from. It contains no secret.
type Invite struct {
	Version       int      `json:"version"`
	Genesis       string   `json:"genesis"`
	Authorizer    string   `json:"authorizer"`
	AuthorizerPub string   `json:"authorizer_pub"`
	Machine       string   `json:"machine"`
	Parents       []string `json:"parents"`
	At            int64    `json:"at"`
}

// JoinRequest is the fresh machine's answer. Code binds its device key,
// machine, export key and exact device_add, and both screens display it.
type JoinRequest struct {
	Version   int             `json:"version"`
	Genesis   string          `json:"genesis"`
	DeviceAdd record.Envelope `json:"device_add"`
	Recipient string          `json:"recipient"`
	Code      string          `json:"code"`
}

// Enrollment is the complete keyring, including the co-signed device_add.
type Enrollment struct {
	Version int               `json:"version"`
	Genesis string            `json:"genesis"`
	Keyring []record.Envelope `json:"keyring"`
}

type joinPending struct {
	Version   int    `json:"version"`
	Genesis   string `json:"genesis"`
	Device    string `json:"device"`
	Machine   string `json:"machine"`
	Handle    string `json:"vault_handle"`
	DeviceAdd string `json:"device_add"`
}

const deviceCodeDomain = "telara-memory device_add v1"

func joinCode(genesis, device, machine, recipient, op string) string {
	return Code(deviceCodeDomain, genesis, device, machine, recipient, op)
}

func heads(keyring []store.SignedRecord) []string {
	parents := map[string]bool{}
	var ids []string
	for _, r := range keyring {
		parsed, err := record.Parse(r.HeaderJCS, r.BodyJCS, r.AdvisoryID)
		if err != nil {
			continue
		}
		ids = append(ids, parsed.ID)
		if b, ok := parsed.Body.(*record.KeyOpBody); ok {
			for _, p := range b.Parents {
				parents[p] = true
			}
		}
	}
	var out []string
	for _, id := range ids {
		if !parents[id] {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}

// NewInvite is issued by an active device of the identity.
func NewInvite(id Identity, keyring []store.SignedRecord, key ed25519.PrivateKey) (Invite, error) {
	st, err := keyringOf(id.Genesis, keyring)
	if err != nil {
		return Invite{}, err
	}
	pub := key.Public().(ed25519.PublicKey)
	k := st.KeyFor(id.Device, record.RoleDevice, "")
	if k == nil || k.Status != sig.KeyActive || sig.KeyID(pub) != id.Device || k.MachineID != id.Machine {
		return Invite{}, ErrNotEnrolled
	}
	h := heads(keyring)
	if len(h) == 0 || len(h) > 16 {
		return Invite{}, ErrEnrollment
	}
	return Invite{Version: 1, Genesis: id.Genesis, Authorizer: id.Device, AuthorizerPub: sig.EncodePub(pub), Machine: id.Machine, Parents: h, At: time.Now().UnixMilli()}, nil
}

func readBounded(r io.Reader, out any) error {
	b, err := io.ReadAll(io.LimitReader(r, 1<<20+1))
	if err != nil || len(b) > 1<<20 || decodeFile(b, out) != nil {
		return ErrEnrollment
	}
	return nil
}

// ParseInvite strictly decodes an invite.
func ParseInvite(r io.Reader) (Invite, error) {
	var inv Invite
	if readBounded(r, &inv) != nil || inv.Version != 1 || !record.IsKeyID(inv.Genesis) || !record.IsKeyID(inv.Authorizer) || !record.IsUUIDv4(inv.Machine) || inv.At <= 0 || len(inv.Parents) == 0 || len(inv.Parents) > 16 {
		return Invite{}, ErrEnrollment
	}
	pub, err := sig.DecodePub(inv.AuthorizerPub)
	if err != nil || sig.KeyID(pub) != inv.Authorizer {
		return Invite{}, ErrEnrollment
	}
	for _, p := range inv.Parents {
		if !record.IsHex64(p) {
			return Invite{}, ErrEnrollment
		}
	}
	return inv, nil
}

// freshJoinDir requires an owner-only directory with no profile or join.
func freshJoinDir(dir string) error {
	if !filepath.IsAbs(dir) || ipc.ValidateDir(dir, true) != nil {
		return ErrProfile
	}
	for _, name := range []string{"memory.sqlite", "installed-authority.json", store.DeviceJoinName, store.JoinPendingName, store.ExportKeyName} {
		if _, err := os.Lstat(filepath.Join(dir, name)); !errors.Is(err, os.ErrNotExist) {
			return ErrProfile
		}
	}
	return nil
}

// Join creates this fresh machine's device key and export key in the vault,
// records the pending join and returns the request for the surviving device.
func Join(ctx context.Context, dir string, v Vault, inv Invite, newMachine func() (string, error)) (JoinRequest, error) {
	if v == nil {
		return JoinRequest{}, ErrProfile
	}
	if err := freshJoinDir(dir); err != nil {
		return JoinRequest{}, err
	}
	var out JoinRequest
	err := custodyguard.With(ctx, dir, func(locked context.Context) error {
		var err error
		out, err = joinLocked(locked, dir, v, inv, newMachine)
		return err
	})
	return out, err
}

func joinLocked(ctx context.Context, dir string, v Vault, inv Invite, newMachine func() (string, error)) (JoinRequest, error) {
	if err := freshJoinDir(dir); err != nil {
		return JoinRequest{}, err
	}
	authorPub, err := sig.DecodePub(inv.AuthorizerPub)
	if err != nil {
		return JoinRequest{}, ErrEnrollment
	}
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return JoinRequest{}, ErrEnrollment
	}
	defer clear(key)
	machine, err := newMachine()
	if err != nil || !record.IsUUIDv4(machine) {
		return JoinRequest{}, ErrEnrollment
	}
	device := sig.KeyID(pub)
	op, err := sig.BuildKeyOp(record.KeyOpBody{Op: record.OpDeviceAdd, Subject: sig.KeyRefOf(pub, record.RoleDevice, machine), Genesis: inv.Genesis, Parents: inv.Parents}, authorPub, inv.Machine, inv.At, key)
	if err != nil {
		return JoinRequest{}, ErrEnrollment
	}
	handle, err := opaqueHandle()
	if err != nil {
		return JoinRequest{}, err
	}
	if v.Put(ctx, handle, key) != nil {
		return JoinRequest{}, ErrEnrollment
	}
	offer, err := EnsureExportKey(ctx, dir, v, Identity{Genesis: inv.Genesis, Device: device, Machine: machine})
	if err != nil {
		_ = v.Delete(ctx, handle)
		return JoinRequest{}, err
	}
	b, err := json.Marshal(joinPending{1, inv.Genesis, device, machine, handle, op.Rec.ID})
	if err != nil || store.WriteProfileRecord(dir, store.JoinPendingName, b) != nil {
		_ = v.Delete(ctx, handle)
		return JoinRequest{}, ErrEnrollment
	}
	return JoinRequest{Version: 1, Genesis: inv.Genesis, DeviceAdd: nodesync.Envelope(op.Rec.HeaderJCS, op.Rec.BodyJCS, op.Sigs, op.Rec.ID), Recipient: offer.Recipient, Code: joinCode(inv.Genesis, device, machine, offer.Recipient, op.Rec.ID)}, nil
}

// ParseJoinRequest strictly decodes a join request.
func ParseJoinRequest(r io.Reader) (JoinRequest, error) {
	var q JoinRequest
	if readBounded(r, &q) != nil || q.Version != 1 || !record.IsKeyID(q.Genesis) {
		return JoinRequest{}, ErrEnrollment
	}
	return q, nil
}

// Authorize is run on the surviving device after the owner typed the code the
// fresh machine shows. It verifies possession and shape, co-signs and checks
// that the completed device_add is authorized under the local keyring. The
// caller admits the returned record and trusts the returned export key.
func Authorize(id Identity, keyring []store.SignedRecord, key ed25519.PrivateKey, q JoinRequest, typedCode string) (store.SignedRecord, Offer, error) {
	fail := func(err error) (store.SignedRecord, Offer, error) { return store.SignedRecord{}, Offer{}, err }
	if q.Genesis != id.Genesis {
		return fail(ErrForeignGenesis)
	}
	if q.DeviceAdd.Receipt != nil || q.DeviceAdd.Grant != nil {
		return fail(ErrEnrollment)
	}
	r, err := nodesync.OpenEnvelope(q.DeviceAdd)
	if err != nil || r.Body == nil {
		return fail(ErrEnrollment)
	}
	b, ok := r.Body.(*record.KeyOpBody)
	if !ok || b.Op != record.OpDeviceAdd || b.Genesis != id.Genesis || b.Subject.Role != record.RoleDevice || !record.IsUUIDv4(b.Subject.MachineID) || r.Header.Author.KeyID != id.Device || r.Header.Author.MachineID != id.Machine {
		return fail(ErrEnrollment)
	}
	if _, err = age.ParseX25519Recipient(q.Recipient); err != nil {
		return fail(ErrEnrollment)
	}
	want := joinCode(q.Genesis, b.Subject.KeyID, b.Subject.MachineID, q.Recipient, r.ID)
	if q.Code != want || typedCode != want {
		return fail(ErrCode)
	}
	before, err := keyringOf(id.Genesis, keyring)
	if err != nil {
		return fail(err)
	}
	if before.Ops[r.ID] != nil {
		return fail(ErrEnrollment)
	}
	for _, k := range before.Keys {
		if k.KeyID == b.Subject.KeyID || k.MachineID == b.Subject.MachineID {
			return fail(ErrEnrollment)
		}
	}
	for _, p := range b.Parents {
		if before.Ops[p] == nil {
			return fail(ErrEnrollment)
		}
	}
	pub, err := sig.DecodePub(b.Subject.Pub)
	if err != nil || len(q.DeviceAdd.Sigs) != 1 || q.DeviceAdd.Sigs[0].KeyID != b.Subject.KeyID {
		return fail(ErrEnrollment)
	}
	msg, err := sig.RecordMessage(r.ID)
	if err != nil || sig.Verify(pub, sig.CtxRecord, msg, q.DeviceAdd.Sigs[0]) != nil {
		return fail(ErrEnrollment)
	}
	cosign, err := sig.SignRecord(key, r.ID)
	if err != nil {
		return fail(ErrEnrollment)
	}
	completed := store.SignedRecord{HeaderJCS: r.HeaderJCS, BodyJCS: r.BodyJCS, Sigs: []record.Signature{q.DeviceAdd.Sigs[0], cosign}, AdvisoryID: r.ID}
	after, err := keyringOf(id.Genesis, keyring, []store.SignedRecord{completed})
	if err != nil || after.Status[r.ID] != sig.OpAuthorized {
		return fail(ErrEnrollment)
	}
	o := Offer{Version: 1, Genesis: id.Genesis, Device: b.Subject.KeyID, Machine: b.Subject.MachineID, Recipient: q.Recipient}
	o.Code = offerCode(o)
	return completed, o, nil
}

// NewEnrollment packages the complete keyring for the fresh machine.
func NewEnrollment(genesis string, keyring []store.SignedRecord) Enrollment {
	e := Enrollment{Version: 1, Genesis: genesis}
	for _, r := range keyring {
		e.Keyring = append(e.Keyring, nodesync.Envelope(r.HeaderJCS, r.BodyJCS, r.Sigs, r.AdvisoryID))
	}
	return e
}

// ParseEnrollment strictly decodes an enrollment.
func ParseEnrollment(r io.Reader) (Enrollment, error) {
	var e Enrollment
	if readBounded(r, &e) != nil || e.Version != 1 || !record.IsKeyID(e.Genesis) || len(e.Keyring) < 2 || len(e.Keyring) > 4096 {
		return Enrollment{}, ErrEnrollment
	}
	return e, nil
}

// Bootstrapper provisions the joined profile; the CLI supplies the installed
// disclosure bootstrap.
type Bootstrapper func(ctx context.Context, key ed25519.PrivateKey, machine, genesis, deviceAdd string, keyring []store.SignedRecord) error

// Enroll verifies that the enrollment's keyring authorizes this machine's
// pending device_add with both the possession signature and a co-signature by
// another active device of the same genesis, then provisions the profile.
func Enroll(ctx context.Context, dir string, v Vault, e Enrollment, bootstrap Bootstrapper) (Identity, error) {
	if v == nil || bootstrap == nil {
		return Identity{}, ErrProfile
	}
	var out Identity
	err := custodyguard.With(ctx, dir, func(locked context.Context) error {
		var err error
		out, err = enrollLocked(locked, dir, v, e, bootstrap)
		return err
	})
	return out, err
}

func enrollLocked(ctx context.Context, dir string, v Vault, e Enrollment, bootstrap Bootstrapper) (Identity, error) {
	if v == nil || bootstrap == nil {
		return Identity{}, ErrProfile
	}
	b, err := store.ReadProfileRecord(dir, store.JoinPendingName)
	if err != nil {
		return Identity{}, ErrProfile
	}
	var p joinPending
	if decodeFile(b, &p) != nil || p.Version != 1 || p.Genesis != e.Genesis || !record.IsKeyID(p.Handle) {
		return Identity{}, ErrEnrollment
	}
	var keyring []store.SignedRecord
	for _, env := range e.Keyring {
		if env.Receipt != nil || env.Grant != nil {
			return Identity{}, ErrEnrollment
		}
		r, err := nodesync.OpenEnvelope(env)
		if err != nil || r.Body == nil || r.Header.Type != record.KindKeyOp {
			return Identity{}, ErrEnrollment
		}
		keyring = append(keyring, store.SignedRecord{HeaderJCS: r.HeaderJCS, BodyJCS: r.BodyJCS, Sigs: env.Sigs, AdvisoryID: r.ID})
	}
	st, err := keyringOf(e.Genesis, keyring)
	if err != nil || st.Status[p.DeviceAdd] != sig.OpAuthorized {
		return Identity{}, ErrEnrollment
	}
	op := st.Ops[p.DeviceAdd]
	if op == nil || op.Body.Op != record.OpDeviceAdd || op.Body.Subject.KeyID != p.Device || op.Body.Subject.MachineID != p.Machine || len(op.Sigs) != 2 || op.Rec.Header.Author.KeyID == p.Device {
		return Identity{}, ErrEnrollment
	}
	k := st.KeyFor(p.Device, record.RoleDevice, "")
	if k == nil || k.Status != sig.KeyActive || k.MachineID != p.Machine {
		return Identity{}, ErrEnrollment
	}
	secret, err := v.Get(ctx, p.Handle)
	defer clear(secret)
	if err != nil || len(secret) != ed25519.PrivateKeySize {
		return Identity{}, ErrEnrollment
	}
	key := ed25519.PrivateKey(secret)
	if sig.KeyID(key.Public().(ed25519.PublicKey)) != p.Device {
		return Identity{}, ErrEnrollment
	}
	if err = bootstrap(ctx, key, p.Machine, p.Genesis, p.DeviceAdd, keyring); err != nil {
		return Identity{}, err
	}
	_ = v.Delete(ctx, p.Handle)
	if err = store.RemoveProfileRecord(dir, store.JoinPendingName); err != nil {
		return Identity{}, err
	}
	return Identity{Genesis: p.Genesis, Device: p.Device, Machine: p.Machine}, nil
}
