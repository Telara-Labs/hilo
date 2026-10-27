package sig

import (
	"crypto/ed25519"
	"fmt"

	"github.com/Telara-Labs/hilo/contract/record"
)

// KeyRefOf describes a public key for a key operation's subject.
func KeyRefOf(pub ed25519.PublicKey, role record.Role, machineID string) record.KeyRef {
	return record.KeyRef{KeyID: KeyID(pub), Alg: AlgEd25519, Pub: EncodePub(pub), Role: role, MachineID: machineID}
}

// BuildKeyOp assembles and signs a key operation. author is the key whose id
// goes in the header (the authorizer when the op needs one, else the
// subject); machineID is that key's machine (empty for service and policy
// keys). Every key in signers signs the record id.
func BuildKeyOp(b record.KeyOpBody, author ed25519.PublicKey, machineID string, at int64, signers ...ed25519.PrivateKey) (*KeyOp, error) {
	h := record.Header{
		Type:   record.KindKeyOp,
		LID:    record.KeyLID(b.Subject.KeyID),
		Author: record.Author{MachineID: machineID, KeyID: KeyID(author)},
		At:     at,
		Prov:   record.ProvUser,
		Red:    record.Redact{Profile: record.ProfileLocal},
	}
	body := b
	r, err := record.Build(h, &body)
	if err != nil {
		return nil, fmt.Errorf("key op: %w", err)
	}
	op := &KeyOp{Rec: r, Body: r.Body.(*record.KeyOpBody)}
	for _, s := range signers {
		sg, err := SignRecord(s, r.ID)
		if err != nil {
			return nil, err
		}
		op.Sigs = append(op.Sigs, sg)
	}
	return op, nil
}
