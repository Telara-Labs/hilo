package capture

import (
	"crypto/ed25519"

	"github.com/Telara-Labs/telara-memory/contract/record"
	"github.com/Telara-Labs/telara-memory/contract/sig"
)

// KeyID returns the public device key id of this preloaded material.
func (k *PreloadedKeyMaterial) KeyID() string {
	if k == nil || !k.valid {
		return ""
	}
	return k.keyID
}

// SignRecordID signs an already sealed record id with the device key. It signs
// nothing else and never returns key bytes. Cleared material refuses.
func (k *PreloadedKeyMaterial) SignRecordID(id string) (record.Signature, error) {
	if k == nil || !k.valid || !record.IsHex64(id) {
		return record.Signature{}, hold("key_material")
	}
	return sig.SignRecord(ed25519.PrivateKey(k.private[:]), id)
}
