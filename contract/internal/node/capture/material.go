package capture

import (
	"bytes"
	"crypto/ed25519"

	"github.com/Telara-Labs/hilo/contract/internal/node/localpolicy"
	"github.com/Telara-Labs/hilo/contract/record"
	"github.com/Telara-Labs/hilo/contract/sig"
)

// PreloadedKeyMaterial is concrete memory, not a callback that could perform
// network, keystore IO or UI inside the writer. Installed key bootstrap is not
// implemented here. Callers remain responsible for their original key buffers.
type PreloadedKeyMaterial struct {
	private [64]byte
	keyID   string
	valid   bool
}

func PreloadKeys(deviceSaltKey []byte, privateKey ed25519.PrivateKey) (PreloadedKeyMaterial, error) {
	var out PreloadedKeyMaterial
	if len(deviceSaltKey) != record.SaltKeySize || len(privateKey) != ed25519.PrivateKeySize {
		return out, hold("key_material")
	}
	expected := ed25519.NewKeyFromSeed(privateKey[:ed25519.SeedSize])
	defer clear(expected)
	if !bytes.Equal(expected, privateKey) {
		return out, hold("key_material")
	}
	copy(out.private[:], privateKey)
	out.keyID = sig.KeyID(privateKey.Public().(ed25519.PublicKey))
	out.valid = true
	return out, nil
}

// Clear erases this owned copy. Go may retain other caller/compiler copies;
// this method is not a guarantee of complete RAM zeroization.
func (k *PreloadedKeyMaterial) Clear() {
	if k == nil {
		return
	}
	clear(k.private[:])
	k.keyID = ""
	k.valid = false
}

func checkedRuleset() (record.Ruleset, error) {
	r, err := localpolicy.Ruleset()
	if err != nil {
		return record.Ruleset{}, hold("ruleset_golden")
	}
	return r, nil
}
