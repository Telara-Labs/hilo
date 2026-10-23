package capture

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"

	tapredact "github.com/Telara-Labs/TAP-Runtime/discover/redact"
	contract "github.com/Telara-Labs/telara-memory/contract"
	"github.com/Telara-Labs/telara-memory/contract/record"
	"github.com/Telara-Labs/telara-memory/contract/sig"
)

// PreloadedKeyMaterial is concrete memory, not a callback that could perform
// network, keystore IO or UI inside the writer. Installed key bootstrap is not
// implemented here. Callers remain responsible for their original key buffers.
type PreloadedKeyMaterial struct {
	salt    [32]byte
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
	copy(out.salt[:], deviceSaltKey)
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
	clear(k.salt[:])
	clear(k.private[:])
	k.keyID = ""
	k.valid = false
}

type behaviorRedactor struct{}

func (behaviorRedactor) Redact(s string) string                  { return tapredact.Redact(s) }
func (behaviorRedactor) Argument(n, s string) string             { return tapredact.Argument(n, s) }
func (behaviorRedactor) Profiles() []string                      { return nil }
func (behaviorRedactor) RedactProfile(_ string, s string) string { return tapredact.Redact(s) }

func checkedRuleset() (record.Ruleset, error) {
	var empty record.Ruleset
	corpus, err := record.ParseCorpus(contract.RedactionCorpusV1())
	if err != nil {
		return empty, hold("ruleset_golden")
	}
	behavior, err := record.Behavior(corpus, behaviorRedactor{})
	if err != nil {
		return empty, hold("ruleset_golden")
	}
	up := tapredact.CurrentRuleset()
	actual := record.Ruleset{Epoch: up.Epoch, Digest: up.Digest, Engine: "tap-discover/cd7b481855de", Behavior: behavior}
	var expected record.Ruleset
	if json.Unmarshal(contract.RedactionGoldenV1(), &expected) != nil || expected != actual || record.CheckGolden(expected, actual) != nil {
		return empty, hold("ruleset_golden")
	}
	return actual, nil
}
