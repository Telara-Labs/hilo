package transport

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"github.com/Telara-Labs/telara-memory/contract/record"
)

type ExposureFact struct {
	OriginMachine      string   `json:"origin_machine"`
	ScopeID            string   `json:"scope_id"`
	SessionKey         string   `json:"session_key,omitempty"`
	Boundary           int64    `json:"boundary"`
	RecalledID         string   `json:"recalled_id"`
	SourceCallOrEvent  string   `json:"source_call_or_event"`
	BindingEvidenceIDs []string `json:"binding_evidence_ids"`
	AffectsIDs         []string `json:"affects_ids"`
	PendingAttribution bool     `json:"pending_attribution"`
}
type Manifest struct {
	Bundle        string             `json:"bundle"`
	CreatedAt     int64              `json:"created_at"`
	ExporterKeyID string             `json:"exporter_key_id"`
	Genesis       string             `json:"genesis"`
	Keyring       int                `json:"keyring"`
	Exposures     int                `json:"exposures"`
	Control       int                `json:"control"`
	Data          int                `json:"data"`
	ItemsDigest   string             `json:"items_digest"`
	Sigs          []record.Signature `json:"sigs,omitempty"`
}

// ItemsDigest covers exact newline-terminated NDJSON item bytes, not a decoded approximation.
func ItemsDigest(lines [][]byte) string {
	h := sha256.New()
	for _, line := range lines {
		h.Write(line)
		h.Write([]byte{'\n'})
	}
	return hex.EncodeToString(h.Sum(nil))
}

type BundleRecord struct {
	ID                                                        string
	CompleteSigned, SelectorIdentity, Selected, Live, Pending bool
	Grants                                                    []record.GrantRef
	RecalledRoots                                             []string
}

// BundleEligible requires selected complete recursive roots. It never auto-adds
// private roots. Signature/owner verification and exposure union precede this gate.
func BundleEligible(id string, records map[string]BundleRecord) bool {
	seen := map[string]bool{}
	active := map[string]bool{}
	var walk func(string) bool
	walk = func(id string) bool {
		if active[id] {
			return false
		}
		if seen[id] {
			return true
		}
		r, ok := records[id]
		if !ok || r.ID != id || !r.CompleteSigned || !r.SelectorIdentity || !r.Selected || !r.Live || r.Pending || len(r.Grants) > 0 {
			return false
		}
		active[id] = true
		for _, root := range r.RecalledRoots {
			if !walk(root) {
				return false
			}
		}
		delete(active, id)
		seen[id] = true
		return true
	}
	return walk(id)
}

// ValidateBundleMode rejects foreign identities and every plaintext exception.
// Encryption adapters must verify age recipient types rather than trust a file label.
func ValidateBundleMode(pinnedGenesis, manifestGenesis, mode string, recipientKinds []string) error {
	if !record.IsKeyID(pinnedGenesis) || pinnedGenesis != manifestGenesis {
		return errors.New("foreign genesis")
	}
	switch mode {
	case "transfer":
		if len(recipientKinds) == 0 {
			return errors.New("recipient required")
		}
		for _, k := range recipientKinds {
			if k != "x25519" {
				return errors.New("transfer requires export keys")
			}
		}
	case "backup":
		if len(recipientKinds) != 1 || recipientKinds[0] != "scrypt" {
			return errors.New("backup requires sole scrypt recipient")
		}
	default:
		return errors.New("encrypted bundle required")
	}
	return nil
}
