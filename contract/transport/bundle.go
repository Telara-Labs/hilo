package transport

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"github.com/Telara-Labs/hilo/contract/record"
)

type ExposureSource struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
}
type Boundary struct {
	Kind    string `json:"kind"`
	OpID    string `json:"op_id,omitempty"`
	Ordinal *int64 `json:"ordinal,omitempty"`
	EventID string `json:"event_id,omitempty"`
	Seq     *int64 `json:"seq,omitempty"`
}
type ExposureFact struct {
	OriginMachine      string         `json:"origin_machine"`
	ScopeID            string         `json:"scope_id,omitempty"`
	SessionKey         string         `json:"session_key,omitempty"`
	Boundary           Boundary       `json:"boundary"`
	RecalledID         string         `json:"recalled_id"`
	SourceCallOrEvent  ExposureSource `json:"source_call_or_event"`
	BindingEvidenceIDs []string       `json:"binding_evidence_ids,omitempty"`
	AffectsIDs         []string       `json:"affects_ids,omitempty"`
	PendingAttribution bool           `json:"pending_attribution"`
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
	Record                                                    *record.Record
	Authorization                                             BundleAuthorization
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
	var walk func(string, bool) bool
	walk = func(id string, strictOrigins bool) bool {
		cacheKey := id
		if strictOrigins {
			cacheKey += "/strict"
		}
		if active[id] {
			return false
		}
		if seen[cacheKey] {
			return true
		}
		r, ok := records[id]
		if !ok || r.ID != id || !r.CompleteSigned || !r.SelectorIdentity || !r.Selected || !r.Live || r.Pending || len(r.Grants) > 0 {
			return false
		}
		if r.Record == nil || r.Record.ID != id {
			return false
		}
		parsed, err := record.Parse(r.Record.HeaderJCS, r.Record.BodyJCS, id)
		if err != nil || parsed.Body == nil || parsed.Header.Type.IsControl() || !BundlePolicyAllowed(parsed, r.Authorization) {
			return false
		}
		active[id] = true
		roots := append([]string(nil), r.RecalledRoots...)
		roots = append(roots, parsed.Header.Links.DerivedFrom...)
		if parsed.Header.Type == record.KindCall {
			strictOrigins = true
		}
		if strictOrigins && parsed.Header.Links.Origin != "" {
			roots = append(roots, parsed.Header.Links.Origin)
		}
		switch b := parsed.Body.(type) {
		case *record.SessionBody:
			roots = append(roots, b.Chunks...)
		case *record.RollupBody:
			roots = append(roots, b.Covers...)
		}
		for _, root := range roots {
			if !walk(root, strictOrigins) {
				return false
			}
		}
		delete(active, id)
		seen[cacheKey] = true
		return true
	}
	return walk(id, false)
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
