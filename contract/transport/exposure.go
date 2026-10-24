package transport

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/Telara-Labs/telara-memory/contract/jcs"
	"github.com/Telara-Labs/telara-memory/contract/record"
	"sort"
)

func ParseExposure(raw []byte) (ExposureFact, error) {
	var f ExposureFact
	fail := func() (ExposureFact, error) { return ExposureFact{}, errors.New("invalid exposure fact") }
	if len(raw) > 16<<10 || record.CheckClosedObject(raw, &f) != nil {
		return fail()
	}
	if json.Unmarshal(raw, &f) != nil {
		return fail()
	}
	canonical, err := jcs.MarshalRecord(f)
	if err != nil || !bytes.Equal(canonical, raw) || !record.IsUUIDv4(f.OriginMachine) || !record.IsHex64(f.RecalledID) || f.ScopeID == "" && f.SessionKey == "" || f.ScopeID != "" && !record.ValidScopeID(f.ScopeID, f.OriginMachine) || f.SessionKey != "" && !record.IsSessionKey(f.SessionKey) {
		return fail()
	}
	for _, xs := range [][]string{f.AffectsIDs, f.BindingEvidenceIDs} {
		if !sort.StringsAreSorted(xs) {
			return fail()
		}
		for i, id := range xs {
			if !record.IsHex64(id) || i > 0 && id == xs[i-1] {
				return fail()
			}
		}
	}
	switch f.SourceCallOrEvent.Kind {
	case "call":
		if !record.IsCallRef(f.SourceCallOrEvent.ID) || f.ScopeID == "" || f.SessionKey == "" && !f.PendingAttribution {
			return fail()
		}
	case "event":
		if !record.IsEventID(f.SourceCallOrEvent.ID) || f.SessionKey == "" {
			return fail()
		}
	default:
		return fail()
	}
	if f.SourceCallOrEvent.Kind == "event" && f.ScopeID != "" || f.SourceCallOrEvent.Kind == "call" && f.SessionKey != "" {
		if len(f.BindingEvidenceIDs) == 0 {
			return fail()
		}
	}
	b := f.Boundary
	switch b.Kind {
	case "call":
		if f.SourceCallOrEvent.Kind != "call" || b.Ordinal == nil || *b.Ordinal <= 0 || !record.IsHex64(b.OpID) || b.Seq != nil || b.EventID != "" {
			return fail()
		}
	case "event":
		if f.SourceCallOrEvent.Kind != "event" || b.Seq == nil || *b.Seq < 0 || b.EventID != f.SourceCallOrEvent.ID || b.Ordinal != nil || b.OpID != "" {
			return fail()
		}
	case "unknown":
		if !f.PendingAttribution || b.Ordinal != nil || b.Seq != nil || b.OpID != "" || b.EventID != "" {
			return fail()
		}
	default:
		return fail()
	}
	return f, nil
}

// ValidateBundleLines checks bounded canonical plaintext framing after bounded
// decompression. Crypto/age, enrolled origin and signature checks remain adapter gates.
func ValidateBundleLines(m Manifest, lines [][]byte) ([]ExposureFact, error) {
	fail := func() ([]ExposureFact, error) { return nil, errors.New("invalid bundle lines") }
	if CheckManifestVersion(m) != nil || m.Keyring < 0 || m.Exposures < 0 || m.Exposures > 8192 || m.Control < 0 || m.Data < 0 || int64(m.Keyring) > jcs.MaxSafeInteger || int64(m.Control) > jcs.MaxSafeInteger || int64(m.Data) > jcs.MaxSafeInteger {
		return fail()
	}
	count := int64(m.Keyring) + int64(m.Exposures) + int64(m.Control) + int64(m.Data)
	if count != int64(len(lines)) || !record.IsHex64(m.ItemsDigest) {
		return fail()
	}
	if m.CreatedAt <= 0 || m.CreatedAt > jcs.MaxSafeInteger || !record.IsKeyID(m.ExporterKeyID) || !record.IsKeyID(m.Genesis) {
		return fail()
	}
	manifestRaw, err := jcs.MarshalRecord(m)
	if err != nil {
		return fail()
	}
	total := int64(len(manifestRaw)) + 1
	entries := 0
	facts := []ExposureFact{}
	for i, line := range lines {
		total += int64(len(line)) + 1
		if total > 64<<20 || !jcs.IsCanonicalRecord(line) {
			return fail()
		}
		if i >= m.Keyring && i < m.Keyring+m.Exposures {
			f, err := ParseExposure(line)
			if err != nil {
				return fail()
			}
			entries += len(f.AffectsIDs) + len(f.BindingEvidenceIDs)
			if entries > 8192 {
				return fail()
			}
			facts = append(facts, f)
		}
	}
	if ItemsDigest(lines) != m.ItemsDigest {
		return fail()
	}
	return facts, nil
}
