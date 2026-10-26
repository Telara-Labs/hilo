package store

import (
	"encoding/base64"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/localpolicy"
	"github.com/Telara-Labs/telara-memory/contract/record"
	"github.com/Telara-Labs/telara-memory/contract/sig"
	"github.com/Telara-Labs/telara-memory/contract/transport"
)

// variantRedactor applies the local measured ruleset and the verified tenant
// shapes of the current policy. It never accepts caller rules.
type variantRedactor struct{ overlay localpolicy.Overlay }

func (r variantRedactor) Redact(s string) string                  { return r.overlay.Text(s) }
func (r variantRedactor) Argument(n, s string) string             { return r.overlay.Argument(n, s) }
func (variantRedactor) Profiles() []string                        { return nil }
func (r variantRedactor) RedactProfile(_ string, s string) string { return r.overlay.Text(s) }

// bundleVariant builds the fresh push-metadata variant of one governed live
// local session or task head of this device, and returns it only when the
// complete current authorization permits it in a bundle. It never copies the
// source body. With sign false it evaluates eligibility only and the result
// is unsigned. A nil result is a denial, never an error.
func (s *Store) bundleVariant(d *databaseState, x *stored, signer ControlSigner, sign bool) (*SignedRecord, error) {
	h := x.rec.Header
	if (h.Type != record.KindSession && h.Type != record.KindTask) || h.Red.Profile != record.ProfileLocal || h.Author.MachineID != s.opts.LocalMachineID || d.tenant == nil {
		return nil, nil
	}
	b := d.tenant.body()
	if b == nil {
		return nil, nil
	}
	overlay, err := localpolicy.TenantOverlay(b)
	if err != nil {
		return nil, nil
	}
	rs, err := localpolicy.Ruleset()
	if err != nil {
		return nil, nil
	}
	var chunks []*record.Record
	if sb, ok := x.rec.Body.(*record.SessionBody); ok {
		for _, id := range sb.Chunks {
			c := d.byID[id]
			if c == nil || c.state != "live" || c.rec.Body == nil || c.owner != x.owner {
				return nil, nil
			}
			chunks = append(chunks, c.rec)
		}
	}
	keyID := h.Author.KeyID
	if sign {
		if signer == nil || !record.IsKeyID(signer.KeyID()) {
			return nil, failure("signing_unavailable")
		}
		keyID = signer.KeyID()
	}
	v, err := record.Export(x.rec, record.Author{MachineID: h.Author.MachineID, KeyID: keyID}, nil, rs, variantRedactor{overlay}, chunks)
	if err != nil {
		return nil, nil
	}
	if !transport.BundlePolicyAllowed(v, d.bundleAuthorization(v)) {
		return nil, nil
	}
	out := &SignedRecord{HeaderJCS: v.HeaderJCS, BodyJCS: v.BodyJCS, AdvisoryID: v.ID}
	if !sign {
		return out, nil
	}
	sg, err := signer.SignRecordID(v.ID)
	if err != nil {
		return nil, failure("signing_unavailable")
	}
	out.Sigs = []record.Signature{sg}
	return out, nil
}

// parseBundleItem is parse for the bundle route: it additionally accepts a
// device push-metadata variant of a session or task, the only non-local
// profile a bundle may carry. Every other check is parse's.
func parseBundleItem(in SignedRecord) (*record.Record, []record.Signature, error) {
	if len(in.HeaderJCS) > record.MaxHeaderBytes || len(in.BodyJCS) > record.MaxBodyBytes || len(in.Sigs) != 1 {
		return parse(in)
	}
	r, err := record.Parse(append([]byte(nil), in.HeaderJCS...), append([]byte(nil), in.BodyJCS...), in.AdvisoryID)
	if err != nil || r.Header.Red.Profile != record.ProfilePushMetadata {
		return parse(in)
	}
	h := r.Header
	if h.Prov != record.ProvDerived || (h.Type != record.KindSession && h.Type != record.KindTask) || r.Body == nil {
		return nil, nil, failure("unsupported_context")
	}
	sg := in.Sigs[0]
	if !record.IsKeyID(sg.KeyID) || sg.Alg != sig.AlgEd25519 || sg.Ctx != sig.CtxRecord || len(sg.Value) != 86 {
		return nil, nil, failure("invalid_record")
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(sg.Value)
	if err != nil || len(raw) != 64 || base64.RawURLEncoding.EncodeToString(raw) != sg.Value {
		return nil, nil, failure("invalid_record")
	}
	return r, []record.Signature{sg}, nil
}
