package store

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"

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
// is unsigned; a non-nil signer then names the key the variant is built for,
// so the unsigned result has the exact bytes that key would sign. A nil
// result is a denial, never an error.
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
	if sign || signer != nil {
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

// variantIdentity is the content identity of one built variant: its exact
// header and body without the random body salt and the body digest that
// salt feeds. Two builds of the same source under the same redaction,
// authorization and key have the same identity; any change to the
// redacted content or the header does not.
func variantIdentity(v SignedRecord) (string, bool) {
	decode := func(raw []byte) map[string]any {
		var out map[string]any
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		if dec.Decode(&out) != nil {
			return nil
		}
		return out
	}
	h, b := decode(v.HeaderJCS), decode(v.BodyJCS)
	if h == nil || b == nil {
		return "", false
	}
	delete(h, "body")
	delete(b, "salt")
	raw, err := json.Marshal([]any{h, b})
	if err != nil {
		return "", false
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), true
}
