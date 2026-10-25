// Package bundle implements 07 §8.4 encrypted same-identity bundles on the
// node: framing and the signed manifest, age encryption to verified device
// export keys or to a sole scrypt passphrase recipient, export keys, and the
// co-signed device_add enrollment that must precede a restore on a fresh
// machine. Selection and admission stay in the store.
package bundle

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"io"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/store"
	nodesync "github.com/Telara-Labs/telara-memory/contract/internal/node/sync"
	"github.com/Telara-Labs/telara-memory/contract/jcs"
	"github.com/Telara-Labs/telara-memory/contract/record"
	"github.com/Telara-Labs/telara-memory/contract/sig"
	"github.com/Telara-Labs/telara-memory/contract/transport"
)

// MaxBytes bounds the uncompressed NDJSON of one bundle (07 §8.4.1).
const MaxBytes = 64 << 20

// Bundle modes.
const (
	ModeTransfer = "transfer"
	ModeBackup   = "backup"
)

// Error is a fixed, content-free refusal code.
type Error string

func (e Error) Error() string { return string(e) }

const (
	ErrInvalid         Error = "bundle_invalid"
	ErrForeignGenesis  Error = "bundle_foreign_genesis"
	ErrGranted         Error = "bundle_granted_data"
	ErrExporter        Error = "bundle_exporter_unauthorized"
	ErrSignature       Error = "bundle_signature_invalid"
	ErrTooLarge        Error = "bundle_too_large"
	ErrDecrypt         Error = "bundle_decrypt_failed"
	ErrRecipient       Error = "bundle_recipient_invalid"
	ErrNotEnrolled     Error = "device_not_enrolled"
	ErrExportKey       Error = "export_key_unavailable"
	ErrCode            Error = "verification_code_mismatch"
	ErrEnrollment      Error = "enrollment_invalid"
	ErrProfile         Error = "profile_invalid"
	ErrPassphrase      Error = "passphrase_invalid"
	ErrExposureOrigin  Error = "bundle_exposure_origin_unknown"
	ErrUnsupportedMode Error = "bundle_mode_invalid"
)

// Contents is one decrypted bundle whose framing, counts, digest and
// exposure fact schema are checked. The manifest signature is checked
// separately by Verify, against the receiver's keyring.
type Contents struct {
	Manifest                transport.Manifest
	Keyring, Controls, Data []store.SignedRecord
	Facts                   []transport.ExposureFact
	FactLines               [][]byte
}

// Encode frames a store selection as NDJSON under a manifest signed by the
// exporting device key with context mnc/v1/bundle: keyring envelopes, exposure
// facts, controls, then data. It carries exact signed envelopes and canonical
// facts only; no key material is ever an input.
func Encode(sel store.BundleSelection, genesis string, key ed25519.PrivateKey, createdAt int64) ([]byte, transport.Manifest, error) {
	var m transport.Manifest
	if len(key) != ed25519.PrivateKeySize || !record.IsKeyID(genesis) || createdAt <= 0 {
		return nil, m, ErrInvalid
	}
	var lines [][]byte
	envelopes := func(part []store.SignedRecord) error {
		for _, r := range part {
			if r.BodyJCS == nil {
				return ErrInvalid
			}
			line, err := jcs.MarshalRecord(nodesync.Envelope(r.HeaderJCS, r.BodyJCS, r.Sigs, r.AdvisoryID))
			if err != nil {
				return ErrInvalid
			}
			lines = append(lines, line)
		}
		return nil
	}
	if err := envelopes(sel.Keyring); err != nil {
		return nil, m, err
	}
	for _, f := range sel.Facts {
		lines = append(lines, append([]byte(nil), f...))
	}
	if err := envelopes(sel.Controls); err != nil {
		return nil, m, err
	}
	if err := envelopes(sel.Data); err != nil {
		return nil, m, err
	}
	m = transport.Manifest{Bundle: "mnc/3", CreatedAt: createdAt, ExporterKeyID: sig.KeyID(key.Public().(ed25519.PublicKey)), Genesis: genesis, Keyring: len(sel.Keyring), Exposures: len(sel.Facts), Control: len(sel.Controls), Data: len(sel.Data), ItemsDigest: transport.ItemsDigest(lines)}
	unsigned, err := jcs.MarshalRecord(m)
	if err != nil {
		return nil, m, ErrInvalid
	}
	m.Sigs = []record.Signature{sig.Sign(key, sig.CtxBundle, sig.BundleMessage(unsigned))}
	head, err := jcs.MarshalRecord(m)
	if err != nil {
		return nil, m, ErrInvalid
	}
	var out bytes.Buffer
	out.Write(head)
	out.WriteByte('\n')
	for _, line := range lines {
		out.Write(line)
		out.WriteByte('\n')
	}
	if out.Len() > MaxBytes {
		return nil, m, ErrTooLarge
	}
	if _, err = transport.ValidateBundleLines(m, lines); err != nil {
		return nil, m, ErrInvalid
	}
	return out.Bytes(), m, nil
}

func strictDecode(raw []byte, out any) error {
	if !jcs.IsCanonicalRecord(raw) {
		return ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil || d.Decode(new(any)) != io.EOF {
		return ErrInvalid
	}
	again, err := jcs.MarshalRecord(out)
	if err != nil || !bytes.Equal(again, raw) {
		return ErrInvalid
	}
	return nil
}

// Decode checks the exact LF framing, the manifest, counts, the items digest,
// size and fact bounds, and every envelope, before any data is admitted. A
// bundle of another genesis is refused whole. Any envelope carrying a hosted
// delivery grant or receipt is refused whole: granted content never travels in
// a bundle and a receipt cannot be trusted without this node's own TLS pin.
func Decode(plaintext []byte, pinnedGenesis string) (Contents, error) {
	var c Contents
	if len(plaintext) > MaxBytes {
		return c, ErrTooLarge
	}
	if len(plaintext) == 0 || plaintext[len(plaintext)-1] != '\n' {
		return c, ErrInvalid
	}
	lines := bytes.Split(plaintext[:len(plaintext)-1], []byte{'\n'})
	if err := strictDecode(lines[0], &c.Manifest); err != nil {
		return c, ErrInvalid
	}
	m := c.Manifest
	if err := transport.CheckManifestVersion(m); err != nil {
		return c, ErrInvalid
	}
	if m.Genesis != pinnedGenesis {
		return c, ErrForeignGenesis
	}
	items := lines[1:]
	facts, err := transport.ValidateBundleLines(m, items)
	if err != nil {
		return c, ErrInvalid
	}
	c.Facts = facts
	for _, line := range items[m.Keyring : m.Keyring+m.Exposures] {
		c.FactLines = append(c.FactLines, append([]byte(nil), line...))
	}
	envelopes := append(append([][]byte(nil), items[:m.Keyring]...), items[m.Keyring+m.Exposures:]...)
	for i, line := range envelopes {
		var e record.Envelope
		if strictDecode(line, &e) != nil {
			return Contents{}, ErrInvalid
		}
		if e.Grant != nil || e.Receipt != nil {
			return Contents{}, ErrGranted
		}
		r, err := nodesync.OpenEnvelope(e)
		if err != nil || r.Body == nil {
			return Contents{}, ErrInvalid
		}
		item := store.SignedRecord{HeaderJCS: r.HeaderJCS, BodyJCS: r.BodyJCS, Sigs: append([]record.Signature(nil), e.Sigs...), AdvisoryID: r.ID}
		switch {
		case i < m.Keyring:
			if r.Header.Type != record.KindKeyOp {
				return Contents{}, ErrInvalid
			}
			c.Keyring = append(c.Keyring, item)
		case i < m.Keyring+m.Control:
			if r.Header.Type != record.KindErasure && r.Header.Type != record.KindRetraction {
				return Contents{}, ErrInvalid
			}
			c.Controls = append(c.Controls, item)
		default:
			if r.Header.Type.IsControl() || r.Header.Type == record.KindKeyOp || r.Header.Type == record.KindPolicy {
				return Contents{}, ErrInvalid
			}
			c.Data = append(c.Data, item)
		}
	}
	return c, nil
}

// keyringOf folds local and carried key operations for the pinned genesis.
func keyringOf(genesis string, parts ...[]store.SignedRecord) (*sig.State, error) {
	kr := sig.NewKeyring(genesis)
	for _, part := range parts {
		for _, r := range part {
			parsed, err := record.Parse(r.HeaderJCS, r.BodyJCS, r.AdvisoryID)
			if err != nil {
				return nil, ErrInvalid
			}
			b, ok := parsed.Body.(*record.KeyOpBody)
			if !ok || b.Genesis != genesis || b.Subject.Role != record.RoleDevice {
				return nil, ErrInvalid
			}
			if kr.Add(&sig.KeyOp{Rec: parsed, Body: b, Sigs: r.Sigs}) != nil {
				return nil, ErrInvalid
			}
		}
	}
	return kr.State(), nil
}

// Verify requires the exporter to be an active device of the pinned genesis
// under the local plus carried keyring, exactly one valid mnc/v1/bundle
// signature by it, and every exposure fact's origin machine to be a device
// machine enrolled under this genesis. It runs before any admission.
func Verify(c Contents, local []store.SignedRecord) error {
	m := c.Manifest
	st, err := keyringOf(m.Genesis, local, c.Keyring)
	if err != nil {
		return err
	}
	k := st.KeyFor(m.ExporterKeyID, record.RoleDevice, "")
	if k == nil || k.Status != sig.KeyActive || k.Genesis != m.Genesis {
		return ErrExporter
	}
	if len(m.Sigs) != 1 || m.Sigs[0].KeyID != m.ExporterKeyID || m.Sigs[0].Ctx != sig.CtxBundle || m.Sigs[0].Alg != sig.AlgEd25519 {
		return ErrSignature
	}
	unsigned := m
	unsigned.Sigs = nil
	raw, err := jcs.MarshalRecord(unsigned)
	if err != nil || sig.Verify(k.Pub, sig.CtxBundle, sig.BundleMessage(raw), m.Sigs[0]) != nil {
		return ErrSignature
	}
	machines := map[string]bool{}
	for _, key := range st.Keys {
		if key.Role == record.RoleDevice && key.Genesis == m.Genesis {
			machines[key.MachineID] = true
		}
	}
	for _, f := range c.Facts {
		if !machines[f.OriginMachine] {
			return ErrExposureOrigin
		}
	}
	return nil
}
