package sync

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/Telara-Labs/hilo/contract/jcs"
	"github.com/Telara-Labs/hilo/contract/record"
	"github.com/Telara-Labs/hilo/contract/sig"
)

func TestOperationRoundtripAndImmutability(t *testing.T) {
	f := newFixture(t, 1)
	op := f.outbox.op
	raw := op.Bytes()
	restored, err := RestoreOperation(raw, op.Digest())
	if err != nil || !bytes.Equal(restored.Bytes(), raw) || restored.OpID() != op.OpID() {
		t.Fatal(err)
	}
	raw[0] = '['
	if bytes.Equal(op.Bytes(), raw) {
		t.Fatal("operation exposes mutable buffer")
	}
	if _, err := RestoreOperation(raw, op.Digest()); !errors.Is(err, ErrInvalid) {
		t.Fatal("mutation accepted")
	}
	if _, err := RestoreOperation(op.Bytes(), strings.Repeat("a", 64)); !errors.Is(err, ErrInvalid) {
		t.Fatal("wrong digest")
	}
}
func TestBatchRecordAndWireLimits(t *testing.T) {
	f := newFixture(t, 0)
	var records []SignedRecord
	for i := 0; i < 65; i++ {
		records = append(records, f.signed(t, i))
	}
	if _, err := NewOperation("limit", records[:64]); err != nil {
		t.Fatal(err)
	}
	if _, err := NewOperation("limit", records); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
	if _, err := NewOperation("limit", records[:0]); err == nil {
		t.Fatal("empty batch")
	}
	if _, err := NewOperation("limit", []SignedRecord{records[0], records[0]}); err == nil {
		t.Fatal("duplicate record")
	}
	if _, err := RestoreOperation(bytes.Repeat([]byte{' '}, MaxRequestBytes+1), ""); err == nil {
		t.Fatal("oversize request")
	}
	// Near-limit session metadata headers consume decoded budget even though raw
	// envelope base64 expansion also imposes a stricter encoded boundary.
	var huge []SignedRecord
	for i := 0; i < 64; i++ {
		r := f.signed(t, i)
		var body map[string]any
		_ = json.Unmarshal(r.Record.BodyJCS, &body)
		body["extra"] = strings.Repeat("x", record.MaxBodyBytes)
		raw, _ := json.Marshal(body)
		r.Record.BodyJCS = raw
		huge = append(huge, r)
	}
	if _, err := NewOperation("too-large", huge); err == nil {
		t.Fatal("oversized body")
	}
}
func TestOperationIDsExactAndBounded(t *testing.T) {
	f := newFixture(t, 0)
	s := []SignedRecord{f.signed(t, 1)}
	for _, id := range []string{"", "space id", "\t", "\n", "é", strings.Repeat("a", 129)} {
		if _, err := NewOperation(id, s); err == nil {
			t.Fatal("invalid op id", fmt.Sprintf("%q", id))
		}
	}
	for _, id := range []string{"a", "op:/._-", strings.Repeat("a", 128)} {
		if _, err := NewOperation(id, s); err != nil {
			t.Fatal(err)
		}
	}
}
func TestMetadataOnlyAndNoUnsignedEnvelope(t *testing.T) {
	f := newFixture(t, 0)
	s := f.signed(t, 1)
	for _, which := range []string{"nil-record", "missing-body", "unsigned", "extra-signature", "wrong-alg", "wrong-context", "wrong-encoding", "bad-id", "local-text", "metadata-free-text"} {
		t.Run(which, func(t *testing.T) {
			r := f.signed(t, 1)
			switch which {
			case "nil-record":
				r.Record = nil
			case "missing-body":
				r.Record = r.Record.WithoutBody()
			case "unsigned":
				r.Sigs = nil
			case "extra-signature":
				r.Sigs = append(r.Sigs, r.Sigs[0])
			case "wrong-alg":
				r.Sigs[0].Alg = "ES256"
			case "wrong-context":
				r.Sigs[0].Ctx = sig.CtxReceipt
			case "wrong-encoding":
				r.Sigs[0].Value = "AAAA"
			case "bad-id":
				r.Record.ID = strings.Repeat("0", 64)
			case "local-text":
				h := r.Record.Header
				h.Red.Profile = record.ProfileLocal
				h.Prov = record.ProvMCPExplicit
				h.Links = record.Links{}
				h.Op = strings.Repeat("a", 64)
				var err error
				r.Record, err = record.Build(h, &record.TaskBody{Status: "active", Name: "private", Goal: "secret goal"})
				if err != nil {
					t.Fatal(err)
				}
			case "metadata-free-text":
				var body map[string]any
				_ = json.Unmarshal(r.Record.BodyJCS, &body)
				body["text"] = "private"
				b, _ := jcs.MarshalRecord(body)
				h := r.Record.Header
				h.Body = &record.BodyRef{Digest: record.BodyDigest(b), Size: int64(len(b))}
				r.Record.HeaderJCS, _ = jcs.MarshalRecord(h)
				r.Record.ID = record.ContentID(r.Record.HeaderJCS)
				r.Record.BodyJCS = b
			}
			if _, err := NewOperation("op", []SignedRecord{r}); err == nil {
				t.Fatal("forbidden export")
			}
		})
	}
	_ = s
}
func TestRestoreStrictEnvelopeShape(t *testing.T) {
	f := newFixture(t, 1)
	var original map[string]any
	_ = json.Unmarshal(f.outbox.op.Bytes(), &original)
	for _, which := range []string{"unknown-field", "receipt", "grant", "codec", "version", "duplicate", "bad-header", "compressed", "body-bomb", "extra-envelope-field"} {
		t.Run(which, func(t *testing.T) {
			var req map[string]any
			_ = json.Unmarshal(f.outbox.op.Bytes(), &req)
			env := req["envelopes"].([]any)[0].(map[string]any)
			switch which {
			case "unknown-field":
				req["bad"] = true
			case "receipt":
				env["receipt"] = map[string]any{}
			case "grant":
				env["grant"] = map[string]any{}
			case "codec":
				env["body"].(map[string]any)["codec"] = "gzip"
			case "version":
				env["v"] = 4
			case "duplicate":
				req["envelopes"] = []any{env, env}
			case "bad-header":
				env["header"] = "!"
			case "compressed":
				env["body"].(map[string]any)["bytes"] = b64.EncodeToString([]byte("not a frame"))
			case "body-bomb":
				raw := rawZstd([]byte("{}"))
				binary.LittleEndian.PutUint32(raw[5:9], record.MaxBodyBytes+1)
				env["body"].(map[string]any)["bytes"] = b64.EncodeToString(raw)
			case "extra-envelope-field":
				env["text"] = "private"
			}
			data, _ := json.Marshal(req)
			if _, err := restore(data, "", false); err == nil {
				t.Fatal("bad restore accepted")
			}
		})
	}
}
func TestRawZstdFramesAndBounds(t *testing.T) {
	for _, size := range []int{1, 255, 256, 65536, 128 << 10, 129 << 10, record.MaxBodyBytes} {
		body := bytes.Repeat([]byte{'x'}, size)
		wire := rawZstd(body)
		decoded, err := readRawZstd(wire)
		if err != nil || !bytes.Equal(decoded, body) {
			t.Fatal(size, err)
		}
	}
	good := rawZstd([]byte("{}"))
	for _, bad := range [][]byte{nil, good[:8], append(append([]byte(nil), good...), 0), bytes.Repeat([]byte{0}, 20)} {
		if _, err := readRawZstd(bad); err == nil {
			t.Fatal("invalid frame")
		}
	}
	for i := 0; i < len(good); i++ {
		bad := append([]byte(nil), good...)
		bad[i] ^= 0x80
		if i < 12 {
			if _, err := readRawZstd(bad); err == nil {
				t.Fatal("invalid frame header", i)
			}
		}
	}
}
func TestOperationScopeAndDeviceGates(t *testing.T) {
	for _, which := range []string{"device", "repo"} {
		t.Run(which, func(t *testing.T) {
			f := newFixture(t, 1)
			if which == "device" {
				f.client.cfg.Scope.Device = "33333333-3333-4333-8333-333333333333"
			} else {
				f.client.cfg.Grant.Repos = []string{"r1:" + strings.Repeat("f", 64)}
			}
			_, err := f.client.Push(t.Context())
			if !errors.Is(err, ErrInvalid) || f.mintCount != 0 {
				t.Fatal(err)
			}
		})
	}
}
func TestSignedControlPermittedMetadataIsNotTextException(t *testing.T) {
	f := newFixture(t, 0)
	h := record.Header{Type: record.KindRetraction, LID: strings.Repeat("b", 64), Author: record.Author{MachineID: device, KeyID: sig.KeyID(f.recordKey.Public().(ed25519.PublicKey))}, At: 1761150000456, Prov: record.ProvUser, Red: record.Redact{Profile: record.ProfileLocal, Epoch: 7, Fingerprint: strings.Repeat("a", 64)}, Op: ""}
	// LID for a control is its operation-derived identity.
	h.LID, _ = record.ControlLID(record.KindRetraction, h.Author.KeyID, strings.Repeat("c", 32))
	r, err := record.Build(h, &record.RetractionBody{IDs: []string{strings.Repeat("e", 64)}, Reason: "rule_removed"})
	if err != nil {
		t.Fatal(err)
	}
	signature, _ := sig.SignRecord(f.recordKey, r.ID)
	if _, err = NewOperation("control", []SignedRecord{{r, []record.Signature{signature}}}); err != nil {
		t.Fatal(err)
	}
}
func FuzzRestoreOperation(f *testing.F) {
	f.Add([]byte(`{"op_id":"x","envelopes":[]}`), strings.Repeat("0", 64))
	f.Add([]byte{}, "")
	f.Fuzz(func(t *testing.T, raw []byte, digest string) {
		if len(raw) > MaxRequestBytes+1 {
			return
		}
		_, _ = RestoreOperation(raw, digest)
		sum := sha256.Sum256(raw)
		_, _ = RestoreOperation(raw, hex.EncodeToString(sum[:]))
	})
}
func FuzzRawZstd(f *testing.F) {
	f.Add(rawZstd([]byte("{}")))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > record.MaxBodyBytes+65536 {
			return
		}
		body, err := readRawZstd(raw)
		if err == nil && len(body) > record.MaxBodyBytes {
			t.Fatal("body bound")
		}
	})
}

func TestControlIgnoredExtensionCannotLeaveNode(t *testing.T) {
	f := newFixture(t, 0)
	h := record.Header{Type: record.KindRetraction, Author: record.Author{MachineID: device, KeyID: sig.KeyID(f.recordKey.Public().(ed25519.PublicKey))}, At: 1761150000456, Prov: record.ProvUser, Red: record.Redact{Profile: record.ProfileLocal, Epoch: 7, Fingerprint: strings.Repeat("a", 64)}}
	h.LID, _ = record.ControlLID(record.KindRetraction, h.Author.KeyID, strings.Repeat("c", 32))
	r, err := record.Build(h, &record.RetractionBody{IDs: []string{strings.Repeat("e", 64)}, Reason: "rule_removed"})
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	_ = json.Unmarshal(r.BodyJCS, &body)
	body["text"] = "private transcript"
	b, _ := jcs.MarshalRecord(body)
	h = r.Header
	h.Body = &record.BodyRef{Digest: record.BodyDigest(b), Size: int64(len(b))}
	header, _ := jcs.MarshalRecord(h)
	if _, err = record.Parse(header, b, ""); record.CodeOf(err) != record.CodeNonMinimalControl {
		t.Fatal("major3 must reject control extensions before typed decode", err)
	}
	// Also prove sync reparses caller-owned bytes rather than trusting the
	// already populated typed record after a caller mutates its sealed bytes.
	r.HeaderJCS, r.BodyJCS, r.ID = header, b, record.ContentID(header)
	signature, _ := sig.SignRecord(f.recordKey, r.ID)
	if _, err = NewOperation("no-text", []SignedRecord{{r, []record.Signature{signature}}}); !errors.Is(err, ErrInvalid) {
		t.Fatal("control smuggled extension text", err)
	}
}

// Frozen frames were independently decoded with the standard zstandard library.
// Comparing our encoder to these bytes catches a shared writer/reader mistake.
func TestZstdIndependentDecoderVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/zstd-raw-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors []struct {
		Size   int    `json:"size"`
		Digest string `json:"sha256"`
	}
	if json.Unmarshal(raw, &vectors) != nil {
		t.Fatal("vectors")
	}
	for _, v := range vectors {
		body := bytes.Repeat([]byte{'x'}, v.Size)
		if v.Size == 2 {
			body = []byte("{}")
		}
		digest := sha256.Sum256(rawZstd(body))
		if hex.EncodeToString(digest[:]) != v.Digest {
			t.Fatal(v.Size)
		}
	}
}
