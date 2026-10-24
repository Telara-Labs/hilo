package sync

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/Telara-Labs/telara-memory/contract/jcs"
	"github.com/Telara-Labs/telara-memory/contract/record"
	"github.com/Telara-Labs/telara-memory/contract/sig"
)

func restoreV3Test(raw []byte) (*Operation, error) {
	digest := sha256.Sum256(raw)
	return RestoreOperation(raw, hex.EncodeToString(digest[:]))
}

func TestV3IndependentVersionGates(t *testing.T) {
	f := newFixture(t, 1)
	for _, versions := range [][2]int{{2, 3}, {3, 2}, {2, 2}, {4, 3}, {3, 4}} {
		t.Run(fmt.Sprintf("envelope%d-header%d", versions[0], versions[1]), func(t *testing.T) {
			var req request
			if err := json.Unmarshal(f.outbox.op.Bytes(), &req); err != nil {
				t.Fatal(err)
			}
			e := &req.Envelopes[0]
			header, err := decode64(e.Header, record.MaxHeaderBytes)
			if err != nil {
				t.Fatal(err)
			}
			var h record.Header
			if err = json.Unmarshal(header, &h); err != nil {
				t.Fatal(err)
			}
			h.V = versions[1]
			header, err = jcs.MarshalRecord(h)
			if err != nil {
				t.Fatal(err)
			}
			e.V, e.ID, e.Header = versions[0], record.ContentID(header), b64.EncodeToString(header)
			e.Sigs[0], err = sig.SignRecord(f.recordKey, e.ID)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := json.Marshal(req)
			if err != nil {
				t.Fatal(err)
			}
			_, err = restoreV3Test(raw)
			var rejection *record.Error
			if !errors.Is(err, ErrInvalid) || !errors.As(err, &rejection) || rejection.Code != record.CodeUnsupportedVersion || rejection.Quarantine != (versions[0] > 3 || versions[1] > 3) {
				t.Fatal("version gates must reject independently", err)
			}
			if versions[1] != 3 {
				signed := f.signed(t, 9)
				// In-memory Header is deliberately major3. Signed bytes are the
				// authority, even when the caller presents a conflicting typed value.
				signed.Record.HeaderJCS, signed.Record.ID = header, e.ID
				signed.Sigs = e.Sigs
				if _, err = NewOperation("legacy-candidate", []SignedRecord{signed}); record.CodeOf(err) != record.CodeUnsupportedVersion {
					t.Fatal("authoring boundary repaired legacy bytes", err)
				}
			}
			f.outbox.op.raw = raw
			f.outbox.op.digest = func() string { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }()
			if _, err = f.client.Push(t.Context()); record.CodeOf(err) != record.CodeUnsupportedVersion || f.mintCount != 0 || f.pushCount != 0 || f.outbox.completes != 0 || f.outbox.ctlCursor != 2 || f.outbox.dataCursor != 3 {
				t.Fatal("legacy outbox must stop before credentials/network/ack", err)
			}
			// Restore the original operation for the next independent case.
			f.outbox.op, err = NewOperation("persistent-operation-1", []SignedRecord{f.signed(t, 0)})
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestV3RejectLossyEnvelopeFields(t *testing.T) {
	f := newFixture(t, 1)
	for _, which := range []string{"envelope-case-alias", "signature-case-alias", "body-case-alias", "receipt", "grant", "signature-alg", "signature-key", "signature-context", "signature-value", "body-codec", "body-bytes"} {
		t.Run(which, func(t *testing.T) {
			var req map[string]any
			if err := json.Unmarshal(f.outbox.op.Bytes(), &req); err != nil {
				t.Fatal(err)
			}
			e := req["envelopes"].([]any)[0].(map[string]any)
			switch which {
			case "envelope-case-alias":
				e["Header"] = e["header"]
				delete(e, "header")
			case "signature-case-alias":
				s := e["sigs"].([]any)[0].(map[string]any)
				s["Alg"] = s["alg"]
				delete(s, "alg")
			case "body-case-alias":
				b := e["body"].(map[string]any)
				b["Codec"] = b["codec"]
				delete(b, "codec")
			case "receipt", "grant":
				e[which] = nil
			case "body-codec", "body-bytes":
				e["body"].(map[string]any)[strings.TrimPrefix(which, "body-")] = nil
			default:
				key := map[string]string{"signature-alg": "alg", "signature-key": "key_id", "signature-context": "ctx", "signature-value": "value"}[which]
				e["sigs"].([]any)[0].(map[string]any)[key] = nil
			}
			raw, err := json.Marshal(req)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = restoreV3Test(raw); !errors.Is(err, ErrInvalid) {
				t.Fatal("lossy hosted envelope accepted", err)
			}
		})
	}
	var req request
	if err := json.Unmarshal(f.outbox.op.Bytes(), &req); err != nil {
		t.Fatal(err)
	}
	spaced, err := json.MarshalIndent(req, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	op, err := restoreV3Test(spaced)
	if err != nil || !bytes.Equal(op.Bytes(), spaced) {
		t.Fatal("comparison must preserve exact durable wire bytes", err)
	}
}

func TestV3FreshMetadataSecretsAndImmutableRetry(t *testing.T) {
	f := newFixture(t, 0)
	first, second := f.signed(t, 1), f.signed(t, 1)
	b1 := first.Record.Body.(*record.TaskMetaBody)
	b2 := second.Record.Body.(*record.TaskMetaBody)
	secret1, err1 := b64.DecodeString(b1.Salt)
	secret2, err2 := b64.DecodeString(b2.Salt)
	if err1 != nil || err2 != nil || len(secret1) != 16 || len(secret2) != 16 || b1.Salt == b2.Salt || first.Record.ID == second.Record.ID || first.Record.Header.Body.Digest == second.Record.Header.Body.Digest {
		t.Fatal("fresh authoring reused record secrets/identity")
	}
	op, err := NewOperation("sealed-once", []SignedRecord{first})
	if err != nil {
		t.Fatal(err)
	}
	var req request
	if err = json.Unmarshal(op.Bytes(), &req); err != nil || req.Envelopes[0].V != 3 || record.ContractVersion != "mnc/3.0" {
		t.Fatal("wrong wire major", err)
	}
	_, records, err := fixtureDecodeRequest(op.Bytes())
	if err != nil || records[0].Header.V != 3 || records[0].Body.(*record.TaskMetaBody).Salt != b1.Salt {
		t.Fatal("metadata secret missing on major3 wire", err)
	}
	restored, err := RestoreOperation(op.Bytes(), op.Digest())
	if err != nil || !bytes.Equal(restored.records[0].BodyJCS, first.Record.BodyJCS) || restored.records[0].ID != first.Record.ID {
		t.Fatal("restart must reuse the committed seal", err)
	}
}

func TestV3SessionMetadataReceipt(t *testing.T) {
	f := newFixture(t, 0)
	h := f.signed(t, 1).Record.Header
	sk, err := record.SessionKey("codex", "local", record.NativeGlobal, "native-session", device)
	if err != nil {
		t.Fatal(err)
	}
	h.Type, h.Subj = record.KindSession, record.Subject{SessionKey: sk, RepoID: repo}
	h.LID = record.SessionLID(sk, device, 0)
	r, err := record.Build(h, &record.SessionMetaBody{NativeIDKind: record.NativeGlobal, MachineOS: "darwin", Title: "codex session"})
	if err != nil {
		t.Fatal(err)
	}
	signature, err := sig.SignRecord(f.recordKey, r.ID)
	if err != nil {
		t.Fatal(err)
	}
	f.outbox.op, err = NewOperation("session-major3", []SignedRecord{{Record: r, Sigs: []record.Signature{signature}}})
	if err != nil {
		t.Fatal(err)
	}
	ack, err := f.client.Push(t.Context())
	if err != nil || len(ack.Results) != 1 || ack.Results[0].ID != r.ID || ack.Results[0].Receipt == nil || f.outbox.completes != 1 || f.outbox.ctlCursor != 2 || f.outbox.dataCursor != 3 {
		t.Fatal("major3 session receipt/cursor boundary", err)
	}
}
