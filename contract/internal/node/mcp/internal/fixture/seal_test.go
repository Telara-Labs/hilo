package fixture

import (
	"bytes"
	"crypto/ed25519"
	"github.com/Telara-Labs/hilo/contract/jcs"
	"github.com/Telara-Labs/hilo/contract/record"
	"github.com/Telara-Labs/hilo/contract/sig"
	"strings"
	"testing"
)

func TestSealMutationAndReceipt(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32))
	defer clear(key)
	owner := sig.KeyID(key.Public().(ed25519.PublicKey))
	machine := "12345678-1234-4234-8234-123456789abc"
	task := "89abcdef-1234-4234-8234-123456789abc"
	s, e := NewSealer(owner, machine, bytes.Repeat([]byte{1}, 32), key)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Clear()
	call := Call{Access: Access{Owner: owner, MachineID: machine, Client: "fixture", ScopeID: "scope"}, Op: strings.Repeat("a", 64), ArgsHash: strings.Repeat("b", 64), Tool: "telara_task_create"}
	secret := "ghp_" + strings.Repeat("a", 36)
	for _, m := range []Mutation{
		{"task", task, map[string]any{"name": "Name", "goal": "x " + secret, "anchors": map[string]any{"repo": "r", "file_paths": []any{"x.go"}, "branch": "main", "ticket_id": "fixture"}}},
		{"checkpoint", task, map[string]any{"milestone": "x " + secret, "next_steps": "test", "decisions": []any{"yes"}, "blocked": []any{}, "task_tree": []any{map[string]any{"step": "parse", "status": "done", "detail": "kept detail"}}, "knowledge_refs": []any{"node"}}},
		{"pause", task, map[string]any{"resume_context": "x " + secret, "progress_notes": "progress", "handoff_hint": "next", "token_estimate": float64(0)}},
		{"conclusion", task, map[string]any{"final_summary": "x " + secret, "changes_made": []any{"file"}, "token_estimate": float64(0)}},
	} {
		sealed, e := s.Mutation(call, m, 100, nil)
		if e != nil {
			t.Fatal(m.Kind, e)
		}
		header, body, signatures, id := sealed.Envelope()
		if strings.Contains(string(body), secret) {
			t.Fatal("secret in body")
		}
		r, e := record.Parse(header, body, id)
		if e != nil {
			t.Fatal(e)
		}
		if r.Header.Red.Findings == 0 || r.Header.Trust.Coverage != "incomplete" || r.Header.Red.Fingerprint == "" {
			t.Fatal("missing seal provenance")
		}
		if e = sig.Verify(key.Public().(ed25519.PublicKey), signatures[0].Ctx, []byte(id), signatures[0]); e == nil {
			t.Fatal("raw id must not be signed message")
		}
		message, e := sig.RecordMessage(id)
		if e != nil {
			t.Fatal(e)
		}
		if e = sig.Verify(key.Public().(ed25519.PublicKey), signatures[0].Ctx, message, signatures[0]); e != nil {
			t.Fatal("signature", e)
		}
		if m.Kind == "checkpoint" && !strings.Contains(string(body), "kept detail") {
			t.Fatal("hosted task_tree detail lost")
		}
		if m.Kind == "conclusion" && r.Body.(*record.ConclusionBody).TokenEstimate == nil {
			t.Fatal("reported zero lost")
		}
		header[0] = '!'
		h, _, _, _ := sealed.Envelope()
		if h[0] != '{' {
			t.Fatal("mutable sealed envelope")
		}
	}
	res := result("x "+secret, false)
	sealed, e := s.Receipt(call, "m1.abcdefghij", task, res, 101)
	if e != nil {
		t.Fatal(e)
	}
	h, b, _, id := sealed.Envelope()
	r, e := record.Parse(h, b, id)
	if e != nil {
		t.Fatal(e)
	}
	raw, _ := jcs.MarshalRecord(res)
	if r.Body.(*record.CallBody).ResultHash == record.BodyDigest(raw) {
		t.Fatal("unredacted result hash")
	}
	if _, e = s.Mutation(call, Mutation{"unsupported", task, nil}, 100, nil); e == nil {
		t.Fatal("unsupported seal")
	}
	s.Clear()
	if _, e = s.Receipt(call, "m1.abcdefghij", task, res, 101); e == nil {
		t.Fatal("cleared key used")
	}
	if _, e = NewSealer(owner, machine, nil, key); e == nil {
		t.Fatal("salt outage bypass")
	}
	broken := append(ed25519.PrivateKey(nil), key...)
	broken[63] ^= 1
	if _, e = NewSealer(owner, machine, bytes.Repeat([]byte{1}, 32), broken); e == nil {
		t.Fatal("inconsistent private key accepted")
	}
}
func TestKnownCredentialsCannotBecomeIdentityHashes(t *testing.T) {
	secret := "ghp_" + strings.Repeat("a", 36)
	for _, raw := range []string{`{"com.telara/op-id":"` + secret + `"}`, `{"com.telara/conversation-handle":"` + secret + `"}`, `{"com.telara/native":{"client":"fixture","id":"` + secret + `","kind":"local","origin":"local"}}`} {
		if _, e := metadata([]byte(raw)); e == nil {
			t.Fatal("credential identity accepted")
		}
	}
}

func TestSealRefusesActivePolicyWithoutOverlay(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, 32))
	defer clear(key)
	owner := sig.KeyID(key.Public().(ed25519.PublicKey))
	s, e := NewSealer(owner, "12345678-1234-4234-8234-123456789abc", bytes.Repeat([]byte{1}, 32), key)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Clear()
	call := Call{Access: Access{Owner: owner, MachineID: "12345678-1234-4234-8234-123456789abc", PolicyID: strings.Repeat("a", 64)}}
	if _, e = s.Mutation(call, Mutation{}, 1, nil); e == nil {
		t.Fatal("policy overlay bypass")
	}
	if _, e = s.Receipt(call, "m1.abcdefghij", "", result("", false), 1); e == nil {
		t.Fatal("policy receipt bypass")
	}
}
