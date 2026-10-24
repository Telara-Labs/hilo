package record

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"testing"
)

func TestV3IssuedOperationTokens(t *testing.T) {
	p := NewOperationTokens()
	if _, err := p.Resolve("cred", "op1:00112233445566778899aabbccddeeff"); err == nil {
		t.Fatal("caller-selected token accepted")
	}
	if _, err := SuppliedOpID("cred", "op1:00112233445566778899aabbccddeeff"); err == nil {
		t.Fatal("syntax bypassed node issuance")
	}
	pool, err := p.Issue("cred")
	if err != nil || len(pool) != 8 {
		t.Fatal(pool, err)
	}
	op, err := p.Resolve("cred", pool[0])
	if err != nil || !IsHex64(op) {
		t.Fatal(err)
	}
	if _, err = p.Resolve("other-credential", pool[0]); err == nil {
		t.Fatal("cross-credential token accepted")
	}
	consumedToken := pool[0]
	if p.Consume("cred", pool[0]) != nil {
		t.Fatal("consume")
	}
	snapshot, err := json.Marshal(p.Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	var restored []IssuedOperationToken
	if json.Unmarshal(snapshot, &restored) != nil {
		t.Fatal("snapshot decode")
	}
	recovered, err := RestoreOperationTokens(restored)
	if err != nil {
		t.Fatal(err)
	}
	if recovered.Consume("cred", consumedToken) != ErrOperationConsumed {
		t.Fatal("consumed token authorized a second first-use")
	}
	clone := recovered.Clone()
	if op2, err := clone.Resolve("cred", consumedToken); err != nil || op2 != op {
		t.Fatal("clone changed settlement")
	}
	if again, err := recovered.Resolve("cred", pool[0]); err != nil || again != op {
		t.Fatal("settlement namespace changed")
	}
	// Old consumed identities cannot reenter an unused pool, even after key scrub.
	for i := 0; i < 20; i++ {
		pool, err = recovered.Issue("cred")
		if err != nil {
			t.Fatal(err)
		}
		for _, token := range pool {
			if token == "" || token == consumedToken {
				t.Fatal("consumed token reissued")
			}
		}
	}
	unused := 0
	for token, cred := range recovered.issued {
		if cred == "cred" && !recovered.consumed[token] {
			unused++
		}
	}
	if unused > 128 || unused < 121 {
		t.Fatal("pool bounds", unused)
	}
	if _, err := FallbackOpID("cred", "sc1:"+tMachine+":00112233445566778899aabbccddeeff", "00112233445566778899aabbccddeeff", "ffeeddccbbaa99887766554433221100", "telara_task_list"); err != nil {
		t.Fatal(err)
	}
	if _, err := FallbackOpID("cred", "scope", "conn", "raw prompt/hash RPC id", "telara_task_list"); err == nil {
		t.Fatal("fallback accepted content identities")
	}
}
func TestV3TokenFailureIsAtomic(t *testing.T) {
	p := NewOperationTokens()
	if _, err := p.issue("cred", failedEntropy{}); err == nil || len(p.issued) != 0 {
		t.Fatal("failed RNG issued tokens")
	}
	// Distinct explicit PUBLIC test-only bytes; external authoring exposes no reader.
	var raw []byte
	for i := 0; i < 8; i++ {
		raw = append(raw, bytes.Repeat([]byte{byte(i + 1)}, 16)...)
	}
	pool, err := p.issue("cred", bytes.NewReader(raw))
	if err != nil || len(pool) != 8 {
		t.Fatal(err)
	}
	for i, token := range pool {
		if token != "op1:"+hex.EncodeToString(raw[i*16:(i+1)*16]) {
			t.Fatal("direct CSPRNG bytes changed")
		}
	}
	before := len(p.issued)
	returned, err := p.issue("cred", bytes.NewReader(raw[:20]))
	if err != nil || len(returned) != 8 || len(p.issued) != before {
		t.Fatal("partial issuance leaked")
	}
	if _, err := p.Resolve("cred", "op1:"+H("guess")[:32]); err == nil {
		t.Fatal("candidate digest token authorized")
	}
}

func TestV3OperationSnapshotRejectsInvalidState(t *testing.T) {
	token := "op1:00112233445566778899aabbccddeeff"
	for _, rows := range [][]IssuedOperationToken{{{Token: "bad", Credential: "c"}}, {{Token: token}}, {{Token: token, Credential: "c"}, {Token: token, Credential: "other"}}} {
		if _, err := RestoreOperationTokens(rows); err == nil {
			t.Fatal("invalid receiver snapshot")
		}
	}
	rows := []IssuedOperationToken{}
	for i := 0; i < 129; i++ {
		raw := make([]byte, 16)
		raw[0] = byte(i)
		rows = append(rows, IssuedOperationToken{Token: "op1:" + hex.EncodeToString(raw), Credential: "c"})
	}
	if _, err := RestoreOperationTokens(rows); err == nil {
		t.Fatal("restored pool exceeds128")
	}
}
