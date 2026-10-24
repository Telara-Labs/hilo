package record

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"github.com/Telara-Labs/telara-memory/contract/jcs"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func TestV3IndependentSecretsEveryBody(t *testing.T) {
	for name, mk := range fixtures() {
		h, b := mk()
		if !salted(h.Type) {
			continue
		}
		t.Run(name, func(t *testing.T) {
			old, err := Build(h, b)
			if err != nil {
				t.Fatal(err)
			}
			oldBody := append([]byte(nil), old.BodyJCS...)
			oldHeader := append([]byte(nil), old.HeaderJCS...)
			for i := 0; i < 8; i++ {
				nh, nb := mk()
				if c, ok := nb.(*ConclusionBody); ok && i%2 == 1 {
					c.Text = "else"
				}
				next, err := Build(nh, nb)
				if err != nil {
					t.Fatal(err)
				}
				salt, _ := saltOf(next.Body)
				oldSalt, _ := saltOf(old.Body)
				if next.Header.LID != old.Header.LID || salt == oldSalt || next.ID == old.ID || next.Header.Body.Digest == old.Header.Body.Digest {
					t.Fatal("fresh-write guessing oracle")
				}
			}
			exact, err := Parse(oldHeader, oldBody, old.ID)
			if err != nil || !bytes.Equal(exact.BodyJCS, oldBody) {
				t.Fatal("retry must copy exact seal")
			}
			if _, err := Build(h, b, nil); err == nil {
				t.Fatal("caller device-key override")
			}
			if _, err := Build(h, old.Body); err == nil {
				t.Fatal("caller salt override")
			}
			before, _ := json.Marshal(b)
			candidate, err := build(h, b, failedEntropy{}, false)
			after, _ := json.Marshal(b)
			if err == nil || candidate != nil || !bytes.Equal(before, after) {
				t.Fatal("failed entropy exposed or mutated candidate")
			}
		})
	}
	h, b := fixtures()["chunk"]()
	r, err := Build(h, b)
	if err != nil {
		t.Fatal(err)
	}
	chunk := r.Body.(*ChunkBody)
	if chunk.Salt == chunk.Events[0].Salt || chunk.Events[0].Salt == chunk.Events[1].Salt {
		t.Fatal("independent event/body secrets reused")
	}
	copied := *chunk
	copied.Salt = ""
	repack, err := Build(h, &copied)
	if err != nil {
		t.Fatal(err)
	}
	if repack.Body.(*ChunkBody).Events[0].Revision != chunk.Events[0].Revision || repack.Body.(*ChunkBody).Salt == chunk.Salt {
		t.Fatal("repack changed event seal or reused outer secret")
	}
}

func TestV3CallCommitmentsAndSignedDependencies(t *testing.T) {
	h, b := fixtures()["call"]()
	body := b.(*CallBody)
	a, z := hx("a"), hx("z")
	deps := []string{a, z}
	sort.Strings(deps)
	body.CommitmentDeps = deps
	h.Links.DerivedFrom = deps
	args := json.RawMessage(`{"text":"private redacted"}`)
	result := json.RawMessage(`[true,"done"]`)
	r, err := BuildCall(h, *body, args, result)
	if err != nil {
		t.Fatal(err)
	}
	c := r.Body.(*CallBody)
	key, _ := base64.RawURLEncoding.DecodeString(c.Salt)
	preimage, _ := jcs.MarshalRecord([]any{"mnc3-call-args", c.Tool, args})
	mac := hmac.New(sha256.New, key)
	mac.Write(preimage)
	if hex.EncodeToString(mac.Sum(nil)) != c.ArgsHash || c.ArgsHash == BodyDigest(args) || c.ArgsHash == c.ResultHash {
		t.Fatal("call commitment domain/value")
	}
	if err := ValidateCommitmentDependencies(r, []string{hx("omitted")}); CodeOf(err) != CodeCommitmentDependencies {
		t.Fatal("known omitted mutation root")
	}
	if err := ValidateCommitmentDependencies(r.WithoutBody(), nil); CodeOf(err) != CodeCommitmentDependencies {
		t.Fatal("bodyless call supplied empty dependencies")
	}
	for _, mutation := range []func(*Header, *CallBody){
		func(_ *Header, c *CallBody) { c.CommitmentDeps = nil },
		func(_ *Header, c *CallBody) { c.CommitmentDeps = []string{a, a} },
		func(_ *Header, c *CallBody) { c.CommitmentDeps = []string{"malformed"} },
		func(_ *Header, c *CallBody) { c.CommitmentDeps = []string{deps[1], deps[0]} },
		func(_ *Header, c *CallBody) { c.CommitmentDeps = []string{} },
		func(h *Header, _ *CallBody) { h.Links.DerivedFrom = []string{a} },
	} {
		hh, cc := r.Header, *c
		mutation(&hh, &cc)
		hh.Body = nil
		bj, _ := json.Marshal(&cc)
		bj, _ = jcs.Canonicalize(bj)
		hh.V = Version
		hh.Body = &BodyRef{Digest: BodyDigest(bj), Size: int64(len(bj))}
		hj, _ := jcs.MarshalRecord(hh)
		if _, err := Parse(hj, bj, ""); CodeOf(err) != CodeCommitmentDependencies {
			t.Fatalf("bad signed deps accepted: %v", err)
		}
	}
	for _, tool := range ReceiptTools {
		hh, cc := h, *body
		cc.Tool = tool
		if _, err := BuildCall(hh, cc, nil, nil); err != nil {
			t.Fatal(tool, err)
		}
	}
	for _, tool := range []string{"task_checkpoint", "other", "write private text"} {
		cc := *body
		cc.Tool = tool
		if _, err := BuildCall(h, cc, args, result); err == nil {
			t.Fatal("unknown tool accepted")
		}
	}
	for _, code := range []string{"invalid_request", "unauthorized", "not_found", "conflict", "unavailable", "timeout", "cancelled", "internal", "unknown"} {
		cc := *body
		cc.Outcome = "error"
		cc.Err = code
		if _, err := BuildCall(h, cc, nil, nil); err != nil {
			t.Fatal(code, err)
		}
	}
	for _, cc := range []CallBody{func() CallBody { c := *body; c.Err = "/private/native error"; c.Outcome = "error"; return c }(), func() CallBody {
		c := *body
		c.ScopeID = "sc1:" + tMachine2 + ":00112233445566778899aabbccddeeff"
		return c
	}(), func() CallBody { c := *body; c.ArgsHash = hx("caller-hash"); return c }()} {
		if _, err := BuildCall(h, cc, args, result); err == nil {
			t.Fatal("unsafe call accepted")
		}
	}
}

func TestV3KeyedTextBeforeTruncation(t *testing.T) {
	e := Event{ID: tEvent(0), Kind: "assistant_final", Prov: "transcript"}
	raw := strings.Repeat("x", 590) + " ghp_" + strings.Repeat("a", 36) + " tail"
	a, err := ReviseTextEvent(e, nil, raw, actualRedactor{}, 600)
	if err != nil {
		t.Fatal(err)
	}
	b, err := ReviseTextEvent(e, nil, raw, actualRedactor{}, 600)
	if err != nil {
		t.Fatal(err)
	}
	full := actualRedactor{}.Redact(raw)
	want, _ := EventTextCommitment(a.Salt, full)
	if a.Text.Digest != want || a.Text.Digest == BodyDigest([]byte(full)) || a.Text.Digest == b.Text.Digest || strings.Contains(a.Text.Body, "ghp_") || !a.Text.Truncated {
		t.Fatal("text digest used raw/unsalted/bounded preimage")
	}
	if _, err := EventPayload(a); err == nil {
		t.Fatal("truncated excerpt established equality")
	}
	a, err = ReviseTextEvent(e, nil, "same redacted text", actualRedactor{}, 600)
	if err != nil {
		t.Fatal(err)
	}
	b, err = ReviseTextEvent(e, nil, "same redacted text", actualRedactor{}, 600)
	if err != nil {
		t.Fatal(err)
	}
	ap, err := EventPayload(a)
	if err != nil {
		t.Fatal(err)
	}
	bp, err := EventPayload(b)
	if err != nil || !bytes.Equal(ap, bp) || a.Text.Digest == b.Text.Digest {
		t.Fatal("cross-secret equality")
	}
	broken := a
	text := *a.Text
	text.Digest = hx("wrong")
	broken.Text = &text
	broken.Revision, _ = EventRevision(broken)
	if ValidateEventText(broken) == nil {
		t.Fatal("valid revision hid invalid keyed digest")
	}
	if _, err := ReviseEvent(a, nil); err == nil {
		t.Fatal("author accepted old secret override")
	}
}

func TestV3RecursiveClosedSchemaShapes(t *testing.T) {
	// Exercise every nested declared field/type/required slot without semantic
	// enum assumptions. Parse's independent cases test actual signed bytes.
	targets := []any{&SessionBody{}, &SessionMetaBody{}, &ChunkBody{}, &ConclusionBody{}, &TaskBody{}, &TaskMetaBody{}, &CheckpointBody{}, &PauseBody{}, &CallBody{}, &BindingBody{}, &DigestBody{}, &RollupBody{}, &RetractionBody{}, &ErasureBody{}, &WithdrawalBody{}, &KeyOpBody{}, &PolicyBody{}}
	seen := map[reflect.Type]bool{}
	var walk func(reflect.Type)
	walk = func(typ reflect.Type) {
		for typ.Kind() == reflect.Pointer || typ.Kind() == reflect.Slice || typ.Kind() == reflect.Map {
			typ = typ.Elem()
		}
		if typ.Kind() != reflect.Struct || seen[typ] {
			return
		}
		seen[typ] = true
		shape := schemaValue(typ)
		raw, _ := jcs.MarshalRecord(shape)
		target := reflect.New(typ).Interface()
		if CheckClosedObject(raw, target) != nil {
			t.Fatal(typ, "complete shape")
		}
		obj := shape.(map[string]any)
		obj["UNKNOWN_PROSE"] = "discard me"
		bad, _ := jcs.MarshalRecord(obj)
		if CheckClosedObject(bad, target) == nil {
			t.Fatal(typ, "unknown field")
		}
		delete(obj, "UNKNOWN_PROSE")
		for i := 0; i < typ.NumField(); i++ {
			f := typ.Field(i)
			tag := strings.Split(f.Tag.Get("json"), ",")
			name := tag[0]
			prior := obj[name]
			obj[name] = nil
			bad, _ := json.Marshal(obj)
			if CheckClosedObject(bad, target) == nil {
				t.Fatal(typ, name, "null")
			}
			obj[name] = []any{nil}
			bad, _ = json.Marshal(obj)
			if CheckClosedObject(bad, target) == nil {
				t.Fatal(typ, name, "wrong type or null array")
			}
			delete(obj, name)
			bad, _ = jcs.MarshalRecord(obj)
			if len(tag) == 1 && CheckClosedObject(bad, target) == nil {
				t.Fatal(typ, name, "required presence")
			}
			obj[name] = prior
			walk(f.Type)
		}
	}
	for _, target := range targets {
		walk(reflect.TypeOf(target))
	}
	if len(seen) < 35 {
		t.Fatal("nested inventory incomplete", len(seen))
	}
}
func schemaValue(t reflect.Type) any {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	switch t.Kind() {
	case reflect.Struct:
		out := map[string]any{}
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			name := strings.Split(f.Tag.Get("json"), ",")[0]
			out[name] = schemaValue(f.Type)
		}
		return out
	case reflect.Slice:
		return []any{schemaValue(t.Elem())}
	case reflect.Map:
		return map[string]any{"example": schemaValue(t.Elem())}
	case reflect.String:
		return "example"
	case reflect.Bool:
		return true
	default:
		return int64(1)
	}
}

func TestV3OptionalOmissionAndPointerZeros(t *testing.T) {
	for _, tc := range []struct {
		name, member string
		value        any
	}{
		{"task", "name", ""}, {"task", "anchors", map[string]any{}}, {"session", "counts", map[string]any{}}, {"session", "page", 0}, {"chunk", "ignored", true},
	} {
		r := mustBuild(t, tc.name)
		var b map[string]any
		json.Unmarshal(r.BodyJCS, &b)
		b[tc.member] = tc.value
		bj, _ := jcs.MarshalRecord(b)
		h := r.Header
		h.Body = &BodyRef{Digest: BodyDigest(bj), Size: int64(len(bj))}
		hj, _ := jcs.MarshalRecord(h)
		if _, err := Parse(hj, bj, ""); err == nil {
			t.Fatal(tc.name, tc.member, "noncanonical omission accepted")
		}
	}
	zero := int64(0)
	no := false
	h, b := fixtures()["pause"]()
	b.(*PauseBody).TokenEstimate = &zero
	if _, err := Build(h, b); err != nil {
		t.Fatal("reported zero estimate lost", err)
	}
	h, b = fixtures()["session"]()
	b.(*SessionBody).Repo = &RepoRef{Dirty: &no}
	b.(*SessionBody).SettledThrough = -1
	if _, err := Build(h, b); err != nil {
		t.Fatal("reported false dirty or -1 settled lost", err)
	}
}

func TestV3NestedEnumsAndPolicyCredentials(t *testing.T) {
	h, b := fixtures()["checkpoint"]()
	b.(*CheckpointBody).TaskTree = []Step{{Title: "step", Status: "unknown-state"}}
	if _, err := Build(h, b); err == nil {
		t.Fatal("unknown step status")
	}
	h, b = fixtures()["session-meta"]()
	b.(*SessionMetaBody).Pointers[0].Outcome = "unknown-outcome"
	if _, err := Build(h, b); err == nil {
		t.Fatal("unknown pointer outcome")
	}
	h, b = fixtures()["policy"]()
	b.(*PolicyBody).Redaction.Shapes = []Shape{{Name: "pattern", RE2: "ghp_" + strings.Repeat("a", 36)}}
	if _, err := Build(h, b); err == nil {
		t.Fatal("known policy credential literal persisted")
	}
	c := loadCorpus(t)
	c.Entries[0].Parts = []string{"private runtime memory"}
	if _, err := Behavior(c, actualRedactor{}); err == nil {
		t.Fatal("private runtime corpus fingerprint")
	}
	if !NeedsErasureConfirmation(Selectors{Events: []EventSelector{{Owner: tKeyID, SessionKey: tSessionKey(), EventID: tEvent(0)}}}, 0, 0) {
		t.Fatal("unbounded event selector bypassed confirmation")
	}
}

func TestV3SelfReviewCallRefHasNoPublicEntropyOverride(t *testing.T) {
	ref, err := NewCallRef(bytes.NewReader(bytes.Repeat([]byte{1}, 7)))
	if err == nil || ref != "" {
		t.Fatal("public call-reference generation accepted caller entropy")
	}
}

func TestV3CallRefInternalEntropyAndFailure(t *testing.T) {
	ref, err := NewCallRef()
	if err != nil || !IsCallRef(ref) {
		t.Fatal("internal call-ref entropy", err)
	}
	if ref, err := newCallRef(failedEntropy{}); err == nil || ref != "" {
		t.Fatal("call-ref RNG failure disclosed candidate")
	}
}

func TestV3MinimalPublicKeyFacts(t *testing.T) {
	for _, mutate := range []func(*KeyOpBody){func(b *KeyOpBody) { b.Subject.Pub = "private prose" }, func(b *KeyOpBody) { b.Subject.Pub = "AAAA" }, func(b *KeyOpBody) { b.Subject.KeyID = tKeyID }, func(b *KeyOpBody) { b.Subject.Pub += "=" }} {
		h, b := fixtures()["key_op"]()
		mutate(b.(*KeyOpBody))
		if _, err := Build(h, b); err == nil {
			t.Fatal("non-public-key bytes reached retained control")
		}
	}
}
