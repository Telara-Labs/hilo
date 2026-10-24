package record

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/Telara-Labs/telara-memory/contract/jcs"
)

const (
	tMachine  = "6f1d2c3b-4a59-4e6f-8a7b-9c0d1e2f3a4b"
	tMachine2 = "0a1b2c3d-4e5f-4a6b-8c7d-0e1f2a3b4c5d"
	tKeyID    = "a91c0e00112233445566778899aabbcc"
	tTask     = "3f2a91c0-1111-4222-8333-444455556666"
	tAt       = int64(1761150000456)
)

var tSaltKey = bytes.Repeat([]byte{7}, 32)

func hx(s string) string { sum := sha256.Sum256([]byte(s)); return hex.EncodeToString(sum[:]) }

func tSessionKey() string {
	k, err := SessionKey("claude-code", "local", NativeGlobal, "2b9d0000-0000-4000-8000-000000000001", "")
	if err != nil {
		panic(err)
	}
	return k
}

func tEvent(n int64) string {
	id, err := EventID(tSessionKey(), "tool_call", Anchor{NativeItemID: fmt.Sprintf("toolu_%d", n)})
	if err != nil {
		panic(err)
	}
	return id
}

func baseHeader(k Kind, p Prov) Header {
	return Header{Type: k, Author: Author{MachineID: tMachine, KeyID: tKeyID}, At: tAt, Prov: p,
		Red: Redact{Profile: ProfileLocal, Epoch: 7, Fingerprint: hx("ruleset")}}
}

// fixtures returns one valid (header, body) per kind and provenance path.
func fixtures() map[string]func() (Header, any) {
	sk := tSessionKey()
	op := hx("op-1")
	return map[string]func() (Header, any){
		"session": func() (Header, any) {
			h := baseHeader(KindSession, ProvTranscript)
			h.Subj = Subject{SessionKey: sk, Client: &ClientRef{ID: "claude-code", Version: "2.1.290", Surface: "cli"}}
			h.LID = SessionLID(sk, tMachine, 0)
			return h, &SessionBody{NativeID: "2b9d0000-0000-4000-8000-000000000001", NativeIDKind: NativeGlobal,
				MachineOS: "darwin", Title: "fix the retry loop", StartedAt: tAt - 1000, LastEventAt: tAt,
				Chunks: []string{hx("chunk-a")}, SettledThrough: 3}
		},
		"session-meta": func() (Header, any) {
			h := baseHeader(KindSession, ProvDerived)
			h.Red.Profile = ProfilePushMetadata
			h.Subj = Subject{SessionKey: sk}
			h.LID = SessionLID(sk, tMachine, 0)
			h.Links = Links{Origin: hx("source-session")}
			return h, &SessionMetaBody{NativeIDKind: NativeGlobal, MachineOS: "darwin", StartedAt: tAt - 1000,
				Counts: &MetaCounts{Requests: 4, ToolCalls: 37, ToolFailures: 2}, Title: "claude-code session",
				Pointers: []MetaPointer{{Tool: "read", Outcome: "ok", Kind: "file", Ref: "src/retry.go"}}}
		},
		"chunk": func() (Header, any) {
			h := baseHeader(KindChunk, ProvTranscript)
			h.Subj = Subject{SessionKey: sk}
			e0, e1 := tEvent(0), tEvent(1)
			h.LID = ChunkLID(sk, tMachine, e0)
			return h, &ChunkBody{Events: []Event{
				{ID: e0, Seq: 0, Kind: "tool_call", At: tAt, Prov: "transcript", Ruleset: 7, Call: &ToolCall{Tool: "shell"}},
				{ID: e1, Seq: 1, Kind: "tool_result", At: tAt, Prov: "transcript", Result: &ToolResult{Outcome: "ok"}},
			}}
		},
		"conclusion-explicit": func() (Header, any) {
			h := baseHeader(KindConclusion, ProvMCPExplicit)
			h.Subj = Subject{SessionKey: sk, TaskID: tTask}
			h.LID = ExplicitConclusionLID(tKeyID, tTask)
			h.Op = op
			te := int64(1200)
			return h, &ConclusionBody{Source: "explicit", State: "answered", Text: "done", Supports: []string{tEvent(0)},
				ChangesMade: []string{"src/retry.go"}, TokenEstimate: &te}
		},
		"conclusion-request": func() (Header, any) {
			h := baseHeader(KindConclusion, ProvTranscript)
			h.Subj = Subject{SessionKey: sk}
			h.LID = RequestConclusionLID(sk, "idx:0")
			return h, &ConclusionBody{Source: "final-answer", State: "unknown", RequestKey: "idx:0", Request: "fix it", Text: "fixed"}
		},
		"task": func() (Header, any) {
			h := baseHeader(KindTask, ProvMCPExplicit)
			h.Subj = Subject{TaskID: tTask}
			h.LID = TaskLID(tKeyID, tTask)
			h.Op = op
			return h, &TaskBody{Name: "retry", Goal: "fix retries", Status: "active"}
		},
		"task-meta": func() (Header, any) {
			h := baseHeader(KindTask, ProvDerived)
			h.Red.Profile = ProfilePushMetadata
			h.Subj = Subject{TaskID: tTask}
			h.LID = TaskLID(tKeyID, tTask)
			h.Links = Links{Origin: hx("source-task")}
			return h, &TaskMetaBody{Status: "active"}
		},
		"task-gateway": func() (Header, any) {
			h := baseHeader(KindTask, ProvGateway)
			h.Author.MachineID = ""
			h.Subj = Subject{TaskID: tTask}
			h.LID = TaskLID("tenant:acme", tTask)
			return h, &TaskBody{Name: "retry", Status: "active"}
		},
		"checkpoint": func() (Header, any) {
			h := baseHeader(KindCheckpoint, ProvMCPExplicit)
			h.Subj = Subject{TaskID: tTask}
			h.Op = op
			h.LID = CheckpointLID(tKeyID, tTask, tMachine, op)
			return h, &CheckpointBody{Milestone: "tests pass", NextSteps: "ship"}
		},
		"pause": func() (Header, any) {
			h := baseHeader(KindPause, ProvMCPExplicit)
			h.Subj = Subject{TaskID: tTask}
			h.Op = op
			h.LID = PauseLID(tKeyID, tTask, tMachine, op)
			return h, &PauseBody{ResumeContext: "halfway"}
		},
		"call": func() (Header, any) {
			h := baseHeader(KindCall, ProvMCPExplicit)
			h.Op = op
			h.LID = CallLID("m1.k7qz3c7xw2")
			return h, &CallBody{CallRef: "m1.k7qz3c7xw2", ScopeID: "sc1:" + tMachine + ":00112233445566778899aabbccddeeff", Tool: "telara_task_checkpoint", CommitmentDeps: []string{},
				TaskID: tTask, Outcome: "ok"}
		},
		"binding": func() (Header, any) {
			h := baseHeader(KindBinding, ProvDerived)
			h.LID = BindingLID("m1.k7qz3c7xw2")
			return h, &BindingBody{CallRef: "m1.k7qz3c7xw2", Target: &BindTarget{SessionKey: sk}, Confidence: "transcript-echo", Status: "bound"}
		},
		"digest": func() (Header, any) {
			h := baseHeader(KindDigest, ProvDerived)
			h.Subj = Subject{SessionKey: sk}
			h.LID = DigestLID(sk, tMachine)
			h.Links = Links{DerivedFrom: []string{hx("chunk-a")}}
			return h, &DigestBody{HasOutcome: true, Outcome: "fixed"}
		},
		"rollup": func() (Header, any) {
			h := baseHeader(KindRollup, ProvDerived)
			h.Subj = Subject{TaskID: tTask}
			h.LID = RollupLID(tKeyID, tTask, tMachine)
			return h, &RollupBody{Covers: []string{hx("cp-1")}, Text: "merged"}
		},
		"retraction": func() (Header, any) {
			h := baseHeader(KindRetraction, ProvUser)
			lid, _ := ControlLID(KindRetraction, tKeyID, "00112233445566778899aabbccddeeff")
			h.LID = lid
			return h, &RetractionBody{IDs: []string{hx("bad")}, Reason: "redaction_repair"}
		},
		"erasure": func() (Header, any) {
			h := baseHeader(KindErasure, ProvUser)
			lid, _ := ControlLID(KindErasure, tKeyID, "00112233445566778899aabbccddeeff")
			h.LID = lid
			return h, &ErasureBody{EventCoverage: "complete", Selectors: Selectors{Sessions: []string{sk}, Sources: []string{hx("src")}}, Reason: "user_request", Resolved: 212}
		},
		"withdrawal": func() (Header, any) {
			h := baseHeader(KindWithdrawal, ProvUser)
			h.Author.MachineID = ""
			lid, _ := ControlLID(KindWithdrawal, tKeyID, "00112233445566778899aabbccddeeff")
			h.LID = lid
			return h, &WithdrawalBody{Tenant: "acme", PolicySeq: 4, All: true, Reason: "kill_switch"}
		},
		"key_op": func() (Header, any) {
			h := baseHeader(KindKeyOp, ProvUser)
			pub := bytes.Repeat([]byte{9}, 32)
			kid := ContentID(pub)[:32]
			h.Author.KeyID = kid
			h.LID = KeyLID(kid)
			return h, &KeyOpBody{Op: OpGenesis, Subject: KeyRef{KeyID: kid, Alg: "ed25519", Pub: base64.RawURLEncoding.EncodeToString(pub), Role: RoleDevice, MachineID: tMachine}, Genesis: kid}
		},
		"policy": func() (Header, any) {
			h := baseHeader(KindPolicy, ProvUser)
			h.Author.MachineID = ""
			h.LID = PolicyLID("acme")
			return h, &PolicyBody{Tenant: "acme", Seq: 1, IssuedAt: tAt, NotAfter: tAt + 86400000,
				Applies: PolicyApplies{Users: []string{"*"}}}
		},
	}
}

func mustBuild(t *testing.T, name string) *Record {
	t.Helper()
	h, b := fixtures()[name]()
	r, err := Build(h, b)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return r
}

func TestBuildAndParseEveryKind(t *testing.T) {
	seen := map[Kind]bool{}
	for name := range fixtures() {
		r := mustBuild(t, name)
		seen[r.Header.Type] = true
		again, err := Parse(r.HeaderJCS, r.BodyJCS, r.ID)
		if err != nil {
			t.Fatalf("%s: reparse: %v", name, err)
		}
		if again.ID != r.ID || len(r.ID) != 64 {
			t.Fatalf("%s: id changed", name)
		}
		// A purged body keeps the id and still parses.
		if _, err := Parse(r.HeaderJCS, nil, r.ID); err != nil {
			t.Fatalf("%s: header-only parse: %v", name, err)
		}
		if salted(r.Header.Type) {
			if s, _ := saltOf(r.Body); len(s) != 22 {
				t.Fatalf("%s: salt %q", name, s)
			}
		}
	}
	for _, k := range Kinds {
		if !seen[k] {
			t.Errorf("no fixture for kind %s", k)
		}
	}
}

func TestReducersAndClasses(t *testing.T) {
	for _, k := range Kinds {
		if k.Class() == "" {
			t.Errorf("%s has no class", k)
		}
	}
	if ReducerOf(KindConclusion, ProvMCPExplicit) != HeadMulti || ReducerOf(KindConclusion, ProvTranscript) != HeadSingle {
		t.Fatal("conclusion reducers")
	}
	if Kind("bogus").Known() || ReducerOf("bogus", ProvUser) != "" {
		t.Fatal("unknown kind")
	}
}

func TestHAndKeys(t *testing.T) {
	// H is sha256 over the canonical array, checked against a hand-written array.
	if got, want := H("t", "a", "b"), hx(`["mnc1","t","a","b"]`); got != want {
		t.Fatalf("H = %s want %s", got, want)
	}
	g1, _ := SessionKey("codex", "local", NativeGlobal, "u-1", "")
	g2, _ := SessionKey("codex", "local", NativeGlobal, "u-1", tMachine)
	if g1 != g2 {
		t.Fatal("global session key must not depend on the machine")
	}
	l1, _ := SessionKey("aider", "local", NativeLocal, "dir@1", tMachine)
	l2, _ := SessionKey("aider", "local", NativeLocal, "dir@1", tMachine2)
	if l1 == l2 || !IsSessionKey(l1) {
		t.Fatal("local session key must depend on the machine")
	}
	if want := "sk1:" + H("sk1", "aider", "local", tMachine+"/dir@1"); l1 != want {
		t.Fatal("local session key formula")
	}
	bad := []func() error{
		func() error { _, err := SessionKey("", "local", NativeGlobal, "x", ""); return err },
		func() error { _, err := SessionKey("c", "remote", NativeGlobal, "x", ""); return err },
		func() error { _, err := SessionKey("c", "local", NativeLocal, "x", ""); return err },
		func() error { _, err := SessionKey("c", "local", "client-uuid", "x", ""); return err },
		func() error { _, err := RepoID("https://u@github.com/a/b"); return err },
		func() error { _, err := RepoID("github.com/a/b.git"); return err },
		func() error { _, err := RepoIDLocal("nope", "/x"); return err },
		func() error { _, err := SourceKey("c", tMachine, ""); return err },
		func() error { _, err := EventID("sk1:zz", "tool_call", Anchor{NativeItemID: "x"}); return err },
		func() error { _, err := EventID(tSessionKey(), "nope", Anchor{NativeItemID: "x"}); return err },
		func() error { _, err := EventID(tSessionKey(), "tool_call", Anchor{}); return err },
		func() error {
			_, err := EventID(tSessionKey(), "tool_call", Anchor{NativeItemID: "x", Line: 2})
			return err
		},
		func() error {
			_, err := EventID(tSessionKey(), "tool_call", Anchor{NativeItemID: "x", Inner: -1})
			return err
		},
		func() error { _, err := OpID("", "r", "t", hx("a")); return err },
		func() error { _, err := RequestIdentityMeta("has space"); return err },
		func() error { _, err := RequestIdentityRPC("c1", []byte(`{"a":1}`)); return err },
		func() error {
			_, err := ControlLID(KindSession, tKeyID, "00112233445566778899aabbccddeeff")
			return err
		},
		func() error { _, err := ControlLID(KindErasure, tKeyID, "short"); return err },
	}
	for i, f := range bad {
		if f() == nil {
			t.Errorf("case %d accepted", i)
		}
	}
	r, _ := RepoID("github.com/acme/api")
	if r != "r1:"+hx("github.com/acme/api") {
		t.Fatal("repo id formula")
	}
	rl, _ := RepoIDLocal(tMachine, "/home/u/x")
	if rl != "r1l:"+H("r1l", tMachine, "/home/u/x") {
		t.Fatal("local repo id formula")
	}
	a, _ := EventID(tSessionKey(), "tool_call", Anchor{NativeItemID: "call_1", Inner: 0})
	b, _ := EventID(tSessionKey(), "tool_call", Anchor{NativeItemID: "call_1", Inner: 1})
	c, _ := EventID(tSessionKey(), "tool_call", Anchor{Path: "~/.codex/x.jsonl", Line: 4, Inner: 1})
	if a == b || b == c || !IsEventID(a) {
		t.Fatal("inner ordinals and forms must give distinct event ids")
	}
	if a != "ev1:"+H("ev1", tSessionKey(), "tool_call", `{"inner":0,"native_item_id":"call_1","part":0}`) {
		t.Fatal("event id formula")
	}
	cr, err := newCallRef(bytes.NewReader([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}))
	if err != nil || !IsCallRef(cr) || cr != "m1.7777777777" {
		t.Fatalf("call ref %q %v", cr, err)
	}
	if _, err := RequestIdentityRPC("conn", []byte(`"candidate"`)); err == nil {
		t.Fatal("raw RPC retained")
	}
	if ValidCallerOpID(strings.Repeat("a", 129)) || !ValidCallerOpID("op1:00112233445566778899aabbccddeeff") {
		t.Fatal("caller token syntax")
	}

}

func TestSalt(t *testing.T) {
	if _, err := Salt(tSaltKey, KindConclusion, hx("l"), []byte(`{"text":"guess"}`)); err == nil {
		t.Fatal("retired deterministic salt API")
	}
	a, b := mustBuild(t, "conclusion-explicit"), mustBuild(t, "conclusion-explicit")
	if a.ID == b.ID || a.Header.Body.Digest == b.Header.Body.Digest {
		t.Fatal("fresh same-LID seal reproduced erased candidate verifier")
	}
}

// raw marshals a header and body without validation, filling the body ref.
func raw(t *testing.T, h Header, body any) ([]byte, []byte) {
	t.Helper()
	bj, err := jcs.MarshalRecord(body)
	if err != nil {
		t.Fatal(err)
	}
	h.V = Version
	if h.Body == nil {
		h.Body = &BodyRef{Digest: BodyDigest(bj), Size: int64(len(bj))}
	}
	hj, err := jcs.MarshalRecord(&h)
	if err != nil {
		t.Fatal(err)
	}
	return hj, bj
}

func TestParseRejections(t *testing.T) {
	type mut func(h *Header, b any) ([]byte, []byte, string)
	fx := fixtures()
	cases := []struct {
		name, fixture, code string
		quarantine          bool
		f                   func(t *testing.T, h Header, b any) ([]byte, []byte, string)
	}{
		{"header too large", "task", CodeTooLarge, false, func(t *testing.T, h Header, b any) ([]byte, []byte, string) {
			b.(*TaskBody).Salt = "AAAAAAAAAAAAAAAAAAAAAA"
			hj, bj := raw(t, h, b)
			return append(hj[:len(hj)-1], []byte(`,"x":"`+strings.Repeat("a", MaxHeaderBytes)+`"}`)...), bj, ""
		}},
		{"body too large", "rollup", CodeTooLarge, false, func(t *testing.T, h Header, b any) ([]byte, []byte, string) {
			b.(*RollupBody).Text = strings.Repeat("a", MaxBodyBytes)
			hj, bj := raw(t, h, b)
			return hj, bj, ""
		}},
		{"whitespace", "task", CodeNotCanonical, false, func(t *testing.T, h Header, b any) ([]byte, []byte, string) {
			hj, bj := raw(t, h, b)
			return append([]byte(" "), hj...), bj, ""
		}},
		{"key order", "task", CodeNotCanonical, false, func(t *testing.T, h Header, b any) ([]byte, []byte, string) {
			hj, bj := raw(t, h, b)
			return bytes.Replace(hj, []byte(`{"at"`), []byte(`{"zz":1,"at"`), 1), bj, ""
		}},
		{"trailing data", "task", CodeNotCanonical, false, func(t *testing.T, h Header, b any) ([]byte, []byte, string) {
			hj, bj := raw(t, h, b)
			return append(hj, 'x'), bj, ""
		}},
		{"null", "task", CodeNotCanonical, false, func(t *testing.T, h Header, b any) ([]byte, []byte, string) {
			hj, bj := raw(t, h, b)
			return bytes.Replace(hj, []byte(`"op":`), []byte(`"nul":null,"op":`), 1), bj, ""
		}},
		{"version 4 quarantined", "task", CodeUnsupportedVersion, true, func(t *testing.T, h Header, b any) ([]byte, []byte, string) {
			hj, bj := raw(t, h, b)
			return bytes.Replace(hj, []byte(`"v":3`), []byte(`"v":4`), 1), bj, ""
		}},
		{"version 0", "task", CodeUnsupportedVersion, false, func(t *testing.T, h Header, b any) ([]byte, []byte, string) {
			hj, bj := raw(t, h, b)
			return bytes.Replace(hj, []byte(`"v":3`), []byte(`"v":0`), 1), bj, ""
		}},
		{"unknown header field", "task", CodeUnknownField, false, func(t *testing.T, h Header, b any) ([]byte, []byte, string) {
			hj, bj := raw(t, h, b)
			hj = bytes.Replace(hj, []byte(`"type"`), []byte(`"title":"x","type"`), 1)
			hj, _ = jcs.CanonicalizeRecord(hj)
			return hj, bj, ""
		}},
		{"member name case", "task", CodeNotCanonical, false, func(t *testing.T, h Header, b any) ([]byte, []byte, string) {
			hj, bj := raw(t, h, b)
			return bytes.Replace(hj, []byte(`"type"`), []byte(`"Type"`), 1), bj, ""
		}},
		{"empty field written", "task", CodeNotCanonical, false, func(t *testing.T, h Header, b any) ([]byte, []byte, string) {
			hj, bj := raw(t, h, b)
			return bytes.Replace(hj, []byte(`"prov"`), []byte(`"links":{},"prov"`), 1), bj, ""
		}},
		{"zero written", "task", CodeNotCanonical, false, func(t *testing.T, h Header, b any) ([]byte, []byte, string) {
			hj, bj := raw(t, h, b)
			return bytes.Replace(hj, []byte(`"epoch":7`), []byte(`"epoch":7,"findings":0`), 1), bj, ""
		}},
		{"advisory id", "task", CodeIDMismatch, false, func(t *testing.T, h Header, b any) ([]byte, []byte, string) {
			hj, bj := raw(t, h, b)
			return hj, bj, hx("other")
		}},
		{"body digest", "task", CodeBodyMismatch, false, func(t *testing.T, h Header, b any) ([]byte, []byte, string) {
			h.Body = &BodyRef{Digest: hx("x"), Size: 10}
			hj, bj := raw(t, h, b)
			return hj, bj, ""
		}},
		{"body non-canonical", "task", CodeNotCanonical, false, func(t *testing.T, h Header, b any) ([]byte, []byte, string) {
			bj := []byte(`{"status":"active", "salt":"AAAAAAAAAAAAAAAAAAAAAA"}`)
			h.Body = &BodyRef{Digest: BodyDigest(bj), Size: int64(len(bj))}
			hj, _ := raw(t, h, b)
			return hj, bj, ""
		}},
		{"body float", "task", CodeNotCanonical, false, func(t *testing.T, h Header, b any) ([]byte, []byte, string) {
			bj := []byte(`{"n":1.5,"salt":"AAAAAAAAAAAAAAAAAAAAAA","status":"active"}`)
			h.Body = &BodyRef{Digest: BodyDigest(bj), Size: int64(len(bj))}
			hj, _ := raw(t, h, b)
			return hj, bj, ""
		}},
		{"body member case", "task", CodeInvalidBody, false, func(t *testing.T, h Header, b any) ([]byte, []byte, string) {
			bj := []byte(`{"STATUS":"active","salt":"AAAAAAAAAAAAAAAAAAAAAA"}`)
			h.Body = &BodyRef{Digest: BodyDigest(bj), Size: int64(len(bj))}
			hj, _ := raw(t, h, b)
			return hj, bj, ""
		}},
		{"unknown kind quarantined", "task", CodeUnknownKind, true, func(t *testing.T, h Header, b any) ([]byte, []byte, string) {
			h.Type = "note"
			hj, bj := raw(t, h, b)
			return hj, bj, ""
		}},
		{"lid mismatch", "digest", CodeLIDMismatch, false, func(t *testing.T, h Header, b any) ([]byte, []byte, string) {
			h.LID = hx("wrong")
			b.(*DigestBody).Salt = "AAAAAAAAAAAAAAAAAAAAAA"
			hj, bj := raw(t, h, b)
			return hj, bj, ""
		}},
		{"reserved profile", "task", CodeProfileNotAllowed, false, func(t *testing.T, h Header, b any) ([]byte, []byte, string) {
			h.Red.Profile = "push-conclusions"
			hj, bj := raw(t, h, b)
			return hj, bj, ""
		}},
		{"unknown profile", "task", CodeProfileNotAllowed, false, func(t *testing.T, h Header, b any) ([]byte, []byte, string) {
			h.Red.Profile = "public"
			hj, bj := raw(t, h, b)
			return hj, bj, ""
		}},
		{"push-metadata on a source record", "task", CodeProfileNotAllowed, false, func(t *testing.T, h Header, b any) ([]byte, []byte, string) {
			h.Red.Profile = ProfilePushMetadata
			hj, bj := raw(t, h, b)
			return hj, bj, ""
		}},
		{"export without origin", "task-meta", CodeInvalidHeader, false, func(t *testing.T, h Header, b any) ([]byte, []byte, string) {
			h.Links.Origin = ""
			hj, bj := raw(t, h, b)
			return hj, bj, ""
		}},
		{"export body extra field", "task-meta", CodeInvalidBody, false, func(t *testing.T, h Header, b any) ([]byte, []byte, string) {
			bj := []byte(`{"name":"secret","salt":"AAAAAAAAAAAAAAAAAAAAAA","status":"active"}`)
			h.Body = &BodyRef{Digest: BodyDigest(bj), Size: int64(len(bj))}
			hj, _ := raw(t, h, b)
			return hj, bj, ""
		}},
		{"prov not allowed", "call", CodeProvNotAllowed, false, func(t *testing.T, h Header, b any) ([]byte, []byte, string) {
			h.Prov = ProvTranscript
			h.Op = ""
			hj, bj := raw(t, h, b)
			return hj, bj, ""
		}},
		{"taint unsorted", "task", CodeInvalidHeader, false, func(t *testing.T, h Header, b any) ([]byte, []byte, string) {
			h.Trust.Taint = []string{"web", "foreign-path"}
			hj, bj := raw(t, h, b)
			return hj, bj, ""
		}},
		{"taint unknown", "task", CodeInvalidHeader, false, func(t *testing.T, h Header, b any) ([]byte, []byte, string) {
			h.Trust.Taint = []string{"cosmic"}
			hj, bj := raw(t, h, b)
			return hj, bj, ""
		}},
		{"op missing", "task", CodeInvalidHeader, false, func(t *testing.T, h Header, b any) ([]byte, []byte, string) {
			h.Op = ""
			hj, bj := raw(t, h, b)
			return hj, bj, ""
		}},
		{"op on transcript", "session", CodeInvalidHeader, false, func(t *testing.T, h Header, b any) ([]byte, []byte, string) {
			h.Op = hx("op")
			hj, bj := raw(t, h, b)
			return hj, bj, ""
		}},
		{"control with links", "erasure", CodeInvalidHeader, false, func(t *testing.T, h Header, b any) ([]byte, []byte, string) {
			h.Links.Supersedes = []string{hx("a")}
			hj, bj := raw(t, h, b)
			return hj, bj, ""
		}},
		{"session without machine", "session", CodeInvalidHeader, false, func(t *testing.T, h Header, b any) ([]byte, []byte, string) {
			h.Author.MachineID = ""
			hj, bj := raw(t, h, b)
			return hj, bj, ""
		}},
		{"machine not uuid", "session", CodeInvalidHeader, false, func(t *testing.T, h Header, b any) ([]byte, []byte, string) {
			h.Author.MachineID = "MACHINE"
			hj, bj := raw(t, h, b)
			return hj, bj, ""
		}},
		{"salt missing", "task", CodeInvalidBody, false, func(t *testing.T, h Header, b any) ([]byte, []byte, string) {
			hj, bj := raw(t, h, b)
			return hj, bj, ""
		}},
		{"too many chunk events", "chunk", CodeListTooLong, false, func(t *testing.T, h Header, b any) ([]byte, []byte, string) {
			c := b.(*ChunkBody)
			c.Salt = "AAAAAAAAAAAAAAAAAAAAAA"
			for i := int64(2); i <= MaxChunkEvents; i++ {
				c.Events = append(c.Events, Event{ID: tEvent(i), Seq: i, Kind: "assistant_text", Prov: "hook"})
			}
			hj, bj := raw(t, h, b)
			return hj, bj, ""
		}},
		{"too many snapshot chunks", "session", CodeInvalidBody, false, func(t *testing.T, h Header, b any) ([]byte, []byte, string) {
			s := b.(*SessionBody)
			s.Salt = "AAAAAAAAAAAAAAAAAAAAAA"
			s.Chunks = nil
			for i := 0; i <= MaxSnapshotChunks; i++ {
				s.Chunks = append(s.Chunks, hx(fmt.Sprint(i)))
			}
			hj, bj := raw(t, h, b)
			return hj, bj, ""
		}},
		{"too many retraction ids", "retraction", CodeListTooLong, false, func(t *testing.T, h Header, b any) ([]byte, []byte, string) {
			r := b.(*RetractionBody)
			for i := 0; i < MaxRetractionIDs; i++ {
				r.IDs = append(r.IDs, hx(fmt.Sprint(i)))
			}
			hj, bj := raw(t, h, b)
			return hj, bj, ""
		}},
		{"too many erasure selectors", "erasure", CodeListTooLong, false, func(t *testing.T, h Header, b any) ([]byte, []byte, string) {
			e := b.(*ErasureBody)
			for i := 0; i < MaxErasureEntries; i++ {
				e.Selectors.IDs = append(e.Selectors.IDs, hx(fmt.Sprint(i)))
			}
			hj, bj := raw(t, h, b)
			return hj, bj, ""
		}},
		{"too many meta pointers", "session-meta", CodeListTooLong, false, func(t *testing.T, h Header, b any) ([]byte, []byte, string) {
			m := b.(*SessionMetaBody)
			m.Salt = "AAAAAAAAAAAAAAAAAAAAAA"
			for i := 0; i < MaxMetaPointers; i++ {
				m.Pointers = append(m.Pointers, MetaPointer{Tool: "read"})
			}
			hj, bj := raw(t, h, b)
			return hj, bj, ""
		}},
		{"source and prov disagree", "conclusion-request", CodeInvalidBody, false, func(t *testing.T, h Header, b any) ([]byte, []byte, string) {
			c := b.(*ConclusionBody)
			c.Salt = "AAAAAAAAAAAAAAAAAAAAAA"
			c.Source = "hook-final"
			hj, bj := raw(t, h, b)
			return hj, bj, ""
		}},
		{"binding target without bound", "binding", CodeInvalidBody, false, func(t *testing.T, h Header, b any) ([]byte, []byte, string) {
			b.(*BindingBody).Status = "ambiguous"
			hj, bj := raw(t, h, b)
			return hj, bj, ""
		}},
		{"events out of order", "chunk", CodeInvalidBody, false, func(t *testing.T, h Header, b any) ([]byte, []byte, string) {
			c := b.(*ChunkBody)
			c.Salt = "AAAAAAAAAAAAAAAAAAAAAA"
			c.Events[1].Seq = 0
			hj, bj := raw(t, h, b)
			return hj, bj, ""
		}},
		{"session end without time", "session", CodeInvalidBody, false, func(t *testing.T, h Header, b any) ([]byte, []byte, string) {
			s := b.(*SessionBody)
			s.Salt = "AAAAAAAAAAAAAAAAAAAAAA"
			s.End = "idle"
			hj, bj := raw(t, h, b)
			return hj, bj, ""
		}},
		{"retraction reason", "retraction", CodeInvalidBody, false, func(t *testing.T, h Header, b any) ([]byte, []byte, string) {
			b.(*RetractionBody).Reason = "because"
			hj, bj := raw(t, h, b)
			return hj, bj, ""
		}},
		{"withdrawal all and selectors", "withdrawal", CodeInvalidBody, false, func(t *testing.T, h Header, b any) ([]byte, []byte, string) {
			b.(*WithdrawalBody).IDs = []string{hx("a")}
			hj, bj := raw(t, h, b)
			return hj, bj, ""
		}},
		{"key op parents on genesis", "key_op", CodeInvalidBody, false, func(t *testing.T, h Header, b any) ([]byte, []byte, string) {
			b.(*KeyOpBody).Parents = []string{hx("p")}
			hj, bj := raw(t, h, b)
			return hj, bj, ""
		}},
		{"pol malformed", "task", CodeInvalidHeader, false, func(t *testing.T, h Header, b any) ([]byte, []byte, string) {
			h.Pol = "policy-1"
			hj, bj := raw(t, h, b)
			return hj, bj, ""
		}},
		{"withdrawal too many ids", "withdrawal", CodeListTooLong, false, func(t *testing.T, h Header, b any) ([]byte, []byte, string) {
			w := b.(*WithdrawalBody)
			w.All = false
			for i := 0; i <= MaxRetractionIDs; i++ {
				w.IDs = append(w.IDs, hx(fmt.Sprint(i)))
			}
			hj, bj := raw(t, h, b)
			return hj, bj, ""
		}},
		{"key op unsupported", "key_op", CodeInvalidBody, false, func(t *testing.T, h Header, b any) ([]byte, []byte, string) {
			b.(*KeyOpBody).Op = "genesis_successor"
			hj, bj := raw(t, h, b)
			return hj, bj, ""
		}},
		{"policy lifetime", "policy", CodeInvalidBody, false, func(t *testing.T, h Header, b any) ([]byte, []byte, string) {
			p := b.(*PolicyBody)
			p.NotAfter = p.IssuedAt + PolicyMaxLifetimeMs + 1
			hj, bj := raw(t, h, b)
			return hj, bj, ""
		}},
		{"policy unknown field", "policy", CodeInvalidBody, false, func(t *testing.T, h Header, b any) ([]byte, []byte, string) {
			p := b.(*PolicyBody)
			bj, _ := jcs.MarshalRecord(p)
			bj = bytes.Replace(bj, []byte(`{"applies"`), []byte(`{"allow_everything":true,"applies"`), 1)
			h.Body = &BodyRef{Digest: BodyDigest(bj), Size: int64(len(bj))}
			hj, _ := raw(t, h, b)
			return hj, bj, ""
		}},
	}
	_ = mut(nil)
	for _, c := range cases {
		h, b := fx[c.fixture]()
		hj, bj, want := c.f(t, h, b)
		_, err := Parse(hj, bj, want)
		if CodeOf(err) != c.code {
			t.Errorf("%s: want %s, got %v", c.name, c.code, err)
			continue
		}
		if e := err.(*Error); e.Quarantine != c.quarantine {
			t.Errorf("%s: quarantine %v", c.name, e.Quarantine)
		}
	}
}

func TestUnknownBodyFieldRejected(t *testing.T) {
	h, b := fixtures()["rollup"]()
	b.(*RollupBody).Salt = "AAAAAAAAAAAAAAAAAAAAAA"
	hj, bj := raw(t, h, b)
	bj = bytes.Replace(bj, []byte(`"text":`), []byte(`"unknown":"private","text":`), 1)
	h.Body = &BodyRef{Digest: BodyDigest(bj), Size: int64(len(bj))}
	hj, _ = jcs.MarshalRecord(h)
	if _, err := Parse(hj, bj, ""); err == nil {
		t.Fatal("unknown body field silently discarded")
	}
}
