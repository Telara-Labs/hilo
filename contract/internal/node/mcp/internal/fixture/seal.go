package fixture

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"sync"

	tapredact "github.com/Telara-Labs/TAP-Runtime/discover/redact"
	contract "github.com/Telara-Labs/telara-memory/contract"
	"github.com/Telara-Labs/telara-memory/contract/jcs"
	"github.com/Telara-Labs/telara-memory/contract/record"
	"github.com/Telara-Labs/telara-memory/contract/sig"
)

// Sealer holds only preloaded key material. It never installs keys, uses a file
// fallback, or performs OS key-store IO inside a writer transaction. The real
// store must independently verify its current enrollment and policy authority.
type Sealer struct {
	mu                    sync.Mutex
	owner, machine, keyID string
	salt                  [32]byte
	private               [64]byte
	rules                 record.Ruleset
	valid                 bool
}
type actualRedactor struct{}

func (actualRedactor) Redact(s string) string                  { return tapredact.Redact(s) }
func (actualRedactor) Argument(k, s string) string             { return tapredact.Argument(k, s) }
func (actualRedactor) Profiles() []string                      { return nil }
func (actualRedactor) RedactProfile(_ string, s string) string { return tapredact.Redact(s) }
func NewSealer(owner, machine string, salt []byte, key ed25519.PrivateKey) (*Sealer, error) {
	if !record.IsKeyID(owner) || !record.IsUUIDv4(machine) || len(salt) != 32 || len(key) != 64 {
		return nil, errors.New("key_material_unavailable")
	}
	checked := ed25519.NewKeyFromSeed(key[:32])
	defer clear(checked)
	if !bytes.Equal(checked, key) {
		return nil, errors.New("key_material_unavailable")
	}
	corpus, e := record.ParseCorpus(contract.RedactionCorpusV1())
	if e != nil {
		return nil, errors.New("ruleset_unavailable")
	}
	behavior, e := record.Behavior(corpus, actualRedactor{})
	if e != nil {
		return nil, errors.New("ruleset_unavailable")
	}
	upstream := tapredact.CurrentRuleset()
	s := &Sealer{owner: owner, machine: machine, keyID: sig.KeyID(key.Public().(ed25519.PublicKey)), valid: true, rules: record.Ruleset{Epoch: upstream.Epoch, Digest: upstream.Digest, Behavior: behavior, Engine: "tap-discover/cd7b481855de"}}
	var golden record.Ruleset
	if json.Unmarshal(contract.RedactionGoldenV1(), &golden) != nil || golden != s.rules {
		return nil, errors.New("ruleset_unavailable")
	}
	copy(s.salt[:], salt)
	copy(s.private[:], key)
	return s, nil
}

// Clear erases this owned copy. It cannot guarantee zeroization of caller or
// compiler copies. Existing Sealed records contain no private or salt keys.
func (s *Sealer) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	clear(s.private[:])
	clear(s.salt[:])
	s.valid = false
}

// Sealed can be constructed only by this producer. Envelope returns detached
// bytes suitable for conversion to the committed store.SignedRecord API.
type Sealed struct {
	header, body []byte
	signatures   []record.Signature
	id           string
}

func (s Sealed) Envelope() (header, body []byte, signatures []record.Signature, id string) {
	return append([]byte(nil), s.header...), append([]byte(nil), s.body...), append([]record.Signature(nil), s.signatures...), s.id
}
func (s *Sealer) Mutation(call Call, m Mutation, at int64, heads []string) (Sealed, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if call.Access.PolicyID != "" {
		return Sealed{}, errors.New("policy_unavailable")
	}
	if !s.valid || call.Access.Owner != s.owner || call.Access.MachineID != s.machine {
		return Sealed{}, errors.New("key_material_unavailable")
	}
	clean := redactObject(m.Fields)
	f := boundObject(clean)
	var body any
	var lid string
	switch m.Kind {
	case "task":
		anchors := &record.Anchors{}
		if a, ok := f["anchors"].(map[string]any); ok {
			anchors.Files = stringsValue(a, "file_paths")
			for _, k := range []string{"repo", "branch", "ticket_id"} {
				if v := stringValue(a, k); v != "" {
					anchors.Refs = append(anchors.Refs, k+"="+v)
				}
			}
		}
		if len(anchors.Files)+len(anchors.Commits)+len(anchors.Refs) == 0 {
			anchors = nil
		}
		body = &record.TaskBody{Name: boundText(stringValue(f, "name"), 100), Goal: stringValue(f, "goal"), Anchors: anchors, Status: "active"}
		lid = record.TaskLID(s.owner, m.TaskID)
	case "checkpoint":
		// Preserve hosted structured sections in the sealed milestone. The current
		// contract's Step has no detail slot; the full task_tree is retained here.
		milestone := stringValue(f, "milestone")
		for _, key := range []string{"decisions", "blocked", "in_progress", "done", "constraints", "critical_context", "resources", "task_tree"} {
			if value, ok := f[key]; ok {
				data, e := jcs.MarshalRecord(value)
				if e != nil {
					return Sealed{}, errors.New("invalid_arguments")
				}
				milestone += "\n" + key + "\n" + string(data)
			}
		}
		body = &record.CheckpointBody{Milestone: milestone, NextSteps: stringValue(f, "next_steps"), KnowledgeRefs: stringsValue(f, "knowledge_refs")}
		lid = record.CheckpointLID(s.owner, m.TaskID, s.machine, call.Op)
	case "pause":
		body = &record.PauseBody{ResumeContext: stringValue(f, "resume_context"), ProgressNotes: stringValue(f, "progress_notes"), HandoffHint: stringValue(f, "handoff_hint"), TokenEstimate: estimate(f)}
		lid = record.PauseLID(s.owner, m.TaskID, s.machine, call.Op)
	case "conclusion":
		body = &record.ConclusionBody{Source: "explicit", State: "answered", Text: stringValue(f, "final_summary"), ChangesMade: stringsValue(f, "changes_made"), TokenEstimate: estimate(f)}
		lid = record.ExplicitConclusionLID(s.owner, m.TaskID)
	default:
		return Sealed{}, errors.New("unsupported_tool")
	}
	before, _ := json.Marshal(m.Fields)
	after, _ := json.Marshal(clean)
	findings := call.RedactionFindings
	if !bytes.Equal(before, after) {
		findings++
	}
	return s.build(call, m.TaskID, record.Kind(m.Kind), record.ProvMCPExplicit, lid, body, at, heads, findings)
}
func estimate(f map[string]any) *int64 {
	if n, ok := f["token_estimate"].(float64); ok {
		v := int64(n)
		return &v
	}
	return nil
}
func (s *Sealer) Receipt(call Call, ref, task string, res Result, at int64) (Sealed, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if call.Access.PolicyID != "" {
		return Sealed{}, errors.New("policy_unavailable")
	}
	if !s.valid || call.Access.Owner != s.owner || call.Access.MachineID != s.machine {
		return Sealed{}, errors.New("key_material_unavailable")
	}
	// Only the redacted canonical representation enters result hashing.
	var detached map[string]any
	raw, e := json.Marshal(res)
	if e != nil {
		return Sealed{}, errors.New("render_unavailable")
	}
	if json.Unmarshal(raw, &detached) != nil {
		return Sealed{}, errors.New("render_unavailable")
	}
	clean, e := jcs.MarshalRecord(redactObject(detached))
	if e != nil {
		return Sealed{}, errors.New("render_unavailable")
	}
	outcome := "ok"
	if res.IsError {
		outcome = "error"
	}
	scope := call.Access.ScopeID
	if scope == "" {
		scope = record.H("unidentified-call", ref)
	}
	scope = "sc1:" + s.machine + ":" + record.H("fixture-scope", scope)[:32]
	body := &record.CallBody{CallRef: ref, ScopeID: scope, Tool: call.Tool, TaskID: task, Outcome: outcome, CommitmentDeps: []string{}}
	if res.IsError {
		body.Err = "unavailable"
	}
	_ = clean
	return s.build(call, task, record.KindCall, record.ProvMCPExplicit, record.CallLID(ref), body, at, nil, call.RedactionFindings)
}
func (s *Sealer) build(call Call, task string, kind record.Kind, prov record.Prov, lid string, body any, at int64, heads []string, findings int) (Sealed, error) {
	h := record.Header{Type: kind, LID: lid, At: at, Author: record.Author{MachineID: s.machine, KeyID: s.keyID}, Prov: prov, Subj: record.Subject{TaskID: task, RepoID: call.Access.RepoID, SessionKey: call.Access.SessionKey, Client: &record.ClientRef{ID: call.Access.Client}}, Op: call.Op, Red: record.Redact{Profile: record.ProfileLocal, Epoch: s.rules.Epoch, Fingerprint: s.rules.Fingerprint(), Findings: findings}, Trust: record.Trust{Coverage: "incomplete", Taint: []string{"taint-unknown"}}, Links: record.Links{Supersedes: append([]string(nil), heads...)}}
	var r *record.Record
	var e error
	if cb, ok := body.(*record.CallBody); ok {
		r, e = record.BuildCall(h, *cb, nil, nil)
	} else {
		r, e = record.Build(h, body)
	}
	if e != nil {
		return Sealed{}, e
	}
	signature, e := sig.SignRecord(ed25519.PrivateKey(s.private[:]), r.ID)
	if e != nil {
		return Sealed{}, e
	}
	return Sealed{r.HeaderJCS, r.BodyJCS, []record.Signature{signature}, r.ID}, nil
}
