// Package teststore is a deliberately nonpersistent test double. It does not
// implement cryptographic Seal, SQLite, real grants, hook/spool capture or sync.
// It must never be registered by the shipped command.
package teststore

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"sync"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/ipc"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/mcp"
	"github.com/Telara-Labs/telara-memory/contract/record"
	"github.com/Telara-Labs/telara-memory/contract/replay"
)

const Owner = "0123456789abcdef0123456789abcdef"
const Machine = "12345678-1234-4234-8234-123456789abc"

type outcome struct {
	call    mcp.Call
	result  mcp.Result
	deps    []string
	version int
}
type Source struct {
	Access     mcp.Access
	Signals    []mcp.Announcement
	Dead       map[ipc.Proc]bool
	DrainError bool
	Drains     int
}

func (s *Source) Authenticate(context.Context, ipc.Hello) (mcp.Access, error) { return s.Access, nil }
func (s *Source) Drain(context.Context, string) ([]mcp.Announcement, error) {
	s.Drains++
	if s.DrainError {
		return nil, errors.New("spool_error")
	}
	return s.Signals, nil
}
func (s *Source) Alive(p ipc.Proc) bool { return !s.Dead[p] }
func Access() mcp.Access {
	return mcp.Access{CredentialID: "installed-fixture", Client: "fixture", MachineID: Machine, Owner: Owner, ScopeID: "fixture-scope"}
}

// Resolver uses a fixed test installation while still resolving each request.
// A fresh Source per request avoids sharing mutable hook fixture state.
type Resolver struct{}

func (Resolver) Resolve(ctx context.Context, h ipc.Hello, m mcp.Metadata) (mcp.Access, error) {
	return (mcp.IdentityResolver{Source: &Source{Access: Access()}}).Resolve(ctx, h, m)
}

type Store struct {
	Sealer                              *mcp.Sealer
	Sealed                              []mcp.Sealed
	mu                                  sync.Mutex
	Rows                                []mcp.Item
	Mutations                           []mcp.Mutation
	Calls                               []mcp.Call
	Exposures                           [][]string
	FailItems, FailAppend, FailExposure bool
	Denied                              bool
	Collisions                          int
	Version                             int
	AllowedOwners                       map[string]bool
	ops                                 map[string]outcome
	refs                                map[string]bool
	seq                                 int64
}

func New() *Store {
	sealer, e := mcp.NewSealer(Owner, Machine, bytes.Repeat([]byte{1}, 32), ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, 32)))
	if e != nil {
		panic(e)
	}
	return &Store{Sealer: sealer, ops: map[string]outcome{}, refs: map[string]bool{}, AllowedOwners: map[string]bool{Owner: true}, Version: 1}
}
func (s *Store) Close() error { s.Sealer.Clear(); return nil }
func (s *Store) Add(items ...mcp.Item) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Rows = append(s.Rows, items...)
}
func (s *Store) Snapshot() ([]mcp.Item, int, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]mcp.Item(nil), s.Rows...), len(s.Mutations), len(s.Exposures)
}

// Audit returns detached immutable call/sealing evidence for transport tests.
func (s *Store) Audit() ([]mcp.Call, []mcp.Sealed) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]mcp.Call(nil), s.Calls...), append([]mcp.Sealed(nil), s.Sealed...)
}
func (s *Store) Change(version int, denied bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Version = version
	s.Denied = denied
}
func (s *Store) Execute(ctx context.Context, call mcp.Call, run func(mcp.Transaction) (mcp.Result, error)) (mcp.Result, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return mcp.Result{}, err
	}
	if old, ok := s.ops[call.Op]; ok {
		if old.call.Tool != call.Tool || old.call.ArgsHash != call.ArgsHash {
			return mcp.Result{}, errors.New("op_conflict")
		}
		eligible := !s.Denied && old.version == s.Version
		for _, dep := range old.deps {
			found := false
			for _, row := range s.Rows {
				if dep == row.LID+"@"+row.ID && row.State == "live" && s.AllowedOwners[row.Owner] {
					found = true
				}
			}
			eligible = eligible && found
		}
		if !eligible {
			return mcp.Result{Content: []mcp.Content{{Type: "text", Text: replay.Unavailable}}}, nil
		}
		return old.result, nil
	}
	if s.Denied {
		return mcp.Result{}, errors.New("not_found")
	}
	// Deep copy the transaction fixture. Failed exposure cannot leak a mutation.
	rows, _ := json.Marshal(s.Rows)
	var copied []mcp.Item
	_ = json.Unmarshal(rows, &copied)
	tx := &transaction{s: s, call: call, rows: copied, seq: s.seq, refs: map[string]bool{}}
	res, err := run(tx)
	if err != nil {
		return mcp.Result{}, err
	}
	var ref string
	for key := range tx.refs {
		ref = key
	}
	task := ""
	if len(tx.mutations) > 0 {
		task = tx.mutations[len(tx.mutations)-1].TaskID
	} else {
		var args map[string]any
		_ = json.Unmarshal(call.Arguments, &args)
		task, _ = args["task_id"].(string)
	}
	receipt, e := s.Sealer.Receipt(call, ref, task, res, tx.seq+1)
	if e != nil {
		return mcp.Result{}, e
	}
	s.Sealed = append(s.Sealed, tx.sealed...)
	s.Sealed = append(s.Sealed, receipt)
	s.Rows = tx.rows
	s.seq = tx.seq
	s.Mutations = append(s.Mutations, tx.mutations...)
	s.Calls = append(s.Calls, call)
	s.Exposures = append(s.Exposures, tx.exposures...)
	for ref := range tx.refs {
		s.refs[ref] = true
	}
	s.ops[call.Op] = outcome{call, res, tx.deps, s.Version}
	return res, nil
}

type transaction struct {
	call      mcp.Call
	sealed    []mcp.Sealed
	s         *Store
	rows      []mcp.Item
	seq       int64
	mutations []mcp.Mutation
	exposures [][]string
	deps      []string
	refs      map[string]bool
}

func (t *transaction) ReserveCallRef(ref string) (bool, error) {
	if t.s.Collisions > 0 {
		t.s.Collisions--
		return false, nil
	}
	if t.s.refs[ref] || t.refs[ref] {
		return false, nil
	}
	t.refs[ref] = true
	return true, nil
}
func (t *transaction) Exposure(ref, nonce string, items []string) error {
	if t.s.FailExposure {
		return errors.New("private exposure error")
	}
	t.exposures = append(t.exposures, append([]string(nil), items...))
	t.deps = append(t.deps, items...)
	return nil
}
func (t *transaction) Items(q mcp.Query) ([]mcp.Item, error) {
	if t.s.FailItems {
		return nil, errors.New("private SQLite failure")
	}
	var out []mcp.Item
	for _, row := range t.rows {
		if !t.s.AllowedOwners[row.Owner] || row.State != "live" {
			continue
		}
		if q.TaskID != "" {
			if row.TaskID == q.TaskID {
				out = append(out, row)
			}
			continue
		}
		if q.Tool == "telara_task_list" {
			if row.Kind != "task" || !q.IncludeCompleted && row.Fields["status"] != "active" && row.Fields["status"] != "paused" {
				continue
			}
			if !matches(row, q.Text) {
				continue
			}
			out = append(out, row)
			continue
		}
		if q.EntityID != "" {
			if row.ID == q.EntityID && row.Kind == q.EntityType {
				out = append([]mcp.Item{row}, out...)
			}
			continue
		}
		if len(q.Kinds) > 0 {
			found := false
			for _, kind := range q.Kinds {
				if row.Kind == kind {
					found = true
				}
			}
			if !found {
				continue
			}
		}
		if !matches(row, q.Text) {
			continue
		}
		out = append(out, row)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Order > out[j].Order })
	return out, nil
}
func matches(row mcp.Item, q string) bool {
	if q == "" {
		return true
	}
	for _, v := range row.Fields {
		if strings.Contains(strings.ToLower(v), strings.ToLower(q)) {
			return true
		}
	}
	return false
}
func (t *transaction) Append(m mcp.Mutation) (mcp.Item, error) {
	if t.s.FailAppend {
		return mcp.Item{}, errors.New("private signer failure")
	}
	t.seq++
	var heads []string
	for _, row := range t.rows {
		if row.Owner == Owner && row.TaskID == m.TaskID && row.Kind == m.Kind {
			heads = append(heads, row.ID)
		}
	}
	sealed, e := t.s.Sealer.Mutation(t.call, m, t.seq, heads)
	if e != nil {
		return mcp.Item{}, e
	}
	header, body, _, id := sealed.Envelope()
	parsed, e := record.Parse(header, body, id)
	if e != nil {
		return mcp.Item{}, e
	}
	t.sealed = append(t.sealed, sealed)
	item := Item(id, m.TaskID, Owner, m.Kind)
	item.LID = parsed.Header.LID
	item.Order = t.seq
	for key, v := range m.Fields {
		if text, ok := v.(string); ok {
			item.Fields[key] = text
		} else {
			raw, _ := json.Marshal(v)
			item.Fields[key] = string(raw)
		}
	}
	item.Fields["task_id"] = m.TaskID
	if m.Kind == "task" {
		item.Fields["status"] = "active"
	}
	if m.Kind == "conclusion" {
		item.Outcome = "agent-declared"
		item.Explicit = true
	}
	// Retain immutable fake records; a detached task projection computes lifecycle.
	for i, row := range t.rows {
		if row.TaskID != m.TaskID || row.Owner != Owner || row.Kind != "task" {
			continue
		}
		if row.Fields["status"] != "completed" {
			switch m.Kind {
			case "conclusion":
				row.Fields["status"] = "completed"
			case "pause":
				row.Fields["status"] = "paused"
			case "checkpoint":
				row.Fields["status"] = "active"
			}
		}
		row.Order = t.seq
		t.rows[i] = row
	}
	t.rows = append(t.rows, item)
	t.mutations = append(t.mutations, m)
	return item, nil
}
func Item(id, task, owner, kind string) mcp.Item {
	if !record.IsHex64(id) {
		id = record.H("fixture", id)
	}
	return mcp.Item{ID: id, LID: record.H("fixture-lid", owner, task, kind, id), TaskID: task, Owner: owner, Kind: kind, State: "live", Source: "fixture capture", Signature: "unverified fixture", Coverage: "incomplete", Trust: "taint-unknown", Evidence: "none captured", Outcome: "agent-declared", Fields: map[string]string{"name": "Fixture task"}}
}
