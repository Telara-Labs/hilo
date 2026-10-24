package store

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/Telara-Labs/telara-memory/contract/record"
	"github.com/Telara-Labs/telara-memory/contract/replay"
)

// These tests exercise actual signed records, the fixed mutation builder, engine
// transactions and SQLite. Lower-level count-cap coverage is explicitly separate
// from successful end-to-end disclosure: central security limits may dominate it.
type countAcceptanceRow struct {
	ID, Scope, State string
	Generation       int64
	Reason           sql.NullString
	Values           [6]sql.NullInt64 // records,total,searchable,excluded,unclassified,records_excluded
}

func countAcceptanceRead(t *testing.T, k *kernelWorld, id string) countAcceptanceRow {
	t.Helper()
	r := countAcceptanceRow{ID: id}
	err := k.s.conn.QueryRowContext(context.Background(), "SELECT scope_key,generation,state,reason,records,total,searchable,excluded,unclassified,records_excluded FROM projection_count_snapshot WHERE id=?", id).
		Scan(&r.Scope, &r.Generation, &r.State, &r.Reason, &r.Values[0], &r.Values[1], &r.Values[2], &r.Values[3], &r.Values[4], &r.Values[5])
	if err != nil {
		t.Fatal("count snapshot", err)
	}
	return r
}

func countAcceptanceOriginal(t *testing.T, k *kernelWorld, r CommittedReplyHandle) countAcceptanceRow {
	t.Helper()
	var id string
	if err := k.s.conn.QueryRowContext(context.Background(), "SELECT snapshot FROM outcome_projection_summary WHERE credential=? AND op=?", r.credential, r.op).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return countAcceptanceRead(t, k, id)
}

func countAcceptanceCurrent(t *testing.T, k *kernelWorld, r CommittedReplyHandle) countAcceptanceRow {
	t.Helper()
	var id string
	if err := k.s.conn.QueryRowContext(context.Background(), "SELECT s.snapshot FROM render_attempt a JOIN render_projection_summary s ON s.attempt=a.id WHERE a.credential=? AND a.op=? ORDER BY a.db_generation DESC LIMIT 1", r.credential, r.op).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return countAcceptanceRead(t, k, id)
}

func countAcceptanceKnown(t *testing.T, r countAcceptanceRow, want [6]int64) {
	t.Helper()
	if r.State != "known" || r.Reason.Valid {
		t.Fatalf("not exact known snapshot: %+v", r)
	}
	for i, v := range r.Values {
		if !v.Valid || v.Int64 != want[i] {
			t.Fatalf("counter %d: %+v, want %v", i, r, want)
		}
	}
}

func countAcceptanceUnknown(t *testing.T, r countAcceptanceRow, reason string) {
	t.Helper()
	if r.State != "unknown" || !r.Reason.Valid || r.Reason.String != reason {
		t.Fatalf("not exact unknown snapshot: %+v", r)
	}
	for _, v := range r.Values {
		if v.Valid {
			t.Fatalf("unknown leaked prefix/zero counter: %+v", r)
		}
	}
}

func countAcceptanceCall(t *testing.T, k *kernelWorld, r CommittedReplyHandle) []byte {
	t.Helper()
	var body []byte
	if err := k.s.conn.QueryRowContext(context.Background(), "SELECT b.body FROM operation o JOIN record_body b ON b.id=o.call_id WHERE o.credential=? AND o.op=?", r.credential, r.op).Scan(&body); err != nil {
		t.Fatal(err)
	}
	return append([]byte(nil), body...)
}

func countAcceptanceCheckpoint(k *kernelWorld, task, op string, b *record.CheckpointBody) SignedRecord {
	opID := record.H("count-acceptance", op)
	r := k.signed(record.Header{Type: record.KindCheckpoint, LID: record.CheckpointLID(k.o.PinnedGenesisID, task, testMachine, opID), Prov: record.ProvMCPExplicit, Subj: record.Subject{TaskID: task}, Op: opID}, b)
	k.append(r)
	return r
}

func countAcceptanceSearch(k *kernelWorld, op, query string, resources ...string) CommittedReplyHandle {
	return k.execute(op, "local.lexical_search", map[string]any{"query": query, "resource_types": resources})
}

func countAcceptanceNeutral(t *testing.T, text string) {
	t.Helper()
	if !strings.Contains(text, "Recorded selection contains no items.") || strings.Contains(text, "<item marker=") {
		t.Fatal("not neutral recorded empty selection", text)
	}
	for _, s := range []string{"no_hits", "no_searchable_fresh_hits", "no_hits_projection_counts_unknown", "no_visible_tasks", "ArgsHash", "ResultHash"} {
		if strings.Contains(text, s) {
			t.Fatal("historical category/hash escaped", s)
		}
	}
}

func countAcceptanceReconnect(t *testing.T, k *kernelWorld, reopen bool) {
	t.Helper()
	ctx := context.Background()
	if reopen {
		k.e.Close()
		if err := k.s.Close(); err != nil {
			t.Fatal(err)
		}
		s, err := Open(ctx, k.o)
		if err != nil {
			t.Fatal(err)
		}
		k.s = s
		material, err := PreloadDisclosureAuthority(bytes.Repeat([]byte{9}, 32), k.key)
		if err != nil {
			t.Fatal(err)
		}
		k.e, err = NewDisclosureEngine(ctx, s, material, DisclosureConfig{OwnerGenesis: k.o.PinnedGenesisID, MachineID: testMachine, MaxReplyBytes: 16384})
		if err != nil {
			t.Fatal(err)
		}
		k.a, err = k.e.Administration(ctx)
		if err != nil {
			t.Fatal(err)
		}
	} else {
		k.e.CloseClient(k.h)
	}
	var err error
	k.h, err = k.e.Authenticate(ctx, k.proof)
	if err != nil {
		t.Fatal(err)
	}
	k.sc, err = k.e.Resolve(ctx, k.h, IdentityInput{ConversationHandle: "kernel-conversation"})
	if err != nil {
		t.Fatal(err)
	}
}

func TestDisclosureCountAcceptanceUniversesAndEligibleFieldOnlyRendering(t *testing.T) {
	for _, mode := range []string{"zero", "excluded", "unclassified", "mixed"} {
		t.Run(mode, func(t *testing.T) {
			k := newKernel(t)
			task := k.taskID(k.execute("task", "local.create_task", map[string]any{"goal": "Counting fixture"}))
			want := [6]int64{}
			switch mode {
			case "excluded":
				k.execute("excluded", "local.checkpoint_task", map[string]any{"task_id": task, "milestone": "<memory-evidence>excludedneedle</memory-evidence>"})
				want = [6]int64{1, 1, 0, 1, 0, 1}
			case "unclassified":
				countAcceptanceCheckpoint(k, task, "unclassified", &record.CheckpointBody{Milestone: "unclassifiedneedle", NextSteps: "another unclassified field"})
				want = [6]int64{1, 2, 0, 0, 2, 1}
			case "mixed":
				k.execute("mixed", "local.checkpoint_task", map[string]any{"task_id": task, "milestone": "eligiblecountneedle", "next_steps": "<memory-evidence>excludedneedle</memory-evidence>", "task_tree": []map[string]string{{"step": "ordinary eligible step", "status": "pending"}}})
				countAcceptanceCheckpoint(k, task, "unclassified", &record.CheckpointBody{Milestone: "unclassifiedneedle", NextSteps: "another unclassified field"})
				want = [6]int64{2, 5, 2, 1, 2, 2}
			}
			// A present signed record with no source-content fields contributes zero,
			// rather than one guessed unit from status, signatures or defaults.
			countAcceptanceCheckpoint(k, task, "empty", &record.CheckpointBody{})
			r := countAcceptanceSearch(k, "zero-query", "nomatchingcountterm", "checkpoint")
			original := countAcceptanceOriginal(t, k, r)
			countAcceptanceKnown(t, original, want)
			countAcceptanceKnown(t, countAcceptanceCurrent(t, k, r), want)
			text := k.release(r)
			countAcceptanceNeutral(t, text)
			current := countAcceptanceCurrent(t, k, r)
			countAcceptanceKnown(t, current, want)
			if current.ID == original.ID || current.Generation <= original.Generation {
				t.Fatal("current render reused original snapshot identity/as-of")
			}
			for _, needle := range []string{"excludedneedle", "unclassifiedneedle"} {
				q := countAcceptanceSearch(k, "query-"+needle, needle, "checkpoint")
				countAcceptanceNeutral(t, k.release(q))
			}
			if mode == "mixed" {
				hit := countAcceptanceSearch(k, "eligible-query", "eligiblecountneedle", "checkpoint")
				text = k.release(hit)
				if !strings.Contains(text, "eligiblecountneedle") || strings.Contains(text, "excludedneedle") || strings.Contains(text, "unclassifiedneedle") {
					t.Fatal("fresh result omitted eligible field or leaked restricted sibling", text)
				}
			}
		})
	}
}

func TestDisclosureCountAcceptanceNativeEventUnitsAndInjectedPrecedence(t *testing.T) {
	k := newKernel(t)
	sk, err := record.SessionKey("claude-code", "local", record.NativeGlobal, "38333333-3333-4333-8333-333333333333", "")
	if err != nil {
		t.Fatal(err)
	}
	var events []record.Event
	for i, kind := range []string{"injected_context", "user_prompt", "assistant_final"} {
		id, e := record.EventID(sk, kind, record.Anchor{NativeItemID: fmt.Sprint("count-native-", i)})
		if e != nil {
			t.Fatal(e)
		}
		ev := record.Event{ID: id, Seq: int64(i), Kind: kind, Prov: "transcript"}
		if i != 2 {
			ev.Text = &record.Text{Body: "nativeunitcanary", Bytes: 16}
			ev.Call = &record.ToolCall{Tool: "native-tool", Command: "native-command", Args: map[string]string{"a": "one", "b": "two"}}
		}
		ev, e = record.ReviseEvent(ev, nil)
		if e != nil {
			t.Fatal(e)
		}
		events = append(events, ev)
	}
	chunk := k.signed(record.Header{Type: record.KindChunk, LID: record.ChunkLID(sk, testMachine, events[0].ID), Prov: record.ProvTranscript, Subj: record.Subject{SessionKey: sk}}, &record.ChunkBody{Events: events})
	k.append(chunk)
	page := k.signed(record.Header{Type: record.KindSession, LID: record.SessionLID(sk, testMachine, 0), Prov: record.ProvTranscript, Subj: record.Subject{SessionKey: sk}}, &record.SessionBody{NativeID: "38333333-3333-4333-8333-333333333333", NativeIDKind: record.NativeGlobal, Chunks: []string{chunk.AdvisoryID}, SettledThrough: 2})
	k.append(page)
	r := countAcceptanceSearch(k, "native-unit-search", "nativeunitcanary", "evidence")
	countAcceptanceKnown(t, countAcceptanceOriginal(t, k, r), [6]int64{1, 2, 0, 1, 1, 1})
	countAcceptanceNeutral(t, k.release(r))
	lookup := k.execute("native-quoted", "local.lookup_record", map[string]any{"record_id": chunk.AdvisoryID})
	if !strings.Contains(k.release(lookup), "nativeunitcanary") {
		t.Fatal("explicit quoted native source was lost")
	}
	var roots, units int64
	if err := k.s.conn.QueryRowContext(context.Background(), "SELECT v.shown_roots,v.shown_units FROM render_visible_counts v JOIN render_attempt a ON a.id=v.attempt WHERE a.credential=? AND a.op=? ORDER BY a.db_generation DESC LIMIT 1", lookup.credential, lookup.op).Scan(&roots, &units); err != nil || roots != 1 || units != 2 {
		t.Fatal("quoted native event units collapsed equal text/ordinals or counted siblings as extra units", roots, units, err)
	}
}

func TestDisclosureCountAcceptanceNativeCurrentEmptyUnitsIgnoreHistoricalFields(t *testing.T) {
	k := newKernel(t)
	sk, err := record.SessionKey("claude-code", "local", record.NativeGlobal, "58333333-3333-4333-8333-333333333333", "")
	if err != nil {
		t.Fatal(err)
	}
	id, err := record.EventID(sk, "user_prompt", record.Anchor{NativeItemID: "corrected-to-empty"})
	if err != nil {
		t.Fatal(err)
	}
	old, err := record.ReviseEvent(record.Event{ID: id, Seq: 0, Kind: "user_prompt", Prov: "transcript", Text: &record.Text{Body: "historicalonlycountcanary", Bytes: 25}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	emptyID, err := record.EventID(sk, "assistant_final", record.Anchor{NativeItemID: "unchanged-empty"})
	if err != nil {
		t.Fatal(err)
	}
	empty, err := record.ReviseEvent(record.Event{ID: emptyID, Seq: 1, Kind: "assistant_final", Prov: "transcript"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	chunk := func(events []record.Event) SignedRecord {
		return k.signed(record.Header{Type: record.KindChunk, LID: record.ChunkLID(sk, testMachine, id), Prov: record.ProvTranscript, Subj: record.Subject{SessionKey: sk}}, &record.ChunkBody{Events: events})
	}
	prior := chunk([]record.Event{old, empty})
	k.append(prior)
	current, err := record.ReviseEvent(record.Event{ID: id, Seq: 0, Kind: "user_prompt", Prov: "transcript"}, []string{old.Revision})
	if err != nil {
		t.Fatal(err)
	}
	next := chunk([]record.Event{current})
	k.append(next)
	page := k.signed(record.Header{Type: record.KindSession, LID: record.SessionLID(sk, testMachine, 0), Prov: record.ProvTranscript, Subj: record.Subject{SessionKey: sk}}, &record.SessionBody{NativeID: "58333333-3333-4333-8333-333333333333", NativeIDKind: record.NativeGlobal, Chunks: []string{prior.AdvisoryID, next.AdvisoryID}, SettledThrough: 1})
	k.append(page)
	r := countAcceptanceSearch(k, "current-empty-native-search", "historicalonlycountcanary", "evidence")
	countAcceptanceKnown(t, countAcceptanceOriginal(t, k, r), [6]int64{})
	text := k.release(r)
	countAcceptanceNeutral(t, text)
	countAcceptanceKnown(t, countAcceptanceCurrent(t, k, r), [6]int64{})
}

func TestDisclosureCountAcceptanceConcreteGrantExcludesUnknownAndUnscoped(t *testing.T) {
	k := newKernel(t)
	ctx := context.Background()
	task := k.taskID(k.execute("task", "local.create_task", map[string]any{"goal": "Fixture"}))
	k.execute("unscoped-builder", "local.checkpoint_task", map[string]any{"task_id": task, "milestone": "reponeedle eligible but explicitly unscoped"})
	countAcceptanceCheckpoint(k, task, "unknown-native", &record.CheckpointBody{Milestone: "reponeedle unknown attribution"})
	all := countAcceptanceSearch(k, "all-local", "reponeedle", "checkpoint")
	countAcceptanceKnown(t, countAcceptanceOriginal(t, k, all), [6]int64{2, 2, 1, 0, 1, 1})
	if !strings.Contains(k.release(all), "eligible but explicitly unscoped") {
		t.Fatal("AllLocal positive universe was not actually usable")
	}
	repos, err := ConcreteRepos([]string{"r1:" + strings.Repeat("b", 64)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = k.a.ReplaceGrant(ctx, "concrete-only", k.proof.CredentialID, 1, Grant{Repos: repos, Channels: []Channel{S}}); err != nil {
		t.Fatal(err)
	}
	countAcceptanceReconnect(t, k, false)
	for i := 0; i < 2; i++ {
		r := countAcceptanceSearch(k, fmt.Sprint("concrete-query-", i), "reponeedle", "checkpoint")
		countAcceptanceKnown(t, countAcceptanceOriginal(t, k, r), [6]int64{})
		text := k.release(r)
		countAcceptanceNeutral(t, text)
		if strings.Contains(text, "reponeedle") {
			t.Fatal("out-of-grant source bytes escaped")
		}
		countAcceptanceKnown(t, countAcceptanceCurrent(t, k, r), [6]int64{})
		if err := k.s.Reindex(ctx); err != nil {
			t.Fatal(err)
		}
		countAcceptanceReconnect(t, k, true)
	}
}

// This fixture supplies explicitly trusted OWNER-side repository evidence to the
// actual private database. It is not ordinary request input, an installed broker,
// native attribution proof, or a public way to assert a repository. Resolve and
// the production current-evidence/authorization checks still execute normally.
func countAcceptanceTrustedRepoFixture(t *testing.T, k *kernelWorld, repo string) {
	t.Helper()
	ctx := context.Background()
	state := "unknown"
	if repo != "" {
		state = "known"
	}
	if err := k.s.write(ctx, func() error {
		r, err := k.s.conn.ExecContext(ctx, "UPDATE local_scope SET repo_state=?,repo=?,evidence=evidence+1 WHERE id=? AND owner=? AND machine=? AND credential=?", state, repo, k.sc.id, k.o.PinnedGenesisID, testMachine, k.proof.CredentialID)
		if err != nil {
			return err
		}
		n, err := r.RowsAffected()
		if err != nil || n != 1 {
			return failure("invalid_fixture")
		}
		return k.s.bump(ctx)
	}); err != nil {
		t.Fatal(err)
	}
	var err error
	k.sc, err = k.e.Resolve(ctx, k.h, IdentityInput{ConversationHandle: "kernel-conversation"})
	if err != nil {
		t.Fatal(err)
	}
}

func TestDisclosureCountAcceptanceTrustedRepoPredicateAndCurrentEvidence(t *testing.T) {
	k := newKernel(t)
	ctx := context.Background()
	repoA := "r1:" + strings.Repeat("a", 64)
	repoB := "r1:" + strings.Repeat("b", 64)
	countAcceptanceTrustedRepoFixture(t, k, repoA)
	stale := k.sc
	create := k.execute("repo-a-task", "local.create_task", map[string]any{"goal": "Trusted fixture A"})
	taskA := k.taskID(create)
	k.execute("repo-a-checkpoint", "local.checkpoint_task", map[string]any{"task_id": taskA, "milestone": "repoapositivecanary"})
	countAcceptanceTrustedRepoFixture(t, k, repoB)
	_, err := k.e.Execute(ctx, k.h, stale, CallIdentity{SuppliedOpID: k.issued("stale-trusted-evidence")}, commandFor(t, "local.lexical_search", map[string]any{"query": "repoapositivecanary"}), ByteBudget{MaxBytes: 4096})
	if Code(err) != "stale_scope" {
		t.Fatal("old evidence handle bypassed current resolution", err)
	}
	taskB := k.taskID(k.execute("repo-b-task", "local.create_task", map[string]any{"goal": "Trusted fixture B"}))
	k.execute("repo-b-checkpoint", "local.checkpoint_task", map[string]any{"task_id": taskB, "milestone": "repobprivatecanary"})
	countAcceptanceTrustedRepoFixture(t, k, "")
	taskU := k.taskID(k.execute("unscoped-task", "local.create_task", map[string]any{"goal": "Unscoped fixture"}))
	k.execute("unscoped-checkpoint", "local.checkpoint_task", map[string]any{"task_id": taskU, "milestone": "unscopedprivatecanary"})
	countAcceptanceCheckpoint(k, taskU, "unknown-attribution", &record.CheckpointBody{Milestone: "unknownprivatecanary"})
	all := countAcceptanceSearch(k, "all-repos-no-match", "no-repo-query-match", "checkpoint")
	before := countAcceptanceOriginal(t, k, all)
	countAcceptanceKnown(t, before, [6]int64{4, 4, 3, 0, 1, 1})
	call := countAcceptanceCall(t, k, all)
	repos, err := ConcreteRepos([]string{repoA})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = k.a.ReplaceGrant(ctx, "repo-a-only", k.proof.CredentialID, 1, Grant{Repos: repos, Channels: []Channel{S}}); err != nil {
		t.Fatal(err)
	}
	countAcceptanceReconnect(t, k, false)
	countAcceptanceTrustedRepoFixture(t, k, repoA)
	for i := 0; i < 2; i++ {
		for j, query := range []string{"repoapositivecanary", "repobprivatecanary", "unscopedprivatecanary", "unknownprivatecanary"} {
			r := countAcceptanceSearch(k, fmt.Sprintf("repo-current-%d-%d", i, j), query, "checkpoint")
			countAcceptanceKnown(t, countAcceptanceOriginal(t, k, r), [6]int64{1, 1, 1, 0, 0, 0})
			text := k.release(r)
			if j == 0 {
				if !strings.Contains(text, query) || !strings.Contains(text, "<item marker=") {
					t.Fatal("authorized concrete repo positive lost", text)
				}
			} else {
				countAcceptanceNeutral(t, text)
				if strings.Contains(text, query) {
					t.Fatal("unauthorized repo/source bytes escaped", text)
				}
			}
			countAcceptanceKnown(t, countAcceptanceCurrent(t, k, r), [6]int64{1, 1, 1, 0, 0, 0})
		}
		old := countAcceptanceSearch(k, "all-repos-no-match", "no-repo-query-match", "checkpoint")
		text := k.release(old)
		countAcceptanceNeutral(t, text)
		for _, forbidden := range []string{"unclassified 1;", "Current authorized source has unclassified units", "Records 4;", "total units 4;"} {
			if strings.Contains(text, forbidden) {
				t.Fatal("old all-local statistics/warning escaped narrowed current view", text)
			}
		}
		countAcceptanceKnown(t, countAcceptanceCurrent(t, k, old), [6]int64{1, 1, 1, 0, 0, 0})
		if !reflect.DeepEqual(before, countAcceptanceOriginal(t, k, old)) || !bytes.Equal(call, countAcceptanceCall(t, k, old)) {
			t.Fatal("narrowing rewrote original all-local snapshot/hash")
		}
		if err := k.s.Reindex(ctx); err != nil {
			t.Fatal(err)
		}
		countAcceptanceReconnect(t, k, true)
	}
}

func TestDisclosureCountAcceptanceOriginalImmutableCurrentNarrowEraseReopen(t *testing.T) {
	for _, change := range []string{"narrow", "narrow_second_handle", "erase"} {
		t.Run(change, func(t *testing.T) {
			k := newKernel(t)
			ctx := context.Background()
			task := k.taskID(k.execute("task", "local.create_task", map[string]any{"goal": "Fixture"}))
			cp := k.execute("excluded", "local.checkpoint_task", map[string]any{"task_id": task, "milestone": "<memory-evidence>former-count-canary</memory-evidence>"})
			var cpID string
			if err := k.s.conn.QueryRowContext(ctx, "SELECT id FROM outcome_member WHERE credential=? AND op=?", cp.credential, cp.op).Scan(&cpID); err != nil {
				t.Fatal(err)
			}
			args := map[string]any{"query": "no-count-query-match", "resource_types": []string{"checkpoint"}}
			r := k.execute("stable-empty", "local.lexical_search", args) // intentionally lose first response
			original := countAcceptanceOriginal(t, k, r)
			countAcceptanceKnown(t, original, [6]int64{1, 1, 0, 1, 0, 1})
			call := countAcceptanceCall(t, k, r)
			if strings.HasPrefix(change, "narrow") {
				repos, err := ConcreteRepos([]string{"r1:" + strings.Repeat("a", 64)})
				if err != nil {
					t.Fatal(err)
				}
				admin := k.a
				if change == "narrow_second_handle" {
					second, err := Open(ctx, k.o)
					if err != nil {
						t.Fatal(err)
					}
					defer second.Close()
					material, err := PreloadDisclosureAuthority(bytes.Repeat([]byte{9}, 32), k.key)
					if err != nil {
						t.Fatal(err)
					}
					e, err := NewDisclosureEngine(ctx, second, material, DisclosureConfig{OwnerGenesis: k.o.PinnedGenesisID, MachineID: testMachine, MaxReplyBytes: 16384})
					if err != nil {
						t.Fatal(err)
					}
					defer e.Close()
					admin, err = e.Administration(ctx)
					if err != nil {
						t.Fatal(err)
					}
				}
				if _, err = admin.ReplaceGrant(ctx, "narrow-counts", k.proof.CredentialID, 1, Grant{Repos: repos, Channels: []Channel{S}}); err != nil {
					t.Fatal(err)
				}
				countAcceptanceReconnect(t, k, false)
			} else {
				k.append(k.control(39001, record.KindErasure, cpID))
			}
			check := func() {
				t.Helper()
				r = k.execute("stable-empty", "local.lexical_search", args)
				text := k.release(r)
				if text != replay.Unavailable {
					countAcceptanceNeutral(t, text)
				}
				if strings.Contains(text, "former-count-canary") || strings.Contains(text, "excluded 1;") {
					t.Fatal("old universe escaped current authorization", text)
				}
				if strings.Contains(text, "Current authorized source has excluded units") {
					t.Fatal("old excluded warning escaped current authorization", text)
				}
				if text != replay.Unavailable {
					countAcceptanceKnown(t, countAcceptanceCurrent(t, k, r), [6]int64{})
				}
				// A fresh operation observes the current universe even if the old
				// operation's erasable selection payload became unavailable.
				fresh := countAcceptanceSearch(k, fmt.Sprint("current-universe-", countAcceptanceGeneration(t, k)), "no-count-query-match", "checkpoint")
				countAcceptanceKnown(t, countAcceptanceOriginal(t, k, fresh), [6]int64{})
				if text := k.release(fresh); text != replay.Unavailable {
					countAcceptanceNeutral(t, text)
				}
				if got := countAcceptanceOriginal(t, k, r); !reflect.DeepEqual(got, original) {
					t.Fatal("original SQL count snapshot mutated", got, original)
				}
				if !bytes.Equal(call, countAcceptanceCall(t, k, r)) {
					t.Fatal("original signed result/hash mutated")
				}
			}
			check()
			if err := k.s.Reindex(ctx); err != nil {
				t.Fatal(err)
			}
			check()
			countAcceptanceReconnect(t, k, true)
			check()
			// A NEW concrete-grant request must exclude both unknown ordinary
			// attribution and explicitly unscoped builder output. No native repo
			// attribution or installation claim is synthesized for this fixture.
			if strings.HasPrefix(change, "narrow") {
				q := countAcceptanceSearch(k, "new-narrowed-query", "anything", "checkpoint")
				countAcceptanceKnown(t, countAcceptanceOriginal(t, k, q), [6]int64{})
				countAcceptanceNeutral(t, k.release(q))
			}
		})
	}
}

func countAcceptanceGeneration(t *testing.T, k *kernelWorld) int64 {
	t.Helper()
	var n int64
	if err := k.s.conn.QueryRowContext(context.Background(), "SELECT generation FROM meta").Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// This is a private storage-schema test, not a fabricated public count result.
// Actual public unit-cap reconstruction and release are exercised separately.
func TestDisclosureCountAcceptanceSnapshotNullSchema(t *testing.T) {
	k := newKernel(t)
	ctx := context.Background()
	for _, state := range []string{"known", "unknown", "not_requested"} {
		t.Run(state, func(t *testing.T) {
			pool, err := newDisclosureEntropy()
			if err != nil {
				t.Fatal(err)
			}
			defer pool.clear()
			var id string
			err = k.s.write(ctx, func() error {
				id, err = pool.uuid(ctx, k.s, "snapshot", "projection_count_snapshot", "id")
				if err != nil {
					return err
				}
				c := &countSnapshot{id: id, state: state, scopeKey: k.sc.id, generation: countAcceptanceGeneration(t, k)}
				if state == "known" {
					c.records = ptr64(0)
					c.total = ptr64(0)
					c.searchable = ptr64(0)
					c.excluded = ptr64(0)
					c.unclassified = ptr64(0)
					c.recordsExcluded = ptr64(0)
				}
				if state == "unknown" {
					c.reason = "count_unit_limit"
				}
				return k.s.persistCount(ctx, k.o.PinnedGenesisID, k.proof.CredentialID, c)
			})
			if err != nil {
				t.Fatal(err)
			}
			r := countAcceptanceRead(t, k, id)
			if state == "known" {
				countAcceptanceKnown(t, r, [6]int64{})
			} else {
				if state == "unknown" {
					countAcceptanceUnknown(t, r, "count_unit_limit")
				} else {
					if r.State != "not_requested" || r.Reason.Valid {
						t.Fatal(r)
					}
					for _, v := range r.Values {
						if v.Valid {
							t.Fatal("not_requested acquired a counter", r)
						}
					}
				}
			}
			for _, column := range []string{"records", "total", "searchable", "excluded", "unclassified", "records_excluded"} {
				value := "NULL"
				if state != "known" {
					value = "0"
				}
				if _, err := k.s.conn.ExecContext(ctx, "UPDATE projection_count_snapshot SET "+column+"="+value+" WHERE id=?", id); err == nil {
					t.Fatal("SQL CHECK accepted contradictory count", state, column)
				}
			}
		})
	}
}

func TestDisclosureCountAcceptancePublicUnitCapUnknown(t *testing.T) {
	k := newKernel(t)
	// Real signed ordinary ingress has NO positive builder completeness. Distinct
	// explicit conclusion heads expose >65536 typed content units below central
	// record/body/edge limits and the separately bounded projection-field capacity.
	const records = 17
	var inputs []SignedRecord
	for i := 0; i < records; i++ {
		task := fmt.Sprintf("48222222-2222-4222-8222-%012x", i)
		changes := make([]string, 4096)
		for j := range changes {
			changes[j] = fmt.Sprintf("ordinary source unit %d", j)
		}
		inputs = append(inputs, k.signed(record.Header{Type: record.KindConclusion, LID: record.ExplicitConclusionLID(k.o.PinnedGenesisID, task), Prov: record.ProvMCPExplicit, Subj: record.Subject{TaskID: task}, Op: record.H("count-cap", task)}, &record.ConclusionBody{Source: "explicit", ChangesMade: changes}))
	}
	k.seedPending(inputs)
	r := countAcceptanceSearch(k, "unit-cap-query", "nocapmatches", "task_summary")
	original := countAcceptanceOriginal(t, k, r)
	countAcceptanceUnknown(t, original, "count_unit_limit")
	countAcceptanceUnknown(t, countAcceptanceCurrent(t, k, r), "count_unit_limit")
	var code string
	if err := k.s.conn.QueryRowContext(context.Background(), "SELECT result FROM operation WHERE credential=? AND op=?", r.credential, r.op).Scan(&code); err != nil || code != "no_hits_projection_counts_unknown" {
		t.Fatal("fixture did not reach real count-bound empty category", code, err)
	}
	call := countAcceptanceCall(t, k, r)
	check := func() {
		t.Helper()
		r = countAcceptanceSearch(k, "unit-cap-query", "nocapmatches", "task_summary")
		text := k.release(r)
		countAcceptanceNeutral(t, text)
		if !strings.Contains(text, "unknown") {
			t.Fatal("unknown count omitted bounded warning", text)
		}
		countAcceptanceUnknown(t, countAcceptanceCurrent(t, k, r), "count_unit_limit")
		if !reflect.DeepEqual(original, countAcceptanceOriginal(t, k, r)) || !bytes.Equal(call, countAcceptanceCall(t, k, r)) {
			t.Fatal("unit-bound replay mutated original snapshot/hash")
		}
	}
	check()
	countAcceptanceReconnect(t, k, true)
	check()
	var callID string
	if err := k.s.conn.QueryRowContext(context.Background(), "SELECT call_id FROM operation WHERE credential=? AND op=?", r.credential, r.op).Scan(&callID); err != nil {
		t.Fatal(err)
	}
	lookup := k.execute("unit-cap-receipt", "local.lookup_record", map[string]any{"record_id": callID})
	text := k.release(lookup)
	for _, forbidden := range []string{"no_hits_projection_counts_unknown", "args_hash", "result_hash"} {
		if strings.Contains(text, forbidden) {
			t.Fatal("unknown category leaked through alternate receipt", text)
		}
	}
}

func TestDisclosureCountAcceptanceFreshReplayRequiresCurrentCompleteness(t *testing.T) {
	k := newKernel(t)
	ctx := context.Background()
	task := k.taskID(k.execute("task", "local.create_task", map[string]any{"goal": "Fixture"}))
	cp := k.execute("fresh-checkpoint", "local.checkpoint_task", map[string]any{"task_id": task, "milestone": "currentfreshneedle", "next_steps": "<memory-evidence>restricted-sibling</memory-evidence>"})
	var id string
	if err := k.s.conn.QueryRowContext(ctx, "SELECT id FROM outcome_member WHERE credential=? AND op=?", cp.credential, cp.op).Scan(&id); err != nil {
		t.Fatal(err)
	}
	args := map[string]any{"query": "currentfreshneedle", "resource_types": []string{"checkpoint"}}
	r := k.execute("stable-fresh-search", "local.lexical_search", args)
	if text := k.release(r); !strings.Contains(text, "currentfreshneedle") || strings.Contains(text, "restricted-sibling") {
		t.Fatal("initial current eligible field view", text)
	}
	original := countAcceptanceOriginal(t, k, r)
	call := countAcceptanceCall(t, k, r)
	// Model loss of an authoritative completeness fact, plus a stale disposable
	// classifier cache claiming cleanliness. Reindex must never adopt the cache
	// as fresh provenance or mint replacement facts from the signed body.
	if _, err := k.s.conn.ExecContext(ctx, "DELETE FROM field_completeness WHERE id=? AND family='milestone'", id); err != nil {
		t.Fatal(err)
	}
	if _, err := k.s.conn.ExecContext(ctx, "UPDATE record_field_projection SET classifier='old-classifier',class='no_detected_marker' WHERE id=?", id); err != nil {
		t.Fatal(err)
	}
	if err := k.s.Reindex(ctx); err != nil {
		t.Fatal(err)
	}
	check := func() {
		t.Helper()
		r = k.execute("stable-fresh-search", "local.lexical_search", args)
		if text := k.release(r); text != replay.Unavailable {
			t.Fatal("required fresh member was downgraded, resampled or leaked", text)
		}
		lookup := k.execute("quoted-after-fact-loss", "local.lookup_record", map[string]any{"record_id": id})
		if text := k.release(lookup); !strings.Contains(text, "currentfreshneedle") {
			t.Fatal("explicit source quote unnecessarily denied", text)
		}
		if !reflect.DeepEqual(original, countAcceptanceOriginal(t, k, r)) || !bytes.Equal(call, countAcceptanceCall(t, k, r)) {
			t.Fatal("unavailable replay changed original logical outcome")
		}
	}
	check()
	countAcceptanceReconnect(t, k, true)
	check()
}

func TestDisclosureCountAcceptanceEmptyCategoryAndQueryRequiredReceipts(t *testing.T) {
	for _, mode := range []string{"no_hits", "no_searchable_fresh_hits", "no_visible_tasks", "query_required"} {
		t.Run(mode, func(t *testing.T) {
			k := newKernel(t)
			tool := "local.lexical_search"
			args := map[string]any{"query": "nomatch", "resource_types": []string{"checkpoint"}}
			if mode == "no_searchable_fresh_hits" {
				task := k.taskID(k.execute("task", "local.create_task", map[string]any{"goal": "Fixture"}))
				k.execute("excluded", "local.checkpoint_task", map[string]any{"task_id": task, "milestone": "<memory-evidence>categorycanary</memory-evidence>"})
			}
			if mode == "no_visible_tasks" {
				tool = "local.list_tasks"
				args = map[string]any{"query": "nomatch"}
			}
			if mode == "query_required" {
				args["query"] = ""
			}
			r := k.execute("empty-receipt", tool, args)
			var category, callID string
			if err := k.s.conn.QueryRowContext(context.Background(), "SELECT result,call_id FROM operation WHERE credential=? AND op=?", r.credential, r.op).Scan(&category, &callID); err != nil {
				t.Fatal(err)
			}
			if category != mode {
				t.Fatalf("fixture did not actually reach intended category: %s != %s", category, mode)
			}
			text := k.release(r)
			if mode == "query_required" {
				if strings.Contains(text, "authorized source units") || strings.Contains(text, "categorycanary") {
					t.Fatal("argument-only empty query enumerated source data", text)
				}
				var n int
				if k.s.conn.QueryRowContext(context.Background(), "SELECT count(*) FROM outcome_projection_summary WHERE credential=? AND op=?", r.credential, r.op).Scan(&n) != nil || n != 0 {
					t.Fatal("query_required acquired source count snapshot")
				}
			} else {
				countAcceptanceNeutral(t, text)
			}
			lookup := k.execute("lookup-receipt", "local.lookup_record", map[string]any{"record_id": callID})
			quoted := k.release(lookup)
			for _, forbidden := range []string{category, "categorycanary", "args_hash", "result_hash"} {
				if strings.Contains(quoted, forbidden) {
					t.Fatal("alternate receipt exposed historical result", forbidden)
				}
			}
			body := countAcceptanceCall(t, k, r)
			var parsed record.CallBody
			if err := json.Unmarshal(body, &parsed); err != nil {
				t.Fatal(err)
			}
			if parsed.Outcome != "ok" || parsed.Err != "" {
				t.Fatal("successful empty category encoded in signed receipt")
			}
		})
	}
}
