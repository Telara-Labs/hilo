package store

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/url"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/Telara-Labs/telara-memory/contract/record"
	"github.com/Telara-Labs/telara-memory/contract/replay"
	"github.com/Telara-Labs/telara-memory/contract/sig"
	"github.com/Telara-Labs/telara-memory/contract/transport"
)

// deviceControl signs an erasure as a specific enrolled device. Unlike
// world.control it never completes coverage from the signer's own store, so
// it states exactly the selectors that device knows.
func deviceControl(t *testing.T, key ed25519.PrivateKey, machine, nonce string, at int64, sel record.Selectors) SignedRecord {
	t.Helper()
	keyID := sig.KeyID(key.Public().(ed25519.PublicKey))
	h := record.Header{Type: record.KindErasure, Prov: record.ProvUser, At: at, Author: record.Author{MachineID: machine, KeyID: keyID}, Red: record.Redact{Profile: record.ProfileLocal}}
	var err error
	if h.LID, err = record.ControlLID(record.KindErasure, keyID, record.H("nonce", nonce)[:32]); err != nil {
		t.Fatal(err)
	}
	sort.Strings(sel.IDs)
	r, err := record.Build(h, &record.ErasureBody{EventCoverage: "complete", Selectors: sel, Reason: "user_request"})
	if err != nil {
		t.Fatal(err)
	}
	sg, err := sig.SignRecord(key, r.ID)
	if err != nil {
		t.Fatal(err)
	}
	return wire(r, []record.Signature{sg})
}

// carryControls moves a device's controls to another device of the same
// genesis the only way the node admits them: a verified bundle import.
func carryControls(t *testing.T, from *Store, to *Store, toKey string) {
	t.Helper()
	ctx := context.Background()
	keyring, err := from.Keyring(ctx)
	if err != nil {
		t.Fatal(err)
	}
	sel, err := from.SelectBundle(ctx, []string{strings.Repeat("0", 64)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = to.ImportBundle(ctx, BundleImport{LocalKeyID: toKey, Keyring: keyring, Controls: sel.Controls}); err != nil {
		t.Fatal("control transfer", err)
	}
}

func reopenStore(t *testing.T, s **Store, o Options) {
	t.Helper()
	(*s).Close()
	st, err := Open(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	*s = st
	t.Cleanup(func() { st.Close() })
}

// Node adapter for vector V11. Device B never saw device A's chunk. B's signed
// event erasure, carried to A, purges it; an id-only erasure without signed
// event coverage durably blocks the owner and never reports a clean scrub
// until a supplemental control supplies the coverage; an invalid late body
// under the erasure fence changes nothing; every state survives restart.
func TestNodeV11TwoDeviceEventControlPendingOwnerAndSupplementalCoverage(t *testing.T) {
	ctx := context.Background()
	a := newWorld(t)
	b := joinDevice(t, a)
	aKey := a.o.PinnedGenesisID
	sk := a.sessionKey()

	// Phase 1: an event erasure from a device that never saw the chunk.
	const canary1 = "v11_never_seen_chunk_canary_4b1e"
	e1 := a.unsealed(canary1, "v11-one", 1)
	k1 := a.chunk(e1)
	a.append(k1)
	s1 := a.session([]string{k1.AdvisoryID})
	a.append(s1)
	x1 := deviceControl(t, b.key, joinedMachine, "v11-x1", a.at+10, record.Selectors{Events: []record.EventSelector{{Owner: aKey, SessionKey: sk, EventID: e1.ID}}})
	if _, err := b.s.ApplyControl(ctx, x1); err != nil {
		t.Fatal("device b could not issue an event control", err)
	}
	carryControls(t, b.s, a.s, aKey)
	for _, id := range []string{k1.AdvisoryID, s1.AdvisoryID} {
		if e := find(a.snapshot(), id); e.State != "invalidated" || len(e.BodyJCS) != 0 {
			t.Fatal("never-seen chunk survived the other device's event control", e.State)
		}
	}
	if countRows(t, a.s, "SELECT count(*) FROM event_ban WHERE owner=? AND session=? AND event_id=? AND cause=?", aKey, sk, e1.ID, x1.AdvisoryID) != 1 {
		t.Fatal("signed event ban not durable")
	}
	if res, err := a.s.Scrub(ctx, x1.AdvisoryID); err != nil || res.State != "complete" {
		t.Fatal(res, err)
	}
	assertAbsent(t, a.o.Dir, canary1)
	// The ban applies before a recaptured occurrence is sealed or stored.
	if supp, err := a.s.Suppressed(ctx, SourceOccurrence{Owner: aKey, SessionKey: sk, EventIDs: []string{e1.ID}}); err != nil || !supp.Suppressed {
		t.Fatal("recapture not suppressed", supp, err)
	}
	recaptured := a.chunk(a.unsealed(canary1+" again", "v11-one", 1))
	a.append(recaptured)
	if e := find(a.snapshot(), recaptured.AdvisoryID); e.State != "invalidated" || len(e.BodyJCS) != 0 {
		t.Fatal("recaptured occurrence escaped the ban", e.State)
	}

	// Phase 2: id-only erasure without signed event coverage.
	const canary2 = "v11_pending_owner_canary_93a0"
	e2 := a.unsealed(canary2, "v11-two", 2)
	k2 := a.chunk(e2)
	a.append(k2)
	x2 := deviceControl(t, b.key, joinedMachine, "v11-x2", a.at+20, record.Selectors{IDs: []string{k2.AdvisoryID}})
	if _, err := b.s.ApplyControl(ctx, x2); err != nil {
		t.Fatal(err)
	}
	carryControls(t, b.s, a.s, aKey)
	blocked := func(stage string) {
		t.Helper()
		if n := countRows(t, a.s, "SELECT count(*) FROM erasure_pending WHERE control=?", x2.AdvisoryID); n != 1 {
			t.Fatal(stage, "pending owner block not durable", n)
		}
		if _, err := a.s.Snapshot(ctx, ReadRequest{}); err == nil {
			t.Fatal(stage, "owner served data with incomplete event coverage")
		}
		if res, err := a.s.Scrub(ctx, x2.AdvisoryID); err != nil || res.State != "blocked" {
			t.Fatal(stage, "early clean receipt", res, err)
		}
	}
	blocked("before restart")
	reopenStore(t, &a.s, a.o)
	blocked("after restart")
	x3 := deviceControl(t, b.key, joinedMachine, "v11-x3", a.at+30, record.Selectors{Events: []record.EventSelector{{Owner: aKey, SessionKey: sk, EventID: e2.ID}}})
	if _, err := b.s.ApplyControl(ctx, x3); err != nil {
		t.Fatal(err)
	}
	carryControls(t, b.s, a.s, aKey)
	if n := countRows(t, a.s, "SELECT count(*) FROM erasure_pending"); n != 0 {
		t.Fatal("supplemental coverage did not complete the earlier control", n)
	}
	for _, c := range []string{x2.AdvisoryID, x3.AdvisoryID} {
		if res, err := a.s.Scrub(ctx, c); err != nil || res.State != "complete" {
			t.Fatal(res, err)
		}
	}
	if e := find(a.snapshot(), k2.AdvisoryID); e.State != "invalidated" || len(e.BodyJCS) != 0 {
		t.Fatal("pending target served", e.State)
	}
	assertAbsent(t, a.o.Dir, canary2)

	// Phase 3: an invalid late body under the erasure fence has no effect.
	const canary3 = "v11_late_body_canary_d61c"
	e3 := a.unsealed(canary3, "v11-three", 3)
	k3 := a.chunk(e3)
	header := k3
	header.BodyJCS = nil
	a.append(header)
	x4 := deviceControl(t, b.key, joinedMachine, "v11-x4", a.at+40, record.Selectors{IDs: []string{k3.AdvisoryID}, Events: []record.EventSelector{{Owner: aKey, SessionKey: sk, EventID: e3.ID}}})
	if _, err := b.s.ApplyControl(ctx, x4); err != nil {
		t.Fatal(err)
	}
	carryControls(t, b.s, a.s, aKey)
	generation := a.snapshot().Generation
	tampered := k3
	tampered.BodyJCS = bytes.Replace(k3.BodyJCS, []byte(canary3), []byte("v11_tampered_body_canary_0000"[:len(canary3)]), 1)
	if bytes.Equal(tampered.BodyJCS, k3.BodyJCS) {
		t.Fatal("fixture did not tamper")
	}
	if _, err := a.s.Append(ctx, tampered); err == nil {
		t.Fatal("invalid late body admitted")
	}
	if a.snapshot().Generation != generation || countRows(t, a.s, "SELECT count(*) FROM body_seen WHERE id=?", k3.AdvisoryID) != 0 || countRows(t, a.s, "SELECT count(*) FROM item_event WHERE id=?", k3.AdvisoryID) != 0 {
		t.Fatal("invalid late body left facts")
	}
	a.append(k3)
	if e := find(a.snapshot(), k3.AdvisoryID); e.State != "invalidated" || len(e.BodyJCS) != 0 {
		t.Fatal("valid late body refilled an erased header", e.State)
	}
	if res, err := a.s.Scrub(ctx, x4.AdvisoryID); err != nil || res.State != "complete" {
		t.Fatal(res, err)
	}
	reopenStore(t, &a.s, a.o)
	snap := a.snapshot()
	for _, id := range []string{k1.AdvisoryID, s1.AdvisoryID, recaptured.AdvisoryID, k2.AdvisoryID, k3.AdvisoryID} {
		if e := find(snap, id); e.State != "invalidated" || len(e.BodyJCS) != 0 {
			t.Fatal("restart resurrected an erased record", e.State)
		}
	}
	assertAbsent(t, a.o.Dir, canary1, canary2, canary3)
}

// Node adapter for vector V13. Two store handles on one database race late
// derived admission against exact erasure of its root. Both use the SQLite
// writer lock; whichever wins, no derived record is ever live afterwards.
func TestNodeV13ConcurrentAdmissionAndEraseLeaveNoLiveLateRecord(t *testing.T) {
	ctx := context.Background()
	w := newWorld(t)
	other, err := Open(ctx, w.o)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	retry := func(f func() error) error {
		var err error
		for i := 0; i < 50; i++ {
			if err = f(); Code(err) != "storage_error" {
				return err
			}
		}
		return err
	}
	const rounds = 16
	type pair struct{ root, derived SignedRecord }
	var pairs []pair
	for i := 0; i < rounds; i++ {
		root := w.task(1000+i, fmt.Sprintf("v13 root %d", i))
		w.append(root)
		pairs = append(pairs, pair{root, w.task(2000+i, fmt.Sprintf("v13_late_derived_canary_%02d", i), root.AdvisoryID)})
	}
	for i, p := range pairs {
		admitter, eraser := w.s, other
		if i%2 == 1 {
			admitter, eraser = other, w.s
		}
		start := make(chan struct{})
		var wg sync.WaitGroup
		var appendErr, eraseErr error
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			appendErr = retry(func() error { _, err := admitter.Append(ctx, p.derived); return err })
		}()
		go func() {
			defer wg.Done()
			<-start
			eraseErr = retry(func() error {
				_, err := eraser.EraseExact(ctx, EraseRequest{IDs: []string{p.root.AdvisoryID}}, worldSigner{w.key})
				return err
			})
		}()
		close(start)
		wg.Wait()
		if appendErr != nil || eraseErr != nil {
			t.Fatal("round", i, appendErr, eraseErr)
		}
	}
	check := func(stage string, s *Store) {
		t.Helper()
		snap, err := s.Snapshot(ctx, ReadRequest{})
		if err != nil {
			t.Fatal(stage, err)
		}
		for i, p := range pairs {
			for _, id := range []string{p.root.AdvisoryID, p.derived.AdvisoryID} {
				if e := find(snap, id); e.State != "invalidated" || len(e.BodyJCS) != 0 {
					t.Fatal(stage, "round", i, "late record live", e.State)
				}
			}
		}
		if n := countRows(t, s, "SELECT count(*) FROM passage WHERE text LIKE '%v13_late_derived_canary%'"); n != 0 {
			t.Fatal(stage, "late record searchable", n)
		}
	}
	check("first handle", w.s)
	check("second handle", other)
	other.Close()
	reopenStore(t, &w.s, w.o)
	check("after restart", w.s)
	var controls []string
	rows, err := w.s.conn.QueryContext(ctx, "SELECT control FROM scrub_job")
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var c string
		rows.Scan(&c)
		controls = append(controls, c)
	}
	rows.Close()
	for _, c := range controls {
		if res, err := w.s.Scrub(ctx, c); err != nil || res.State != "complete" {
			t.Fatal(res, err)
		}
	}
	assertAbsent(t, w.o.Dir, "v13_late_derived_canary")
}

// rendered is text as the evidence frame escapes it.
func rendered(text string) string { return strings.ReplaceAll(text, "_", `\u005f`) }

// plainRedactor returns text unchanged; the fixture text holds no secrets.
type plainRedactor struct{}

func (plainRedactor) Redact(s string) string                  { return s }
func (plainRedactor) Argument(_, v string) string             { return v }
func (plainRedactor) Profiles() []string                      { return nil }
func (plainRedactor) RedactProfile(_ string, s string) string { return s }

// secretsOf collects every per-record secret and commitment in a body: salts,
// event text digests and call argument/result commitments.
func secretsOf(t *testing.T, body []byte) []string {
	t.Helper()
	var v any
	if err := json.Unmarshal(body, &v); err != nil {
		t.Fatal(err)
	}
	var out []string
	var walk func(any)
	walk = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			for k, child := range x {
				if s, ok := child.(string); ok && s != "" && (k == "salt" || k == "digest" || k == "args_hash" || k == "result_hash") {
					out = append(out, s)
				}
				walk(child)
			}
		case []any:
			for _, child := range x {
				walk(child)
			}
		}
	}
	walk(v)
	return out
}

// Node adapter for vector V23. The pinned SQLite refuses to open without FTS5
// secure-delete, runs FULL synchronous, and after exact erasure plus scrub no
// planted text, body/event/call salt, event text digest or call commitment
// survives in any managed file, including FTS shadow tables and the WAL.
func TestNodeV23SecureDeleteAtOpenAndNoSecretSurvivesScrub(t *testing.T) {
	ctx := context.Background()
	k := newKernel(t)
	for name, want := range map[string]string{"synchronous": "2", "secure_delete": "1", "journal_mode": "wal"} {
		var got string
		if err := k.s.conn.QueryRowContext(ctx, "PRAGMA "+name).Scan(&got); err != nil || got != want {
			t.Fatal("pragma", name, got, err)
		}
	}
	var secure int
	if err := k.s.conn.QueryRowContext(ctx, "SELECT v FROM search_config WHERE k='secure-delete'").Scan(&secure); err != nil || secure != 1 {
		t.Fatal("fts secure-delete", secure, err)
	}

	const taskText, checkpointText, eventText = "v23_task_goal_canary_a1", "v23_checkpoint_canary_b2", "v23 event text canary c3"
	task := k.taskID(k.execute("v23-task", "local.create_task", map[string]any{"goal": taskText}))
	k.release(k.execute("v23-checkpoint", "local.checkpoint_task", map[string]any{"task_id": task, "milestone": checkpointText}))
	ev, err := record.ReviseTextEvent(record.Event{ID: k.event("x").ID, Seq: 4, Kind: "assistant_final", Prov: "transcript"}, nil, eventText, plainRedactor{}, 600)
	if err != nil || ev.Text.Digest == "" {
		t.Fatal("text event fixture", err)
	}
	chunk := k.chunk(ev)
	k.append(chunk)
	k.release(k.execute("v23-search", "local.lexical_search", map[string]any{"query": "v23_checkpoint_canary_b2"}))

	snap := k.snapshot()
	forbidden := []string{taskText, checkpointText, eventText}
	var ids []string
	for _, e := range snap.Entries {
		r, err := record.Parse(e.HeaderJCS, e.BodyJCS, e.ID)
		if err != nil {
			t.Fatal(err)
		}
		if r.Header.Type.IsControl() || r.Header.Type == record.KindKeyOp || len(e.BodyJCS) == 0 {
			continue
		}
		ids = append(ids, e.ID)
		forbidden = append(forbidden, secretsOf(t, e.BodyJCS)...)
	}
	if len(ids) < 4 || len(forbidden) < 8 {
		t.Fatal("fixture planted too little", len(ids), len(forbidden))
	}
	receipt, err := k.s.EraseExact(ctx, EraseRequest{IDs: ids}, worldSigner{k.key})
	if err != nil || receipt.Pending {
		t.Fatal(receipt, err)
	}
	if res, err := k.s.Scrub(ctx, receipt.Control); err != nil || res.State != "complete" {
		t.Fatal(res, err)
	}
	assertAbsent(t, k.o.Dir, forbidden...)
	if n := countRows(t, k.s, "SELECT count(*) FROM search WHERE search MATCH ?", `"`+checkpointText+`"`); n != 0 {
		t.Fatal("fts still matches erased text", n)
	}
	sk := k.sessionKey()
	if supp, err := k.s.Suppressed(ctx, SourceOccurrence{Owner: k.o.PinnedGenesisID, SessionKey: sk, EventIDs: []string{ev.ID}}); err != nil || !supp.Suppressed {
		t.Fatal("recapture tomb does not apply before sealing", supp, err)
	}

	// Open refuses a database whose FTS secure-delete was turned off.
	k.e.Close()
	k.s.Close()
	raw, err := sql.Open("sqlite", (&url.URL{Scheme: "file", Path: filepath.Join(k.o.Dir, "memory.sqlite")}).String())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = raw.Exec("INSERT INTO search(search,rank) VALUES('secure-delete',0)"); err != nil {
		t.Fatal(err)
	}
	if st, err := Open(ctx, k.o); Code(err) != "unsafe_sqlite" {
		if st != nil {
			st.Close()
		}
		raw.Close()
		t.Fatal("opened without fts secure-delete", err)
	}
	if _, err = raw.Exec("INSERT INTO search(search,rank) VALUES('secure-delete',1)"); err != nil {
		t.Fatal(err)
	}
	raw.Close()
	st, err := Open(ctx, k.o)
	if err != nil {
		t.Fatal(err)
	}
	k.s = st
}

// reopenKernel restarts the store and the disclosure engine with the same
// preloaded authority and credential.
func reopenKernel(k *kernelWorld) {
	k.t.Helper()
	ctx := context.Background()
	k.e.Close()
	k.s.Close()
	st, err := Open(ctx, k.o)
	if err != nil {
		k.t.Fatal(err)
	}
	k.s = st
	material, err := PreloadDisclosureAuthority(bytes.Repeat([]byte{9}, 32), k.key)
	if err != nil {
		k.t.Fatal(err)
	}
	if k.e, err = NewDisclosureEngine(ctx, st, material, DisclosureConfig{OwnerGenesis: k.o.PinnedGenesisID, MachineID: testMachine, MaxReplyBytes: 16384}); err != nil {
		k.t.Fatal(err)
	}
	if k.h, err = k.e.Authenticate(ctx, k.proof); err != nil {
		k.t.Fatal(err)
	}
	if k.sc, err = k.e.Resolve(ctx, k.h, IdentityInput{ConversationHandle: "kernel-conversation"}); err != nil {
		k.t.Fatal(err)
	}
	k.t.Cleanup(func() { k.e.Close() })
}

// Node adapter for vector V24. One issued operation token commits the
// mutation, its signed CallBody with commitment dependencies, the operation
// row and outcome atomically; release commits the render version, exposure and
// dedup generation atomically; confirmation is a separate durable fact.
// Competing retries and a restart replay the one mutation. After exact erasure
// and scrub, matching and changed retries get the same keyless result.
func TestNodeV24AtomicOperationTokenAndUniformKeylessRetry(t *testing.T) {
	ctx := context.Background()
	k := newKernel(t)
	task := k.taskID(k.execute("v24-task", "local.create_task", map[string]any{"goal": "v24 task"}))
	const text = "v24_checkpoint_canary_6e3f"
	args := map[string]any{"task_id": task, "milestone": text}
	tables := []string{"record", "record_body", "operation", "outcome_member", "outcome_dependency", "record_attribution", "render_attempt", "render_item", "render_dep", "exposure", "delivery_confirmation"}
	counts := func() map[string]int {
		out := map[string]int{}
		for _, table := range tables {
			out[table] = countRows(t, k.s, "SELECT count(*) FROM "+table)
		}
		out["consumed"] = countRows(t, k.s, "SELECT count(*) FROM operation_token WHERE consumed=1")
		return out
	}
	same := func(stage string, a, b map[string]int) {
		t.Helper()
		for key, v := range a {
			if b[key] != v {
				t.Fatal(stage, "partial commit in", key, v, b[key])
			}
		}
	}
	token := k.issued("v24-checkpoint")
	command := commandFor(t, "local.checkpoint_task", args)
	execute := func(c TypedCommand) (CommittedReplyHandle, error) {
		return k.e.Execute(ctx, k.h, k.sc, CallIdentity{SuppliedOpID: token}, c, ByteBudget{MaxBytes: 4096})
	}

	// An unknown supplied token never falls back to a fresh operation.
	before := counts()
	if _, err := k.e.Execute(ctx, k.h, k.sc, CallIdentity{SuppliedOpID: "op1:" + strings.Repeat("7", 32)}, command, ByteBudget{MaxBytes: 4096}); Code(err) != "unissued_operation" {
		t.Fatal("unknown token accepted", err)
	}
	same("unknown token", before, counts())

	// A failure at the last mutation table rolls back the whole operation.
	for _, table := range []string{"operation", "outcome_member", "record_attribution"} {
		if _, err := k.s.conn.ExecContext(ctx, "CREATE TRIGGER v24_fault BEFORE INSERT ON "+table+" BEGIN SELECT RAISE(ABORT,'fault'); END"); err != nil {
			t.Fatal(err)
		}
		if _, err := execute(command); err == nil {
			t.Fatal("faulted operation committed", table)
		}
		if _, err := k.s.conn.ExecContext(ctx, "DROP TRIGGER v24_fault"); err != nil {
			t.Fatal(err)
		}
		same("execute fault "+table, before, counts())
	}

	// Competing retries of one token commit exactly one mutation.
	var wg sync.WaitGroup
	handles := make([]CommittedReplyHandle, 4)
	errs := make([]error, 4)
	start := make(chan struct{})
	for i := range handles {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			handles[i], errs[i] = execute(command)
		}(i)
	}
	close(start)
	wg.Wait()
	for i, err := range errs {
		if err != nil || handles[i].op != handles[0].op {
			t.Fatal("competing retry", i, err)
		}
	}
	executed := counts()
	if executed["operation"] != before["operation"]+1 || executed["consumed"] != before["consumed"]+1 {
		t.Fatal("competing retries minted extra operations", executed, before)
	}
	var callID, argsHash string
	if err := k.s.conn.QueryRowContext(ctx, "SELECT call_id,args_hash FROM operation WHERE op=?", handles[0].op).Scan(&callID, &argsHash); err != nil || argsHash == "" {
		t.Fatal("operation without comparator", err)
	}
	var root string
	if err := k.s.conn.QueryRowContext(ctx, "SELECT id FROM outcome_member WHERE op=? AND role='mutation'", handles[0].op).Scan(&root); err != nil {
		t.Fatal(err)
	}
	var callBody []byte
	if err := k.s.conn.QueryRowContext(ctx, "SELECT body FROM record_body WHERE id=?", callID).Scan(&callBody); err != nil {
		t.Fatal("call body not committed with the mutation", err)
	}
	var call record.CallBody
	if json.Unmarshal(callBody, &call) != nil || call.ArgsHash != argsHash || !containsID(call.CommitmentDeps, root) || countRows(t, k.s, "SELECT count(*) FROM dep WHERE id=? AND parent=?", callID, root) != 1 {
		t.Fatal("call key and dependency not committed together")
	}

	// Release commits render version, exposure and dedup generation together.
	if _, err := k.s.conn.ExecContext(ctx, "CREATE TRIGGER v24_fault BEFORE INSERT ON exposure BEGIN SELECT RAISE(ABORT,'fault'); END"); err != nil {
		t.Fatal(err)
	}
	if _, err := k.e.Release(ctx, k.h, handles[0]); err == nil {
		t.Fatal("release committed without its exposure")
	}
	if _, err := k.s.conn.ExecContext(ctx, "DROP TRIGGER v24_fault"); err != nil {
		t.Fatal(err)
	}
	same("release fault", executed, counts())
	if got := k.release(handles[0]); !strings.Contains(got, rendered(text)) {
		t.Fatal("release lost the mutation", got)
	}
	var version string
	var dbGeneration int64
	if err := k.s.conn.QueryRowContext(ctx, "SELECT version,db_generation FROM render_attempt WHERE op=? ORDER BY db_generation DESC LIMIT 1", handles[0].op).Scan(&version, &dbGeneration); err != nil || version == "" || dbGeneration <= 0 {
		t.Fatal("render version not persisted", err)
	}
	if countRows(t, k.s, "SELECT count(*) FROM exposure WHERE root=?", root) == 0 {
		t.Fatal("release without exposure")
	}
	k.acknowledgeLatest(handles[0].op)
	if countRows(t, k.s, "SELECT count(*) FROM delivery_confirmation WHERE id=?", root) == 0 {
		t.Fatal("confirmation not durable")
	}

	// A restart replays the committed outcome without a new mutation.
	reopenKernel(k)
	executed = counts()
	replayed, err := execute(command)
	if err != nil {
		t.Fatal(err)
	}
	if got := k.release(replayed); !strings.Contains(got, rendered(text)) || got == replay.Unavailable {
		t.Fatal("restart lost the committed outcome", got)
	}
	if after := counts(); after["operation"] != executed["operation"] || after["record"] != executed["record"] {
		t.Fatal("restart retry mutated again")
	}

	// After exact erasure and scrub the result is uniform and keyless.
	receipt, err := k.s.EraseExact(ctx, EraseRequest{IDs: []string{root}}, worldSigner{k.key})
	if err != nil {
		t.Fatal(err)
	}
	if res, err := k.s.Scrub(ctx, receipt.Control); err != nil || res.State != "complete" {
		t.Fatal(res, err)
	}
	var results []string
	for _, milestone := range []string{text, "a different candidate milestone"} {
		r, err := execute(commandFor(t, "local.checkpoint_task", map[string]any{"task_id": task, "milestone": milestone}))
		if err != nil {
			t.Fatal("keyless retry refused differently", err)
		}
		results = append(results, k.release(r))
	}
	if results[0] != replay.Unavailable || results[1] != results[0] {
		t.Fatal("keyless retry is an oracle", results)
	}
	if countRows(t, k.s, "SELECT count(*) FROM record_body WHERE id IN(?,?)", root, callID) != 0 || countRows(t, k.s, "SELECT count(*) FROM operation WHERE op=? AND args_hash=''", handles[0].op) != 1 {
		t.Fatal("call key survived erasure")
	}
	assertAbsent(t, k.o.Dir, append([]string{text}, secretsOf(t, callBody)...)...)
	reopenKernel(k)
	r, err := execute(command)
	if err != nil || k.release(r) != replay.Unavailable {
		t.Fatal("restart restored a keyless comparison", err)
	}
}

// Node adapter for vector V28. Exposure facts cross devices byte-exact with
// their recalled and affected identities, survive a delivered-set reset and
// body erasure on both devices, hold data that arrives after the fact, and a
// selection never auto-selects the recalled root it depends on.
func TestNodeV28LateExposureHoldsAcrossTransferCompactionAndErasure(t *testing.T) {
	ctx := context.Background()
	w := newWorld(t)
	recv := joinDevice(t, w)
	k := newKernelForWorld(w)
	root := k.task(1, "v28 recalled root body")
	k.append(root)
	k.release(k.execute("v28-lookup", "local.lookup_record", map[string]any{"record_id": root.AdvisoryID}))
	signal, err := k.a.issueSyntheticCompaction(ctx, k.sc)
	if err != nil {
		t.Fatal(err)
	}
	if err = k.a.applySyntheticCompaction(ctx, signal); err != nil {
		t.Fatal(err)
	}
	const affectedText = "v28_late_affected_canary_8d2b"
	affected := k.task(2, affectedText)
	k.append(affected)
	exposures := countRows(t, k.s, "SELECT count(*) FROM exposure WHERE root=?", root.AdvisoryID)
	if exposures == 0 {
		t.Fatal("no exposure ledger entry")
	}

	// The dependent alone is excluded; its recalled root is never auto-selected.
	alone, err := k.s.SelectBundle(ctx, []string{affected.AdvisoryID})
	if err != nil {
		t.Fatal(err)
	}
	if len(alone.Data) != 0 || excludedReason(alone, affected.AdvisoryID) != ExcludedLineageIncomplete {
		t.Fatal("affected record exported without its recalled root", alone.Excluded)
	}
	sel, err := k.s.SelectBundle(ctx, []string{affected.AdvisoryID, root.AdvisoryID})
	if err != nil || len(sel.Data) != 2 || len(sel.Facts) == 0 {
		t.Fatal("complete selection", sel.Excluded, err)
	}
	var carried bool
	for _, line := range sel.Facts {
		f, err := transport.ParseExposure(line)
		if err != nil {
			t.Fatal(err)
		}
		if f.RecalledID == root.AdvisoryID && containsID(f.AffectsIDs, affected.AdvisoryID) && f.OriginMachine == testMachine {
			carried = true
		}
	}
	if !carried {
		t.Fatal("exposure fact did not carry recalled and affected identities")
	}

	// Late arrival: the fact lands first, then data without its root is held
	// out; the complete bundle later admits both.
	if r, err := recv.s.ImportBundle(ctx, BundleImport{LocalKeyID: recv.KeyID(), Keyring: sel.Keyring, Facts: sel.Facts}); err != nil || r.Facts != len(sel.Facts) {
		t.Fatal("facts-only import", r, err)
	}
	if r, err := recv.s.ImportBundle(ctx, BundleImport{LocalKeyID: recv.KeyID(), Keyring: sel.Keyring, Facts: sel.Facts, Data: []SignedRecord{affected}}); err != nil || r.Data != 0 || len(r.Excluded) != 1 || r.Excluded[0].Reason != ExcludedLineageIncomplete {
		t.Fatal("late data admitted without its recalled root", r, err)
	}
	full := BundleImport{LocalKeyID: recv.KeyID(), Keyring: sel.Keyring, Facts: sel.Facts, Data: []SignedRecord{sel.Data[1], sel.Data[0]}}
	if r, err := recv.s.ImportBundle(ctx, full); err != nil || r.Data != 2 {
		t.Fatal("complete bundle", r, err)
	}
	stored := map[string]bool{}
	rows, err := recv.s.conn.QueryContext(ctx, "SELECT fact FROM imported_exposure")
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var raw []byte
		rows.Scan(&raw)
		stored[string(raw)] = true
	}
	rows.Close()
	for _, line := range sel.Facts {
		if !stored[string(line)] {
			t.Fatal("imported fact not persisted byte-exact")
		}
	}
	// Onward export from the receiver forwards the same fact unchanged.
	onward, err := recv.s.SelectBundle(ctx, []string{affected.AdvisoryID, root.AdvisoryID})
	if err != nil || len(onward.Data) != 2 {
		t.Fatal(onward.Excluded, err)
	}
	for _, line := range sel.Facts {
		found := false
		for _, o := range onward.Facts {
			found = found || bytes.Equal(o, line)
		}
		if !found {
			t.Fatal("onward bundle changed or dropped a fact")
		}
	}

	// Body erasure of the root holds the affected record on both devices and
	// keeps every fact.
	receipt, err := recv.s.EraseExact(ctx, EraseRequest{IDs: []string{root.AdvisoryID}}, recv)
	if err != nil {
		t.Fatal(err)
	}
	if res, err := recv.s.Scrub(ctx, receipt.Control); err != nil || res.State != "complete" {
		t.Fatal(res, err)
	}
	k.append(k.control(28001, record.KindErasure, root.AdvisoryID))
	checkHeld := func(stage string, s *Store, ledger string, want int) {
		t.Helper()
		snap, err := s.Snapshot(ctx, ReadRequest{IDs: []string{root.AdvisoryID, affected.AdvisoryID}})
		if err != nil {
			t.Fatal(stage, err)
		}
		if e := find(snap, root.AdvisoryID); e.State != "invalidated" || len(e.BodyJCS) != 0 {
			t.Fatal(stage, "erased root served", e.State)
		}
		if e := find(snap, affected.AdvisoryID); e.State != "lineage-hold" || len(e.BodyJCS) != 0 {
			t.Fatal(stage, "late affected record served after root erasure", e.State)
		}
		if n := countRows(t, s, ledger); n != want {
			t.Fatal(stage, "exposure facts dropped", n, want)
		}
	}
	recvLedger, senderLedger := "SELECT count(*) FROM imported_exposure", "SELECT count(*) FROM exposure WHERE root='"+root.AdvisoryID+"'"
	checkHeld("receiver", recv.s, recvLedger, len(stored))
	checkHeld("sender", k.s, senderLedger, exposures)
	reopenStore(t, &recv.s, recv.o)
	if err = recv.s.Reindex(ctx); err != nil {
		t.Fatal(err)
	}
	checkHeld("receiver restart", recv.s, recvLedger, len(stored))
	// Restoring the older complete bundle cannot release the hold or refill.
	if _, err = recv.s.ImportBundle(ctx, full); err != nil {
		t.Fatal(err)
	}
	checkHeld("receiver rollback restore", recv.s, recvLedger, len(stored))
	if again, err := recv.s.SelectBundle(ctx, []string{affected.AdvisoryID}); err != nil || len(again.Data) != 0 {
		t.Fatal("held record re-exported", again.Excluded, err)
	}
	k.e.Close()
	reopenStore(t, &k.s, k.o)
	checkHeld("sender restart", k.s, senderLedger, exposures)
	assertAbsent(t, recv.o.Dir, "v28 recalled root body")
}
