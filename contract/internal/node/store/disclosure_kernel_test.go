package store

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/Telara-Labs/hilo/contract/internal/node/disclosuretext"
	"github.com/Telara-Labs/hilo/contract/record"
	"strings"
	"testing"
)

type kernelWorld struct {
	*world
	e     *DisclosureEngine
	a     *DisclosureAdministration
	h     ClientHandle
	sc    ScopeHandle
	proof CredentialProof
}

func newKernel(t *testing.T) *kernelWorld {
	return newKernelForWorld(newWorld(t))
}
func newKernelForWorld(w *world) *kernelWorld {
	t := w.t
	k := &kernelWorld{world: w}
	material, err := PreloadDisclosureAuthority(bytes.Repeat([]byte{9}, 32), w.key)
	if err != nil {
		t.Fatal(err)
	}
	k.e, err = NewDisclosureEngine(context.Background(), w.s, material, DisclosureConfig{OwnerGenesis: w.o.PinnedGenesisID, MachineID: testMachine, MaxReplyBytes: 16384})
	if err != nil {
		t.Fatal(err)
	}
	k.a, err = k.e.Administration(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	r, err := k.a.Register(context.Background(), RegisterClient{AdminOpID: "register-kernel-client", ClientName: "Kernel fixture", ReadGrant: Grant{Repos: AllLocalRepos(), Channels: []Channel{S}}, TaskWrites: TaskWriteGrant{Actions: []TaskMutation{Create, Checkpoint, Pause, Complete}, Repos: AllLocalRepos(), AllowUnscoped: true}})
	if err != nil {
		t.Fatal(err)
	}
	token, err := r.Secret.Take()
	if err != nil {
		t.Fatal(err)
	}
	k.proof = CredentialProof{r.CredentialID, token}
	k.h, err = k.e.Authenticate(context.Background(), k.proof)
	if err != nil {
		t.Fatal(err)
	}
	k.sc, err = k.e.Resolve(context.Background(), k.h, IdentityInput{ConversationHandle: "kernel-conversation"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { k.e.Close(); clear(token) })
	return k
}
func commandFor(t *testing.T, tool string, args any) TypedCommand {
	t.Helper()
	raw, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	c, err := disclosuretext.DecodeCommand(tool, raw)
	if err != nil {
		t.Fatal(err)
	}
	return c
}
func (k *kernelWorld) execute(op, tool string, args any) CommittedReplyHandle {
	k.t.Helper()
	r, err := k.e.Execute(context.Background(), k.h, k.sc, CallIdentity{SuppliedOpID: k.issued(op)}, commandFor(k.t, tool, args), ByteBudget{MaxBytes: 4096})
	if err != nil {
		k.t.Fatal(op, err)
	}
	return r
}
func (k *kernelWorld) release(r CommittedReplyHandle) string {
	k.t.Helper()
	v, err := k.e.Release(context.Background(), k.h, r)
	if err != nil {
		k.t.Fatal(err)
	}
	return v.Text()
}
func (k *kernelWorld) taskID(r CommittedReplyHandle) string {
	var id string
	if err := k.s.conn.QueryRowContext(context.Background(), "SELECT task FROM outcome_task WHERE credential=? AND op=?", r.credential, r.op).Scan(&id); err != nil {
		k.t.Fatal(err)
	}
	return id
}
func TestKernelPositiveCompletenessSearchAndCursor(t *testing.T) {
	k := newKernel(t)
	ctx := context.Background()
	task := k.execute("create", "local.create_task", map[string]any{"goal": "ordinary source"})
	id := k.taskID(task)
	for i := 0; i < 3; i++ {
		k.execute(fmt.Sprint("checkpoint", i), "local.checkpoint_task", map[string]any{"task_id": id, "milestone": fmt.Sprint("Résumé cafécontinuity ", i)})
	}
	var n int
	if err := k.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM search WHERE search MATCH ?", lexicalFTSQuery("cafécontinuity")).Scan(&n); err != nil || n != 3 {
		t.Fatal("trusted builder did not create fresh projection", n, err)
	}
	r := k.execute("search", "local.lexical_search", map[string]any{"query": "cafécontinuity", "resource_types": []string{"checkpoint"}, "limit": 1})
	text := k.release(r)
	if !strings.Contains(text, "cafécontinuity") {
		t.Fatal(text)
	}
	var cursor string
	var expected, g int64
	if err := k.s.conn.QueryRowContext(ctx, "SELECT cursor FROM outcome_continuation WHERE credential=? AND op=?", r.credential, r.op).Scan(&cursor); err != nil {
		t.Fatal(err)
	}
	k.s.conn.QueryRowContext(ctx, "SELECT expected_generation FROM query_cursor WHERE id=?", cursor).Scan(&expected)
	k.s.conn.QueryRowContext(ctx, "SELECT generation FROM meta").Scan(&g)
	if expected != g {
		t.Fatal("own Release expired continuation", expected, g)
	}
	second, err := k.e.Next(ctx, k.h, k.sc, CallIdentity{SuppliedOpID: k.issued("page-two")}, cursor, ByteBudget{MaxBytes: 4096})
	if err != nil {
		t.Fatal(err)
	}
	k.release(second)
	retry, err := k.e.Next(ctx, k.h, k.sc, CallIdentity{SuppliedOpID: k.issued("page-two")}, cursor, ByteBudget{MaxBytes: 4096})
	if err != nil || retry.op != second.op {
		t.Fatal("lost page response replay", err)
	}
	_, err = k.e.Next(ctx, k.h, k.sc, CallIdentity{SuppliedOpID: k.issued("different-page")}, cursor, ByteBudget{MaxBytes: 4096})
	if Code(err) != "cursor_consumed" {
		t.Fatal("cursor reused", err)
	}
}
func TestKernelACKExactSetAndOriginalCompactionGeneration(t *testing.T) {
	k := newKernel(t)
	ctx := context.Background()
	r := k.execute("create", "local.create_task", map[string]any{"goal": "ACK source"})
	k.release(r)
	var nonce string
	var generation int64
	if err := k.s.conn.QueryRowContext(ctx, "SELECT nonce,original_generation FROM render_attempt WHERE op=? ORDER BY db_generation DESC LIMIT 1", r.op).Scan(&nonce, &generation); err != nil {
		t.Fatal(err)
	}
	rows, err := k.s.conn.QueryContext(ctx, "SELECT lid,id FROM render_item WHERE attempt=(SELECT id FROM render_attempt WHERE nonce=?)", nonce)
	if err != nil {
		t.Fatal(err)
	}
	var items []ItemMarker
	for rows.Next() {
		var m ItemMarker
		rows.Scan(&m.LID, &m.ID)
		items = append(items, m)
	}
	rows.Close()
	if _, err = k.e.Acknowledge(ctx, k.h, ACK{nonce, nil}); Code(err) != "invalid_ack" {
		t.Fatal("inexact ACK", err)
	}
	got, err := k.e.Acknowledge(ctx, k.h, ACK{nonce, items})
	if err != nil || got.Status != "confirmed" {
		t.Fatal(got, err)
	}
	got, err = k.e.Acknowledge(ctx, k.h, ACK{nonce, items})
	if err != nil || got.Status != "already_confirmed" {
		t.Fatal(got, err)
	}
	signal, err := k.a.issueSyntheticCompaction(ctx, k.sc)
	if err != nil {
		t.Fatal(err)
	}
	if err = k.a.applySyntheticCompaction(ctx, signal); err != nil {
		t.Fatal(err)
	}
	got, err = k.e.Acknowledge(ctx, k.h, ACK{nonce, items})
	if err != nil || got.Status != "stale_generation" {
		t.Fatal(got, err)
	}
	var original int64
	k.s.conn.QueryRowContext(ctx, "SELECT generation FROM delivery_confirmation WHERE attempt=(SELECT id FROM render_attempt WHERE nonce=?) LIMIT 1", nonce).Scan(&original)
	if original != generation {
		t.Fatal("ACK moved original generation", original, generation)
	}
	k.sc, err = k.e.Resolve(ctx, k.h, IdentityInput{ConversationHandle: "kernel-conversation"})
	if err != nil {
		t.Fatal(err)
	}
	empty := k.execute("empty", "local.lexical_search", map[string]any{"query": ""})
	k.release(empty)
	k.s.conn.QueryRowContext(ctx, "SELECT nonce FROM render_attempt WHERE op=? ORDER BY db_generation DESC LIMIT 1", empty.op).Scan(&nonce)
	if got, err = k.e.Acknowledge(ctx, k.h, ACK{nonce, nil}); err != nil || got.Status != "confirmed" {
		t.Fatal(got, err)
	}
	if got, err = k.e.Acknowledge(ctx, k.h, ACK{nonce, nil}); err != nil || got.Status != "already_confirmed" {
		t.Fatal("empty ACK not idempotent", got, err)
	}
}
func TestKernelExposureErasureUnionAndOrdinaryIngressNotComplete(t *testing.T) {
	k := newKernel(t)
	ctx := context.Background()
	root := k.task(999, "ordinary ingress canary")
	k.append(root)
	var n int
	k.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM field_completeness WHERE id=?", root.AdvisoryID).Scan(&n)
	if n != 0 {
		t.Fatal("Append minted completeness")
	}
	r := k.execute("lookup", "local.lookup_record", map[string]any{"record_id": root.AdvisoryID})
	if !strings.Contains(k.release(r), "ordinary ingress canary") {
		t.Fatal("quoted S lost")
	}
	future := k.task(1000, "future observed output")
	k.append(future)
	erase := k.control(88, record.KindErasure, root.AdvisoryID)
	k.append(erase)
	var state string
	k.s.conn.QueryRowContext(ctx, "SELECT state FROM record WHERE id=?", future.AdvisoryID).Scan(&state)
	if state != "lineage-hold" {
		t.Fatal("future same-machine output escaped exposure", state)
	}
	k.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM erasure_effect WHERE control=? AND target=?", erase.AdvisoryID, future.AdvisoryID).Scan(&n)
	if n != 1 {
		t.Fatal("semantic hold not charged", n)
	}
	k.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM render_body").Scan(&n)
	if n != 0 {
		t.Fatal("old quoted source retained")
	}
	if err := k.s.Reindex(ctx); err != nil {
		t.Fatal(err)
	}
	k.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM erasure_effect WHERE control=? AND target=?", erase.AdvisoryID, future.AdvisoryID).Scan(&n)
	if n != 1 {
		t.Fatal("rebuild refunded/doubled effect", n)
	}
}

// seedFreshCheckpoint exercises the trusted fixed-builder path. Direct Append
// and native capture intentionally cannot issue positive completeness facts.
func seedFreshCheckpoint(w *world, text string) SignedRecord {
	k := newKernelForWorld(w)
	root := k.execute("seed-task", "local.create_task", map[string]any{"goal": "projection fixture"})
	task := k.taskID(root)
	r := k.execute("seed-checkpoint", "local.checkpoint_task", map[string]any{"task_id": task, "milestone": text})
	var id string
	if err := w.s.conn.QueryRowContext(context.Background(), "SELECT id FROM outcome_member WHERE credential=? AND op=? AND role='mutation'", r.credential, r.op).Scan(&id); err != nil {
		w.t.Fatal(err)
	}
	e := find(w.snapshot(), id)
	return SignedRecord{HeaderJCS: e.HeaderJCS, BodyJCS: e.BodyJCS, Sigs: e.Sigs, AdvisoryID: id}
}
