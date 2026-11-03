package store

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Telara-Labs/hilo/contract/policy"
	"github.com/Telara-Labs/hilo/contract/record"
	"github.com/Telara-Labs/hilo/contract/replay"
	"github.com/Telara-Labs/hilo/contract/sig"
)

func TestV3ErasureDestroysOriginalComparatorAndFreshSameLIDCannotMatch(t *testing.T) {
	k := newKernel(t)
	ctx := context.Background()
	task := k.taskID(k.execute("v3-task", "local.create_task", map[string]any{"goal": "live task"}))
	const text = "erasable prose 37263b5de30299ec16bf exact candidate"
	args := map[string]any{"task_id": task, "milestone": text}
	r := k.execute("v3-checkpoint", "local.checkpoint_task", args)
	k.release(r)
	var root, callID string
	var callBytes []byte
	if k.s.conn.QueryRowContext(ctx, "SELECT id FROM outcome_member WHERE op=?", r.op).Scan(&root) != nil {
		k.t.Fatal("root")
	}
	if k.s.conn.QueryRowContext(ctx, "SELECT o.call_id,b.body FROM operation o JOIN record_body b ON b.id=o.call_id WHERE o.op=?", r.op).Scan(&callID, &callBytes) != nil {
		k.t.Fatal("call")
	}
	snapshot, err := k.s.Snapshot(ctx, ReadRequest{IDs: []string{callID}})
	if err != nil || len(snapshot.Entries) != 1 {
		t.Fatal("original call", err)
	}
	originalCall := snapshot.Entries[0].SignedRecord
	var call record.CallBody
	if json.Unmarshal(callBytes, &call) != nil || !containsID(call.CommitmentDeps, root) {
		t.Fatal("unsigned commitment ancestry")
	}
	if k.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM operation_token WHERE consumed=1").Scan(new(int)) != nil {
		t.Fatal("settlement")
	}
	// The only standalone comparator is the original CallBody commitment.
	var comparator string
	k.s.conn.QueryRowContext(ctx, "SELECT args_hash FROM operation WHERE op=?", r.op).Scan(&comparator)
	if comparator != call.ArgsHash {
		t.Fatal("independent comparator")
	}
	hash := sha256.Sum256([]byte(text))
	if strings.Contains(string(callBytes), hex.EncodeToString(hash[:])) {
		t.Fatal("plain prose digest")
	}
	control := k.control(97001, record.KindErasure, root)
	k.append(control)
	for _, changed := range []string{text, "different candidate of the same erased operation"} {
		retry := k.execute("v3-checkpoint", "local.checkpoint_task", map[string]any{"task_id": task, "milestone": changed})
		if got := k.release(retry); got != replay.Unavailable {
			t.Fatal("keyless retry oracle", got)
		}
	}
	var count int
	k.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM record_body WHERE id IN(?,?)", root, callID).Scan(&count)
	if count != 0 {
		t.Fatal("key-bearing body survived")
	}
	k.s.conn.QueryRowContext(ctx, "SELECT args_hash FROM operation WHERE op=?", r.op).Scan(&comparator)
	if comparator != "" {
		t.Fatal("copied comparator survived")
	}
	scrub, err := k.s.Scrub(ctx, control.AdvisoryID)
	if err != nil || scrub.State != "complete" {
		t.Fatal(scrub, err)
	}
	key, _ := base64.RawURLEncoding.DecodeString(call.Salt)
	for _, suffix := range []string{"", "-wal", "-shm", "-journal"} {
		content, err := os.ReadFile(filepath.Join(k.o.Dir, "memory.sqlite") + suffix)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		for _, forbidden := range [][]byte{[]byte(text), []byte(call.Salt), key, []byte(call.ArgsHash)} {
			if bytes.Contains(content, forbidden) {
				t.Fatal("erased text/key/comparator in managed SQLite bytes", suffix)
			}
		}
	}
	a := k.task(98001, text)
	b := k.task(98001, text)
	ra, _ := record.Parse(a.HeaderJCS, a.BodyJCS, a.AdvisoryID)
	rb, _ := record.Parse(b.HeaderJCS, b.BodyJCS, b.AdvisoryID)
	if ra.Header.LID != rb.Header.LID || ra.Header.Body.Digest == rb.Header.Body.Digest {
		t.Fatal("fresh same-LID oracle")
	}
	k.e.Close()
	k.s.Close()
	st, err := Open(ctx, k.o)
	if err != nil {
		t.Fatal(err)
	}
	k.s = st
	if _, err = st.Append(ctx, originalCall); err != nil {
		t.Fatal("exact signed replay", err)
	}
	if err = st.conn.QueryRowContext(ctx, "SELECT count(*) FROM record_body WHERE id=?", callID).Scan(&count); err != nil || count != 0 {
		t.Fatal("replayed original refilled erased key", count, err)
	}
}

func TestV3LookupProjectionPredicateAndReleasedTaskIdentity(t *testing.T) {
	k := newKernel(t)
	create := k.execute("uuid", "local.create_task", map[string]any{"goal": "private body content"})
	task := k.taskID(create)
	text := k.release(create)
	if !strings.Contains(text, "task_id "+task) {
		t.Fatal("create omitted authenticated UUID")
	}
	for _, tool := range []string{"local.list_tasks", "local.resume_task"} {
		args := map[string]any{}
		if tool == "local.resume_task" {
			args["task_id"] = task
		}
		if got := k.release(k.execute(tool, tool, args)); !strings.Contains(got, "task_id "+task) {
			t.Fatal("missing released UUID", tool)
		}
	}
	var id string
	k.s.conn.QueryRowContext(context.Background(), "SELECT id FROM outcome_member WHERE op=?", create.op).Scan(&id)
	metadata := k.execute("metadata", "local.lookup_record", map[string]any{"record_id": id, "record_kind": "task", "include_content": false})
	text = k.release(metadata)
	if strings.Contains(text, "private body content") || !strings.Contains(text, "task_id "+task) {
		t.Fatal("metadata projection leak/lost identity", text)
	}
	full := k.execute("full", "local.lookup_record", map[string]any{"record_id": id, "record_kind": "task", "include_content": true})
	if got := k.release(full); !strings.Contains(got, "private body content") {
		t.Fatal("full projection unavailable", got)
	}
	wrong := k.execute("wrong-kind", "local.lookup_record", map[string]any{"record_id": id, "record_kind": "checkpoint", "include_content": true})
	if got := k.release(wrong); strings.Contains(got, "private body content") || strings.Contains(got, id) {
		t.Fatal("wrong kind escaped", got)
	}
	var exposures int
	k.s.conn.QueryRowContext(context.Background(), "SELECT count(*) FROM exposure WHERE root=?", id).Scan(&exposures)
	if exposures < 5 {
		t.Fatal("identity/metadata release not exposure covered")
	}
}

func TestV3IssuedTokensAndEphemeralScopeQuotaRetirement(t *testing.T) {
	k := newKernel(t)
	ctx := context.Background()
	cmd := commandFor(t, "local.list_tasks", map[string]any{})
	for _, token := range []string{"op1:" + strings.Repeat("1", 32), "arbitrary"} {
		if _, err := k.e.Execute(ctx, k.h, k.sc, CallIdentity{SuppliedOpID: token}, cmd, ByteBudget{MaxBytes: 4096}); Code(err) != "unissued_operation" {
			t.Fatal("caller issuance assertion accepted", err)
		}
	}
	for i := 0; i < 140; i++ {
		h, err := k.e.Authenticate(ctx, k.proof)
		if err != nil {
			t.Fatal(err)
		}
		sc, err := k.e.Resolve(ctx, h, IdentityInput{})
		if err != nil {
			t.Fatal(err)
		}
		r, err := k.e.Execute(ctx, h, sc, CallIdentity{JSONRPCID: json.RawMessage(`1`)}, cmd, ByteBudget{MaxBytes: 4096})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = k.e.Release(ctx, h, r); err != nil {
			t.Fatal(err)
		}
		if _, err = k.e.Execute(ctx, h, sc, CallIdentity{JSONRPCID: json.RawMessage(`1`)}, cmd, ByteBudget{MaxBytes: 4096}); Code(err) != "unauthorized" {
			t.Fatal("retired ephemeral handle reused", err)
		}
	}
	var n int
	k.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM local_scope WHERE identity_kind='connection'").Scan(&n)
	if n != 0 {
		t.Fatal("unidentified calls exhausted durable scopes", n)
	}
	if len(k.e.clients) != 1 {
		t.Fatal("retirement markers leaked", len(k.e.clients))
	}
}

func tenantFixture(t *testing.T, k *kernelWorld) (ed25519.PrivateKey, func(int64, *record.PolicyBody) SignedRecord) {
	t.Helper()
	ctx := context.Background()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{63}, 32))
	pub := key.Public().(ed25519.PublicKey)
	root, err := sig.BuildKeyOp(record.KeyOpBody{Op: record.OpTenantKey, Subject: sig.KeyRefOf(pub, record.RolePolicy, ""), Genesis: "tenant-fixture"}, pub, "", time.Now().UnixMilli(), key)
	if err != nil {
		t.Fatal(err)
	}
	if err = k.s.InstallTenantPolicyContext(ctx, TenantPolicyContext{Tenant: "tenant-fixture", UserID: "fixture-user", Origin: "https://tenant.example", Root: wire(root.Rec, root.Sigs)}); err != nil {
		t.Fatal(err)
	}
	build := func(seq int64, b *record.PolicyBody) SignedRecord {
		b.Tenant = "tenant-fixture"
		b.Seq = seq
		b.IssuedAt = time.Now().UnixMilli() - 1000
		b.NotAfter = time.Now().UnixMilli() + 3600000
		b.Applies.Users = []string{"fixture-user"}
		r, err := record.Build(record.Header{Type: record.KindPolicy, LID: record.PolicyLID(b.Tenant), At: time.Now().UnixMilli(), Author: record.Author{KeyID: sig.KeyID(pub)}, Prov: record.ProvUser, Red: record.Redact{Profile: record.ProfileLocal}}, b)
		if err != nil {
			t.Fatal(err)
		}
		sg, err := sig.SignRecord(key, r.ID)
		if err != nil {
			t.Fatal(err)
		}
		return wire(r, []record.Signature{sg})
	}
	return key, build
}

func TestV3TenantPolicySignatureTamperHighWaterAndEnforcement(t *testing.T) {
	k := newKernel(t)
	ctx := context.Background()
	_, build := tenantFixture(t, k)
	b := &record.PolicyBody{Redaction: record.PolicyRedact{Shapes: []record.Shape{{Name: "private", RE2: "tenant-secret-[0-9]+"}}}}
	first := build(1, b)
	if _, err := k.s.Append(ctx, first); err != nil {
		t.Fatal(err)
	}
	r := k.execute("tenant-create", "local.create_task", map[string]any{"goal": "A tenant-secret-123 value"})
	text := k.release(r)
	if strings.Contains(text, "tenant-secret-123") || !strings.Contains(text, "REDACTED") {
		t.Fatal("tenant overlay not enforced", text)
	}
	var root string
	k.s.conn.QueryRowContext(ctx, "SELECT id FROM outcome_member WHERE op=?", r.op).Scan(&root)
	var h []byte
	k.s.conn.QueryRowContext(ctx, "SELECT header FROM record WHERE id=?", root).Scan(&h)
	var header record.Header
	json.Unmarshal(h, &header)
	if header.Pol != first.AdvisoryID {
		t.Fatal("missing signed policy provenance")
	}
	bad := first
	bad.Sigs = append([]record.Signature(nil), first.Sigs...)
	bad.Sigs[0].Value = strings.Repeat("A", 86)
	if _, err := k.s.Append(ctx, bad); Code(err) != "invalid_policy" {
		t.Fatal("invalid signature accepted", err)
	}
	conflict := build(1, &record.PolicyBody{})
	result, err := k.s.Append(ctx, conflict)
	if err != nil || result.State != "tamper" {
		t.Fatal(result, err)
	}
	if got := k.release(r); got != replay.Unavailable {
		t.Fatal("tamper allowed tenant readback", got)
	}
	if _, err = k.s.Append(ctx, first); err != nil {
		t.Fatal(err)
	}
	if got := k.release(r); got != replay.Unavailable {
		t.Fatal("same-id replay cleared latch")
	}
	higher := build(2, &record.PolicyBody{Kill: record.PolicyKill{CaptureTenantRepos: true}})
	if _, err = k.s.Append(ctx, higher); err != nil {
		t.Fatal(err)
	}
	if _, err = k.s.Append(ctx, first); Code(err) != "policy_rollback" {
		t.Fatal("rollback accepted", err)
	}
	_, err = k.e.Execute(ctx, k.h, k.sc, CallIdentity{SuppliedOpID: k.issued("kill-create")}, commandFor(t, "local.create_task", map[string]any{"goal": "blocked"}), ByteBudget{MaxBytes: 4096})
	if Code(err) != "policy_violation" {
		t.Fatal("capture kill did not stop admission", err)
	}
	var oldBody []byte
	k.s.conn.QueryRowContext(ctx, "SELECT body FROM tenant_policy WHERE id=?", first.AdvisoryID).Scan(&oldBody)
	if len(oldBody) != 0 {
		t.Fatal("old policy secret retained")
	}
	if err = k.s.LogoutTenant(ctx); err != nil {
		t.Fatal(err)
	}
	if got := k.release(r); got != replay.Unavailable {
		t.Fatal("logout allowed governed readback")
	}
}

func TestV3TenantTimeRollbackLatchPersistsAndOnlyAuthenticatedDateClears(t *testing.T) {
	k := newKernel(t)
	ctx := context.Background()
	_, build := tenantFixture(t, k)
	p := build(1, &record.PolicyBody{})
	if _, err := k.s.Append(ctx, p); err != nil {
		t.Fatal(err)
	}
	if err := k.s.write(ctx, func() error {
		k.s.policyClock.Now(time.Now().UnixMilli()+60000, time.Since(k.s.policyStart).Milliseconds())
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := k.s.write(ctx, func() error { _, err := k.s.tenant(ctx); return err }); err != nil {
		t.Fatal(err)
	}
	var floor int64
	var rollback bool
	if k.s.conn.QueryRowContext(ctx, "SELECT floor,rollback FROM trusted_time WHERE singleton=1").Scan(&floor, &rollback) != nil || !rollback {
		t.Fatal("rollback not durable")
	}
	k.e.Close()
	k.s.Close()
	st, err := Open(ctx, k.o)
	if err != nil {
		t.Fatal(err)
	}
	k.s = st
	if err = st.write(ctx, func() error {
		state, err := st.tenant(ctx)
		if err != nil {
			return err
		}
		if state.freshness != policy.RolledBack {
			t.Fatal("restart cleared rollback", state.freshness)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	read := st.PolicyTimeReading()
	date := floor / 1000 * 1000
	bad := policy.DateObservation{Date: date, RequestStartMono: read, ReceiptMono: read, ReceiptWall: time.Now().UnixMilli(), ConfiguredEndpoint: true, BoundLiveResponse: true, NoStore: true, DateCount: 1}
	if err = st.ObserveTenantDate(ctx, "https://tenant.example", bad); Code(err) != "untrusted_time" {
		t.Fatal("unauthenticated Date accepted", err)
	}
	bad.Authenticated = true
	bad.Date -= 100000
	read = st.PolicyTimeReading()
	bad.RequestStartMono = read
	bad.ReceiptMono = read
	if err = st.ObserveTenantDate(ctx, "https://tenant.example", bad); Code(err) != "untrusted_time" {
		t.Fatal("stale Date cleared rollback", err)
	}
	read = st.PolicyTimeReading()
	bad.Date = date
	bad.RequestStartMono = read
	bad.ReceiptMono = read
	if err = st.ObserveTenantDate(ctx, "https://tenant.example", bad); err != nil {
		t.Fatal("synchronized bounded Date refused", err)
	}
	if st.conn.QueryRowContext(ctx, "SELECT rollback FROM trusted_time WHERE singleton=1").Scan(&rollback) != nil || rollback {
		t.Fatal("valid Date did not clear latch")
	}
	if err = st.write(ctx, func() error {
		state, err := st.tenant(ctx)
		if err != nil {
			return err
		}
		if !state.effects.TenantReadback {
			t.Fatal("fresh authorized readback not restored")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestV3TenantReplacementAndLogoutScrubPhysicalPolicySecrets(t *testing.T) {
	k := newKernel(t)
	ctx := context.Background()
	_, build := tenantFixture(t, k)
	first := build(1, &record.PolicyBody{Redaction: record.PolicyRedact{Shapes: []record.Shape{{Name: "secret", RE2: "private-policy-pattern-702d8c3a"}}}})
	old, err := record.Parse(first.HeaderJCS, first.BodyJCS, first.AdvisoryID)
	if err != nil {
		t.Fatal(err)
	}
	salt := old.Body.(*record.PolicyBody).Salt
	if _, err = k.s.Append(ctx, first); err != nil {
		t.Fatal(err)
	}
	reader, err := sql.Open("sqlite", SQLiteURI(k.s.path, ""))
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	conn, err := reader.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err = conn.ExecContext(ctx, "BEGIN"); err != nil {
		t.Fatal(err)
	}
	var body []byte
	if conn.QueryRowContext(ctx, "SELECT body FROM tenant_policy WHERE id=?", first.AdvisoryID).Scan(&body) != nil {
		t.Fatal("reader snapshot")
	}
	next := build(2, &record.PolicyBody{})
	result, err := k.s.Append(ctx, next)
	if err != nil || result.Physical != "pending" {
		t.Fatal("busy reader falsely clean", result, err)
	}
	var state string
	k.s.conn.QueryRowContext(ctx, "SELECT state FROM scrub_job WHERE control=?", first.AdvisoryID).Scan(&state)
	if state != "pending" {
		t.Fatal("no durable cleanup retry")
	}
	if _, err = conn.ExecContext(ctx, "COMMIT"); err != nil {
		t.Fatal(err)
	}
	result, err = k.s.Append(ctx, next)
	if err != nil || result.Physical != "complete" {
		t.Fatal("exact policy replay did not finish cleanup", result, err)
	}
	physicalMissing := func(values ...string) {
		t.Helper()
		for _, suffix := range []string{"", "-wal", "-shm", "-journal"} {
			b, err := os.ReadFile(k.s.path + suffix)
			if os.IsNotExist(err) {
				continue
			}
			if err != nil {
				t.Fatal(err)
			}
			for _, value := range values {
				if bytes.Contains(b, []byte(value)) {
					t.Fatal("policy secret survived managed SQLite scrub", suffix)
				}
			}
		}
	}
	physicalMissing(salt, "private-policy-pattern-702d8c3a")
	current, _ := record.Parse(next.HeaderJCS, next.BodyJCS, next.AdvisoryID)
	nextSalt := current.Body.(*record.PolicyBody).Salt
	if err = k.s.LogoutTenant(ctx); err != nil {
		t.Fatal(err)
	}
	physicalMissing(nextSalt)
}

func TestV3TenantLogoutCannotBeAuthorizedByAnotherTenant(t *testing.T) {
	k := newKernel(t)
	ctx := context.Background()
	_, build := tenantFixture(t, k)
	first := build(1, &record.PolicyBody{})
	if _, err := k.s.Append(ctx, first); err != nil {
		t.Fatal(err)
	}
	original := k.execute("A-governed", "local.create_task", map[string]any{"goal": "tenant-A-private-81c123f5"})
	var id string
	k.s.conn.QueryRowContext(ctx, "SELECT id FROM outcome_member WHERE op=?", original.op).Scan(&id)
	if err := k.s.LogoutTenant(ctx); err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{64}, 32))
	pub := key.Public().(ed25519.PublicKey)
	root, err := sig.BuildKeyOp(record.KeyOpBody{Op: record.OpTenantKey, Subject: sig.KeyRefOf(pub, record.RolePolicy, ""), Genesis: "tenant-B"}, pub, "", time.Now().UnixMilli(), key)
	if err != nil {
		t.Fatal(err)
	}
	if err = k.s.InstallTenantPolicyContext(ctx, TenantPolicyContext{Tenant: "tenant-B", UserID: "fixture-user", Origin: "https://other.example", Root: wire(root.Rec, root.Sigs)}); err != nil {
		t.Fatal(err)
	}
	body := &record.PolicyBody{Tenant: "tenant-B", Seq: 1, IssuedAt: time.Now().UnixMilli() - 1000, NotAfter: time.Now().UnixMilli() + 3600000, Applies: record.PolicyApplies{Users: []string{"fixture-user"}}}
	recordB, err := record.Build(record.Header{Type: record.KindPolicy, LID: record.PolicyLID("tenant-B"), At: time.Now().UnixMilli(), Author: record.Author{KeyID: sig.KeyID(pub)}, Prov: record.ProvUser, Red: record.Redact{Profile: record.ProfileLocal}}, body)
	if err != nil {
		t.Fatal(err)
	}
	signature, _ := sig.SignRecord(key, recordB.ID)
	if _, err = k.s.Append(ctx, wire(recordB, []record.Signature{signature})); err != nil {
		t.Fatal(err)
	}
	for _, args := range []map[string]any{{"goal": "tenant-A-private-81c123f5"}, {"goal": "different candidate"}} {
		retry := k.execute("A-governed", "local.create_task", args)
		if text := k.release(retry); text != replay.Unavailable {
			t.Fatal("tenant B authorized A comparator/result", text)
		}
	}
	lookup := k.execute("B-lookup-A", "local.lookup_record", map[string]any{"record_id": id, "include_content": true})
	if text := k.release(lookup); strings.Contains(text, "tenant-A-private-81c123f5") || strings.Contains(text, id) {
		t.Fatal("cross-tenant lookup leaked", text)
	}
	snapshot, err := k.s.Snapshot(ctx, ReadRequest{IDs: []string{id}})
	if err != nil || len(snapshot.Entries) != 1 || len(snapshot.Entries[0].BodyJCS) != 0 {
		t.Fatal("inspection bypassed current policy", err)
	}
}

func TestV3EarlyValidationRefusalsRetireUnidentifiedScope(t *testing.T) {
	k := newKernel(t)
	ctx := context.Background()
	cmd := commandFor(t, "local.list_tasks", map[string]any{})
	for _, bad := range []string{"budget", "rpc", "op", "missing", "cursor"} {
		t.Run(bad, func(t *testing.T) {
			h, err := k.e.Authenticate(ctx, k.proof)
			if err != nil {
				t.Fatal(err)
			}
			sc, err := k.e.Resolve(ctx, h, IdentityInput{})
			if err != nil {
				t.Fatal(err)
			}
			call := CallIdentity{JSONRPCID: json.RawMessage(`1`)}
			budget := ByteBudget{MaxBytes: 4096}
			switch bad {
			case "budget":
				budget.MaxBytes = 1
			case "rpc":
				call.JSONRPCID = json.RawMessage(`{}`)
			case "op":
				call.SuppliedOpID = "contains forbidden spaces"
			case "missing":
				call.JSONRPCID = nil
			}
			if bad == "cursor" {
				_, err = k.e.Next(ctx, h, sc, call, "invalid cursor", budget)
			} else {
				_, err = k.e.Execute(ctx, h, sc, call, cmd, budget)
			}
			if err == nil {
				t.Fatal("invalid invocation accepted")
			}
			var n int
			if err = k.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM local_scope WHERE identity_kind='connection'").Scan(&n); err != nil || n != 0 {
				t.Fatal("refusal consumed durable ephemeral quota", n, err)
			}
			if len(k.e.clients) != 1 {
				t.Fatal("refusal retained active handle", len(k.e.clients))
			}
		})
	}
	// Identified connections preserve their live fallback retry identity even on
	// the same early validation refusal.
	if _, err := k.e.Execute(ctx, k.h, k.sc, CallIdentity{JSONRPCID: json.RawMessage(`1`)}, cmd, ByteBudget{MaxBytes: 1}); Code(err) != "invalid_budget" {
		t.Fatal(err)
	}
	if _, err := k.e.IssueOperationTokens(ctx, k.h); err != nil {
		t.Fatal("identified handle retired", err)
	}
}
