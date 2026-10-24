package store_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/disclosure"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/disclosuretext"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/store"
	"github.com/Telara-Labs/telara-memory/contract/record"
	"github.com/Telara-Labs/telara-memory/contract/replay"
)

// These cases exercise the public facade against the actual SQLite store.
// Synthetic preloaded authority proves this boundary, not installed bootstrap.
type disclosureExternalFixture struct {
	base    *captureFixture
	service *disclosure.Service
	admin   *disclosure.Administration
	client  *disclosure.Connection
	scope   disclosure.RequestScope
	proof   disclosure.CredentialProof
	epoch   int64
	ops     map[string]string
}

func newDisclosureExternalFixture(t *testing.T, native string, write bool) *disclosureExternalFixture {
	t.Helper()
	d := &disclosureExternalFixture{base: newCaptureFixture(t, native)}
	d.service = d.newService(t, d.base.s)
	var err error
	d.admin, err = d.service.Administration(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	writes := disclosure.TaskWriteGrant{}
	if write {
		writes = disclosure.TaskWriteGrant{
			Actions:       []disclosure.TaskMutation{disclosure.Checkpoint, disclosure.Complete, disclosure.Create, disclosure.Pause},
			Repos:         disclosure.AllLocalRepos(),
			AllowUnscoped: true,
		}
	}
	registered, err := d.admin.Register(context.Background(), disclosure.RegisterClient{
		AdminOpID: "register-external-client", ClientName: "External boundary fixture",
		ReadGrant:  disclosure.Grant{Repos: disclosure.AllLocalRepos(), Channels: []disclosure.Channel{disclosure.S}},
		TaskWrites: writes,
	})
	if err != nil {
		t.Fatal(err)
	}
	secret, err := registered.Secret.Take()
	if err != nil {
		t.Fatal(err)
	}
	d.proof = disclosure.CredentialProof{CredentialID: registered.CredentialID, Token: secret}
	d.epoch = registered.GrantEpoch
	d.connect(t, "first-conversation")
	t.Cleanup(func() {
		_ = d.client.Close()
		_ = d.service.Close()
		clear(d.proof.Token)
	})
	return d
}

func (d *disclosureExternalFixture) newService(t *testing.T, st *store.Store) *disclosure.Service {
	t.Helper()
	salt := bytes.Repeat([]byte{0x73}, record.SaltKeySize)
	defer clear(salt)
	material, err := disclosure.PreloadRuntimeMaterial(salt, d.base.key)
	if err != nil {
		t.Fatal(err)
	}
	defer material.Clear()
	svc, err := disclosure.New(context.Background(), st, disclosure.Config{
		OwnerGenesis: d.base.opts.PinnedGenesisID, MachineID: d.base.opts.LocalMachineID, MaxReplyBytes: 16384,
	}, material)
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

func (d *disclosureExternalFixture) connect(t *testing.T, conversation string) {
	t.Helper()
	var err error
	d.client, err = d.service.Authenticate(context.Background(), d.proof)
	if err != nil {
		t.Fatal(err)
	}
	d.scope, err = d.client.Resolve(context.Background(), disclosure.IdentityInput{ConversationHandle: conversation})
	if err != nil {
		t.Fatal(err)
	}
}

func (d *disclosureExternalFixture) reopen(t *testing.T) {
	t.Helper()
	if err := d.client.Close(); err != nil {
		t.Fatal(err)
	}
	if err := d.service.Close(); err != nil {
		t.Fatal(err)
	}
	if err := d.base.s.Close(); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(context.Background(), d.base.opts)
	if err != nil {
		t.Fatal(err)
	}
	d.base.s = st
	d.service = d.newService(t, st)
	d.admin, err = d.service.Administration(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	d.connect(t, "reopened-conversation")
}

func externalDisclosureCommand(t *testing.T, tool string, args any) disclosure.Command {
	t.Helper()
	raw, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	command, err := disclosure.DecodeCommand(tool, raw)
	if err != nil {
		t.Fatal(err)
	}
	return command
}

func (d *disclosureExternalFixture) call(t *testing.T, op string) disclosure.CallIdentity {
	t.Helper()
	if disclosuretext.ValidateIdentity(disclosuretext.ExternalOpID, op) != nil {
		return disclosure.CallIdentity{SuppliedOpID: op, JSONRPCID: json.RawMessage(`1`)}
	}
	if d.ops == nil {
		d.ops = map[string]string{}
	}
	if token := d.ops[op]; token != "" {
		return disclosure.CallIdentity{SuppliedOpID: token}
	}
	pool, err := d.client.IssueOperationTokens(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	used := map[string]bool{}
	for _, token := range d.ops {
		used[token] = true
	}
	for _, token := range pool {
		if !used[token] {
			d.ops[op] = token
			return disclosure.CallIdentity{SuppliedOpID: token}
		}
	}
	t.Fatal("test token pool exhausted")
	return disclosure.CallIdentity{}
}

func (d *disclosureExternalFixture) execute(t *testing.T, op string, command disclosure.Command) *disclosure.Reply {
	t.Helper()
	r, err := d.client.Execute(context.Background(), d.scope, d.call(t, op), command, disclosure.ByteBudget{MaxBytes: 4096})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func externalDisclosureText(t *testing.T, reply *disclosure.Reply) string {
	t.Helper()
	r, err := reply.Release(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if r.IsError || len(r.Content) != 1 || r.Content[0].Type != "text" {
		t.Fatal("release did not produce exactly one successful text channel")
	}
	wire, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var object map[string]json.RawMessage
	if json.Unmarshal(wire, &object) != nil || len(object) != 2 || object["content"] == nil || object["isError"] == nil {
		t.Fatal("release exposed an additional result channel")
	}
	return r.Content[0].Text
}

func (d *disclosureExternalFixture) records(t *testing.T) map[string]store.Entry {
	t.Helper()
	snapshot, err := d.base.s.Snapshot(context.Background(), store.ReadRequest{})
	if err != nil {
		t.Fatal(err)
	}
	out := make(map[string]store.Entry, len(snapshot.Entries))
	for _, entry := range snapshot.Entries {
		out[entry.ID] = entry
	}
	return out
}

func externalDisclosureTasks(t *testing.T, entries map[string]store.Entry) int {
	t.Helper()
	n := 0
	for _, entry := range entries {
		var h record.Header
		if json.Unmarshal(entry.HeaderJCS, &h) != nil {
			t.Fatal("invalid retained header")
		}
		if h.Type == record.KindTask {
			n++
		}
	}
	return n
}

func externalDisclosureOnlyTaskID(t *testing.T, entries map[string]store.Entry) string {
	t.Helper()
	var id string
	for _, entry := range entries {
		var h record.Header
		if json.Unmarshal(entry.HeaderJCS, &h) != nil {
			t.Fatal("invalid retained header")
		}
		if h.Type == record.KindTask {
			if id != "" {
				t.Fatal("fixture has more than one task")
			}
			id = h.Subj.TaskID
		}
	}
	if id == "" {
		t.Fatal("fixture has no task")
	}
	return id
}

func externalDisclosureSameRecords(t *testing.T, before, after map[string]store.Entry) {
	t.Helper()
	if len(before) != len(after) {
		t.Fatalf("record count changed from %d to %d", len(before), len(after))
	}
	for id, first := range before {
		second, exists := after[id]
		if !exists || !bytes.Equal(first.HeaderJCS, second.HeaderJCS) || !bytes.Equal(first.BodyJCS, second.BodyJCS) {
			t.Fatal("retry replaced or resealed a committed record")
		}
	}
}

var externalDisclosureItem = regexp.MustCompile(`(?m)^<item marker="[^"]+">$`)

func TestDisclosurePublicReplayReopenKeepsSignedMutation(t *testing.T) {
	d := newDisclosureExternalFixture(t, "native fixture", true)
	goal := strings.Repeat("alpha context ", 200) + "originalmiddle" + strings.Repeat("omega context ", 200)
	args := map[string]any{"name": "Replay fixture", "goal": goal}
	command := externalDisclosureCommand(t, "local.create_task", args)
	prepared := d.execute(t, "stable-create-operation", command)
	encoded, err := json.Marshal(prepared)
	if err != nil || string(encoded) != "{}" {
		t.Fatal("a prepared reply exposed fields before Release")
	}
	before := d.records(t)
	if externalDisclosureTasks(t, before) != 1 {
		t.Fatal("actual builder did not create exactly one task")
	}
	// Simulate a lost response, process restart and a newly resolved scope.
	d.reopen(t)
	text := externalDisclosureText(t, d.execute(t, "stable-create-operation", command))
	if text == replay.Unavailable || len(externalDisclosureItem.FindAllString(text, -1)) == 0 {
		t.Fatal("durable retry failed to render the original available mutation")
	}
	externalDisclosureSameRecords(t, before, d.records(t))
	args["goal"] = strings.Replace(goal, "originalmiddle", "differentmiddle", 1)
	changed := externalDisclosureCommand(t, "local.create_task", args)
	_, err = d.client.Execute(context.Background(), d.scope, d.call(t, "stable-create-operation"), changed, disclosure.ByteBudget{MaxBytes: 4096})
	if err == nil || !strings.Contains(err.Error(), "op_conflict") {
		t.Fatal("changed full arguments did not conflict with the original operation")
	}
	externalDisclosureSameRecords(t, before, d.records(t))
}

func TestDisclosurePublicRevocationFencesPreparedBytesAcrossHandles(t *testing.T) {
	d := newDisclosureExternalFixture(t, "native fixture", true)
	command := externalDisclosureCommand(t, "local.create_task", map[string]any{"name": "Revocation fixture", "goal": "revocationprivatebodyneedle"})
	prepared := d.execute(t, "prepare-before-revocation", command)
	if externalDisclosureTasks(t, d.records(t)) != 1 {
		t.Fatal("mutation was not recorded before revocation")
	}
	second, err := store.Open(context.Background(), d.base.opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = second.Close() })
	secondService := d.newService(t, second)
	t.Cleanup(func() { _ = secondService.Close() })
	admin, err := secondService.Administration(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = admin.RevokeCredential(context.Background(), "revoke-before-release", d.proof.CredentialID, d.epoch); err != nil {
		t.Fatal(err)
	}
	result, err := prepared.Release(context.Background())
	if err == nil || len(result.Content) != 0 {
		t.Fatal("a revoked credential released previously prepared data")
	}
	if _, err = d.service.Authenticate(context.Background(), d.proof); err == nil {
		t.Fatal("revocation did not invalidate fresh authentication")
	}
	if externalDisclosureTasks(t, d.records(t)) != 1 {
		t.Fatal("revocation incorrectly undid the already committed mutation")
	}
}

func TestDisclosurePublicNativeCompletenessCannotBeClaimed(t *testing.T) {
	const needle = "nativeonlyneedlezz"
	d := newDisclosureExternalFixture(t, needle, true)
	if _, err := d.base.s.Capture(context.Background(), d.base.req, func(*store.CaptureTxn) (store.CommitPlan, error) {
		return d.base.plan, nil
	}); err != nil {
		t.Fatal(err)
	}
	search := externalDisclosureCommand(t, "local.lexical_search", map[string]any{"query": needle})
	text := externalDisclosureText(t, d.execute(t, "search-uncertified-native", search))
	if len(externalDisclosureItem.FindAllString(text, -1)) != 0 || !strings.Contains(text, "Recorded selection contains no items.") {
		t.Fatal("native metadata manufactured a positively complete fresh hit")
	}
	lookup := externalDisclosureCommand(t, "local.lookup_record", map[string]any{"record_id": d.base.chunk.AdvisoryID})
	quoted := externalDisclosureText(t, d.execute(t, "quote-uncertified-native", lookup))
	if !strings.Contains(quoted, needle) || len(externalDisclosureItem.FindAllString(quoted, -1)) == 0 {
		t.Fatal("fresh exclusion incorrectly removed separately permitted quoted source")
	}
}

func TestDisclosurePublicIdentityRejectionLeavesNoManagedTrace(t *testing.T) {
	d := newDisclosureExternalFixture(t, "native fixture", true)
	command := externalDisclosureCommand(t, "local.create_task", map[string]any{"goal": "Identity positive control"})
	before := d.records(t)
	bad := []string{"ghp_" + strings.Repeat("A", 32), "glpat-" + strings.Repeat("B", 24), "sk-" + strings.Repeat("C", 24)}
	for _, value := range bad {
		call := d.call(t, value)
		_, err := d.client.Execute(context.Background(), d.scope, call, command, disclosure.ByteBudget{MaxBytes: 4096})
		if err == nil || err.Error() != "unsafe_identity" {
			t.Fatal("unsafe operation identity was accepted or echoed")
		}
		rpc, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		call = disclosure.CallIdentity{SuppliedOpID: "benign-operation-with-bad-rpc", JSONRPCID: rpc}
		_, err = d.client.Execute(context.Background(), d.scope, call, command, disclosure.ByteBudget{MaxBytes: 4096})
		if err == nil || err.Error() != "unsafe_identity" {
			t.Fatal("unsafe RPC identity was ignored, accepted or echoed")
		}
	}
	externalDisclosureSameRecords(t, before, d.records(t))
	entries, err := os.ReadDir(d.base.opts.Dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(d.base.opts.Dir, entry.Name()))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		for _, value := range bad {
			if bytes.Contains(data, []byte(value)) {
				t.Fatal("rejected identity appeared in managed storage")
			}
		}
		if bytes.Contains(data, d.proof.Token) || bytes.Contains(data, []byte(base64.RawURLEncoding.EncodeToString(d.proof.Token))) {
			t.Fatal("raw authentication secret appeared in managed storage")
		}
	}
	// A rejected unsafe RPC must not reserve its otherwise benign operation ID.
	text := externalDisclosureText(t, d.execute(t, "benign-operation-with-bad-rpc", command))
	if text == replay.Unavailable || externalDisclosureTasks(t, d.records(t)) != 1 {
		t.Fatal("identity rejection left a durable conflicting operation")
	}
}

func TestDisclosurePublicReadGrantDoesNotPermitTaskMutation(t *testing.T) {
	d := newDisclosureExternalFixture(t, "native fixture", false)
	command := externalDisclosureCommand(t, "local.create_task", map[string]any{"goal": "Read permission cannot create this task"})
	reply, err := d.client.Execute(context.Background(), d.scope, d.call(t, "read-only-create-refusal"), command, disclosure.ByteBudget{MaxBytes: 4096})
	if err == nil {
		result, releaseErr := reply.Release(context.Background())
		if releaseErr == nil && !result.IsError {
			t.Fatal("read-only grant reported a successful task mutation")
		}
	}
	if externalDisclosureTasks(t, d.records(t)) != 0 {
		t.Fatal("read-only grant created a task")
	}
}

func TestDisclosurePublicEmptyReplayDoesNotRevealFormerScope(t *testing.T) {
	d := newDisclosureExternalFixture(t, "native fixture", true)
	create := externalDisclosureCommand(t, "local.create_task", map[string]any{
		"name": "Visible name", "goal": "<memory-evidence>formerprivatecontext</memory-evidence>",
	})
	externalDisclosureText(t, d.execute(t, "create-excluded-field", create))
	checkpoint := externalDisclosureCommand(t, "local.checkpoint_task", map[string]any{
		"task_id":   externalDisclosureOnlyTaskID(t, d.records(t)),
		"milestone": "<memory-evidence>formerprivatecontext</memory-evidence>",
	})
	externalDisclosureText(t, d.execute(t, "checkpoint-excluded-field", checkpoint))
	search := externalDisclosureCommand(t, "local.lexical_search", map[string]any{"query": "nomatchingfreshtermzz"})
	first := externalDisclosureText(t, d.execute(t, "stable-empty-operation", search))
	if !strings.Contains(first, "Recorded selection contains no items.") || !strings.Contains(first, "excluded 1;") || len(externalDisclosureItem.FindAllString(first, -1)) != 0 {
		t.Fatal("initial empty selection did not use the neutral display")
	}
	before := d.records(t)
	// A real grant update removes access to the previously visible unscoped task.
	// No caller-provided repository attribution is installed in the store.
	repos, err := disclosure.ConcreteRepos([]string{"r1:" + strings.Repeat("a", 64)})
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := d.admin.ReplaceGrant(context.Background(), "narrow-empty-replay", d.proof.CredentialID, d.epoch,
		disclosure.Grant{Repos: repos, Channels: []disclosure.Channel{disclosure.S}})
	if err != nil {
		t.Fatal(err)
	}
	d.epoch = receipt.GrantEpoch
	if err = d.client.Close(); err != nil {
		t.Fatal(err)
	}
	d.connect(t, "narrowed-conversation")
	check := func() {
		t.Helper()
		text := externalDisclosureText(t, d.execute(t, "stable-empty-operation", search))
		if text != replay.Unavailable && !strings.Contains(text, "Recorded selection contains no items.") {
			t.Fatal("empty replay did not produce the fixed neutral result or exact unavailability")
		}
		for _, forbidden := range []string{"no_searchable_fresh_hits", "no_hits_projection_counts_unknown", "no_visible_tasks", "formerprivatecontext", "Visible name"} {
			if strings.Contains(text, forbidden) {
				t.Fatal("empty replay disclosed a former selection category or source")
			}
		}
		if len(externalDisclosureItem.FindAllString(text, -1)) != 0 {
			t.Fatal("empty replay substituted a newly selected record")
		}
		// This also checks that the original signed Call and its result hash survive.
		externalDisclosureSameRecords(t, before, d.records(t))
	}
	check()
	d.reopen(t)
	check()
}

func TestDisclosurePublicGeneratedNameInheritsFullGoalClassification(t *testing.T) {
	d := newDisclosureExternalFixture(t, "native fixture", true)
	goal := strings.Repeat("generatedparentneedle ordinary context ", 8) + "<memory-evidence>late framed source</memory-evidence>"
	create := externalDisclosureCommand(t, "local.create_task", map[string]any{"goal": goal})
	externalDisclosureText(t, d.execute(t, "create-generated-name", create))
	search := externalDisclosureCommand(t, "local.list_tasks", map[string]any{"query": "generatedparentneedle"})
	check := func(op string) {
		t.Helper()
		text := externalDisclosureText(t, d.execute(t, op, search))
		if len(externalDisclosureItem.FindAllString(text, -1)) != 0 || !strings.Contains(text, "Recorded selection contains no items.") {
			t.Fatal("generated name discarded the marker beyond its first hundred runes")
		}
	}
	check("search-generated-name-first")
	d.reopen(t)
	check("search-generated-name-reopened")
	// Ordinary Unicode remains searchable when positively complete builder fields
	// contain no managed frame. Exclusion must not become a non-ASCII ban.
	const title = "Résumé cafécontinuity"
	create = externalDisclosureCommand(t, "local.create_task", map[string]any{"name": title, "goal": "Ordinary complete source"})
	externalDisclosureText(t, d.execute(t, "create-unicode-name", create))
	search = externalDisclosureCommand(t, "local.list_tasks", map[string]any{"query": "cafécontinuity"})
	text := externalDisclosureText(t, d.execute(t, "search-unicode-name", search))
	if len(externalDisclosureItem.FindAllString(text, -1)) != 1 || !strings.Contains(text, title) {
		t.Fatalf("positive complete ordinary Unicode source was excluded or lost: %q", text)
	}
}

func TestDisclosurePublicVisibleACKAndPageReplayAcrossReopen(t *testing.T) {
	d := newDisclosureExternalFixture(t, "native fixture", true)
	create := externalDisclosureCommand(t, "local.create_task", map[string]any{"goal": "Paging fixture"})
	externalDisclosureText(t, d.execute(t, "create-paging-task", create))
	task := externalDisclosureOnlyTaskID(t, d.records(t))
	for i := 0; i < 3; i++ {
		checkpoint := externalDisclosureCommand(t, "local.checkpoint_task", map[string]any{
			"task_id": task, "milestone": fmt.Sprintf("publicpagecanary checkpoint %d", i),
		})
		externalDisclosureText(t, d.execute(t, fmt.Sprintf("public-page-checkpoint-%d", i), checkpoint))
	}
	search := externalDisclosureCommand(t, "local.lexical_search", map[string]any{"query": "publicpagecanary", "resource_types": []string{"checkpoint"}, "limit": 1})
	first := externalDisclosureText(t, d.execute(t, "public-page-one", search))
	marker := regexp.MustCompile(`(?m)^<item marker="([a-f0-9]{64})@([a-f0-9]{64})">$`).FindAllStringSubmatch(first, -1)
	nonce := regexp.MustCompile(`(?m)^<memory-evidence nonce="([a-f0-9]{20})">$`).FindStringSubmatch(first)
	cursor := regexp.MustCompile(`(?m)^    \| continuation ([a-f0-9-]{36})$`).FindStringSubmatch(first)
	if len(marker) != 1 || len(nonce) != 2 || len(cursor) != 2 {
		t.Fatal("actual one-item page did not expose a bounded marker, nonce and continuation")
	}
	ctx := context.Background()
	if _, err := d.client.Acknowledge(ctx, disclosure.ACK{Nonce: nonce[1]}); err == nil || err.Error() != "invalid_ack" {
		t.Fatal("partial visible ACK was accepted")
	}
	ack := disclosure.ACK{Nonce: nonce[1], Items: []disclosure.ItemMarker{{LID: marker[0][1], ID: marker[0][2]}}}
	receipt, err := d.client.Acknowledge(ctx, ack)
	if err != nil || receipt.Status != "confirmed" {
		t.Fatal("visible exact ACK was refused", err)
	}
	receipt, err = d.client.Acknowledge(ctx, ack)
	if err != nil || receipt.Status != "already_confirmed" {
		t.Fatal("visible exact ACK was not idempotent", err)
	}
	call := d.call(t, "public-page-two")
	prepared, err := d.client.Next(ctx, d.scope, call, cursor[1], disclosure.ByteBudget{MaxBytes: 4096})
	if err != nil {
		t.Fatal("own Release or ACK prematurely expired the continuation", err)
	}
	second := externalDisclosureText(t, prepared)
	secondMarkers := externalDisclosureItem.FindAllString(second, -1)
	if len(secondMarkers) != 1 || secondMarkers[0] == marker[0][0] {
		t.Fatal("next page did not advance the frozen selection")
	}
	before := d.records(t)
	if _, err = d.client.Next(ctx, d.scope, d.call(t, "other-page-two"), cursor[1], disclosure.ByteBudget{MaxBytes: 4096}); err == nil || err.Error() != "cursor_consumed" {
		t.Fatal("a second operation consumed the same cursor")
	}
	d.reopen(t)
	prepared, err = d.client.Next(ctx, d.scope, call, cursor[1], disclosure.ByteBudget{MaxBytes: 4096})
	if err != nil {
		t.Fatal("durable page operation was lost after restart", err)
	}
	retried := externalDisclosureText(t, prepared)
	retriedMarkers := externalDisclosureItem.FindAllString(retried, -1)
	if len(retriedMarkers) != 1 || retriedMarkers[0] != secondMarkers[0] {
		t.Fatal("retry resampled or lost the original committed page")
	}
	externalDisclosureSameRecords(t, before, d.records(t))
}

func TestDisclosurePublicAuthenticationScopeBindingAndRotation(t *testing.T) {
	d := newDisclosureExternalFixture(t, "native fixture", true)
	ctx := context.Background()
	wrongToken := bytes.Clone(d.proof.Token)
	defer clear(wrongToken)
	wrongToken[0] ^= 1
	for _, proof := range []disclosure.CredentialProof{
		{CredentialID: d.proof.CredentialID, Token: wrongToken},
		{CredentialID: "00000000-0000-4000-8000-000000000001", Token: d.proof.Token},
	} {
		if _, err := d.service.Authenticate(ctx, proof); err == nil || err.Error() != "unauthorized" {
			t.Fatal("invalid credential proofs did not share the fixed refusal")
		}
	}
	other := d.newService(t, d.base.s)
	defer other.Close()
	client, err := other.Authenticate(ctx, d.proof)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	scope, err := client.Resolve(ctx, disclosure.IdentityInput{ConversationHandle: "other-service-conversation"})
	if err != nil {
		t.Fatal(err)
	}
	command := externalDisclosureCommand(t, "local.create_task", map[string]any{"goal": "Rotation fixture"})
	before := d.records(t)
	if _, err = d.client.Execute(ctx, scope, d.call(t, "foreign-service-scope"), command, disclosure.ByteBudget{MaxBytes: 4096}); err == nil {
		t.Fatal("scope from another service crossed the opaque capability boundary")
	}
	externalDisclosureSameRecords(t, before, d.records(t))
	prepared := d.execute(t, "prepare-before-rotation", command)
	oldToken := d.proof.Token
	defer clear(oldToken)
	rotated, err := d.admin.RotateCredential(ctx, "rotate-public-credential", d.proof.CredentialID, d.epoch)
	if err != nil {
		t.Fatal(err)
	}
	newToken, err := rotated.Secret.Take()
	if err != nil {
		t.Fatal(err)
	}
	if repeated, err := rotated.Secret.Take(); err == nil || len(repeated) != 0 {
		t.Fatal("rotation returned its authentication secret more than once")
	}
	if _, err = d.service.Authenticate(ctx, d.proof); err == nil || err.Error() != "unauthorized" {
		t.Fatal("rotated old token remained valid")
	}
	result, err := prepared.Release(ctx)
	if err == nil || len(result.Content) != 0 {
		t.Fatal("old connection released prepared bytes after credential rotation")
	}
	if err = d.client.Close(); err != nil {
		t.Fatal(err)
	}
	d.proof = disclosure.CredentialProof{CredentialID: rotated.CredentialID, Token: newToken}
	d.epoch = rotated.GrantEpoch
	d.connect(t, "rotated-conversation")
	list := externalDisclosureCommand(t, "local.list_tasks", map[string]any{})
	if len(externalDisclosureItem.FindAllString(externalDisclosureText(t, d.execute(t, "read-after-rotation", list)), -1)) != 1 {
		t.Fatal("new valid token lost the committed pre-rotation task")
	}
}

func TestDisclosurePublicAdministrativeReplayAndWriteActionCAS(t *testing.T) {
	d := newDisclosureExternalFixture(t, "native fixture", true)
	ctx := context.Background()
	create := externalDisclosureCommand(t, "local.create_task", map[string]any{"goal": "Action grant fixture"})
	externalDisclosureText(t, d.execute(t, "create-action-task", create))
	task := externalDisclosureOnlyTaskID(t, d.records(t))
	request := disclosure.RegisterClient{AdminOpID: "register-lost-secret", ClientName: "Lost secret fixture", ReadGrant: disclosure.Grant{Repos: disclosure.AllLocalRepos(), Channels: []disclosure.Channel{disclosure.S}}}
	registered, err := d.admin.Register(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := registered.Secret.Take()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(secret)
	replayed, err := d.admin.Register(ctx, request)
	if err == nil || err.Error() != "secret_unavailable_rotate_required" || replayed.CredentialID != registered.CredentialID || replayed.Secret != nil {
		t.Fatal("registration retry duplicated a credential or disclosed its old secret")
	}
	writes := disclosure.TaskWriteGrant{Actions: []disclosure.TaskMutation{disclosure.Pause}, Repos: disclosure.AllLocalRepos(), AllowUnscoped: true}
	priorEpoch := d.epoch
	first, err := d.admin.ReplaceTaskWrites(ctx, "restrict-public-actions", d.proof.CredentialID, priorEpoch, writes)
	if err != nil {
		t.Fatal(err)
	}
	again, err := d.admin.ReplaceTaskWrites(ctx, "restrict-public-actions", d.proof.CredentialID, priorEpoch, writes)
	if err != nil || again.CredentialID != first.CredentialID || again.GrantEpoch != first.GrantEpoch || first.Status != "changed" || again.Status != "already_recorded" {
		t.Fatal("administrative retry changed its original credential or epoch", err)
	}
	changed := writes
	changed.Actions = []disclosure.TaskMutation{disclosure.Checkpoint}
	if _, err = d.admin.ReplaceTaskWrites(ctx, "restrict-public-actions", d.proof.CredentialID, priorEpoch, changed); err == nil || err.Error() != "op_conflict" {
		t.Fatal("changed administrative retry replaced the accepted action set")
	}
	if _, err = d.admin.ReplaceTaskWrites(ctx, "stale-public-actions", d.proof.CredentialID, priorEpoch, writes); err == nil || err.Error() != "stale_grant" {
		t.Fatal("a stale independent action update bypassed epoch CAS")
	}
	confirmed, err := d.admin.ReplaceTaskWrites(ctx, "confirm-current-public-actions", d.proof.CredentialID, first.GrantEpoch, writes)
	if err != nil || confirmed.GrantEpoch != first.GrantEpoch+1 {
		t.Fatal("administrative retry secretly advanced its credential epoch", err)
	}
	d.epoch = confirmed.GrantEpoch
	if err = d.client.Close(); err != nil {
		t.Fatal(err)
	}
	d.connect(t, "restricted-action-conversation")
	before := d.records(t)
	checkpoint := externalDisclosureCommand(t, "local.checkpoint_task", map[string]any{"task_id": task, "milestone": "Forbidden action"})
	for i, command := range []disclosure.Command{create, checkpoint} {
		if _, err = d.client.Execute(ctx, d.scope, d.call(t, fmt.Sprintf("denied-action-%d", i)), command, disclosure.ByteBudget{MaxBytes: 4096}); err == nil || err.Error() != "write_not_permitted" {
			t.Fatal("ungranted task action was accepted")
		}
	}
	externalDisclosureSameRecords(t, before, d.records(t))
	pause := externalDisclosureCommand(t, "local.pause_task", map[string]any{"task_id": task, "resume_context": "Allowed pause", "token_estimate": 0})
	externalDisclosureText(t, d.execute(t, "allowed-pause-action", pause))
}

func TestDisclosurePublicLegacyAttributionAndTypedMutationReplay(t *testing.T) {
	d := newDisclosureExternalFixture(t, "native fixture", true)
	const legacyTask = "36333333-3333-4333-8333-333333333333"
	legacy, err := record.Build(record.Header{
		Type: record.KindTask, LID: record.TaskLID(d.base.opts.PinnedGenesisID, legacyTask),
		Author: record.Author{KeyID: d.base.opts.PinnedGenesisID, MachineID: d.base.opts.LocalMachineID},
		At:     1761150000100, Prov: record.ProvMCPExplicit, Subj: record.Subject{TaskID: legacyTask}, Red: record.Redact{Profile: record.ProfileLocal}, Op: record.H("external-legacy-fixture", legacyTask),
	}, &record.TaskBody{Name: "Legacy fixture", Goal: "Signed legacy task", Status: "active"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.base.s.Append(context.Background(), extensionInput(t, legacy, d.base.key)); err != nil {
		t.Fatal(err)
	}
	before := d.records(t)
	pause := externalDisclosureCommand(t, "local.pause_task", map[string]any{"task_id": legacyTask, "resume_context": "Claimed legacy write", "token_estimate": 0})
	if _, err = d.client.Execute(context.Background(), d.scope, d.call(t, "deny-legacy-write"), pause, disclosure.ByteBudget{MaxBytes: 4096}); err == nil || err.Error() != "write_not_permitted" {
		t.Fatal("signed legacy identity fabricated trusted task-write attribution")
	}
	externalDisclosureSameRecords(t, before, d.records(t))
	create := externalDisclosureCommand(t, "local.create_task", map[string]any{"goal": "Typed mutation fixture"})
	externalDisclosureText(t, d.execute(t, "create-typed-task", create))
	tasks := d.records(t)
	delete(tasks, legacy.ID)
	task := externalDisclosureOnlyTaskID(t, tasks)
	checkpoint := externalDisclosureCommand(t, "local.checkpoint_task", map[string]any{"task_id": task, "milestone": "Typed milestone", "task_tree": []map[string]any{{"step": "Verified fixture step", "status": "done"}}})
	externalDisclosureText(t, d.execute(t, "typed-checkpoint", checkpoint))
	pause = externalDisclosureCommand(t, "local.pause_task", map[string]any{"task_id": task, "resume_context": "Typed resume", "progress_notes": "Typed progress", "token_estimate": 0})
	externalDisclosureText(t, d.execute(t, "typed-pause", pause))
	args := map[string]any{"task_id": task, "changes_made": []string{"Typed change"}, "token_estimate": 0}
	complete := externalDisclosureCommand(t, "local.complete_task", args)
	externalDisclosureText(t, d.execute(t, "typed-complete", complete))
	before = d.records(t)
	d.reopen(t)
	externalDisclosureText(t, d.execute(t, "typed-complete", complete))
	externalDisclosureSameRecords(t, before, d.records(t))
	args["final_summary"] = ""
	changed := externalDisclosureCommand(t, "local.complete_task", args)
	if _, err = d.client.Execute(context.Background(), d.scope, d.call(t, "typed-complete"), changed, disclosure.ByteBudget{MaxBytes: 4096}); err == nil || err.Error() != "op_conflict" {
		t.Fatal("absent and explicitly empty conclusion arguments lost their distinction")
	}
	externalDisclosureSameRecords(t, before, d.records(t))
}
