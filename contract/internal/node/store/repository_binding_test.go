//go:build linux || darwin

package store

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Telara-Labs/hilo/contract/record"
	"github.com/Telara-Labs/hilo/contract/sig"
)

// Bound fixture records enter through Capture, so the producer guard and
// durable association run. Actual native-reader attribution has its own capture
// component test; no manual repo record substitutes for that product proof.
func enrolledProducer(t *testing.T) (*producerFixture, RepositoryBinding, []string) {
	t.Helper()
	ctx := context.Background()
	f := newProducer(t, "repository source fixture")
	f.commit()
	root, remote := repositoryProject(t)
	b, err := f.w.s.EnrollRepository(ctx, RepositoryEnrollment{Observation: f.plan.Next.SessionPageIDs[0].ID, ProjectRoot: root, Remote: remote})
	if err != nil {
		t.Fatal(err)
	}
	f.q.RepositoryBinding, f.q.RepositoryGeneration, f.q.Repository = b.ID, b.Generation, &record.RepoRef{ID: b.Repo, Remote: b.Remote}
	f.q.ExpectedVersion = 1
	var old []SignedRecord = append([]SignedRecord(nil), f.plan.NewRecords...)
	for i, in := range old {
		r, err := record.Parse(in.HeaderJCS, in.BodyJCS, in.AdvisoryID)
		if err != nil {
			t.Fatal(err)
		}
		h := r.Header
		switch body := r.Body.(type) {
		case *record.ChunkBody:
			body.Salt = ""
		case *record.SessionBody:
			body.Salt = ""
		}
		h.Subj.RepoID = b.Repo
		if sb, ok := r.Body.(*record.SessionBody); ok {
			sb.Repo = &record.RepoRef{ID: b.Repo, Remote: b.Remote}
			sb.Chunks = append(append([]string(nil), sb.Chunks...), f.plan.NewRecords[0].AdvisoryID)
			h.Links.Prev = in.AdvisoryID
			h.Links.Supersedes = []string{in.AdvisoryID}
		}
		next, err := record.Build(h, r.Body)
		if err != nil {
			t.Fatal(err)
		}
		sg, err := sig.SignRecord(f.w.key, next.ID)
		if err != nil {
			t.Fatal(err)
		}
		f.plan.NewRecords[i] = wire(next, []record.Signature{sg})
	}
	f.plan.Next.LastSourceRecordIDs = []string{f.plan.NewRecords[0].AdvisoryID}
	f.plan.Next.SessionPageIDs = []PageRef{{0, f.plan.NewRecords[1].AdvisoryID}}
	receipt := f.commit()
	ids := []string{}
	for _, ref := range receipt.ActualRecordRefs {
		ids = append(ids, ref.ID)
	}
	return f, b, ids
}
func TestRepositoryBindingCurrentnessAndUnboundCapturePreserved(t *testing.T) {
	ctx := context.Background()
	f, b, ids := enrolledProducer(t)
	k := newKernelForWorld(f.w)
	repos, _ := ConcreteRepos([]string{b.Repo})
	reg, err := k.a.RegisterRepository(ctx, RegisterClient{AdminOpID: "repository-test-current", ClientName: "Repository fixture", ReadGrant: Grant{Repos: repos, Channels: []Channel{S}}, TaskWrites: TaskWriteGrant{Repos: repos, Actions: []TaskMutation{Create, Checkpoint}}}, b.ID, b.Generation)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := reg.Secret.Take()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(secret)
	h, err := k.e.Authenticate(ctx, CredentialProof{reg.CredentialID, secret})
	if err != nil {
		t.Fatal(err)
	}
	sc, err := k.e.Resolve(ctx, h, IdentityInput{ConversationHandle: "repo-current"})
	if err != nil {
		t.Fatal(err)
	}
	r, err := k.e.Execute(ctx, h, sc, CallIdentity{JSONRPCID: json.RawMessage(`1`)}, commandFor(t, "local.create_task", map[string]any{"goal": "bound repository task"}), ByteBudget{MaxBytes: 8192})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = k.e.Release(ctx, h, r); err != nil {
		t.Fatal(err)
	}
	var task string
	if err = f.w.s.conn.QueryRowContext(ctx, "SELECT task FROM outcome_task WHERE credential=? AND op=?", r.credential, r.op).Scan(&task); err != nil {
		t.Fatal(err)
	}
	var boundTask string
	for _, e := range f.w.snapshot().Entries {
		rec, err := record.Parse(e.HeaderJCS, e.BodyJCS, e.ID)
		if err == nil && rec.Header.Type == record.KindTask && rec.Header.Subj.TaskID == task {
			if rec.Header.Subj.RepoID != b.Repo {
				t.Fatal("task header unbound")
			}
			boundTask = e.ID
		}
	}
	if boundTask == "" {
		t.Fatal("bound task absent")
	}
	ids = append(ids, boundTask)
	snapshot := f.w.snapshot()
	copies := map[string]SignedRecord{}
	for _, e := range snapshot.Entries {
		copies[e.ID] = e.SignedRecord
	}
	controls, err := f.w.s.RevokeRepository(ctx, b.ID, worldSigner{f.w.key})
	if err != nil || len(controls) == 0 {
		t.Fatal(controls, err)
	}
	if _, err = k.e.Resolve(ctx, h, IdentityInput{}); err == nil {
		t.Fatal("retired credential resolved")
	}
	for _, id := range ids {
		if _, err = f.w.s.Append(ctx, copies[id]); err != nil {
			t.Fatal("same id replay", err)
		}
	}
	snap := f.w.snapshot()
	if original := find(snap, b.Observation); original.State != "live" || len(original.BodyJCS) == 0 {
		t.Fatal("unbound observation was retracted")
	}
	for _, id := range ids {
		e := find(snap, id)
		if e.State == "live" || len(e.BodyJCS) > 0 {
			t.Fatal("bound replay revived", id)
		}
	}
	// No fallback to another imported repo proof can strip the local association.
	if _, err = f.w.s.ImportBundle(ctx, BundleImport{LocalKeyID: f.w.o.PinnedGenesisID, Data: []SignedRecord{copies[boundTask]}}); err != nil {
		t.Fatal(err)
	}
	if e := find(f.w.snapshot(), boundTask); e.State == "live" {
		t.Fatal("same-id bundle stripped local fence")
	}
	if _, err = f.w.s.RevokeRepository(ctx, b.ID, worldSigner{f.w.key}); err != nil {
		t.Fatal("repeat retirement", err)
	}
}

func TestRepositoryBindingSourceCurrentnessRefusesFallback(t *testing.T) {
	for _, mode := range []string{"config-change", "observation-retracted", "generation", "source", "session", "empty-request", "cross-repo-grant"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			f, b, _ := enrolledProducer(t)
			switch mode {
			case "config-change":
				if err := os.WriteFile(filepath.Join(b.Root, ".git", "config"), []byte("[remote \"origin\"]\nurl=git@github.com:other/project.git\n"), 0644); err != nil {
					t.Fatal(err)
				}
			case "observation-retracted":
				f.w.append(f.w.control(721, record.KindRetraction, b.Observation))
			case "generation":
				f.q.RepositoryGeneration++
			case "source":
				f.q.Occurrence.Source = record.H("unassociated-source")
			case "session":
				f.q.Occurrence.SessionKey = "sk1:" + record.H("unassociated-session")
			case "empty-request":
				f.q.RepositoryBinding = ""
				f.q.RepositoryGeneration = 0
				f.q.Repository = nil
			case "cross-repo-grant":
				k := newKernelForWorld(f.w)
				other, _ := record.RepoID("github.com/other/project")
				repos, _ := ConcreteRepos([]string{other})
				if _, err := k.a.RegisterRepository(ctx, RegisterClient{AdminOpID: "wrong-repo-context", ClientName: "Wrong repository", ReadGrant: Grant{Repos: repos, Channels: []Channel{S}}, TaskWrites: TaskWriteGrant{Repos: repos, Actions: []TaskMutation{Create}}}, b.ID, b.Generation); err == nil {
					t.Fatal("cross-repo credential registered")
				}
				return
			}
			f.q.ExpectedVersion = 2
			called := false
			_, err := f.w.s.Capture(ctx, f.q, func(*CaptureTxn) (CommitPlan, error) { called = true; return f.plan, nil })
			if err == nil || called {
				t.Fatal("invalid context reached producer", mode, called, err)
			}
		})
	}
}

func TestRepositoryRetiredOccurrenceFenceBeforeFirstBoundCapture(t *testing.T) {
	ctx := context.Background()
	f := newProducer(t, "original unbound observation")
	f.commit()
	root, remote := repositoryProject(t)
	b, err := f.w.s.EnrollRepository(ctx, RepositoryEnrollment{Observation: f.plan.Next.SessionPageIDs[0].ID, ProjectRoot: root, Remote: remote})
	if err != nil {
		t.Fatal(err)
	}
	controls, err := f.w.s.RevokeRepository(ctx, b.ID, worldSigner{f.w.key})
	if err != nil || len(controls) != 0 {
		t.Fatal("pre-first-bound retirement", controls, err)
	}
	if err = f.w.s.Close(); err != nil {
		t.Fatal(err)
	}
	f.w.s, err = Open(ctx, f.w.o)
	if err != nil {
		t.Fatal(err)
	}
	defer f.w.s.Close()
	for _, mode := range []string{"both", "source-only", "session-only"} {
		q := f.q.Occurrence
		if mode == "source-only" {
			q.SessionKey = "sk1:" + record.H("different-native-session")
		}
		if mode == "session-only" {
			q.Source = record.H("different-native-source")
		}
		if resolved, err := f.w.s.CaptureRepository(ctx, q); Code(err) != "repository_binding_inactive" || resolved.ID != "" {
			t.Fatal("retired source/session resolved as unknown", mode, resolved, err)
		}
	}
	q := f.q // Nil binding is exactly the former resolver fallback.
	q.ExpectedVersion = 1
	for _, state := range []string{"retiring", "retired"} {
		if _, err = f.w.s.conn.ExecContext(ctx, "UPDATE repository_binding SET state=? WHERE id=?", state, b.ID); err != nil {
			t.Fatal(err)
		}
		called := false
		if _, err = f.w.s.Capture(ctx, q, func(*CaptureTxn) (CommitPlan, error) { called = true; return f.plan, nil }); Code(err) != "repository_binding_inactive" || called {
			t.Fatal("nil-binding writer bypassed retired occurrence", state, called, err)
		}
	}
	if _, err = f.w.s.EnrollRepository(ctx, RepositoryEnrollment{Observation: b.Observation, ProjectRoot: root, Remote: remote}); Code(err) != "repository_binding_inactive" {
		t.Fatal("retired occurrence was reopened", err)
	}
	unknown := SourceOccurrence{Owner: f.w.o.PinnedGenesisID, Source: record.H("unrelated-native-source"), SessionKey: "sk1:" + record.H("unrelated-native-session")}
	if resolved, err := f.w.s.CaptureRepository(ctx, unknown); err != nil || resolved.ID != "" {
		t.Fatal("retirement fenced unrelated source/session", resolved, err)
	}
	if original := find(f.w.snapshot(), b.Observation); original.State != "live" || len(original.BodyJCS) == 0 {
		t.Fatal("pre-existing unbound observation lost")
	}
	// Only local owner/machine history fences this producer. These synthetic
	// foreign namespace rows carry no associated records or capture authority.
	for _, namespace := range []string{"owner", "machine"} {
		owner, machine := f.w.o.PinnedGenesisID, f.w.o.LocalMachineID
		if namespace == "owner" {
			owner = strings.Repeat("f", 32)
		} else {
			machine = "33333333-3333-4333-8333-333333333333"
		}
		if _, err = f.w.s.conn.ExecContext(ctx, "UPDATE repository_binding SET owner=?,machine=? WHERE id=?", owner, machine, b.ID); err != nil {
			t.Fatal(err)
		}
		if resolved, err := f.w.s.CaptureRepository(ctx, f.q.Occurrence); err != nil || resolved.ID != "" {
			t.Fatal("foreign history fenced local occurrence", namespace, resolved, err)
		}
	}
}

func TestRepositoryGovernedContextVariantReceiverRetirement(t *testing.T) {
	ctx := context.Background()
	f, b, _ := enrolledProducer(t)
	w := f.w
	recv := joinDevice(t, w)
	sign := installTenant(t, w, "tenant-owner-ingress")
	head := sign(1, pushPolicy(nil))
	w.append(head)
	// The next bound capture is sealed under the actual current tenant head.
	old := append([]SignedRecord(nil), f.plan.NewRecords...)
	for i, in := range old {
		r, err := record.Parse(in.HeaderJCS, in.BodyJCS, in.AdvisoryID)
		if err != nil {
			t.Fatal(err)
		}
		h := r.Header
		switch body := r.Body.(type) {
		case *record.ChunkBody:
			body.Salt = ""
		case *record.SessionBody:
			body.Salt = ""
		}
		h.Pol = head.AdvisoryID
		h.At++
		if sb, ok := r.Body.(*record.SessionBody); ok {
			sb.Chunks = append(append([]string(nil), sb.Chunks...), f.plan.NewRecords[0].AdvisoryID)
			h.Links.Prev = in.AdvisoryID
			h.Links.Supersedes = []string{in.AdvisoryID}
		}
		r, err = record.Build(h, r.Body)
		if err != nil {
			t.Fatal(err)
		}
		sg, err := sig.SignRecord(w.key, r.ID)
		if err != nil {
			t.Fatal(err)
		}
		f.plan.NewRecords[i] = wire(r, []record.Signature{sg})
	}
	f.q.ExpectedVersion = 2
	f.q.PolicyID = head.AdvisoryID
	f.plan.Next.LastSourceRecordIDs = []string{f.plan.NewRecords[0].AdvisoryID}
	session := f.plan.NewRecords[1].AdvisoryID
	f.plan.Next.SessionPageIDs = []PageRef{{0, session}}
	f.commit()
	k := newKernelForWorld(w)
	repos, _ := ConcreteRepos([]string{b.Repo})
	reg, err := k.a.RegisterRepository(ctx, RegisterClient{AdminOpID: "governed-repository", ClientName: "Governed repository", ReadGrant: Grant{Repos: repos, Channels: []Channel{S}}, TaskWrites: TaskWriteGrant{Repos: repos, Actions: []TaskMutation{Create}}}, b.ID, b.Generation)
	if err != nil {
		t.Fatal(err)
	}
	token, err := reg.Secret.Take()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(token)
	h, err := k.e.Authenticate(ctx, CredentialProof{reg.CredentialID, token})
	if err != nil {
		t.Fatal(err)
	}
	sc, err := k.e.Resolve(ctx, h, IdentityInput{ConversationHandle: "governed-context"})
	if err != nil {
		t.Fatal(err)
	}
	reply, err := k.e.Execute(ctx, h, sc, CallIdentity{JSONRPCID: json.RawMessage(`1`)}, commandFor(t, "local.create_task", map[string]any{"goal": "governed metadata task"}), ByteBudget{MaxBytes: 8192})
	if err != nil {
		t.Fatal(err)
	}
	if result, err := k.e.Release(ctx, h, reply); err != nil || result.IsError() {
		t.Fatal("mutation", err)
	}
	var task string
	if err = w.s.conn.QueryRowContext(ctx, "SELECT id FROM record_attribution WHERE scope=? AND kind='fixed-mcp-builder' AND id IN(SELECT id FROM record WHERE json_extract(header,'$.type')='task')", sc.id).Scan(&task); err != nil {
		t.Fatal(err)
	}
	ids := []string{session, task}
	rootFacts := rootOnlyBundleFacts(t, w.s, session, task)
	paused, selected := registerExport(t, w.s, w.o, 71, ids, worldSigner{w.key}, []byte("sealed metadata"))
	defer paused.lock.Close()
	if len(selected.Data) != 2 {
		t.Fatal("governed actual-builder selection", selected.Excluded, "session", session, "task", task)
	}
	assertBundleFacts(t, selected.Facts, rootFacts)
	for _, in := range selected.Data {
		r, err := record.Parse(in.HeaderJCS, in.BodyJCS, in.AdvisoryID)
		if err != nil || r.Header.Red.Profile != record.ProfilePushMetadata || r.Header.Subj.RepoID != b.Repo {
			t.Fatal("governed metadata", err)
		}
	}
	installTenant(t, &world{t: t, s: recv.s, o: recv.o}, "tenant-owner-ingress")
	if _, err = recv.s.Append(ctx, head); err != nil {
		t.Fatal(err)
	}
	if result, err := recv.s.ImportBundle(ctx, BundleImport{LocalKeyID: recv.KeyID(), Keyring: selected.Keyring, Facts: selected.Facts, Data: selected.Data}); err != nil || result.Data != 2 {
		t.Fatal("same tenant receiver", result, err)
	}
	controls, err := w.s.RevokeRepository(ctx, b.ID, worldSigner{w.key})
	if err != nil {
		t.Fatal(err)
	}
	if err = paused.publish(w.s, ids); Code(err) != "bundle_invalidated" {
		t.Fatal("stale metadata published", err)
	}
	importSenderBundleControls(t, w.s, recv, controls...)
	if result, err := recv.s.ImportBundle(ctx, BundleImport{LocalKeyID: recv.KeyID(), Keyring: selected.Keyring, Facts: selected.Facts, Data: selected.Data}); err != nil || result.Data != 0 {
		t.Fatal("replay after receiver retirement", result, err)
	}
	for _, in := range selected.Data {
		snap, err := recv.s.Snapshot(ctx, ReadRequest{IDs: []string{in.AdvisoryID}})
		if err != nil {
			t.Fatal(err)
		}
		if len(snap.Entries) != 1 || snap.Entries[0].State == "live" || len(snap.Entries[0].BodyJCS) > 0 {
			t.Fatal("variant retirement did not cross node")
		}
	}
}
