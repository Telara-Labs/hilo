package store

import (
	"bytes"
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/Telara-Labs/hilo/contract/record"
	"github.com/Telara-Labs/hilo/contract/replay"
)

func TestDisclosureCurrentDependencyRenderWorkRefusalDoesNotHoldOwner(t *testing.T) {
	k := newKernel(t)
	ctx := context.Background()
	op := k.execute("render-work-call", "local.create_task", map[string]any{"goal": "bounded original source"}).op
	// Actual signed owner records share an existing call identity. No metadata
	// permission/completeness flags are installed. Two bounded intermediate
	// headers keep every wire record below its real16KiB header limit.
	var inputs []SignedRecord
	var ids []string
	build := func(n int, deps []string) SignedRecord {
		task := fmt.Sprintf("92222222-2222-4222-8222-%012x", n)
		return k.signed(record.Header{Type: record.KindTask, Prov: record.ProvMCPExplicit, LID: record.TaskLID(k.o.PinnedGenesisID, task), Subj: record.Subject{TaskID: task}, Op: op, Links: record.Links{DerivedFrom: deps}}, &record.TaskBody{Name: "bounded record", Goal: "boundedsource", Status: "active"})
	}
	for i := 0; i < 400; i++ {
		r := build(i, nil)
		inputs = append(inputs, r)
		ids = append(ids, r.AdvisoryID)
	}
	left, right := build(401, ids[:200]), build(402, ids[200:])
	root := build(403, []string{left.AdvisoryID, right.AdvisoryID})
	inputs = append(inputs, left, right, root)
	k.seedPending(inputs)
	before := disclosureGuardState(t, k)
	r, err := k.e.Execute(ctx, k.h, k.sc, CallIdentity{SuppliedOpID: k.issued("costly-current-render")}, commandFor(t, "local.lookup_record", map[string]any{"record_id": root.AdvisoryID}), ByteBudget{MaxBytes: 4096})
	if Code(err) != "render_limit" || r.engine != nil {
		t.Fatal("request-local work bound did not refuse without identity", err)
	}
	requireSameDisclosureGuardState(t, k, before)
	snapshot, err := k.s.Snapshot(ctx, ReadRequest{IDs: []string{root.AdvisoryID}})
	if err != nil || len(snapshot.Entries) != 1 || len(snapshot.Entries[0].BodyJCS) == 0 {
		t.Fatal("costly render froze prior available owner state", err)
	}
	small := k.execute("small-after-costly", "local.lookup_record", map[string]any{"record_id": ids[0]})
	if text := k.release(small); !strings.Contains(text, "boundedsource") {
		t.Fatal("ordinary later authorized delivery was poisoned", text)
	}
}

func currentDependencySession(t *testing.T, k *kernelWorld, native string, deps ...string) (string, SignedRecord, SignedRecord, record.Event) {
	t.Helper()
	sk, err := record.SessionKey("claude-code", "local", record.NativeGlobal, native, "")
	if err != nil {
		t.Fatal(err)
	}
	eid, err := record.EventID(sk, "assistant_final", record.Anchor{NativeItemID: "current-dependency-boundary"})
	if err != nil {
		t.Fatal(err)
	}
	ev, err := record.ReviseEvent(record.Event{ID: eid, Seq: 0, Kind: "assistant_final", Prov: "transcript", Text: &record.Text{Body: "repo B boundary"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	chunk := k.signed(record.Header{Type: record.KindChunk, Prov: record.ProvTranscript, Subj: record.Subject{SessionKey: sk}, LID: record.ChunkLID(sk, testMachine, eid), Links: record.Links{DerivedFrom: deps}}, &record.ChunkBody{Events: []record.Event{ev}})
	k.append(chunk)
	page := k.signed(record.Header{Type: record.KindSession, Prov: record.ProvTranscript, Subj: record.Subject{SessionKey: sk}, LID: record.SessionLID(sk, testMachine, 0)}, &record.SessionBody{NativeID: native, NativeIDKind: record.NativeGlobal, Chunks: []string{chunk.AdvisoryID}, SettledThrough: 0})
	k.append(page)
	return sk, chunk, page, ev
}

func TestDisclosureCurrentDependencyNestedBindingRequiresExpansion(t *testing.T) {
	k := newKernel(t)
	ctx := context.Background()
	repoA, repoB := countAcceptanceRepoID(t, "a"), countAcceptanceRepoID(t, "b")
	countAcceptanceTrustedRepoFixture(t, k, repoA)
	args := map[string]any{"goal": "nestedcurrentdependencycontent"}
	root := k.execute("nested-root", "local.create_task", args)
	k.release(root)
	child := k.execute("nested-child", "local.create_task", map[string]any{"goal": "child dependency"})
	var rootRef, childRef, childID string
	for _, x := range []struct {
		q   string
		out *string
		r   CommittedReplyHandle
	}{
		{"SELECT call_ref FROM operation WHERE credential=? AND op=?", &rootRef, root},
		{"SELECT call_ref FROM operation WHERE credential=? AND op=?", &childRef, child},
		{"SELECT id FROM outcome_member WHERE credential=? AND op=?", &childID, child},
	} {
		if err := k.s.conn.QueryRowContext(ctx, x.q, x.r.credential, x.r.op).Scan(x.out); err != nil {
			t.Fatal(err)
		}
	}
	bind := func(ref, sk string, ev record.Event) SignedRecord {
		r := k.signed(record.Header{Type: record.KindBinding, Prov: record.ProvDerived, LID: record.BindingLID(ref)}, &record.BindingBody{CallRef: ref, Status: "bound", Confidence: "transcript-echo", Target: &record.BindTarget{SessionKey: sk}, Evidence: &record.BindEvidence{SightingEventIDs: []string{ev.ID}}})
		k.append(r)
		return r
	}
	zsk, zchunk, zpage, zev := currentDependencySession(t, k, "77777777-7777-4777-8777-777777777777")
	childBinding := bind(childRef, zsk, zev)
	bsk, bchunk, bpage, bev := currentDependencySession(t, k, "88888888-8888-4888-8888-888888888888", childID)
	rootBinding := bind(rootRef, bsk, bev)
	if err := k.s.write(ctx, func() error {
		for _, x := range []struct {
			r    SignedRecord
			repo string
		}{{zchunk, repoB}, {zpage, repoB}, {childBinding, repoA}, {bchunk, repoA}, {bpage, repoA}, {rootBinding, repoA}} {
			if _, err := k.s.conn.ExecContext(ctx, "INSERT INTO record_attribution VALUES(?,?,?,?,?,?,?)", x.r.AdvisoryID, k.o.PinnedGenesisID, testMachine, k.sc.id, "fixture", "known", x.repo); err != nil {
				return err
			}
		}
		return k.s.bump(ctx)
	}); err != nil {
		t.Fatal(err)
	}
	before, err := k.s.loadOutcome(ctx, root.credential, root.op)
	if err != nil {
		t.Fatal(err)
	}
	call := countAcceptanceCall(t, k, root)
	for i, ids := range [][]string{{repoA}, {repoA, repoB}} {
		repos, err := ConcreteRepos(ids)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = k.a.ReplaceGrant(ctx, []string{"nested-narrow", "nested-expand"}[i], k.proof.CredentialID, int64(i+1), Grant{Repos: repos, Channels: []Channel{S}}); err != nil {
			t.Fatal(err)
		}
		countAcceptanceReconnect(t, k, false)
		r := k.execute("nested-root", "local.create_task", args)
		text := k.release(r)
		if i == 0 {
			if text != replay.Unavailable {
				t.Fatal("newly discovered dependency's binding escaped current authorization", text)
			}
		} else {
			if !strings.Contains(text, "nestedcurrentdependencycontent") {
				t.Fatal("complete current expanded graph was withheld", text)
			}
			for _, id := range []string{childID, childBinding.AdvisoryID, zchunk.AdvisoryID, zpage.AdvisoryID, bchunk.AdvisoryID, bpage.AdvisoryID, rootBinding.AdvisoryID} {
				var n int
				if err := k.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM render_dep WHERE attempt=(SELECT id FROM render_attempt WHERE credential=? AND op=? ORDER BY db_generation DESC LIMIT 1) AND id=?", r.credential, r.op, id).Scan(&n); err != nil || n != 1 {
					t.Fatal("nested current dependency missing from render ledger", id, n, err)
				}
			}
		}
		after, err := k.s.loadOutcome(ctx, root.credential, root.op)
		if err != nil || !reflect.DeepEqual(before.members, after.members) || !bytes.Equal(call, countAcceptanceCall(t, k, root)) {
			t.Fatal("nested current expansion changed immutable outcome", err)
		}
	}
}

func TestDisclosureCurrentDependencyOutOfGrantBindingUnavailable(t *testing.T) {
	for _, mode := range []string{"execute_replay", "direct_release"} {
		t.Run(mode, func(t *testing.T) {
			k := newKernel(t)
			ctx := context.Background()
			repoA := countAcceptanceRepoID(t, "a")
			repoB := countAcceptanceRepoID(t, "b")
			countAcceptanceTrustedRepoFixture(t, k, repoA)
			args := map[string]any{"goal": "currentdependencyrepocontent"}
			original := k.execute("current-dependency-create", "local.create_task", args)
			if text := k.release(original); !strings.Contains(text, "currentdependencyrepocontent") {
				t.Fatal("original unbound positive fixture failed", text)
			}
			before, err := k.s.loadOutcome(ctx, original.credential, original.op)
			if err != nil {
				t.Fatal(err)
			}
			call := countAcceptanceCall(t, k, original)
			var id, ref string
			if err := k.s.conn.QueryRowContext(ctx, "SELECT id FROM outcome_member WHERE credential=? AND op=?", original.credential, original.op).Scan(&id); err != nil {
				t.Fatal(err)
			}
			if err := k.s.conn.QueryRowContext(ctx, "SELECT call_ref FROM operation WHERE credential=? AND op=?", original.credential, original.op).Scan(&ref); err != nil {
				t.Fatal(err)
			}
			sk, chunk, page, ev := currentDependencySession(t, k, "55555555-5555-4555-8555-555555555555")
			binding := k.signed(record.Header{Type: record.KindBinding, Prov: record.ProvDerived, LID: record.BindingLID(ref)}, &record.BindingBody{CallRef: ref, Status: "bound", Confidence: "transcript-echo", Target: &record.BindTarget{SessionKey: sk}, Evidence: &record.BindEvidence{SightingEventIDs: []string{ev.ID}}})
			k.append(binding)
			// Explicitly trusted owner-side facts only. This is not native repo
			// bootstrap or an ordinary caller's ability to assert attribution.
			if err := k.s.write(ctx, func() error {
				for _, entry := range []struct{ id, repo string }{{chunk.AdvisoryID, repoB}, {page.AdvisoryID, repoB}, {binding.AdvisoryID, repoA}} {
					if _, err := k.s.conn.ExecContext(ctx, "INSERT INTO record_attribution VALUES(?,?,?,?,?,?,?)", entry.id, k.o.PinnedGenesisID, testMachine, k.sc.id, "fixture", "known", entry.repo); err != nil {
						return err
					}
				}
				return k.s.bump(ctx)
			}); err != nil {
				t.Fatal(err)
			}
			repos, err := ConcreteRepos([]string{repoA})
			if err != nil {
				t.Fatal(err)
			}
			if _, err = k.a.ReplaceGrant(ctx, "current-dependency-repo-a-only", k.proof.CredentialID, 1, Grant{Repos: repos, Channels: []Channel{S}}); err != nil {
				t.Fatal(err)
			}
			countAcceptanceReconnect(t, k, false)
			// A newly reconstructed lookup must see and refuse B under precisely
			// the same current rights used below for the old mutation outcome.
			lookup := k.execute("current-dependency-fresh-lookup", "local.lookup_record", map[string]any{"record_id": id})
			if text := k.release(lookup); text != replay.Unavailable {
				t.Fatal("fresh lookup failed to establish out-of-grant current dependency", text)
			}
			r := original
			if mode == "execute_replay" {
				r = k.execute("current-dependency-create", "local.create_task", args)
			}
			out, err := k.e.Release(ctx, k.h, r)
			if err != nil {
				t.Fatal(err)
			}
			if out.Text() != replay.Unavailable {
				t.Errorf("old outcome released content/current B labels while fresh lookup withheld: %q", out.Text())
			}
			after, err := k.s.loadOutcome(ctx, original.credential, original.op)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(before.members, after.members) || !bytes.Equal(call, countAcceptanceCall(t, k, original)) {
				t.Fatal("current authorization mutated original member dependencies or signed result/hash")
			}
			grant := func(op string, epoch int64, ids ...string) {
				t.Helper()
				repos, err := ConcreteRepos(ids)
				if err != nil {
					t.Fatal(err)
				}
				if _, err = k.a.ReplaceGrant(ctx, op, k.proof.CredentialID, epoch, Grant{Repos: repos, Channels: []Channel{S}}); err != nil {
					t.Fatal(err)
				}
				countAcceptanceReconnect(t, k, false)
			}
			assertOriginal := func() {
				t.Helper()
				got, err := k.s.loadOutcome(ctx, original.credential, original.op)
				if err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(before.members, got.members) || !bytes.Equal(call, countAcceptanceCall(t, k, original)) {
					t.Fatal("current view rewrote immutable original outcome")
				}
			}
			assertDeps := func(r CommittedReplyHandle, required []string, forbidden []string) {
				t.Helper()
				var attempt string
				if err := k.s.conn.QueryRowContext(ctx, "SELECT id FROM render_attempt WHERE credential=? AND op=? ORDER BY db_generation DESC LIMIT 1", r.credential, r.op).Scan(&attempt); err != nil {
					t.Fatal(err)
				}
				for _, id := range append(append([]string(nil), required...), forbidden...) {
					var n int
					if err := k.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM render_dep WHERE attempt=? AND id=?", attempt, id).Scan(&n); err != nil {
						t.Fatal(err)
					}
					want := 1
					for _, f := range forbidden {
						if id == f {
							want = 0
						}
					}
					if n != want {
						t.Fatal("render dependency is not exact current closure", id, n, want)
					}
				}
			}
			grant("current-dependency-expand", 2, repoA, repoB)
			positive := k.execute("current-dependency-create", "local.create_task", args)
			if text := k.release(positive); !strings.Contains(text, "currentdependencyrepocontent") {
				t.Fatal("expanded current grant did not permit original content", text)
			}
			assertDeps(positive, []string{id, binding.AdvisoryID, chunk.AdvisoryID, page.AdvisoryID}, nil)
			assertOriginal()
			grant("current-dependency-remove-b", 3, repoA)
			if out, err := k.e.Release(ctx, k.h, positive); err != nil || out.Text() != replay.Unavailable {
				t.Fatal("grant removal did not fence already prepared bytes", out.Text(), err)
			}
			// A new current binding selects clean repo-A evidence instead. Prior
			// binding/session evidence is not overwritten in the logical outcome.
			csk, cchunk, cpage, cev := currentDependencySession(t, k, "66666666-6666-4666-8666-666666666666")
			corrected := k.signed(record.Header{Type: record.KindBinding, Prov: record.ProvDerived, LID: record.BindingLID(ref), Links: record.Links{Supersedes: []string{binding.AdvisoryID}}}, &record.BindingBody{CallRef: ref, Status: "bound", Confidence: "transcript-echo", Target: &record.BindTarget{SessionKey: csk}, Evidence: &record.BindEvidence{SightingEventIDs: []string{cev.ID}}})
			k.append(corrected)
			if err := k.s.write(ctx, func() error {
				for _, r := range []SignedRecord{cchunk, cpage, corrected} {
					if _, err := k.s.conn.ExecContext(ctx, "INSERT INTO record_attribution VALUES(?,?,?,?,?,?,?)", r.AdvisoryID, k.o.PinnedGenesisID, testMachine, k.sc.id, "fixture", "known", repoA); err != nil {
						return err
					}
				}
				return k.s.bump(ctx)
			}); err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 2; i++ {
				positive = k.execute("current-dependency-create", "local.create_task", args)
				if text := k.release(positive); !strings.Contains(text, "currentdependencyrepocontent") {
					t.Fatal("rebound current authorized evidence unavailable", text)
				}
				assertDeps(positive, []string{id, corrected.AdvisoryID, cchunk.AdvisoryID, cpage.AdvisoryID}, []string{chunk.AdvisoryID, page.AdvisoryID})
				assertOriginal()
				if i == 0 {
					countAcceptanceReconnect(t, k, true)
				}
			}
			if _, err := k.a.RevokeCredential(ctx, "current-dependency-revoke", k.proof.CredentialID, 4); err != nil {
				t.Fatal(err)
			}
			if out, err := k.e.Release(ctx, k.h, positive); err == nil || out.Text() != "" {
				t.Fatal("revoked credential released bytes", out.Text(), err)
			}
			assertOriginal()
		})
	}
}
