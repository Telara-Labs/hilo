package store

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Telara-Labs/hilo/contract/internal/node/localpolicy"
	"github.com/Telara-Labs/hilo/contract/record"
	"github.com/Telara-Labs/hilo/contract/sig"
)

func governedFixture(w *world, in SignedRecord, pol string) SignedRecord {
	w.t.Helper()
	r, err := record.Parse(in.HeaderJCS, in.BodyJCS, in.AdvisoryID)
	if err != nil {
		w.t.Fatal(err)
	}
	r.Header.Pol = pol
	return w.signed(r.Header, r.Body)
}

func TestV3BodyPolicyIncludesNonDisplayedFields(t *testing.T) {
	const secret = "tenant-marker-123"
	// Every fixture is a real parsed/signed body, not renderer inventory.
	fixtures := map[string]func(*world) SignedRecord{}
	for _, field := range []string{"refs", "commits"} {
		fixtures["anchors-"+field] = func(w *world) SignedRecord {
			r, _ := record.Parse(w.task(7001, "safe goal").HeaderJCS, nil, "")
			a := &record.Anchors{}
			if field == "refs" {
				a.Refs = []string{secret}
			} else {
				a.Commits = []string{secret}
			}
			return w.signed(r.Header, &record.TaskBody{Goal: "safe goal", Status: "active", Anchors: a})
		}
	}
	for _, field := range []string{"path", "record", "meta-key", "args-key", "raw-args-key"} {
		fixtures["event-"+field] = func(w *world) SignedRecord {
			ev := w.event("safe text")
			switch field {
			case "path":
				ev.Src = &record.SourcePos{Path: secret, Line: 1}
			case "record":
				ev.Src = &record.SourcePos{Record: secret}
			case "meta-key":
				ev.Meta = map[string]string{secret: "safe value"}
			case "args-key":
				ev.Call = &record.ToolCall{Args: map[string]string{secret: "safe value"}}
			case "raw-args-key":
				ev.Call = &record.ToolCall{RawArgs: map[string]bool{secret: true}}
			}
			ev.Salt, ev.Revision, ev.Text.Digest = "", "", ""
			ev, err := record.ReviseEvent(ev, nil)
			if err != nil {
				w.t.Fatal(err)
			}
			return w.chunk(ev)
		}
	}
	for _, field := range []string{"source", "kind", "ref", "location", "revision"} {
		fixtures["digest-evidence-"+field] = func(w *world) SignedRecord {
			p := record.EvidencePointer{}
			switch field {
			case "source":
				p.Source = secret
			case "kind":
				p.Kind = secret
			case "ref":
				p.Ref = secret
			case "location":
				p.Location = secret
			case "revision":
				p.Revision = secret
			}
			return w.signed(record.Header{Type: record.KindDigest, Prov: record.ProvDerived, Subj: record.Subject{SessionKey: w.sessionKey()}, LID: record.DigestLID(w.sessionKey(), testMachine)}, &record.DigestBody{Evidence: []record.EvidencePointer{p}})
		}
	}
	for name, buildBody := range fixtures {
		t.Run(name, func(t *testing.T) {
			k := newKernel(t)
			ctx := context.Background()
			_, policy := tenantFixture(t, k)
			permissive := policy(1, &record.PolicyBody{})
			k.append(permissive)
			old := governedFixture(k.world, buildBody(k.world), permissive.AdvisoryID)
			k.append(old)
			if b := find(k.snapshot(), old.AdvisoryID).BodyJCS; len(b) == 0 || !strings.Contains(string(b), secret) {
				t.Fatal("permissive control did not retain signed body")
			}
			restrictive := policy(2, &record.PolicyBody{Redaction: record.PolicyRedact{Shapes: []record.Shape{{Name: "marker", RE2: "tenant-marker-[0-9]+"}}}})
			k.append(restrictive)
			if len(find(k.snapshot(), old.AdvisoryID).BodyJCS) != 0 {
				t.Fatal("readback disclosed non-displayed forbidden field")
			}
			full := governedFixture(k.world, buildBody(k.world), restrictive.AdvisoryID)
			if _, err := k.s.Append(ctx, full); Code(err) != "policy_violation" {
				t.Fatal("admission retained forbidden field", err)
			}
			header := full
			header.BodyJCS = nil
			k.append(header)
			before := k.snapshot().Generation
			if _, err := k.s.Append(ctx, full); Code(err) != "policy_violation" {
				t.Fatal("enrichment retained forbidden field", err)
			}
			if after := k.snapshot(); after.Generation != before || len(find(after, full.AdvisoryID).BodyJCS) != 0 {
				t.Fatal("refused enrichment mutated record")
			}
			var n int
			if err := k.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM body_seen WHERE id=?", full.AdvisoryID).Scan(&n); err != nil || n != 0 {
				t.Fatal("refusal learned material", n, err)
			}
		})
	}
}

func TestV3BodyPolicySchemaWalk(t *testing.T) {
	o, err := localpolicy.TenantOverlay(&record.PolicyBody{Redaction: record.PolicyRedact{Shapes: []record.Shape{{Name: "hidden", RE2: "hidden-value"}}}})
	if err != nil {
		t.Fatal(err)
	}
	// Exercise nested optional structures, dynamic boolean keys and future schema
	// strings, without treating static member names as retained data.
	for _, body := range []any{nil, (*record.TaskBody)(nil), &record.SessionBody{Counts: &record.Counts{Requests: 2}, Repo: &record.RepoRef{Dirty: new(bool)}}, &record.ChunkBody{Events: []record.Event{{Call: &record.ToolCall{RawArgs: map[string]bool{"safe": false}}}}}} {
		if !bodyPolicyAllowed(body, o) {
			t.Fatal("safe body refused")
		}
	}
	for _, body := range []any{&record.SessionBody{Reader: &record.SourceRef{ReaderVersion: "hidden-value"}}, &record.BindingBody{Evidence: &record.BindEvidence{Handle: "hidden-value"}}, &record.CheckpointBody{TaskTree: []record.Step{{Status: "hidden-value"}}}, &record.ChunkBody{Events: []record.Event{{Text: &record.Text{Digest: "hidden-value"}}}}, &record.ChunkBody{Events: []record.Event{{Call: &record.ToolCall{Args: map[string]string{"password": "innocent-looking-value"}}}}}, make(chan string)} {
		if bodyPolicyAllowed(body, o) {
			t.Fatal("hidden or unsupported field allowed")
		}
	}
}

func TestV3EnrichmentRechecksCurrentPolicy(t *testing.T) {
	for _, change := range []string{"unchanged-forbidden", "replaced", "kill", "epoch", "logout"} {
		t.Run(change, func(t *testing.T) {
			k := newKernel(t)
			ctx := context.Background()
			_, build := tenantFixture(t, k)
			p := build(1, &record.PolicyBody{Redaction: record.PolicyRedact{Shapes: []record.Shape{{Name: "secret", RE2: "tenant-secret-[0-9]+"}}}})
			k.append(p)
			goal := "safe goal"
			if change == "unchanged-forbidden" {
				goal = "tenant-secret-123"
			}
			full := governedFixture(k.world, k.task(7101, goal), p.AdvisoryID)
			header := full
			header.BodyJCS = nil
			admitted := k.append(header)
			if change == "logout" {
				if err := k.s.LogoutTenant(ctx); err != nil {
					t.Fatal(err)
				}
			} else if change != "unchanged-forbidden" {
				b := &record.PolicyBody{}
				if change == "kill" {
					b.Kill.CaptureTenantRepos = true
				}
				if change == "epoch" {
					b.Redaction.MinEpoch = 1
				}
				k.append(build(2, b))
			}
			before := k.snapshot().Generation
			if _, err := k.s.Append(ctx, full); Code(err) != "policy_violation" && Code(err) != "policy_unavailable" {
				t.Fatal("enrichment bypassed current policy", err)
			}
			after := k.snapshot()
			if e := find(after, full.AdvisoryID); after.Generation != before || e.Sequence != admitted.Sequence || len(e.BodyJCS) != 0 {
				t.Fatal("rejected enrichment mutated original admission")
			}
		})
	}
}

func TestV3EnrichmentRejectsKnownCommitmentOmission(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	op := record.H("header-first-omitted-mutation")
	task := "4a333333-3333-4333-8333-333333333333"
	source := w.signed(record.Header{Type: record.KindCheckpoint, LID: record.CheckpointLID(w.o.PinnedGenesisID, task, testMachine, op), Prov: record.ProvMCPExplicit, Subj: record.Subject{TaskID: task}, Op: op}, &record.CheckpointBody{Milestone: "dependency"})
	ref, err := record.NewCallRef()
	if err != nil {
		t.Fatal(err)
	}
	r, err := record.BuildCall(record.Header{Type: record.KindCall, LID: record.CallLID(ref), At: w.at + 1, Author: record.Author{MachineID: testMachine, KeyID: w.o.PinnedGenesisID}, Prov: record.ProvMCPExplicit, Subj: record.Subject{TaskID: task}, Op: op, Red: record.Redact{Profile: record.ProfileLocal}}, record.CallBody{CallRef: ref, ScopeID: "sc1:" + testMachine + ":" + strings.Repeat("1", 32), Tool: "telara_task_checkpoint", TaskID: task, Outcome: "ok", CommitmentDeps: []string{}}, json.RawMessage(`{"milestone":"dependency"}`), json.RawMessage(`{"status":"checkpointed"}`))
	if err != nil {
		t.Fatal(err)
	}
	sg, err := sig.SignRecord(w.key, r.ID)
	if err != nil {
		t.Fatal(err)
	}
	full := wire(r, []record.Signature{sg})
	header := full
	header.BodyJCS = nil
	w.append(header)
	w.append(source)
	if _, err = w.s.Append(ctx, full); Code(err) != "commitment_dependencies" {
		t.Fatal("header-first call omitted known dependency", err)
	}
	var n int
	if err = w.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM body_seen WHERE id=?", r.ID).Scan(&n); err != nil || n != 0 {
		t.Fatal("omitted call learned material", n, err)
	}
}

func TestV3LateSessionMembershipSurvivesPurgeAndCrash(t *testing.T) {
	for _, order := range []string{"session-first", "chunk-first", "header-first"} {
		t.Run(order, func(t *testing.T) {
			w := newWorld(t)
			ctx := context.Background()
			chunk := w.chunk(w.event("membership erase crash marker"))
			session := w.session([]string{chunk.AdvisoryID})
			switch order {
			case "chunk-first":
				w.append(chunk)
				w.append(session)
			case "session-first":
				w.append(session)
				w.append(chunk)
			case "header-first":
				header := chunk
				header.BodyJCS = nil
				w.append(header)
				w.append(session)
				w.append(chunk)
			}
			var count int
			if err := w.s.conn.QueryRowContext(ctx, "SELECT event_count FROM event_membership WHERE id=?", session.AdvisoryID).Scan(&count); err != nil || count != 1 {
				t.Fatal("late membership not durably completed", count, err)
			}
			control := w.control(7201, record.KindErasure, session.AdvisoryID)
			sealed, err := json.Marshal(control)
			if err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(filepath.Join(w.o.Dir, "crash-candidate.json"), sealed, 0600); err != nil {
				t.Fatal(err)
			}
			w.s.Close()
			// Existing Go child helper exits immediately after Append, without Close
			// or any SQLite cleanup, leaving the actual committed WAL for recovery.
			cmd := exec.Command(os.Args[0], "-test.run=^TestCrashChild$", "--", "--store-crash", "after", w.o.Dir, w.o.PinnedGenesisID)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("erase child failed %v %s", err, out)
			}
			w.s, err = Open(ctx, w.o)
			if err != nil {
				t.Fatal(err)
			}
			snapshot, err := w.s.Snapshot(ctx, ReadRequest{})
			if err != nil {
				t.Fatal("restart lost complete membership", err)
			}
			for _, id := range []string{session.AdvisoryID, chunk.AdvisoryID} {
				if e := find(snapshot, id); e.State != "invalidated" || len(e.BodyJCS) != 0 {
					t.Fatal("purged body resurrected", e.State)
				}
			}
			if result, err := w.s.Scrub(ctx, control.AdvisoryID); err != nil || result.State != "complete" {
				t.Fatal("complete erasure did not recover cleanly", result, err)
			}
		})
	}
}

func TestV3MembershipFailurePreventsLateChunkAndPurge(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	chunk := w.chunk(w.event("late membership atomicity"))
	session := w.session([]string{chunk.AdvisoryID})
	w.append(session)
	if _, err := w.s.conn.ExecContext(ctx, "CREATE TRIGGER membership_fault BEFORE INSERT ON event_membership WHEN NEW.id='"+session.AdvisoryID+"' BEGIN SELECT RAISE(ABORT,'private fault'); END"); err != nil {
		t.Fatal(err)
	}
	if _, err := w.s.Append(ctx, chunk); Code(err) != "storage_error" {
		t.Fatal("failed existing-session proof was acknowledged", err)
	}
	var count int
	if err := w.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM record WHERE id=?", chunk.AdvisoryID).Scan(&count); err != nil || count != 0 {
		t.Fatal("late chunk partially committed", count, err)
	}
	if _, err := w.s.conn.ExecContext(ctx, "DROP TRIGGER membership_fault"); err != nil {
		t.Fatal(err)
	}
	w.append(chunk)
	control := w.control(7301, record.KindErasure, session.AdvisoryID)
	if _, err := w.s.conn.ExecContext(ctx, "CREATE TRIGGER membership_fault BEFORE INSERT ON event_membership BEGIN SELECT RAISE(ABORT,'private fault'); END"); err != nil {
		t.Fatal(err)
	}
	if _, err := w.s.Append(ctx, control); Code(err) != "storage_error" {
		t.Fatal("purge bypassed failed membership write", err)
	}
	if err := w.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM record_body WHERE id IN(?,?)", session.AdvisoryID, chunk.AdvisoryID).Scan(&count); err != nil || count != 2 {
		t.Fatal("purge partially committed", count, err)
	}
}

func TestV3ScrubReconcilesRecoveredMembershipBeforeCleanReceipt(t *testing.T) {
	for _, reopen := range []bool{false, true} {
		t.Run(map[bool]string{false: "same-process", true: "reopen"}[reopen], func(t *testing.T) {
			w := newWorld(t)
			ctx := context.Background()
			chunk := w.chunk(w.event("lost membership proof"))
			session := w.session([]string{chunk.AdvisoryID})
			w.append(chunk)
			w.append(session)
			control := w.control(7401, record.KindErasure, session.AdvisoryID)
			w.append(control)
			// Model an old writer's missing proof after body purge. No body remains
			// from which recovery can truthfully manufacture completeness.
			if _, err := w.s.conn.ExecContext(ctx, "DELETE FROM event_membership WHERE id=?", session.AdvisoryID); err != nil {
				t.Fatal(err)
			}
			if _, err := w.s.conn.ExecContext(ctx, "DELETE FROM erasure_pending"); err != nil {
				t.Fatal(err)
			}
			if reopen {
				w.s.Close()
				var err error
				w.s, err = Open(ctx, w.o)
				if err != nil {
					t.Fatal(err)
				}
			}
			if result, err := w.s.Scrub(ctx, control.AdvisoryID); err != nil || result.State != "blocked" {
				t.Fatal("missing recovered coverage falsely clean", result, err)
			}
			var count int
			if err := w.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM erasure_pending WHERE control=?", control.AdvisoryID).Scan(&count); err != nil || count != 1 {
				t.Fatal("recovered pending state not durable", count, err)
			}
		})
	}
}
