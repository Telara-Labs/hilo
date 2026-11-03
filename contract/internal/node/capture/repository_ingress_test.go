//go:build linux || darwin

package capture

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Telara-Labs/hilo/contract/internal/node/disclosure"
	"github.com/Telara-Labs/hilo/contract/internal/node/ipc"
	"github.com/Telara-Labs/hilo/contract/internal/node/store"
	"github.com/Telara-Labs/hilo/contract/record"
)

// This component proof uses the actual fixed native reader, store, signing,
// disclosure mutation and registered bundle publication. Real vendor-session
// resumption and hosted acceptance remain separate required e2e gates.
func TestRepositoryActualCaptureContextTaskRetirement(t *testing.T) {
	ctx := context.Background()
	f := runtimeWorld(t, sourceMessages(t, 8, -1, ""))
	quietSource()
	first := requireCaptured(t, f)
	var observation string
	initial, _ := runtimeSnapshot(t, f.s)
	for _, id := range first.CommittedRecordIDs {
		if r := initial[id]; r != nil && r.Header.Type == record.KindSession {
			observation = id
		}
	}
	if observation == "" {
		t.Fatal("native observation absent")
	}
	root := filepath.Join(f.c.Home, "owner-project")
	if err := os.Mkdir(root, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, ".git"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".git", "config"), []byte("[remote \"origin\"]\nurl=git@github.com:acme/widgets.git\n"), 0644); err != nil {
		t.Fatal(err)
	}
	b, err := f.s.EnrollRepository(ctx, store.RepositoryEnrollment{Observation: observation, ProjectRoot: root, Remote: "github.com/acme/widgets"})
	if err != nil {
		t.Fatal("owner enroll", err)
	}
	if _, err = f.s.EnrollRepository(ctx, store.RepositoryEnrollment{Observation: observation, ProjectRoot: root, Remote: b.Remote}); err == nil {
		t.Fatal("duplicate enrollment admitted")
	}
	second := requireCaptured(t, f)
	records, _ := runtimeSnapshot(t, f.s)
	var sessionID string
	for _, id := range second.CommittedRecordIDs {
		r := records[id]
		if r == nil || r.Header.Subj.RepoID != b.Repo {
			t.Fatal("bound capture missing exact repository", id)
		}
		if sb, ok := r.Body.(*record.SessionBody); ok {
			if sb.Repo == nil || sb.Repo.ID != b.Repo || sb.Repo.Remote != b.Remote {
				t.Fatal("native session body lost repository")
			}
			sessionID = id
		}
	}
	if sessionID == "" || sessionID == observation {
		t.Fatal("enrollment rewrote old observation")
	}
	if initial[observation].Header.Subj.RepoID != "" {
		t.Fatal("unbound observation changed")
	}
	material, err := disclosure.PreloadRuntimeMaterial(bytes.Repeat([]byte{0}, 32), f.key)
	if err != nil {
		t.Fatal(err)
	}
	svc, err := disclosure.New(ctx, f.s, disclosure.Config{OwnerGenesis: f.c.OwnerGenesis, MachineID: f.c.MachineID}, material)
	material.Clear()
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close()
	admin, err := svc.Administration(ctx)
	if err != nil {
		t.Fatal(err)
	}
	repos, _ := disclosure.ConcreteRepos([]string{b.Repo})
	client, err := admin.Register(ctx, disclosure.RegisterClient{AdminOpID: "repository-component", ClientName: "Repository component", ReadGrant: disclosure.Grant{Repos: repos, Channels: []disclosure.Channel{disclosure.S}}, TaskWrites: disclosure.TaskWriteGrant{Repos: repos, Actions: []disclosure.TaskMutation{disclosure.Create, disclosure.Checkpoint}}})
	if err != nil {
		t.Fatal(err)
	}
	if err = f.s.BindRepositoryCredential(ctx, b.ID, b.Generation, client.CredentialID); err != nil {
		t.Fatal(err)
	}
	token, err := client.Secret.Take()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(token)
	conn, err := svc.Authenticate(ctx, disclosure.CredentialProof{CredentialID: client.CredentialID, Token: token})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	scope, err := conn.Resolve(ctx, disclosure.IdentityInput{ConversationHandle: "owner-selected-repository"})
	if err != nil {
		t.Fatal(err)
	}
	command, err := disclosure.DecodeCommand("local.create_task", []byte(`{"goal":"owner enrolled task","name":"Enrolled task"}`))
	if err != nil {
		t.Fatal(err)
	}
	reply, err := conn.Execute(ctx, scope, disclosure.CallIdentity{JSONRPCID: json.RawMessage(`1`)}, command, disclosure.ByteBudget{MaxBytes: 8192})
	if err != nil {
		t.Fatal("task execute", err)
	}
	result, err := reply.Release(ctx)
	if err != nil || result.IsError {
		t.Fatal("task release", result, err)
	}
	snap, err := f.s.Snapshot(ctx, store.ReadRequest{})
	if err != nil {
		t.Fatal(err)
	}
	var taskID string
	var taskWire store.SignedRecord
	for _, e := range snap.Entries {
		r, err := record.Parse(e.HeaderJCS, e.BodyJCS, e.ID)
		if err != nil {
			continue
		}
		if r.Header.Type == record.KindTask {
			if r.Header.Subj.RepoID != b.Repo {
				t.Fatal("task header lacks exact repo")
			}
			taskID = r.ID
			taskWire = e.SignedRecord
		}
	}
	if taskID == "" {
		raw, _ := json.Marshal(result)
		t.Fatal("task absent", string(raw))
	}
	signer, err := PreloadKeys(bytes.Repeat([]byte{0}, 32), f.key)
	if err != nil {
		t.Fatal(err)
	}
	defer signer.Clear()
	tokenID := strings.Repeat("e", 32)
	lock, err := ipc.Lock(store.BundleExportLock(f.c.Home, tokenID))
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	staging := filepath.Join(f.c.Home, "prepared.age")
	ids := []string{sessionID, taskID}
	// LOCAL full-body bundles retain copied-content closure. The bound chunk
	// reuses protected event seals from the original local chunk, so both are
	// required; this does not associate/retract the original local observation.
	for _, entry := range snap.Entries {
		r, err := record.Parse(entry.HeaderJCS, entry.BodyJCS, entry.ID)
		if err == nil && r.Header.Type == record.KindChunk {
			ids = append(ids, r.ID)
		}
	}
	selected, err := f.s.RegisterBundleExport(ctx, tokenID, staging, ids, &signer)
	if err != nil || len(selected.Data) != len(ids) {
		t.Fatal("bound bundle selection", selected.Excluded, err)
	}
	if err = os.WriteFile(staging, []byte("synthetic sealed bundle"), 0600); err != nil {
		t.Fatal(err)
	}
	controls, err := f.s.RevokeRepository(ctx, b.ID, &signer)
	if err != nil || len(controls) == 0 {
		t.Fatal("retire", controls, err)
	}
	published := false
	err = f.s.PublishBundleExport(ctx, tokenID, ids, func() error { published = true; return nil })
	if store.Code(err) != "bundle_invalidated" || published {
		t.Fatal("stale prepared bundle published", err)
	}
	if _, err = conn.Resolve(ctx, disclosure.IdentityInput{}); err == nil {
		t.Fatal("retired context credential authorized")
	}
	if _, err = f.s.Append(ctx, taskWire); err != nil {
		t.Fatal("same-id replay", err)
	}
	snap, err = f.s.Snapshot(ctx, store.ReadRequest{IDs: []string{observation, sessionID, taskID}})
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range snap.Entries {
		if e.ID == observation {
			if e.State != "live" || len(e.BodyJCS) == 0 {
				t.Fatal("original local observation retracted")
			}
		} else if e.State == "live" || len(e.BodyJCS) != 0 {
			t.Fatal("retired bound id restored", e.ID)
		}
	}
}

func TestRepositoryRetirementFencesNativeAppendAfterRestart(t *testing.T) {
	for _, boundFirst := range []bool{false, true} {
		t.Run(map[bool]string{false: "before-first-bound", true: "after-bound"}[boundFirst], func(t *testing.T) {
			ctx := context.Background()
			f := runtimeWorld(t, sourceMessages(t, 8, -1, ""))
			quietSource()
			first := requireCaptured(t, f)
			initial, _ := runtimeSnapshot(t, f.s)
			observation := ""
			for _, id := range first.CommittedRecordIDs {
				if r := initial[id]; r != nil && r.Header.Type == record.KindSession {
					observation = id
				}
			}
			root := filepath.Join(f.c.Home, "retired-project")
			if err := os.MkdirAll(filepath.Join(root, ".git"), 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, ".git", "config"), []byte("[remote \"origin\"]\nurl=https://github.com/acme/retired.git\n"), 0644); err != nil {
				t.Fatal(err)
			}
			b, err := f.s.EnrollRepository(ctx, store.RepositoryEnrollment{Observation: observation, ProjectRoot: root, Remote: "github.com/acme/retired"})
			if err != nil {
				t.Fatal(err)
			}
			if boundFirst {
				requireCaptured(t, f)
			}
			signer, err := PreloadKeys(bytes.Repeat([]byte{0}, 32), f.key)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = f.s.RevokeRepository(ctx, b.ID, &signer); err != nil {
				t.Fatal(err)
			}
			signer.Clear()
			before, err := f.s.InspectCapture(ctx, store.SourceOccurrence{Owner: b.Owner, Source: b.Source, SessionKey: b.Session})
			if err != nil {
				t.Fatal(err)
			}
			if err = f.p.Close(); err != nil {
				t.Fatal(err)
			}
			if err = f.s.Close(); err != nil {
				t.Fatal(err)
			}
			f.s, err = store.Open(ctx, store.Options{Dir: filepath.Join(f.c.Home, "synthetic-node"), PinnedGenesisID: f.c.OwnerGenesis, LocalMachineID: f.c.MachineID})
			if err != nil {
				t.Fatal(err)
			}
			defer f.s.Close()
			material, err := PreloadKeys(bytes.Repeat([]byte{52}, 32), f.key)
			if err != nil {
				t.Fatal(err)
			}
			f.p, err = NewPipeline(ctx, f.s, f.c, material)
			material.Clear()
			if err != nil {
				t.Fatal(err)
			}
			defer f.p.Close()
			const later = "post-retirement native append must not be captured"
			appended := sourceMessages(t, 9, 8, later)
			old, err := os.ReadFile(f.path)
			if err != nil || !bytes.HasPrefix(appended, old) {
				t.Fatal("fixture must append unchanged native transcript", err)
			}
			file, err := os.OpenFile(f.path, os.O_WRONLY|os.O_APPEND, 0)
			if err != nil {
				t.Fatal(err)
			}
			_, err = file.Write(appended[len(old):])
			closeErr := file.Close()
			if err != nil || closeErr != nil {
				t.Fatal(err, closeErr)
			}
			quietSource()
			if result, err := f.p.Capture(ctx, f.unit); err == nil || result.Status != "held" || len(result.CommittedRecordIDs) != 0 {
				t.Fatal("restarted native reader captured retired source", result, err)
			}
			read := false
			_, err = f.p.capture(ctx, f.unit, func(context.Context, preparationConfig, unitLocator, preOpenGate) (preparedBatch, *openedUnitHandle, error) {
				read = true
				return preparedBatch{}, nil, hold("test-reader-reached")
			})
			if err == nil || read {
				t.Fatal("retired source reached native read", read, err)
			}
			after, err := f.s.InspectCapture(ctx, store.SourceOccurrence{Owner: b.Owner, Source: b.Source, SessionKey: b.Session})
			if err != nil || after.Progress.Version != before.Progress.Version {
				t.Fatal("retired capture advanced progress", before, after, err)
			}
			snapshot, err := f.s.Snapshot(ctx, store.ReadRequest{})
			if err != nil {
				t.Fatal(err)
			}
			original := false
			for _, entry := range snapshot.Entries {
				if bytes.Contains(entry.BodyJCS, []byte(later)) {
					t.Fatal("post-retirement content persisted")
				}
				if entry.ID == observation {
					original = entry.State == "live" && len(entry.BodyJCS) != 0
				}
			}
			if !original {
				t.Fatal("original unbound observation no longer readable")
			}
		})
	}
}
