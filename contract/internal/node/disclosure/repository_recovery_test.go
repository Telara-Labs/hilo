//go:build linux || darwin

package disclosure_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Telara-Labs/hilo/contract/internal/node/capture"
	"github.com/Telara-Labs/hilo/contract/internal/node/disclosure"
	"github.com/Telara-Labs/hilo/contract/internal/node/store"
)

type contextFaultVault struct {
	unitVault
	fail                    string
	dir                     string
	puts, deletes, abandons int
	metadataBackup          string
	metadataBlocked         bool
	metadataBefore          []byte
}

func (v *contextFaultVault) Put(ctx context.Context, id string, b []byte) error {
	v.puts++
	if v.fail == "before-put" {
		return errors.New("synthetic_native_refusal")
	}
	if err := v.unitVault.Put(ctx, id, b); err != nil {
		return err
	}
	if v.fail == "after-put" {
		return errors.New("synthetic_unknown_outcome")
	}
	if v.fail == "active-metadata" {
		// A mode-only fault is ineffective for privileged CI users. Preserve the
		// exact creating descriptor and obstruct its final publication instead.
		path := filepath.Join(v.dir, store.RepositoryContextsName)
		before, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		backupDir, err := os.MkdirTemp(v.dir, ".repository-context-fault-")
		if err != nil {
			return err
		}
		backup := filepath.Join(backupDir, store.RepositoryContextsName)
		if err = os.Rename(path, backup); err != nil {
			os.Remove(backupDir)
			return err
		}
		v.metadataBackup, v.metadataBefore = backup, before
		if err = os.Mkdir(path, 0700); err != nil {
			return err
		}
		v.metadataBlocked = true
	}
	return nil
}

func (v *contextFaultVault) restoreMetadata() error {
	path := filepath.Join(v.dir, store.RepositoryContextsName)
	if v.metadataBlocked {
		if err := os.Remove(path); err != nil {
			return err
		}
		v.metadataBlocked = false
	}
	if v.metadataBackup != "" {
		backup := v.metadataBackup
		if err := os.Rename(backup, path); err != nil {
			return err
		}
		v.metadataBackup = ""
		return os.Remove(filepath.Dir(backup))
	}
	return nil
}
func (v *contextFaultVault) Delete(ctx context.Context, id string) error {
	v.deletes++
	return v.unitVault.Delete(ctx, id)
}
func (v *contextFaultVault) AbandonPlanned(ctx context.Context, id string) error {
	v.abandons++
	return v.unitVault.Delete(ctx, id)
}

type repositoryRecoveryFixture struct {
	dir    string
	s      *store.Store
	admin  *disclosure.Administration
	svc    *disclosure.Service
	vault  *contextFaultVault
	q      store.RepositoryEnrollment
	signer capture.PreloadedKeyMaterial
}

func repositoryRecoveryWorld(t *testing.T) *repositoryRecoveryFixture {
	t.Helper()
	ctx := context.Background()
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(home, 0700); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(home, "data")
	v := &contextFaultVault{dir: dir}
	if err = disclosure.BootstrapInstalled(ctx, dir, "Repository recovery", disclosure.Grant{Repos: disclosure.AllLocalRepos(), Channels: []disclosure.Channel{disclosure.S}}, disclosure.TaskWriteGrant{}, v); err != nil {
		t.Fatal(err)
	}
	owner, machine, key, err := disclosure.InstalledDeviceKey(ctx, dir, v)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	s, err := store.Open(ctx, store.Options{Dir: dir, PinnedGenesisID: owner, LocalMachineID: machine})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	root := filepath.Join(home, "sessions")
	if err = os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "rollout-2026-10-24-01990000-0000-4000-8000-000000000001.jsonl")
	raw, err := os.ReadFile(filepath.Join("..", "capture", "testdata", "codex.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	past := time.Now().Add(-10 * time.Second)
	if err = os.Chtimes(path, past, past); err != nil {
		t.Fatal(err)
	}
	keys, err := capture.PreloadKeys(make([]byte, 32), key)
	if err != nil {
		t.Fatal(err)
	}
	p, err := capture.NewPipeline(ctx, s, capture.Config{Home: home, OwnerGenesis: owner, MachineID: machine, CaptureEnabled: true, Roots: map[string]capture.Root{"fixture": {Client: "codex", AbsPath: root}}}, keys)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	time.Sleep(2100 * time.Millisecond) // mtime and ctime must both be quiet; Chtimes cannot backdate ctime.
	if result, err := p.Capture(ctx, capture.Unit{RootID: "fixture", RelativePath: filepath.Base(path)}); err != nil || result.Status != "committed" {
		t.Fatal("real reader fixture", result, err)
	}
	inspected, err := s.InspectRepositories(ctx)
	if err != nil || len(inspected.Observations) != 1 {
		t.Fatal("native observation", inspected, err)
	}
	project := filepath.Join(home, "project")
	if err = os.Mkdir(project, 0755); err != nil {
		t.Fatal(err)
	}
	if err = os.Mkdir(filepath.Join(project, ".git"), 0755); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(project, ".git", "config"), []byte("[remote \"origin\"]\nurl=git@github.com:acme/widgets.git\n"), 0644); err != nil {
		t.Fatal(err)
	}
	material, err := disclosure.PreloadRuntimeMaterial(bytes.Repeat([]byte{0}, 32), key)
	if err != nil {
		t.Fatal(err)
	}
	svc, err := disclosure.New(ctx, s, disclosure.Config{OwnerGenesis: owner, MachineID: machine}, material)
	material.Clear()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { svc.Close() })
	admin, err := svc.Administration(ctx)
	if err != nil {
		t.Fatal(err)
	}
	v.puts = 0
	return &repositoryRecoveryFixture{dir, s, admin, svc, v, store.RepositoryEnrollment{Observation: inspected.Observations[0].ID, ProjectRoot: project, Remote: "github.com/acme/widgets"}, keys}
}
func TestRepositoryContextFailedEnrollmentRetiresEveryNativePhase(t *testing.T) {
	for _, phase := range []string{"register", "binding", "before-put", "after-put", "active-metadata", "active"} {
		t.Run(phase, func(t *testing.T) {
			f := repositoryRecoveryWorld(t)
			t.Cleanup(func() {
				if err := f.vault.restoreMetadata(); err != nil {
					t.Error("restore metadata fault", err)
				}
			})
			defer f.signer.Clear()
			ctx := context.Background()
			var db *sql.DB
			if phase == "register" || phase == "binding" {
				var err error
				db, err = sql.Open("sqlite", filepath.Join(f.dir, "memory.sqlite"))
				if err != nil {
					t.Fatal(err)
				}
				defer db.Close()
				table := "client_credential"
				if phase == "binding" {
					table = "repository_credential"
				}
				if _, err = db.Exec("CREATE TRIGGER context_fault BEFORE INSERT ON " + table + " BEGIN SELECT RAISE(ABORT,'synthetic'); END"); err != nil {
					t.Fatal(err)
				}
			} else if phase != "active" {
				f.vault.fail = phase
			}
			result, err := disclosure.EnrollRepositoryContext(ctx, f.dir, f.s, f.admin, f.vault, f.q)
			if phase == "active" {
				if err != nil || result.State != "active" {
					t.Fatal(result, err)
				}
			} else if err == nil {
				t.Fatal("injected boundary acknowledged")
			}
			if phase == "active-metadata" {
				if !f.vault.metadataBlocked || f.vault.puts != 1 {
					t.Fatal("metadata fault did not reach publication after native creation")
				}
				if err = f.vault.restoreMetadata(); err != nil {
					t.Fatal("restore metadata fault", err)
				}
				raw, readErr := os.ReadFile(filepath.Join(f.dir, store.RepositoryContextsName))
				if readErr != nil || !bytes.Equal(raw, f.vault.metadataBefore) {
					t.Fatal("pending metadata changed during fault restoration", readErr)
				}
				var pending struct {
					Contexts []disclosure.RepositoryContext `json:"contexts"`
				}
				if json.Unmarshal(raw, &pending) != nil || len(pending.Contexts) != 1 || pending.Contexts[0].State != "pending" || pending.Contexts[0].Native != "creating" || pending.Contexts[0].Credential == "" {
					t.Fatal("metadata fault did not retain the issued pending context")
				}
			}
			f.vault.fail = ""
			if db != nil {
				if _, err = db.Exec("DROP TRIGGER context_fault"); err != nil {
					t.Fatal(err)
				}
			}
			inspected, err := f.s.InspectRepositories(ctx)
			if err != nil || len(inspected.Bindings) != 1 {
				t.Fatal("durable pending binding", inspected, err)
			}
			binding := inspected.Bindings[0]
			if _, err = disclosure.RetireRepositoryContext(ctx, f.dir, binding.ID, f.s, f.vault, &f.signer); err != nil {
				t.Fatal("owner pending recovery", err)
			}
			if _, err = disclosure.RetireRepositoryContext(ctx, f.dir, binding.ID, f.s, f.vault, &f.signer); err != nil {
				t.Fatal("repeat owner recovery", err)
			}
			handles, err := disclosure.OwnedCredentialHandles(f.dir)
			if err != nil || len(handles) != 0 {
				t.Fatal("retired inventory stranded", handles, err)
			}
			if phase == "register" || phase == "binding" {
				if f.vault.puts != 0 || f.vault.deletes != 0 || f.vault.abandons != 0 {
					t.Fatal("unstarted phase touched native namespace")
				}
			}
			if phase == "before-put" || phase == "after-put" || phase == "active-metadata" {
				if f.vault.abandons != 1 {
					t.Fatal("ambiguous creation skipped narrow cleanup")
				}
			}
			if phase == "active" && f.vault.deletes != 1 {
				t.Fatal("bound native slot not retired")
			}
			if len(f.vault.values) != 1 {
				t.Fatal("context retirement changed base authority")
			}
		})
	}
}

func TestRepositoryContextCrashAfterAtomicRegisterBeforeMetadata(t *testing.T) {
	f := repositoryRecoveryWorld(t)
	defer f.signer.Clear()
	ctx := context.Background()
	b, err := f.s.EnrollRepository(ctx, f.q)
	if err != nil {
		t.Fatal(err)
	}
	owner, machine, err := store.InstalledIdentity(f.dir)
	if err != nil {
		t.Fatal(err)
	}
	c := disclosure.RepositoryContext{ID: strings.Repeat("a", 32), Binding: b.ID, Generation: b.Generation, Handle: strings.Repeat("c", 32), State: "pending", Native: "unstarted"}
	raw, _ := json.Marshal(map[string]any{"version": 1, "owner": owner, "machine": machine, "contexts": []disclosure.RepositoryContext{c}})
	if err = store.WriteProfileRecord(f.dir, store.RepositoryContextsName, raw); err != nil {
		t.Fatal(err)
	}
	repos, _ := disclosure.ConcreteRepos([]string{b.Repo})
	registered, err := f.admin.RegisterRepository(ctx, disclosure.RegisterClient{AdminOpID: "repository-" + c.ID, ClientName: "Owner repository context", ReadGrant: disclosure.Grant{Repos: repos, Channels: []disclosure.Channel{disclosure.S}}, TaskWrites: disclosure.TaskWriteGrant{Repos: repos, Actions: []disclosure.TaskMutation{disclosure.Create}}}, b.ID, b.Generation)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := registered.Secret.Take()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(secret)
	if _, err = disclosure.RetireRepositoryContext(ctx, f.dir, b.ID, f.s, f.vault, &f.signer); err != nil {
		t.Fatal(err)
	}
	// Authenticate itself must fail because the mapped verifier was revoked,
	// even though the crash prevented its UUID from reaching the descriptor.
	if conn, err := f.svc.Authenticate(ctx, disclosure.CredentialProof{CredentialID: registered.CredentialID, Token: secret}); err == nil {
		conn.Close()
		t.Fatal("issued orphan verifier survived retirement")
	}
	if f.vault.puts != 0 || f.vault.deletes != 0 || f.vault.abandons != 0 {
		t.Fatal("known unstarted slot probed native namespace")
	}
}
