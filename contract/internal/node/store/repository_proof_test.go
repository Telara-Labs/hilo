package store

import (
	"context"
	"crypto/ed25519"
	"strings"
	"testing"

	"github.com/Telara-Labs/telara-memory/contract/record"
	"github.com/Telara-Labs/telara-memory/contract/sig"
)

func repoProofFixture(t *testing.T, w *world, pol, remote string, deps ...string) SignedRecord {
	t.Helper()
	repo, err := record.RepoID(remote)
	if err != nil {
		t.Fatal(err)
	}
	sk := w.sessionKey()
	return w.signed(record.Header{Type: record.KindSession, Prov: record.ProvTranscript, Subj: record.Subject{SessionKey: sk, RepoID: repo}, LID: record.SessionLID(sk, testMachine, 0), Pol: pol, Links: record.Links{DerivedFrom: deps}}, &record.SessionBody{NativeID: "22222222-2222-4222-8222-222222222222", NativeIDKind: record.NativeGlobal, Repo: &record.RepoRef{ID: repo, Remote: remote}})
}

func TestRepositoryProofRequiresCurrentVerifiedIdentity(t *testing.T) {
	for _, mode := range []string{"missing", "live", "retracted", "held", "revoked", "conflict"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			w := newWorld(t)
			joined := joinDevice(t, w)
			sign := installTenant(t, w, "tenant-repoproof")
			head := sign(1, pushPolicy(nil))
			w.append(head)
			const remote = "github.com/acme/widgets"
			repo, _ := record.RepoID(remote)
			proof := repoProofFixture(t, w, head.AdvisoryID, remote)
			if mode == "held" {
				proof = repoProofFixture(t, w, head.AdvisoryID, remote, strings.Repeat("9", 64))
			}
			if mode == "revoked" {
				r, err := record.Parse(proof.HeaderJCS, proof.BodyJCS, proof.AdvisoryID)
				if err != nil {
					t.Fatal(err)
				}
				h := r.Header
				h.Author = record.Author{MachineID: joined.o.LocalMachineID, KeyID: joined.KeyID()}
				h.LID = record.SessionLID(h.Subj.SessionKey, joined.o.LocalMachineID, 0)
				h.Prov = record.ProvDerived
				h.Red = record.Redact{Profile: record.ProfilePushMetadata, Epoch: 1, Fingerprint: strings.Repeat("a", 64)}
				h.Links = record.Links{Origin: strings.Repeat("b", 64)}
				r, err = record.Build(h, &record.SessionMetaBody{Repo: &record.MetaRepo{ID: repo, Remote: remote}})
				if err != nil {
					t.Fatal(err)
				}
				sg, err := sig.SignRecord(joined.key, r.ID)
				if err != nil {
					t.Fatal(err)
				}
				proof = wire(r, []record.Signature{sg})
			}
			if mode == "revoked" {
				if result, err := w.s.ImportBundle(ctx, BundleImport{LocalKeyID: w.o.PinnedGenesisID, Data: []SignedRecord{proof}}); err != nil || result.Data != 1 {
					t.Fatal("joined proof import", result, err)
				}
			} else if mode != "missing" {
				w.append(proof)
			}
			if mode == "retracted" {
				w.append(w.control(90, record.KindRetraction, proof.AdvisoryID))
			}
			if mode == "revoked" {
				revoke, err := sig.BuildKeyOp(record.KeyOpBody{Op: record.OpDeviceRevoke, Subject: sig.KeyRefOf(joined.key.Public().(ed25519.PublicKey), record.RoleDevice, joined.o.LocalMachineID), Genesis: w.o.PinnedGenesisID, Parents: []string{joined.add.AdvisoryID}, Reason: "lost"}, w.key.Public().(ed25519.PublicKey), testMachine, w.at+1, w.key)
				if err != nil {
					t.Fatal(err)
				}
				w.append(wire(revoke.Rec, revoke.Sigs))
			}
			if mode == "conflict" {
				sk := w.sessionKey()
				bad := w.signed(record.Header{Type: record.KindSession, Prov: record.ProvTranscript, Subj: record.Subject{SessionKey: sk, RepoID: repo}, LID: record.SessionLID(sk, testMachine, 1), Pol: head.AdvisoryID}, &record.SessionBody{NativeID: "22222222-2222-4222-8222-222222222222", NativeIDKind: record.NativeGlobal, Page: 1, Repo: &record.RepoRef{ID: repo, Remote: "github.com/other/project"}})
				if _, err := w.s.Append(ctx, bad); err != nil {
					return
				} // A rejected contradictory proof is already fail-closed.
			}
			got, err := w.s.RepositoryRemote(ctx, repo)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "live" && got != remote {
				t.Fatal("valid proof unavailable", got)
			}
			if mode != "live" && got != "" {
				t.Fatal("ineligible proof authorized identity", mode, got)
			}
		})
	}
}

func TestGovernedTaskBundleUsesSignedRepositoryProof(t *testing.T) {
	ctx := context.Background()
	w := newWorld(t)
	recv := joinDevice(t, w)
	sign := installTenant(t, w, "tenant-taskbundle")
	head := sign(1, pushPolicy(nil))
	w.append(head)
	installTenant(t, &world{t: t, s: recv.s, o: recv.o}, "tenant-taskbundle")
	if _, err := recv.s.Append(ctx, head); err != nil {
		t.Fatal(err)
	}
	const remote = "github.com/acme/widgets"
	repo, _ := record.RepoID(remote)
	taskID := "33333333-3333-4333-8333-333333333333"
	task := w.signed(record.Header{Type: record.KindTask, Prov: record.ProvMCPExplicit, Subj: record.Subject{TaskID: taskID, RepoID: repo}, LID: record.TaskLID(w.o.PinnedGenesisID, taskID), Pol: head.AdvisoryID, Op: record.H("op", "proof-task")}, &record.TaskBody{Name: "private task", Status: "active"})
	w.append(task)
	no, sel := registerExport(t, w.s, w.o, 40, []string{task.AdvisoryID}, worldSigner{w.key}, []byte("sealed"))
	if len(sel.Data) != 0 {
		t.Fatal("task without proof exported")
	}
	if err := no.publish(w.s, []string{task.AdvisoryID}); err != nil {
		t.Fatal(err)
	}
	no.lock.Close()
	proof := repoProofFixture(t, w, head.AdvisoryID, remote)
	w.append(proof)
	ids := []string{task.AdvisoryID, proof.AdvisoryID}
	e, sel := registerExport(t, w.s, w.o, 41, ids, worldSigner{w.key}, []byte("sealed"))
	if len(sel.Data) != 2 {
		t.Fatal("task with proof not exported", sel.Excluded)
	}
	if err := e.publish(w.s, ids); err != nil {
		t.Fatal(err)
	}
	e.lock.Close()
	var taskMeta, sessionMeta SignedRecord
	for _, item := range sel.Data {
		r, err := record.Parse(item.HeaderJCS, item.BodyJCS, item.AdvisoryID)
		if err != nil {
			t.Fatal(err)
		}
		if r.Header.Type == record.KindTask {
			taskMeta = item
		} else {
			sessionMeta = item
		}
	}
	in := BundleImport{LocalKeyID: recv.KeyID(), Keyring: sel.Keyring, Data: []SignedRecord{taskMeta}}
	if r, err := recv.s.ImportBundle(ctx, in); err != nil || r.Data != 0 {
		t.Fatal("receiver without proof accepted task", r, err)
	}
	in.Data = []SignedRecord{taskMeta, sessionMeta} // Deliberately task-first.
	if r, err := recv.s.ImportBundle(ctx, in); err != nil || r.Data != 2 || len(r.Excluded) != 0 {
		t.Fatal("task-first bundle with proof", r, err)
	}
	w.append(w.control(91, record.KindRetraction, proof.AdvisoryID))
	no, sel = registerExport(t, w.s, w.o, 42, []string{task.AdvisoryID}, worldSigner{w.key}, []byte("sealed"))
	if len(sel.Data) != 0 {
		t.Fatal("task exported after proof invalidation")
	}
	if err := no.publish(w.s, []string{task.AdvisoryID}); err != nil {
		t.Fatal(err)
	}
	no.lock.Close()
}
