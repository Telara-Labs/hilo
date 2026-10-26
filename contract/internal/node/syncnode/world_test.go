package syncnode

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/capture"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/store"
	nodesync "github.com/Telara-Labs/telara-memory/contract/internal/node/sync"
	"github.com/Telara-Labs/telara-memory/contract/record"
	"github.com/Telara-Labs/telara-memory/contract/sig"
)

const testMachine = "11111111-1111-4111-8111-111111111111"

var (
	repoA = "r1:" + strings.Repeat("a", 64)
	repoB = "r1:" + strings.Repeat("b", 64)
)

// memVault models native custody: slots are never overwritten in place.
type memVault struct {
	mu    sync.Mutex
	items map[string][]byte
}

func newMemVault() *memVault { return &memVault{items: map[string][]byte{}} }
func (v *memVault) Put(_ context.Context, h string, b []byte) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if _, ok := v.items[h]; ok {
		return fmt.Errorf("exists")
	}
	v.items[h] = append([]byte(nil), b...)
	return nil
}
func (v *memVault) Get(_ context.Context, h string) ([]byte, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	b, ok := v.items[h]
	if !ok {
		return nil, fmt.Errorf("missing")
	}
	return append([]byte(nil), b...), nil
}
func (v *memVault) Delete(_ context.Context, h string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	delete(v.items, h)
	return nil
}
func (v *memVault) count() int {
	v.mu.Lock()
	defer v.mu.Unlock()
	return len(v.items)
}

// world is a real node store plus device key in a private data directory.
type world struct {
	t       *testing.T
	dir     string
	st      *store.Store
	key     ed25519.PrivateKey
	genesis string
	machine string
	// keyring is this device's enrollment: the genesis operation, then its
	// device_add when it joined an existing genesis.
	keyring []store.SignedRecord
	at      int64
	keys    *capture.PreloadedKeyMaterial
	vault   *memVault
	hosted  *hosted
}

func newWorld(t *testing.T) *world {
	t.Helper()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(base, "data")
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32))
	pub := key.Public().(ed25519.PublicKey)
	w := &world{t: t, dir: dir, key: key, genesis: sig.KeyID(pub), machine: testMachine, at: 1761150000000, vault: newMemVault()}
	w.st, err = store.Open(context.Background(), store.Options{Dir: dir, PinnedGenesisID: w.genesis, LocalMachineID: testMachine})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { w.st.Close() })
	op, err := sig.BuildKeyOp(record.KeyOpBody{Op: record.OpGenesis, Subject: sig.KeyRefOf(pub, record.RoleDevice, testMachine), Genesis: w.genesis}, pub, testMachine, w.at, key)
	if err != nil {
		t.Fatal(err)
	}
	w.append(op.Rec, op.Sigs)
	w.keyring = []store.SignedRecord{{HeaderJCS: op.Rec.HeaderJCS, BodyJCS: op.Rec.BodyJCS, Sigs: op.Sigs, AdvisoryID: op.Rec.ID}}
	keys, err := capture.PreloadKeys(make([]byte, 32), key)
	if err != nil {
		t.Fatal(err)
	}
	w.keys = &keys
	w.hosted = newHosted(t, pub, testMachine, []string{repoA})
	return w
}

func (w *world) append(r *record.Record, sigs []record.Signature) store.AdmissionResult {
	w.t.Helper()
	a, err := w.st.Append(context.Background(), store.SignedRecord{HeaderJCS: r.HeaderJCS, BodyJCS: r.BodyJCS, Sigs: sigs, AdvisoryID: r.ID})
	if err != nil {
		w.t.Fatal(err)
	}
	return a
}

func (w *world) signed(h record.Header, body any) (*record.Record, []record.Signature) {
	w.t.Helper()
	w.at++
	h.Author = record.Author{MachineID: w.machine, KeyID: sig.KeyID(w.key.Public().(ed25519.PublicKey))}
	h.At = w.at
	h.Red = record.Redact{Profile: record.ProfileLocal}
	r, err := record.Build(h, body)
	if err != nil {
		w.t.Fatal(err)
	}
	s, err := sig.SignRecord(w.key, r.ID)
	if err != nil {
		w.t.Fatal(err)
	}
	return r, []record.Signature{s}
}

// task appends a local task whose goal text must never leave the node.
func (w *world) task(n int, repo, status string) *record.Record {
	w.t.Helper()
	id := fmt.Sprintf("22222222-2222-4222-8222-%012d", n)
	r, s := w.signed(record.Header{Type: record.KindTask, LID: record.TaskLID(w.genesis, id), Prov: record.ProvMCPExplicit, Subj: record.Subject{TaskID: id, RepoID: repo}, Op: record.H("op", fmt.Sprint(n))}, &record.TaskBody{Name: "private task name", Goal: "private goal text never pushed", Status: status})
	w.append(r, s)
	return r
}

// control builds a device-signed control envelope of kind k over ids.
func (w *world) control(n int, k record.Kind, ids ...string) record.Envelope {
	w.t.Helper()
	h := record.Header{Type: k, Prov: record.ProvUser}
	h.LID, _ = record.ControlLID(k, w.genesis, record.H("nonce", fmt.Sprint(n))[:32])
	var body any = &record.RetractionBody{IDs: ids, Reason: "redaction_repair"}
	if k == record.KindErasure {
		body = &record.ErasureBody{EventCoverage: "complete", Selectors: record.Selectors{IDs: ids}, Reason: "user_request"}
	}
	r, s := w.signed(h, body)
	return envelopeOf(r, s)
}

// foreignData is a data envelope another device pushed. v1 quarantines it.
func (w *world) foreignData(n int) record.Envelope {
	w.t.Helper()
	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{byte(40 + n)}, 32))
	id := fmt.Sprintf("33333333-3333-4333-8333-%012d", n)
	h := record.Header{Type: record.KindTask, LID: record.TaskLID(sig.KeyID(other.Public().(ed25519.PublicKey)), id), Author: record.Author{MachineID: "44444444-4444-4444-8444-444444444444", KeyID: sig.KeyID(other.Public().(ed25519.PublicKey))}, At: w.at, Prov: record.ProvDerived, Subj: record.Subject{TaskID: id, RepoID: repoA}, Red: record.Redact{Profile: record.ProfilePushMetadata, Epoch: 1, Fingerprint: strings.Repeat("d", 64)}, Links: record.Links{Origin: strings.Repeat("e", 64)}}
	r, err := record.Build(h, &record.TaskMetaBody{Status: "active"})
	if err != nil {
		w.t.Fatal(err)
	}
	s, _ := sig.SignRecord(other, r.ID)
	return envelopeOf(r, []record.Signature{s})
}

// enroll writes an enabled profile bound to the hosted fixture.
func (w *world) enroll() Profile {
	w.t.Helper()
	ctx := context.Background()
	key, _, err := NewCredential(ctx, w.vault)
	if err != nil {
		w.t.Fatal(err)
	}
	refresh, err := StoreRefresh(ctx, w.vault, w.hosted.bootstrap)
	if err != nil {
		w.t.Fatal(err)
	}
	jwk, err := nodesync.PublicJWKOf(&w.hosted.authKey.PublicKey)
	if err != nil {
		w.t.Fatal(err)
	}
	w.hosted.mu.Lock()
	grant, _ := w.hosted.grantFor(w.machine)
	w.hosted.mu.Unlock()
	p := Profile{Version: ProfileVersion, Enabled: true, Genesis: w.genesis, Device: w.machine, Credential: key, Refresh: refresh, Origin: w.hosted.srv.URL, Tenant: w.hosted.tenant, User: w.hosted.user, Config: w.hosted.config, AuthIssuer: "https://auth.example", AuthKey: &jwk, ServiceKeys: []ServiceKey{w.hosted.serviceKey()}, ServiceKeyPins: string(sig.PinnedTLSLogin), Grant: &grant}
	if err := SaveProfile(w.dir, p); err != nil {
		w.t.Fatal(err)
	}
	return p
}

func (w *world) worker() *Worker {
	w.t.Helper()
	wk, err := NewWorker(context.Background(), Config{Dir: w.dir, Store: w.st, Signer: w.keys, Vault: w.vault, TLSRoots: w.hosted.srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs, MaxRetry: 1})
	if err != nil {
		w.t.Fatal(err)
	}
	w.t.Cleanup(func() { _ = wk.state.Close() })
	return wk
}

func (w *world) selectRepo(wk *Worker, repo string) Rule {
	w.t.Helper()
	r, err := wk.state.PutRule(context.Background(), "default", []string{repo}, []string{"session", "task"}, true)
	if err != nil {
		w.t.Fatal(err)
	}
	return r
}

// rows returns record id -> state for the destination outbox.
func rows(t *testing.T, wk *Worker, p Profile) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := wk.state.tx(context.Background(), func(q querier) error {
		rs, err := q.QueryContext(context.Background(), "SELECT source_id,state FROM outbox WHERE destination=?", destination(p.Scope()))
		if err != nil {
			return err
		}
		defer rs.Close()
		for rs.Next() {
			var id, state string
			if err := rs.Scan(&id, &state); err != nil {
				return err
			}
			out[id] = state
		}
		return rs.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func count(t *testing.T, wk *Worker, query string, args ...any) int {
	t.Helper()
	var n int
	err := wk.state.tx(context.Background(), func(q querier) error {
		return q.QueryRowContext(context.Background(), query, args...).Scan(&n)
	})
	if err != nil && err != sql.ErrNoRows {
		t.Fatal(err)
	}
	return n
}

func cursorsOf(t *testing.T, wk *Worker, p Profile) cursorState {
	t.Helper()
	c, err := wk.state.cursors(context.Background(), destination(p.Scope()))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func storeRead(ids ...string) store.ReadRequest { return store.ReadRequest{IDs: ids} }
