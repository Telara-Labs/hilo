package doctor

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/store"
	nodesync "github.com/Telara-Labs/telara-memory/contract/internal/node/sync"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/syncnode"
	"github.com/Telara-Labs/telara-memory/contract/record"
	"github.com/Telara-Labs/telara-memory/contract/sig"
)

// snapshot is every file under dir with its mode and content digest.
func snapshot(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, path)
		entry := info.Mode().String()
		if info.Mode().IsRegular() {
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			sum := sha256.Sum256(b)
			entry += " " + hex.EncodeToString(sum[:])
		}
		out[rel] = entry
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// syncRows dumps every row of the sync database through a read-only handle.
func syncRows(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, store.SyncDatabaseName)
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		return "absent"
	}
	// Immutable without a WAL, so the dump itself creates no -wal or -shm.
	query := "?mode=ro"
	if _, err := os.Lstat(path + "-wal"); os.IsNotExist(err) {
		query = "?mode=ro&immutable=1"
	}
	db, err := sql.Open("sqlite", "file:"+path+query)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	names := []string{}
	rows, err := db.Query("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var n string
		if err = rows.Scan(&n); err != nil {
			t.Fatal(err)
		}
		names = append(names, n)
	}
	rows.Close()
	var b strings.Builder
	for _, n := range names {
		r, err := db.Query("SELECT * FROM " + n)
		if err != nil {
			t.Fatal(err)
		}
		cols, _ := r.Columns()
		var lines []string
		for r.Next() {
			vals := make([]any, len(cols))
			ptrs := make([]any, len(cols))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			if err = r.Scan(ptrs...); err != nil {
				t.Fatal(err)
			}
			lines = append(lines, fmt.Sprint(vals...))
		}
		r.Close()
		sort.Strings(lines)
		fmt.Fprintf(&b, "%s:%v\n", n, lines)
	}
	return b.String()
}

func randomHandle(t *testing.T) string {
	t.Helper()
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b[:])
}

// syncProfile writes a valid sync profile, enrolled or not, without a vault.
func syncProfile(t *testing.T, dir string, enrolled bool) {
	t.Helper()
	device := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{21}, 32))
	p := syncnode.Profile{Version: syncnode.ProfileVersion, Genesis: sig.KeyID(device.Public().(ed25519.PublicKey)), Device: "33333333-3333-4333-8333-333333333333", Credential: randomHandle(t)}
	if enrolled {
		auth, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		jwk, err := nodesync.PublicJWKOf(&auth.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		service := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{22}, 32)).Public().(ed25519.PublicKey)
		p.Enabled, p.Refresh = true, randomHandle(t)
		p.Origin, p.Tenant, p.User, p.Config, p.AuthIssuer = "https://tenant.example", "tenant", "user", "config", "https://auth.example"
		p.AuthKey = &jwk
		p.ServiceKeys = []syncnode.ServiceKey{{KeyID: sig.KeyID(service), Public: base64.RawURLEncoding.EncodeToString(service)}}
		p.Grant = &nodesync.MemoryGrant{Ops: []string{"push"}, Repos: []string{"github.com/a/*"}, Origin: "local", GenesisID: p.Genesis, DeviceID: p.Device, ExpiresAtUnix: time.Now().Add(time.Hour).Unix()}
	}
	if err := syncnode.SaveProfile(dir, p); err != nil {
		t.Fatal(err)
	}
}

// Doctor is a read-only diagnostic. Its sync inspection must not create the
// sync database, apply its schema, insert a cursor row or change any byte,
// whatever state the profile is in, and its inspection of a stopped main
// store must not create the store's -wal or -shm files. Each case is
// compared with a fresh snapshot of every file, main store included, and
// every sync row.
func TestDoctorSyncInspectionWritesNothing(t *testing.T) {
	for _, kind := range []string{"enrolled", "enrolled-missing-sidecar", "incomplete", "incomplete-empty-sidecar"} {
		t.Run(kind, func(t *testing.T) {
			base, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			dir := filepath.Join(base, "data")
			home := filepath.Join(base, "home")
			for _, d := range []string{dir, home} {
				if err = os.Mkdir(d, 0700); err != nil {
					t.Fatal(err)
				}
			}
			ctx := context.Background()
			stoppedStore(t, dir)
			enrolled := strings.HasPrefix(kind, "enrolled")
			syncProfile(t, dir, enrolled)
			switch kind {
			case "enrolled":
				// A real sidecar with a rule and no cursor row for this
				// destination yet, as before the first round.
				st, err := syncnode.OpenState(ctx, dir)
				if err != nil {
					t.Fatal(err)
				}
				if _, err = st.PutRule(ctx, "metadata", []string{"r1:" + strings.Repeat("a", 64)}, []string{string(record.KindTask)}, true); err != nil {
					t.Fatal(err)
				}
				if err = st.Close(); err != nil {
					t.Fatal(err)
				}
			case "incomplete-empty-sidecar":
				// A writer that crashed after creating the file, before schema.
				if err = os.WriteFile(filepath.Join(dir, store.SyncDatabaseName), nil, 0600); err != nil {
					t.Fatal(err)
				}
			}
			files, rows := snapshot(t, dir), syncRows(t, dir)
			r, err := Run(ctx, Config{DataDir: dir, Home: home, ProbeTimeout: 200 * time.Millisecond})
			if err != nil {
				t.Fatal(err)
			}
			if after := snapshot(t, dir); !reflect.DeepEqual(files, after) {
				t.Fatalf("doctor changed files:\nbefore %v\nafter  %v", files, after)
			}
			if after := syncRows(t, dir); after != rows {
				t.Fatalf("doctor changed sync rows:\nbefore %s\nafter  %s", rows, after)
			}
			if mainStoreSupported && (r.Store.State != "ok" || r.Store.Records != 1) {
				t.Fatalf("main store section %+v", r.Store)
			}
			if !r.Sync.Configured || r.Sync.Enrolled != enrolled || r.Sync.Error != "" {
				t.Fatalf("sync section %+v", r.Sync)
			}
			wantState := "absent"
			if kind == "enrolled" || kind == "incomplete-empty-sidecar" {
				wantState = "present"
			}
			if r.Sync.State != wantState {
				t.Fatalf("sidecar state %q, want %q", r.Sync.State, wantState)
			}
			// The read-only report matches the writing status a round would
			// produce from the same state.
			st, err := syncnode.Status(ctx, dir)
			if err != nil {
				t.Fatal(err)
			}
			want := append([]string{}, syncnode.Blockers(st, time.Now())...)
			if r.Sync.Enabled != st.Enabled || r.Sync.LastRound != st.LastRound || !reflect.DeepEqual(r.Sync.Outbox, st.Outbox) || !reflect.DeepEqual(r.Sync.Blockers, want) {
				t.Fatalf("read-only status differs from status:\n%+v\n%+v %v", r.Sync, st, want)
			}
		})
	}
}
