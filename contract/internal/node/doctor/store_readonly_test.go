package doctor

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/store"
	"github.com/Telara-Labs/telara-memory/contract/record"
	"github.com/Telara-Labs/telara-memory/contract/sig"
)

// stoppedStore initializes a real main store in dir with its genesis and
// closes it, as an installation whose daemon is stopped: the database file
// exists and its -wal and -shm files do not.
func stoppedStore(t *testing.T, dir string) {
	t.Helper()
	st, _ := openMain(t, dir)
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{"-wal", "-shm"} {
		if _, err := os.Lstat(filepath.Join(dir, "memory.sqlite"+suffix)); !os.IsNotExist(err) {
			t.Fatal("stopped store left a sidecar", suffix, err)
		}
	}
}

func openMain(t *testing.T, dir string) (*store.Store, ed25519.PrivateKey) {
	t.Helper()
	key := ed25519.NewKeyFromSeed([]byte(strings.Repeat("m", 32)))
	pub := key.Public().(ed25519.PublicKey)
	genesis, machine := sig.KeyID(pub), "22222222-2222-4222-8222-222222222222"
	st, err := store.Open(context.Background(), store.Options{Dir: dir, PinnedGenesisID: genesis, LocalMachineID: machine})
	if err != nil {
		t.Fatal(err)
	}
	op, err := sig.BuildKeyOp(record.KeyOpBody{Op: record.OpGenesis, Subject: sig.KeyRefOf(pub, record.RoleDevice, machine), Genesis: genesis}, pub, machine, 1761150000000, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = st.Append(context.Background(), store.SignedRecord{HeaderJCS: op.Rec.HeaderJCS, BodyJCS: op.Rec.BodyJCS, Sigs: op.Sigs, AdvisoryID: op.Rec.ID}); err != nil {
		st.Close()
		t.Fatal(err)
	}
	return st, key
}

// mainFileRecords counts records in the main database file alone, ignoring
// any WAL, through an immutable handle that creates nothing. It is -1 when
// the main file does not yet hold the record table at all.
func mainFileRecords(t *testing.T, dir string) int64 {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(dir, "memory.sqlite")+"?mode=ro&immutable=1")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var n int64
	if err = db.QueryRow("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='record'").Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		return -1
	}
	if err = db.QueryRow("SELECT count(*) FROM record").Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// TestDoctorMainStoreInspectionSidecars covers the three sidecar states of
// the main store. Stopped (no -wal or -shm): doctor creates neither and
// changes no byte. Live (a running writer with committed rows only in its
// WAL): doctor reads through the WAL, reporting rows the main file alone
// does not hold, without changing the database or its WAL. A WAL whose index
// is missing cannot be read without creating one: doctor reports it and
// creates nothing.
func TestDoctorMainStoreInspectionSidecars(t *testing.T) {
	ctx := context.Background()
	newDir := func() string {
		base, err := filepath.EvalSymlinks(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		dir := filepath.Join(base, "data")
		if err = os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
		return dir
	}
	run := func(dir string) Report {
		t.Helper()
		r, err := Run(ctx, Config{DataDir: dir, Home: filepath.Dir(dir), ProbeTimeout: 200 * time.Millisecond})
		if err != nil {
			t.Fatal(err)
		}
		return r
	}

	t.Run("stopped", func(t *testing.T) {
		dir := newDir()
		stoppedStore(t, dir)
		before := snapshot(t, dir)
		r := run(dir)
		if after := snapshot(t, dir); fmt.Sprint(before) != fmt.Sprint(after) {
			t.Fatalf("doctor changed main-store files:\nbefore %v\nafter  %v", before, after)
		}
		if r.Store.State != "ok" || r.Store.Records != 1 || r.Scrub.WALBytes != 0 {
			t.Fatalf("stopped store %+v %+v", r.Store, r.Scrub)
		}
	})

	t.Run("live", func(t *testing.T) {
		dir := newDir()
		st, key := openMain(t, dir)
		defer st.Close()
		if _, err := st.EraseExact(ctx, store.EraseRequest{IDs: []string{strings.Repeat("ab", 32)}}, keySigner{key}); err != nil {
			t.Fatal(err)
		}
		wal := filepath.Join(dir, "memory.sqlite-wal")
		info, err := os.Lstat(wal)
		if err != nil || info.Size() == 0 {
			t.Fatal("live store has no WAL", err)
		}
		inMain := mainFileRecords(t, dir)
		before := snapshot(t, dir)
		r := run(dir)
		after := snapshot(t, dir)
		for name, entry := range before {
			// Readers record read marks in the live index; every other
			// byte, the database and its WAL included, is unchanged.
			if !strings.HasSuffix(name, "-shm") && after[name] != entry {
				t.Fatalf("doctor changed %s", name)
			}
		}
		if len(after) != len(before) {
			t.Fatalf("doctor created files:\nbefore %v\nafter  %v", before, after)
		}
		if r.Store.State != "ok" || r.Store.Records != 2 || r.Store.Records == inMain || r.Scrub.WALBytes != info.Size() {
			t.Fatalf("live WAL not read: %+v main-file records %d wal %+v", r.Store, inMain, r.Scrub)
		}
	})

	t.Run("wal-without-index", func(t *testing.T) {
		dir := newDir()
		stoppedStore(t, dir)
		if err := os.WriteFile(filepath.Join(dir, "memory.sqlite-wal"), nil, 0600); err != nil {
			t.Fatal(err)
		}
		before := snapshot(t, dir)
		r := run(dir)
		if after := snapshot(t, dir); fmt.Sprint(before) != fmt.Sprint(after) {
			t.Fatalf("doctor changed main-store files:\nbefore %v\nafter  %v", before, after)
		}
		if r.Store.State != "error" || r.Store.Error != "wal_index_missing" {
			t.Fatalf("WAL without index %+v", r.Store)
		}
	})
}
