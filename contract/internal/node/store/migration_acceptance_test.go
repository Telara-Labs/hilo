package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// The immutable SQL fixtures define the pre-disclosure schema. Records and
// receipts are actual signed native capture output. This is schema-upgrade
// acceptance; no execution of an older binary is asserted.
func migrationLegacyDatabase(t *testing.T, f *producerFixture) (Options, map[string]string) {
	t.Helper()
	ctx := context.Background()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	o := f.w.o
	o.Dir = dir
	path := filepath.Join(dir, "memory.sqlite")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	file.Close()
	db, err := sql.Open("sqlite", SQLiteURI(path, ""))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	conn, err := db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	st := &Store{db: db, conn: conn, opts: o, path: path}
	if err = st.configure(ctx); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"pre_disclosure_schema.sql", "pre_disclosure_capture.sql"} {
		b, e := os.ReadFile(filepath.Join("testdata", name))
		if e != nil {
			t.Fatal(e)
		}
		if _, e = conn.ExecContext(ctx, string(b)); e != nil {
			t.Fatal(e)
		}
	}
	rows, err := conn.QueryContext(ctx, "SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'search%' ORDER BY rowid")
	if err != nil {
		t.Fatal(err)
	}
	var tables []string
	for rows.Next() {
		var table string
		if err = rows.Scan(&table); err != nil {
			t.Fatal(err)
		}
		tables = append(tables, table)
	}
	if err = rows.Err(); err != nil {
		t.Fatal(err)
	}
	rows.Close()
	if _, err = conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		t.Fatal(err)
	}
	for _, table := range tables {
		source, e := f.w.s.conn.QueryContext(ctx, "SELECT * FROM "+table+" ORDER BY rowid")
		if e != nil {
			t.Fatal(e)
		}
		columns, e := source.Columns()
		if e != nil {
			t.Fatal(e)
		}
		for source.Next() {
			values := make([]any, len(columns))
			pointers := make([]any, len(columns))
			for i := range values {
				pointers[i] = &values[i]
			}
			if e = source.Scan(pointers...); e != nil {
				t.Fatal(e)
			}
			marks := strings.TrimSuffix(strings.Repeat("?,", len(columns)), ",")
			if _, e = conn.ExecContext(ctx, "INSERT INTO "+table+" VALUES("+marks+")", values...); e != nil {
				t.Fatal(table, e)
			}
		}
		if e = source.Err(); e != nil {
			t.Fatal(e)
		}
		source.Close()
	}
	if _, err = conn.ExecContext(ctx, "UPDATE meta SET schema_version=1"); err != nil {
		t.Fatal(err)
	}
	id := f.plan.NewRecords[0].AdvisoryID
	for _, query := range []string{"DELETE FROM passage", "DELETE FROM vector", "DELETE FROM projection_job"} {
		if _, err = conn.ExecContext(ctx, query); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = conn.ExecContext(ctx, "INSERT INTO passage VALUES(?,?)", id, "migrationnativecanary"); err != nil {
		t.Fatal(err)
	}
	if _, err = conn.ExecContext(ctx, "INSERT INTO search(search) VALUES('rebuild')"); err != nil {
		t.Fatal(err)
	}
	if _, err = conn.ExecContext(ctx, "INSERT INTO search(search,rank) VALUES('secure-delete',1)"); err != nil {
		t.Fatal(err)
	}
	if _, err = conn.ExecContext(ctx, "INSERT INTO vector VALUES(?,1,'legacy-native',?)", id, []byte{1, 2, 3}); err != nil {
		t.Fatal(err)
	}
	if _, err = conn.ExecContext(ctx, "INSERT INTO projection_job VALUES(?,1)", id); err != nil {
		t.Fatal(err)
	}
	if _, err = conn.ExecContext(ctx, "COMMIT"); err != nil {
		t.Fatal(err)
	}
	var hits int
	if err = conn.QueryRowContext(ctx, "SELECT count(*) FROM search WHERE search MATCH 'migrationnativecanary'").Scan(&hits); err != nil || hits != 1 {
		t.Fatal("legacy positive projection missing", hits, err)
	}
	before := migrationRows(t, conn, []string{"record", "record_body", "capture_instance", "capture_progress", "capture_source", "capture_page", "capture_transition", "capture_transition_record", "capture_transition_source", "capture_transition_page"})
	if err = conn.Close(); err != nil {
		t.Fatal(err)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{"", "-wal", "-shm", "-journal"} {
		if e := os.Chmod(path+suffix, 0600); e != nil && !os.IsNotExist(e) {
			t.Fatal(e)
		}
	}
	return o, before
}

// Hashes stay only in test RAM. Exact bodies, salts, signatures and mutable
// capture progress are compared without logging their contents.
func migrationRows(t *testing.T, conn *sql.Conn, tables []string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, table := range tables {
		rows, err := conn.QueryContext(context.Background(), "SELECT * FROM "+table+" ORDER BY rowid")
		if err != nil {
			t.Fatal(err)
		}
		columns, err := rows.Columns()
		if err != nil {
			t.Fatal(err)
		}
		h := sha256.New()
		for rows.Next() {
			values := make([]any, len(columns))
			pointers := make([]any, len(columns))
			for i := range values {
				pointers[i] = &values[i]
			}
			if err = rows.Scan(pointers...); err != nil {
				t.Fatal(err)
			}
			fmt.Fprintf(h, "%#v\n", values)
		}
		if err = rows.Err(); err != nil {
			t.Fatal(err)
		}
		rows.Close()
		out[table] = fmt.Sprintf("%x", h.Sum(nil))
	}
	return out
}
func TestPreDisclosureSchemaUpgradePreservesCaptureWithoutNativeCompleteness(t *testing.T) {
	f := newProducer(t, "migrationnativecanary")
	ctx := context.Background()
	original := f.commit()
	inspection, err := f.w.s.InspectCapture(ctx, f.q.Occurrence)
	if err != nil {
		t.Fatal(err)
	}
	o, before := migrationLegacyDatabase(t, f)
	st, err := Open(ctx, o)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { st.Close() }()
	var schemaVersion, disclosureVersion int
	if err = st.conn.QueryRowContext(ctx, "SELECT schema_version FROM meta").Scan(&schemaVersion); err != nil {
		t.Fatal(err)
	}
	if err = st.conn.QueryRowContext(ctx, "SELECT version FROM disclosure_meta").Scan(&disclosureVersion); err != nil {
		t.Fatal(err)
	}
	if schemaVersion != 2 || disclosureVersion != 2 {
		t.Fatal("upgrade version", schemaVersion, disclosureVersion)
	}
	var tables []string
	for table := range before {
		tables = append(tables, table)
	}
	if !reflect.DeepEqual(before, migrationRows(t, st.conn, tables)) {
		t.Fatal("upgrade rewrote signed records or original capture state")
	}
	for _, table := range []string{"passage", "vector", "projection_job", "field_completeness"} {
		var n int
		if err = st.conn.QueryRowContext(ctx, "SELECT count(*) FROM "+table).Scan(&n); err != nil || n != 0 {
			t.Fatal("uncertified legacy projection survived", table, n, err)
		}
	}
	var n int
	if err = st.conn.QueryRowContext(ctx, "SELECT count(*) FROM search WHERE search MATCH 'migrationnativecanary'").Scan(&n); err != nil || n != 0 {
		t.Fatal("legacy FTS survived", n, err)
	}
	got, err := st.InspectCapture(ctx, f.q.Occurrence)
	if err != nil || !reflect.DeepEqual(inspection, got) {
		t.Fatal("capture progress changed", err)
	}
	retried, err := st.Capture(ctx, f.q, func(*CaptureTxn) (CommitPlan, error) {
		t.Fatal("upgrade resealed native source")
		return CommitPlan{}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	original.Status = "prior_transition_committed"
	if !reflect.DeepEqual(original, retried) {
		t.Fatal("original capture receipt changed")
	}
	mw := *f.w
	mw.s = st
	mw.o = o
	k := newKernelForWorld(&mw)
	quote := k.execute("migration-quote", "local.lookup_record", map[string]any{"record_id": f.plan.NewRecords[0].AdvisoryID})
	if text := k.release(quote); !strings.Contains(text, "migrationnativecanary") {
		t.Fatal("retained native source could not be quoted")
	}
	checkFresh := func(op string) {
		t.Helper()
		reply := k.execute(op, "local.lexical_search", map[string]any{"query": "migrationnativecanary", "resource_types": []string{"evidence"}})
		if text := k.release(reply); strings.Contains(text, "migrationnativecanary") {
			t.Fatal("native source became fresh via migration")
		}
		var n int
		if e := k.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM search WHERE search MATCH 'migrationnativecanary'").Scan(&n); e != nil || n != 0 {
			t.Fatal("fresh native FTS appeared", n, e)
		}
		if e := k.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM field_completeness WHERE id=?", f.plan.NewRecords[0].AdvisoryID).Scan(&n); e != nil || n != 0 {
			t.Fatal("native completeness adopted", n, e)
		}
	}
	checkFresh("migration-fresh-before-reindex")
	if err = k.s.Reindex(ctx); err != nil {
		t.Fatal(err)
	}
	checkFresh("migration-fresh-after-reindex")
	reopenDisclosureKernel(t, k)
	st = k.s
	checkFresh("migration-fresh-after-reopen")
	snap, err := k.s.Snapshot(ctx, ReadRequest{IDs: []string{f.plan.NewRecords[0].AdvisoryID}})
	if err != nil || len(snap.Entries) != 1 || !bytes.Equal(snap.Entries[0].HeaderJCS, f.plan.NewRecords[0].HeaderJCS) || !bytes.Equal(snap.Entries[0].BodyJCS, f.plan.NewRecords[0].BodyJCS) || !reflect.DeepEqual(snap.Entries[0].Sigs, f.plan.NewRecords[0].Sigs) {
		t.Fatal("source seal changed after upgrade/reindex/reopen", err)
	}
}
func TestWeakUnreleasedDisclosureSchemaRefusesUpgradeAtomically(t *testing.T) {
	f := newProducer(t, "migrationnativecanary")
	f.commit()
	ctx := context.Background()
	o, before := migrationLegacyDatabase(t, f)
	path := filepath.Join(o.Dir, "memory.sqlite")
	db, err := sql.Open("sqlite", SQLiteURI(path, ""))
	if err != nil {
		t.Fatal(err)
	}
	conn, err := db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = conn.ExecContext(ctx, "CREATE TABLE disclosure_meta(singleton INTEGER PRIMARY KEY CHECK(singleton=1),version INTEGER NOT NULL CHECK(version=1)); INSERT INTO disclosure_meta VALUES(1,1)"); err != nil {
		t.Fatal(err)
	}
	schemaBefore := migrationRows(t, conn, []string{"sqlite_schema", "meta", "passage", "vector", "projection_job", "disclosure_meta"})
	conn.Close()
	db.Close()
	got, err := Open(ctx, o)
	if got != nil || Code(err) != "incompatible_database" {
		t.Fatal("weak disclosure schema opened", Code(err))
	}
	db, err = sql.Open("sqlite", SQLiteURI(path, ""))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	conn, err = db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if !reflect.DeepEqual(schemaBefore, migrationRows(t, conn, []string{"sqlite_schema", "meta", "passage", "vector", "projection_job", "disclosure_meta"})) {
		t.Fatal("failed migration partly wrote schema or cleared prior projections")
	}
	var tables []string
	for table := range before {
		tables = append(tables, table)
	}
	if !reflect.DeepEqual(before, migrationRows(t, conn, tables)) {
		t.Fatal("failed migration changed source or capture receipt")
	}
}
