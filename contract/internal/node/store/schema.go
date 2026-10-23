package store

import "context"

const schema = `
CREATE TABLE IF NOT EXISTS meta(singleton INTEGER PRIMARY KEY CHECK(singleton=1), schema_version INTEGER NOT NULL, contract_major INTEGER NOT NULL, genesis TEXT NOT NULL, machine TEXT NOT NULL, next_seq INTEGER NOT NULL, generation INTEGER NOT NULL, authority_epoch INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS record(id TEXT PRIMARY KEY, header BLOB NOT NULL, sigs BLOB NOT NULL, owner TEXT NOT NULL, seq INTEGER NOT NULL UNIQUE, generation INTEGER NOT NULL, sig_status TEXT NOT NULL, state TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS record_body(id TEXT PRIMARY KEY REFERENCES record(id), body BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS dep(id TEXT NOT NULL REFERENCES record(id), parent TEXT NOT NULL, PRIMARY KEY(id,parent));
CREATE INDEX IF NOT EXISTS dep_reverse ON dep(parent);
CREATE TABLE IF NOT EXISTS item_event(id TEXT NOT NULL REFERENCES record(id), event_id TEXT NOT NULL, PRIMARY KEY(id,event_id));
CREATE TABLE IF NOT EXISTS body_seen(id TEXT PRIMARY KEY REFERENCES record(id));
CREATE TABLE IF NOT EXISTS item_order(id TEXT PRIMARY KEY REFERENCES record(id), known INTEGER NOT NULL, first_seq INTEGER NOT NULL, last_seq INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS item_recall(id TEXT NOT NULL REFERENCES record(id), event_seq INTEGER NOT NULL, recalled TEXT NOT NULL, PRIMARY KEY(id,event_seq,recalled));
CREATE TABLE IF NOT EXISTS tomb(target TEXT NOT NULL, kind TEXT NOT NULL, cause TEXT NOT NULL, PRIMARY KEY(target,kind,cause));
CREATE TABLE IF NOT EXISTS event_ban(owner TEXT NOT NULL, session TEXT NOT NULL, event_id TEXT NOT NULL, cause TEXT NOT NULL, PRIMARY KEY(owner,session,event_id,cause));
CREATE TABLE IF NOT EXISTS privacy_barrier(owner TEXT PRIMARY KEY, control TEXT NOT NULL, reason TEXT NOT NULL, generation INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS erasure_effect(control TEXT NOT NULL, target TEXT NOT NULL, author TEXT NOT NULL, PRIMARY KEY(control,target));
CREATE TABLE IF NOT EXISTS presence(owner TEXT NOT NULL, session TEXT NOT NULL, event_id TEXT NOT NULL, revision TEXT NOT NULL, source TEXT NOT NULL REFERENCES record(id), seq INTEGER NOT NULL, PRIMARY KEY(owner,session,event_id,revision,source));
CREATE TABLE IF NOT EXISTS presence_parent(owner TEXT NOT NULL, session TEXT NOT NULL, event_id TEXT NOT NULL, revision TEXT NOT NULL, source TEXT NOT NULL, predecessor TEXT NOT NULL, PRIMARY KEY(owner,session,event_id,revision,source,predecessor));
CREATE TABLE IF NOT EXISTS presence_taint(owner TEXT NOT NULL, session TEXT NOT NULL, event_id TEXT NOT NULL, revision TEXT NOT NULL, source TEXT NOT NULL, tag TEXT NOT NULL, PRIMARY KEY(owner,session,event_id,revision,source,tag));
CREATE TABLE IF NOT EXISTS witness(owner TEXT NOT NULL, session TEXT NOT NULL, event_id TEXT NOT NULL, a TEXT NOT NULL, b TEXT NOT NULL, source_a TEXT NOT NULL, source_b TEXT NOT NULL, PRIMARY KEY(owner,session,event_id,a,b,source_a,source_b));
CREATE TABLE IF NOT EXISTS supersession(owner TEXT NOT NULL, kind TEXT NOT NULL, lid TEXT NOT NULL, successor TEXT NOT NULL, predecessor TEXT NOT NULL, PRIMARY KEY(owner,kind,lid,successor,predecessor));
CREATE TABLE IF NOT EXISTS task_state(owner TEXT NOT NULL, task TEXT NOT NULL, status TEXT NOT NULL, PRIMARY KEY(owner,task));
CREATE TABLE IF NOT EXISTS passage(id TEXT PRIMARY KEY REFERENCES record(id), text TEXT NOT NULL);
CREATE VIRTUAL TABLE IF NOT EXISTS search USING fts5(text,content='passage',content_rowid='rowid');
CREATE TABLE IF NOT EXISTS vector(id TEXT PRIMARY KEY REFERENCES record(id), generation INTEGER NOT NULL, model TEXT NOT NULL, value BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS projection_job(id TEXT PRIMARY KEY REFERENCES record(id), generation INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS scrub_job(control TEXT PRIMARY KEY, target_generation INTEGER NOT NULL, state TEXT NOT NULL, attempts INTEGER NOT NULL);
`

func (s *Store) initialize(ctx context.Context) error {
	if _, err := s.conn.ExecContext(ctx, schema); err != nil {
		return failure("storage_error")
	}
	var count int
	if s.conn.QueryRowContext(ctx, "SELECT count(*) FROM meta").Scan(&count) != nil {
		return failure("storage_error")
	}
	if count == 0 {
		if _, err := s.conn.ExecContext(ctx, "INSERT INTO meta VALUES(1,1,2,?,?,1,0,0)", s.opts.PinnedGenesisID, s.opts.LocalMachineID); err != nil {
			return failure("storage_error")
		}
		if _, err := s.conn.ExecContext(ctx, "INSERT INTO search(search,rank) VALUES('secure-delete',1)"); err != nil {
			return failure("unsafe_sqlite")
		}
	}
	var schemaVersion, major int
	var genesis, machine string
	if s.conn.QueryRowContext(ctx, "SELECT schema_version,contract_major,genesis,machine FROM meta WHERE singleton=1").Scan(&schemaVersion, &major, &genesis, &machine) != nil || schemaVersion != 1 || major != 2 || genesis != s.opts.PinnedGenesisID || machine != s.opts.LocalMachineID {
		return failure("incompatible_database")
	}
	var secure int
	if s.conn.QueryRowContext(ctx, "SELECT v FROM search_config WHERE k='secure-delete'").Scan(&secure) != nil || secure != 1 {
		return failure("unsafe_sqlite")
	}
	return s.initializeCapture(ctx)
}
