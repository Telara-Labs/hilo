package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"sort"
	"time"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/localpolicy"
	"github.com/Telara-Labs/telara-memory/contract/record"
	"github.com/Telara-Labs/telara-memory/contract/sig"
)

const repositoryRetirementBatch = 256

const repositorySchema = `
CREATE TABLE IF NOT EXISTS repository_binding(id TEXT PRIMARY KEY,owner TEXT NOT NULL,machine TEXT NOT NULL,source TEXT NOT NULL,session TEXT NOT NULL,observation TEXT NOT NULL,observed_version INTEGER NOT NULL,generation INTEGER NOT NULL CHECK(generation>0),root TEXT NOT NULL,remote TEXT NOT NULL,repo TEXT NOT NULL,root_identity TEXT NOT NULL,config_identity TEXT NOT NULL,state TEXT NOT NULL CHECK(state IN('active','retiring','retired')));
CREATE UNIQUE INDEX IF NOT EXISTS repository_active_source ON repository_binding(source) WHERE state='active';
CREATE TABLE IF NOT EXISTS repository_credential(credential TEXT PRIMARY KEY REFERENCES client_credential(id),binding TEXT NOT NULL REFERENCES repository_binding(id),generation INTEGER NOT NULL CHECK(generation>0));
CREATE TABLE IF NOT EXISTS repository_record(id TEXT PRIMARY KEY,binding TEXT NOT NULL REFERENCES repository_binding(id),generation INTEGER NOT NULL CHECK(generation>0));
CREATE TABLE IF NOT EXISTS repository_retirement(binding TEXT NOT NULL REFERENCES repository_binding(id),id TEXT NOT NULL,control TEXT NOT NULL DEFAULT '',PRIMARY KEY(binding,id));
`

// RepositoryBinding is an explicit owner declaration about one captured source
// and session. Its public fields carry no secret and are not issuance authority.
type RepositoryBinding struct {
	ID              string `json:"id"`
	Owner           string `json:"owner"`
	Machine         string `json:"machine"`
	Source          string `json:"source"`
	Session         string `json:"session"`
	Observation     string `json:"observation"`
	ObservedVersion int64  `json:"observed_version"`
	Generation      int64  `json:"generation"`
	Root            string `json:"project_root"`
	Remote          string `json:"remote"`
	Repo            string `json:"repo"`
	RootIdentity    string `json:"root_identity"`
	ConfigIdentity  string `json:"config_identity"`
	State           string `json:"state"`
}

type RepositoryEnrollment struct{ Observation, ProjectRoot, Remote string }

func (p *repositoryPath) identity(name string) string {
	for _, h := range p.held {
		if h.path == name {
			if name == p.config {
				return h.identity + ":" + p.digest
			}
			return h.identity
		}
	}
	return ""
}

// EnrollRepository is an owner administration seam. Native input, MCP fields
// and cwd cannot call it or select a repository on their own.
func (s *Store) EnrollRepository(ctx context.Context, q RepositoryEnrollment) (RepositoryBinding, error) {
	var out RepositoryBinding
	if !record.IsHex64(q.Observation) {
		return out, failure("invalid_repository")
	}
	p, err := checkRepository(q.ProjectRoot, q.Remote)
	if err != nil {
		return out, err
	}
	defer p.close()
	var nonce [16]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return out, failure("entropy_unavailable")
	}
	err = s.write(ctx, func() error {
		d, err := s.load(ctx)
		if err != nil {
			return err
		}
		if d.blocked {
			return d.blockedError()
		}
		x := d.byID[q.Observation]
		if x == nil || !available(x) || x.owner != s.opts.PinnedGenesisID || x.sigStatus != sig.StatusVerified || x.rec.Header.Author.MachineID != s.opts.LocalMachineID || x.rec.Header.Type != record.KindSession || x.rec.Header.Prov != record.ProvTranscript {
			return failure("repository_observation_unavailable")
		}
		h := x.rec.Header
		b, ok := x.rec.Body.(*record.SessionBody)
		if !ok || b.Reader == nil || h.Subj.Source == "" || h.Subj.SessionKey == "" || !readerValid(*b.Reader) {
			return failure("repository_observation_unavailable")
		}
		key := d.keyState().KeyFor(h.Author.KeyID, record.RoleDevice, "")
		if key == nil || (key.Status != sig.KeyActive && key.Status != sig.KeyRetired) || key.Owner() != x.owner || key.MachineID != h.Author.MachineID {
			return failure("repository_observation_unavailable")
		}
		occ := SourceOccurrence{Owner: x.owner, Source: h.Subj.Source, SessionKey: h.Subj.SessionKey}
		if err = s.repositoryCaptureFence(ctx, occ); err != nil {
			return err
		}
		progress, err := s.captureProgress(ctx, occ)
		if err != nil {
			return err
		}
		current := false
		for _, page := range progress.SessionPages {
			if page.ID == x.rec.ID {
				current = true
			}
		}
		if !current || progress.Version <= 0 || progress.Reader != *b.Reader {
			return failure("repository_observation_stale")
		}
		if d.tenant != nil && !d.tenant.sealAllowed(q.Remote, h.Red.Epoch) {
			return failure("policy_violation")
		}
		var count int
		if s.conn.QueryRowContext(ctx, "SELECT count(*) FROM repository_binding").Scan(&count) != nil {
			return failure("storage_error")
		}
		if count >= 64 {
			return failure("repository_binding_limit")
		}
		if s.conn.QueryRowContext(ctx, "SELECT count(*) FROM repository_binding WHERE owner=? AND machine=? AND (source=? OR session=?) AND state='active'", occ.Owner, s.opts.LocalMachineID, occ.Source, occ.SessionKey).Scan(&count) != nil {
			return failure("storage_error")
		}
		if count != 0 {
			return failure("repository_binding_exists")
		}
		id, err := record.HE("repository-binding", x.owner, s.opts.LocalMachineID, occ.Source, occ.SessionKey, hex.EncodeToString(nonce[:]))
		if err != nil {
			return failure("invalid_repository")
		}
		repo, err := record.RepoID(q.Remote)
		if err != nil {
			return failure("invalid_repository")
		}
		out = RepositoryBinding{id, x.owner, s.opts.LocalMachineID, occ.Source, occ.SessionKey, q.Observation, progress.Version, 1, q.ProjectRoot, q.Remote, repo, p.identity(p.root), p.identity(p.config), "active"}
		if err = p.current(); err != nil {
			return err
		}
		_, err = s.conn.ExecContext(ctx, "INSERT INTO repository_binding VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)", out.ID, out.Owner, out.Machine, out.Source, out.Session, out.Observation, out.ObservedVersion, out.Generation, out.Root, out.Remote, out.Repo, out.RootIdentity, out.ConfigIdentity, out.State)
		if err != nil {
			return failure("storage_error")
		}
		return s.bump(ctx)
	})
	if err != nil {
		return RepositoryBinding{}, err
	}
	return out, nil
}

// Retirement permanently fences this local native occurrence in this version.
// Retained binding history is independent of associated bound records, including
// retirement before the first bound capture. Neither a nil repository request
// nor a different source path for the same session can reopen capture. Existing
// unbound records remain readable; this gate applies only to new producers.
func (s *Store) repositoryCaptureFence(ctx context.Context, q SourceOccurrence) error {
	var fenced bool
	if err := s.conn.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM repository_binding WHERE owner=? AND machine=? AND (source=? OR session=?) AND state IN('retiring','retired'))", q.Owner, s.opts.LocalMachineID, q.Source, q.SessionKey).Scan(&fenced); err != nil {
		return failure("storage_error")
	}
	if fenced {
		return failure("repository_binding_inactive")
	}
	return nil
}

type repositoryScanner interface{ Scan(...any) error }

func scanRepository(row repositoryScanner) (RepositoryBinding, error) {
	var b RepositoryBinding
	err := row.Scan(&b.ID, &b.Owner, &b.Machine, &b.Source, &b.Session, &b.Observation, &b.ObservedVersion, &b.Generation, &b.Root, &b.Remote, &b.Repo, &b.RootIdentity, &b.ConfigIdentity, &b.State)
	if err == sql.ErrNoRows {
		return b, failure("repository_binding_unknown")
	}
	if err != nil {
		return b, failure("storage_error")
	}
	if !record.IsHex64(b.ID) || !record.IsKeyID(b.Owner) || !record.IsUUIDv4(b.Machine) || !record.IsHex64(b.Source) || !record.IsSessionKey(b.Session) || !record.IsHex64(b.Observation) || b.ObservedVersion <= 0 || b.Generation <= 0 || b.RootIdentity == "" || b.ConfigIdentity == "" {
		return RepositoryBinding{}, failure("corrupt_database")
	}
	r, err := record.RepoID(b.Remote)
	if err != nil || r != b.Repo || (b.State != "active" && b.State != "retiring" && b.State != "retired") {
		return RepositoryBinding{}, failure("corrupt_database")
	}
	return b, nil
}

func (s *Store) currentRepository(ctx context.Context, d *databaseState, b RepositoryBinding) error {
	if b.Owner != s.opts.PinnedGenesisID || b.Machine != s.opts.LocalMachineID || b.State != "active" || d.blocked {
		return failure("repository_binding_inactive")
	}
	x := d.byID[b.Observation]
	if x == nil || !available(x) || x.owner != b.Owner || x.sigStatus != sig.StatusVerified || x.rec.Header.Subj.Source != b.Source || x.rec.Header.Subj.SessionKey != b.Session || x.rec.Header.Type != record.KindSession || x.rec.Header.Prov != record.ProvTranscript || x.rec.Header.Author.MachineID != b.Machine {
		return failure("repository_observation_unavailable")
	}
	key := d.keyState().KeyFor(x.rec.Header.Author.KeyID, record.RoleDevice, "")
	if key == nil || (key.Status != sig.KeyActive && key.Status != sig.KeyRetired) || key.Owner() != b.Owner || key.MachineID != b.Machine {
		return failure("repository_observation_unavailable")
	}
	progress, err := s.captureProgress(ctx, SourceOccurrence{Owner: b.Owner, Source: b.Source, SessionKey: b.Session})
	if err != nil {
		return err
	}
	if progress.Version < b.ObservedVersion {
		return failure("repository_observation_stale")
	}
	p, err := checkRepository(b.Root, b.Remote)
	if err != nil {
		return err
	}
	defer p.close()
	if p.identity(p.root) != b.RootIdentity || p.identity(p.config) != b.ConfigIdentity {
		return failure("repository_changed")
	}
	return p.current()
}

// CaptureRepository resolves only an explicitly enrolled actual source/session.
// Unknown sources retain ordinary local unscoped capture. Retired source/session
// history is checked before the native reader opens the source.
func (s *Store) CaptureRepository(ctx context.Context, q SourceOccurrence) (RepositoryBinding, error) {
	var out RepositoryBinding
	if !validOccurrence(s.opts, q) {
		return out, failure("invalid_request")
	}
	err := s.write(ctx, func() error {
		d, err := s.load(ctx)
		if err != nil {
			return err
		}
		if d.blocked {
			return d.blockedError()
		}
		if err = s.repositoryCaptureFence(ctx, q); err != nil {
			return err
		}
		b, err := scanRepository(s.conn.QueryRowContext(ctx, "SELECT * FROM repository_binding WHERE source=? AND session=? AND state='active'", q.Source, q.SessionKey))
		if Code(err) == "repository_binding_unknown" {
			return nil
		}
		if err != nil {
			return err
		}
		if err = s.currentRepository(ctx, d, b); err != nil {
			return err
		}
		rules, err := localpolicy.Ruleset()
		if err != nil {
			return failure("policy_unavailable")
		}
		if d.tenant != nil && !d.tenant.sealAllowed(b.Remote, rules.Epoch) {
			return failure("policy_violation")
		}
		out = b
		return nil
	})
	if err != nil {
		return RepositoryBinding{}, err
	}
	return out, nil
}

func (s *Store) captureRepositoryLocked(ctx context.Context, d *databaseState, q CaptureRequest) (*RepositoryBinding, error) {
	if err := s.repositoryCaptureFence(ctx, q.Occurrence); err != nil {
		return nil, err
	}
	if q.RepositoryBinding == "" {
		if q.RepositoryGeneration != 0 || q.Repository != nil {
			return nil, failure("invalid_repository")
		}
		var count int
		if s.conn.QueryRowContext(ctx, "SELECT count(*) FROM repository_binding WHERE owner=? AND machine=? AND (source=? OR session=?) AND state='active'", q.Occurrence.Owner, s.opts.LocalMachineID, q.Occurrence.Source, q.Occurrence.SessionKey).Scan(&count) != nil {
			return nil, failure("storage_error")
		}
		if count != 0 {
			return nil, failure("repository_binding_required")
		}
		return nil, nil
	}
	if !record.IsHex64(q.RepositoryBinding) || q.RepositoryGeneration <= 0 || q.Repository == nil {
		return nil, failure("invalid_repository")
	}
	b, err := scanRepository(s.conn.QueryRowContext(ctx, "SELECT * FROM repository_binding WHERE id=?", q.RepositoryBinding))
	if err != nil {
		return nil, err
	}
	want := record.RepoRef{ID: b.Repo, Remote: b.Remote}
	if b.Source != q.Occurrence.Source || b.Session != q.Occurrence.SessionKey || b.Owner != q.Occurrence.Owner || b.Generation != q.RepositoryGeneration || *q.Repository != want {
		return nil, failure("repository_binding_mismatch")
	}
	if err = s.currentRepository(ctx, d, b); err != nil {
		return nil, err
	}
	return &b, nil
}

func (s *Store) associateCaptureRepository(ctx context.Context, d *databaseState, q CaptureRequest, refs []RecordRef) error {
	if q.RepositoryBinding == "" {
		return nil
	}
	if _, err := s.captureRepositoryLocked(ctx, d, q); err != nil {
		return s.refuseVerified(ctx, d, err)
	}
	var count int
	if s.conn.QueryRowContext(ctx, "SELECT count(*) FROM repository_record WHERE binding=?", q.RepositoryBinding).Scan(&count) != nil {
		return failure("storage_error")
	}
	for _, ref := range refs {
		var binding string
		var generation int64
		err := s.conn.QueryRowContext(ctx, "SELECT binding,generation FROM repository_record WHERE id=?", ref.ID).Scan(&binding, &generation)
		if err == nil {
			if binding != q.RepositoryBinding || generation != q.RepositoryGeneration {
				return failure("repository_binding_mismatch")
			}
			continue
		}
		if err != sql.ErrNoRows {
			return failure("storage_error")
		}
		if count >= 4096 {
			return s.refuseVerified(ctx, d, failure("repository_binding_limit"))
		}
		if _, err = s.conn.ExecContext(ctx, "INSERT INTO repository_record VALUES(?,?,?)", ref.ID, q.RepositoryBinding, q.RepositoryGeneration); err != nil {
			return failure("storage_error")
		}
		count++
	}
	return nil
}

// RepositoryBinding inspects one owner-enrolled binding under the current writer.
func (s *Store) RepositoryBinding(ctx context.Context, id string) (RepositoryBinding, error) {
	var out RepositoryBinding
	if !record.IsHex64(id) {
		return out, failure("invalid_repository")
	}
	err := s.write(ctx, func() error {
		var err error
		out, err = scanRepository(s.conn.QueryRowContext(ctx, "SELECT * FROM repository_binding WHERE id=?", id))
		return err
	})
	return out, err
}
func (s *Store) BindRepositoryCredential(ctx context.Context, id string, generation int64, credential string) error {
	if !record.IsHex64(id) || !record.IsUUIDv4(credential) || generation <= 0 {
		return failure("invalid_repository")
	}
	return s.write(ctx, func() error { return s.bindRepositoryCredentialLocked(ctx, id, generation, credential) })
}
func (s *Store) bindRepositoryCredentialLocked(ctx context.Context, id string, generation int64, credential string) error {
	d, err := s.load(ctx)
	if err != nil {
		return err
	}
	b, err := scanRepository(s.conn.QueryRowContext(ctx, "SELECT * FROM repository_binding WHERE id=?", id))
	if err != nil {
		return err
	}
	if b.Generation != generation {
		return failure("repository_binding_mismatch")
	}
	if err = s.currentRepository(ctx, d, b); err != nil {
		return err
	}
	c, err := s.credential(ctx, credential)
	if err != nil {
		return err
	}
	if c.revoked || c.readKind != "concrete" || !c.repos[b.Repo] || len(c.repos) != 1 || c.writeKind != "concrete" || !c.writeRepos[b.Repo] || len(c.writeRepos) != 1 || c.unscoped {
		return failure("invalid_grant")
	}
	if _, err = s.conn.ExecContext(ctx, "INSERT INTO repository_credential VALUES(?,?,?)", credential, id, generation); err != nil {
		return failure("storage_error")
	}
	return s.bump(ctx)
}

func (s *Store) credentialRepository(ctx context.Context, credential string) (*RepositoryBinding, error) {
	var id string
	var generation int64
	err := s.conn.QueryRowContext(ctx, "SELECT binding,generation FROM repository_credential WHERE credential=?", credential).Scan(&id, &generation)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, failure("storage_error")
	}
	b, err := scanRepository(s.conn.QueryRowContext(ctx, "SELECT * FROM repository_binding WHERE id=?", id))
	if err != nil {
		return nil, err
	}
	d, err := s.load(ctx)
	if err != nil {
		return nil, err
	}
	if b.Generation != generation {
		return nil, failure("repository_binding_inactive")
	}
	if err = s.currentRepository(ctx, d, b); err != nil {
		return nil, err
	}
	return &b, nil
}

// loadRepositoryFacts retains local content associations independently of wire
// import. Restoring the same content id never removes its retirement fence.
func (s *Store) loadRepositoryFacts(ctx context.Context, d *databaseState) error {
	d.repositoryHeld = map[string]bool{}
	rows, err := s.conn.QueryContext(ctx, "SELECT id,binding,generation FROM repository_record LIMIT 262145")
	if err != nil {
		return failure("storage_error")
	}
	type association struct {
		id, binding string
		generation  int64
	}
	var all []association
	for rows.Next() {
		var a association
		if rows.Scan(&a.id, &a.binding, &a.generation) != nil {
			rows.Close()
			return failure("storage_error")
		}
		all = append(all, a)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return failure("storage_error")
	}
	if len(all) > 262144 {
		return failure("repository_binding_limit")
	}
	inactive := map[string]bool{}
	generations := map[string]int64{}
	for _, a := range all {
		if _, ok := generations[a.binding]; !ok {
			b, err := scanRepository(s.conn.QueryRowContext(ctx, "SELECT * FROM repository_binding WHERE id=?", a.binding))
			if err != nil {
				return err
			}
			generations[a.binding] = b.Generation
			err = s.currentRepository(ctx, d, b)
			if Code(err) == "storage_error" {
				return err
			}
			inactive[a.binding] = err != nil
		}
		if inactive[a.binding] || a.generation != generations[a.binding] {
			d.repositoryHeld[a.id] = true
		}
	}
	return nil
}

// RevokeRepository fences new producers and credentials before retirement.
// Every subsequent retry signs exact bound ids; the original local observation
// remains untouched. Completed controls survive partial work and restart.
func (s *Store) RevokeRepository(ctx context.Context, id string, signer ControlSigner) ([]string, error) {
	if !record.IsHex64(id) || signer == nil {
		return nil, failure("invalid_repository")
	}
	err := s.write(ctx, func() error {
		b, err := scanRepository(s.conn.QueryRowContext(ctx, "SELECT * FROM repository_binding WHERE id=?", id))
		if err != nil {
			return err
		}
		if b.State == "retired" {
			return nil
		}
		if b.State == "active" {
			if _, err = s.conn.ExecContext(ctx, "UPDATE repository_binding SET state='retiring',generation=generation+1 WHERE id=?", id); err != nil {
				return failure("storage_error")
			}
		}
		if _, err = s.conn.ExecContext(ctx, "UPDATE client_credential SET revoked=1,verifier=NULL,epoch=CASE WHEN epoch<9223372036854775807 THEN epoch+1 ELSE epoch END WHERE revoked=0 AND id IN (SELECT credential FROM repository_credential WHERE binding=?)", id); err != nil {
			return failure("storage_error")
		}
		if _, err = s.conn.ExecContext(ctx, "UPDATE query_cursor SET state='expired' WHERE selection IN (SELECT id FROM query_selection WHERE credential IN (SELECT credential FROM repository_credential WHERE binding=?))", id); err != nil {
			return failure("storage_error")
		}
		return s.bump(ctx)
	})
	if err != nil {
		return nil, err
	}
	err = s.write(ctx, func() error {
		// The fixed limit is checked on issuance. Include every signed copied variant
		// through its exact copied-content closure, never the unbound observation.
		d, err := s.load(ctx)
		if err != nil {
			return err
		}
		targets := map[string]bool{}
		rows, err := s.conn.QueryContext(ctx, "SELECT id FROM repository_record WHERE binding=? LIMIT 8193", id)
		if err != nil {
			return failure("storage_error")
		}
		for rows.Next() {
			var target string
			if rows.Scan(&target) != nil {
				rows.Close()
				return failure("storage_error")
			}
			if !record.IsHex64(target) {
				rows.Close()
				return failure("corrupt_database")
			}
			if len(targets) >= 8192 {
				rows.Close()
				return failure("repository_binding_limit")
			}
			targets[target] = true
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return failure("storage_error")
		}
		budget, err := d.reductions()
		if err != nil {
			return err
		}
		closed, err := repositoryRetirementClosure(d.records, targets, s.opts.PinnedGenesisID, budget)
		if err != nil {
			return err
		}

		for _, target := range closed {
			if _, err = s.conn.ExecContext(ctx, "INSERT OR IGNORE INTO repository_retirement(binding,id) VALUES(?,?)", id, target); err != nil {
				return failure("storage_error")
			}
		}
		return s.bump(ctx)
	})
	if err != nil {
		return nil, err
	}
	var controls []string
	for batch := 0; batch < 8192/repositoryRetirementBatch+1; batch++ {
		var nonce [16]byte
		if _, err = rand.Read(nonce[:]); err != nil {
			return controls, failure("entropy_unavailable")
		}
		done := false
		err = s.write(ctx, func() error {
			rows, err := s.conn.QueryContext(ctx, "SELECT id FROM repository_retirement WHERE binding=? AND control='' ORDER BY id LIMIT ?", id, repositoryRetirementBatch)
			if err != nil {
				return failure("storage_error")
			}
			var ids []string
			for rows.Next() {
				var target string
				if rows.Scan(&target) != nil {
					rows.Close()
					return failure("storage_error")
				}
				ids = append(ids, target)
			}
			err = rows.Err()
			rows.Close()
			if err != nil {
				return failure("storage_error")
			}
			if len(ids) == 0 {
				_, err = s.conn.ExecContext(ctx, "UPDATE repository_binding SET state='retired' WHERE id=? AND state='retiring'", id)
				done = true
				return err
			}
			sort.Strings(ids)
			h := record.Header{Type: record.KindRetraction, Prov: record.ProvUser, Author: record.Author{MachineID: s.opts.LocalMachineID, KeyID: signer.KeyID()}, At: time.Now().UnixMilli(), Red: record.Redact{Profile: record.ProfileLocal}}
			h.LID, err = record.ControlLID(record.KindRetraction, signer.KeyID(), hex.EncodeToString(nonce[:]))
			if err != nil {
				return failure("invalid_record")
			}
			r, err := record.Build(h, &record.RetractionBody{IDs: ids, Reason: "rule_removed"})
			if err != nil {
				return failure("invalid_record")
			}
			sg, err := signer.SignRecordID(r.ID)
			if err != nil {
				return failure("signing_unavailable")
			}
			parsed, signatures, err := parse(SignedRecord{HeaderJCS: r.HeaderJCS, BodyJCS: r.BodyJCS, Sigs: []record.Signature{sg}, AdvisoryID: r.ID})
			if err != nil {
				return err
			}
			if _, err = s.appendLocked(ctx, parsed, signatures); err != nil {
				return err
			}
			for _, target := range ids {
				if _, err = s.conn.ExecContext(ctx, "UPDATE repository_retirement SET control=? WHERE binding=? AND id=? AND control=''", r.ID, id, target); err != nil {
					return failure("storage_error")
				}
			}
			controls = append(controls, r.ID)
			return nil
		})
		if err != nil {
			return controls, err
		}
		if done {
			return controls, nil
		}
	}
	return controls, failure("repository_retirement_pending")
}

// RepositoryInspection is an owner-only content-free enrollment view.
type RepositoryObservation struct{ ID, Source, Session string }
type RepositoryInspection struct {
	Observations []RepositoryObservation `json:"observations"`
	Bindings     []RepositoryBinding     `json:"bindings"`
}

func (s *Store) InspectRepositories(ctx context.Context) (RepositoryInspection, error) {
	out := RepositoryInspection{Observations: []RepositoryObservation{}, Bindings: []RepositoryBinding{}}
	err := s.write(ctx, func() error {
		d, err := s.load(ctx)
		if err != nil {
			return err
		}
		if d.blocked {
			return d.blockedError()
		}
		for _, x := range d.records {
			h := x.rec.Header
			if !available(x) || x.owner != s.opts.PinnedGenesisID || h.Author.MachineID != s.opts.LocalMachineID || h.Type != record.KindSession || h.Prov != record.ProvTranscript {
				continue
			}
			p, err := s.captureProgress(ctx, SourceOccurrence{Owner: x.owner, Source: h.Subj.Source, SessionKey: h.Subj.SessionKey})
			if err != nil {
				return err
			}
			for _, page := range p.SessionPages {
				if page.ID == x.rec.ID {
					if len(out.Observations) >= 64 {
						return failure("repository_binding_limit")
					}
					out.Observations = append(out.Observations, RepositoryObservation{x.rec.ID, h.Subj.Source, h.Subj.SessionKey})
					break
				}
			}
		}
		rows, err := s.conn.QueryContext(ctx, "SELECT * FROM repository_binding ORDER BY id LIMIT 65")
		if err != nil {
			return failure("storage_error")
		}
		defer rows.Close()
		for rows.Next() {
			b, err := scanRepository(rows)
			if err != nil {
				return err
			}
			if len(out.Bindings) >= 64 {
				return failure("corrupt_database")
			}
			out.Bindings = append(out.Bindings, b)
		}
		return rows.Err()
	})
	return out, err
}

func (s *Store) associateRepositoryRecord(ctx context.Context, source, id string) error {
	var binding string
	var generation int64
	err := s.conn.QueryRowContext(ctx, "SELECT binding,generation FROM repository_record WHERE id=?", source).Scan(&binding, &generation)
	if err == sql.ErrNoRows {
		return nil
	}
	if err != nil {
		return failure("storage_error")
	}
	var existing string
	var prior int64
	err = s.conn.QueryRowContext(ctx, "SELECT binding,generation FROM repository_record WHERE id=?", id).Scan(&existing, &prior)
	if err == nil {
		if existing != binding || generation != prior {
			return failure("repository_binding_mismatch")
		}
		return nil
	}
	if err != sql.ErrNoRows {
		return failure("storage_error")
	}
	var count int
	if s.conn.QueryRowContext(ctx, "SELECT count(*) FROM repository_record WHERE binding=?", binding).Scan(&count) != nil {
		return failure("storage_error")
	}
	if count >= 4096 {
		return failure("repository_binding_limit")
	}
	_, err = s.conn.ExecContext(ctx, "INSERT INTO repository_record VALUES(?,?,?)", id, binding, generation)
	if err != nil {
		return failure("storage_error")
	}
	return nil
}

// RegisterRepositoryVariant durably associates a verified signed transport copy
// before it may leave the node. This inventory is not an unsigned wire grant.
func (s *Store) RegisterRepositoryVariant(ctx context.Context, source string, in SignedRecord) error {
	r, signatures, err := parseBundleItem(in)
	if err != nil {
		return err
	}
	if !record.IsHex64(source) || r.Header.Links.Origin != source || r.Header.Red.Profile != record.ProfilePushMetadata {
		return failure("invalid_record")
	}
	return s.write(ctx, func() error {
		d, err := s.load(ctx)
		if err != nil {
			return err
		}
		x := d.byID[source]
		if !available(x) || x.owner != s.opts.PinnedGenesisID || r.Header.Subj.RepoID != x.rec.Header.Subj.RepoID || r.Header.Author.MachineID != s.opts.LocalMachineID {
			return failure("repository_source_unavailable")
		}
		result := sig.VerifyRecord(r, signatures, d.keyState(), sig.Context{Route: record.RouteBundleImport})
		if result.Status != sig.StatusVerified || result.Owner != s.opts.PinnedGenesisID {
			return failure("invalid_record")
		}
		return s.associateRepositoryRecord(ctx, source, r.ID)
	})
}

// repositoryRetirementClosure walks only exact copied-content dependencies and
// export Origin edges of this owner. It never uses permission/scope associations
// as derived-content edges. Admission already authenticated retained owner and
// dependency facts; historical signer retirement does not discard an owned id.
func repositoryRetirementClosure(records []*stored, known map[string]bool, owner string, budget *reductionContext) ([]string, error) {
	const limit = 8192
	if budget == nil || !record.IsKeyID(owner) {
		return nil, failure("invalid_repository")
	}
	if len(known) > limit {
		return nil, failure("repository_binding_limit")
	}
	// Charge both graph scans, all potential edges and the initial frontier
	// BEFORE allocating adjacency slices. Traversal charges every visited edge.
	if err := budget.product(2, len(records)); err != nil {
		return nil, err
	}
	if err := budget.charge(len(known)); err != nil {
		return nil, err
	}
	for _, x := range records {
		if x.owner != owner || x.rec.Header.Type.IsControl() {
			continue
		}
		n := len(x.deps)
		if x.rec.Header.Links.Origin != "" {
			n++
		}
		if err := budget.charge(n); err != nil {
			return nil, err
		}
	}
	targets := map[string]bool{}
	frontier := make([]string, 0, len(known))
	for id := range known {
		if !record.IsHex64(id) {
			return nil, failure("corrupt_database")
		}
		targets[id] = true
		frontier = append(frontier, id)
	}
	reverse := map[string][]string{}
	for _, x := range records {
		if targets[x.rec.ID] && x.owner != owner {
			return nil, failure("corrupt_database")
		}
		if x.owner != owner || x.rec.Header.Type.IsControl() {
			continue
		}
		for _, parent := range x.deps {
			reverse[parent] = append(reverse[parent], x.rec.ID)
		}
		if parent := x.rec.Header.Links.Origin; parent != "" {
			reverse[parent] = append(reverse[parent], x.rec.ID)
		}
	}
	for cursor := 0; cursor < len(frontier); cursor++ {
		for _, child := range reverse[frontier[cursor]] {
			if err := budget.charge(1); err != nil {
				return nil, err
			}
			if targets[child] {
				continue
			}
			if len(targets) >= limit {
				return nil, failure("repository_binding_limit")
			}
			targets[child] = true
			frontier = append(frontier, child)
		}
	}
	sort.Strings(frontier)
	return frontier, nil
}
