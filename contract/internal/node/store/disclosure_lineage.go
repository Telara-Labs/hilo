package store

import (
	"context"
	"math"
	"sort"
	"strings"

	"github.com/Telara-Labs/telara-memory/contract/invalidate"
	"github.com/Telara-Labs/telara-memory/contract/record"
)

type exposureFact struct {
	id, owner, machine, credential, scope, root, source, attempt string
	fence                                                        int64
	evidence                                                     []string
	affects                                                      map[string]bool
	persisted                                                    bool
}
type attributionFact struct{ owner, machine, scope, kind, repoState, repo string }
type completenessFact struct {
	owner, id, event, revision, family               string
	ordinal                                          int
	instance, credential, op, sourceKind, sourceSlot string
	sourceOrdinal                                    int
	builder, schema, ruleset                         string
	full, retained                                   int64
	trusted                                          bool
}
type fieldKey struct {
	id, event, revision, family string
	ordinal                     int
}
type projectionLimit struct{}

func (*projectionLimit) Error() string { return "lineage_evaluation_required" }
func (s *Store) loadDisclosureFacts(ctx context.Context, d *databaseState) error {
	d.attrs = map[string]attributionFact{}
	d.completeness = map[fieldKey]completenessFact{}
	d.retainedHolds = map[string]map[string]bool{}
	d.taint = map[string]map[string]bool{}
	d.nonces = map[string]bool{}
	rows, err := s.conn.QueryContext(ctx, "SELECT id,owner,machine,scope,kind,repo_state,repo FROM record_attribution LIMIT 8193")
	if err != nil {
		return failure("storage_error")
	}
	for rows.Next() {
		var id string
		var a attributionFact
		if rows.Scan(&id, &a.owner, &a.machine, &a.scope, &a.kind, &a.repoState, &a.repo) != nil {
			rows.Close()
			return failure("storage_error")
		}
		if len(d.attrs) >= 8192 {
			rows.Close()
			return &projectionLimit{}
		}
		if d.byID[id] == nil || a.owner != s.opts.PinnedGenesisID || a.machine != s.opts.LocalMachineID {
			rows.Close()
			return failure("corrupt_database")
		}
		d.attrs[id] = a
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return failure("storage_error")
	}
	rows, err = s.conn.QueryContext(ctx, "SELECT id,owner,machine,credential,scope,root,source_call,attempt,fence FROM exposure ORDER BY id")
	if err != nil {
		return failure("storage_error")
	}
	for rows.Next() {
		f := &exposureFact{affects: map[string]bool{}, persisted: true}
		if rows.Scan(&f.id, &f.owner, &f.machine, &f.credential, &f.scope, &f.root, &f.source, &f.attempt, &f.fence) != nil {
			rows.Close()
			return failure("storage_error")
		}
		if f.owner != s.opts.PinnedGenesisID || f.machine != s.opts.LocalMachineID || f.fence < 0 || f.fence >= d.nextSeq || !record.IsUUIDv4(f.id) || !record.IsHex64(f.root) {
			rows.Close()
			return failure("corrupt_database")
		}
		d.exposures = append(d.exposures, f)
		if len(d.exposures) > 8192 {
			rows.Close()
			return &projectionLimit{}
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return failure("storage_error")
	}
	byExposure := map[string]*exposureFact{}
	for _, f := range d.exposures {
		byExposure[f.id] = f
	}
	for _, f := range d.exposures {
		rows, err = s.conn.QueryContext(ctx, "SELECT evidence FROM exposure_evidence WHERE exposure=? LIMIT 65", f.id)
		if err != nil {
			return failure("storage_error")
		}
		for rows.Next() {
			var id string
			if rows.Scan(&id) != nil {
				rows.Close()
				return failure("storage_error")
			}
			x := d.byID[id]
			if !record.IsHex64(id) || x == nil || x.owner != f.owner {
				rows.Close()
				return failure("corrupt_database")
			}
			f.evidence = append(f.evidence, id)
			if len(f.evidence) > 64 {
				rows.Close()
				return &projectionLimit{}
			}
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return failure("storage_error")
		}
	}
	rows, err = s.conn.QueryContext(ctx, "SELECT exposure,target FROM exposure_affect")
	if err != nil {
		return failure("storage_error")
	}
	n := 0
	for rows.Next() {
		var id, target string
		if rows.Scan(&id, &target) != nil {
			rows.Close()
			return failure("storage_error")
		}
		f := byExposure[id]
		if f == nil || !record.IsHex64(target) {
			rows.Close()
			return failure("corrupt_database")
		}
		f.affects[target] = true
		n++
		if n > 65536 {
			rows.Close()
			return &projectionLimit{}
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return failure("storage_error")
	}
	rows, err = s.conn.QueryContext(ctx, "SELECT owner,target,root,control FROM semantic_hold_cause")
	if err != nil {
		return failure("storage_error")
	}
	n = 0
	for rows.Next() {
		var owner, id, root, c string
		if rows.Scan(&owner, &id, &root, &c) != nil {
			rows.Close()
			return failure("storage_error")
		}
		if owner != s.opts.PinnedGenesisID || !record.IsHex64(id) || !record.IsHex64(root) || !record.IsHex64(c) {
			rows.Close()
			return failure("corrupt_database")
		}
		if d.retainedHolds[id] == nil {
			d.retainedHolds[id] = map[string]bool{}
		}
		d.retainedHolds[id][root+"/"+c] = true
		n++
		if n > 65536 {
			rows.Close()
			return &projectionLimit{}
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return failure("storage_error")
	}
	rows, err = s.conn.QueryContext(ctx, "SELECT owner,id,tag FROM record_observed_taint LIMIT 32769")
	if err != nil {
		return failure("storage_error")
	}
	taintRows := 0
	for rows.Next() {
		var owner, id, tag string
		if rows.Scan(&owner, &id, &tag) != nil {
			rows.Close()
			return failure("storage_error")
		}
		taintRows++
		if taintRows > 32768 {
			rows.Close()
			return &projectionLimit{}
		}
		if d.byID[id] == nil || owner != s.opts.PinnedGenesisID || !observedTag(tag) {
			rows.Close()
			return failure("corrupt_database")
		}
		if d.taint[id] == nil {
			d.taint[id] = map[string]bool{}
		}
		d.taint[id][tag] = true
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return failure("storage_error")
	}
	rows, err = s.conn.QueryContext(ctx, "SELECT owner,id,event,revision,family,ordinal,instance,credential,op,source_kind,source_slot,source_ordinal,builder,arg_schema,ruleset,full_bytes,retained_bytes FROM field_completeness LIMIT 65537")
	if err != nil {
		return failure("storage_error")
	}
	for rows.Next() {
		var f completenessFact
		if rows.Scan(&f.owner, &f.id, &f.event, &f.revision, &f.family, &f.ordinal, &f.instance, &f.credential, &f.op, &f.sourceKind, &f.sourceSlot, &f.sourceOrdinal, &f.builder, &f.schema, &f.ruleset, &f.full, &f.retained) != nil {
			rows.Close()
			return failure("storage_error")
		}
		if len(d.completeness) >= 65536 {
			rows.Close()
			return &projectionLimit{}
		}
		if d.byID[f.id] == nil || f.ordinal < 0 || f.ordinal > 4095 {
			rows.Close()
			return failure("corrupt_database")
		}
		d.completeness[fieldKey{f.id, f.event, f.revision, f.family, f.ordinal}] = f
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return failure("storage_error")
	}
	// Validate provenance from immutable fixed-builder operation membership. This
	// never adopts ordinary signed records or infers full input from byte counts.
	for key, f := range d.completeness {
		var n int
		err = s.conn.QueryRowContext(ctx, "SELECT count(*) FROM operation o JOIN outcome_member m ON m.owner=o.owner AND m.credential=o.credential AND m.op=o.op JOIN record_attribution a ON a.id=m.id WHERE o.owner=? AND o.credential=? AND o.op=? AND o.builder=? AND o.arg_schema=? AND o.ruleset=? AND m.id=? AND m.role='mutation' AND a.kind='fixed-mcp-builder'", f.owner, f.credential, f.op, f.builder, f.schema, f.ruleset, f.id).Scan(&n)
		if err != nil {
			return failure("storage_error")
		}
		f.trusted = n == 1 && f.instance == s.instanceID && f.builder == disclosureBuilderVersion && f.owner == s.opts.PinnedGenesisID
		d.completeness[key] = f
	}

	return nil
}
func observedTag(s string) bool {
	return s == "web" || s == "third-party-mcp" || s == "foreign-path" || s == "recalled-memory"
}
func (d *databaseState) semanticFacts(o Options) error {
	d.semantic = map[string]map[string]bool{}
	edges := 0
	bodyBytes := 0
	controls := 0
	work := 0
	add := func(id, root string) error {
		work++
		if work > 1048576 {
			return &projectionLimit{}
		}
		if d.semantic[id] == nil {
			d.semantic[id] = map[string]bool{}
		}
		if !d.semantic[id][root] {
			d.semantic[id][root] = true
			edges++
			if edges > 65536 {
				return &projectionLimit{}
			}
		}
		return nil
	}
	if len(d.records) > 8192 || len(d.exposures) > 8192 {
		return &projectionLimit{}
	}
	for _, x := range d.records {
		if len(x.rec.BodyJCS) > 64<<20-bodyBytes {
			return &projectionLimit{}
		}
		bodyBytes += len(x.rec.BodyJCS)
		if x.rec.Header.Type == record.KindErasure || x.rec.Header.Type == record.KindRetraction {
			controls++
		}
		edges += len(x.deps)
		if edges > 65536 {
			return &projectionLimit{}
		}
	}
	if controls*len(d.records) > 1048576 {
		return &projectionLimit{}
	}
	for _, f := range d.exposures {
		root := d.byID[f.root]
		if root == nil || root.owner != f.owner || root.seq > f.fence || root.rec.Header.Type.IsControl() {
			return failure("corrupt_database")
		}
		for _, x := range d.records {
			work++
			if work > 1048576 {
				return &projectionLimit{}
			}
			if x.owner == f.owner && x.rec.Header.Author.MachineID == f.machine && !x.rec.Header.Type.IsControl() && x.seq > f.fence {
				f.affects[x.rec.ID] = true
			}
		}
		ids := make([]string, 0, len(f.affects))
		for id := range f.affects {
			x := d.byID[id]
			if x == nil || x.owner != f.owner || x.rec.Header.Type.IsControl() || x.seq <= f.fence {
				return failure("corrupt_database")
			}
			if err := add(id, f.root); err != nil {
				return err
			}
			ids = append(ids, id)
		}
		sort.Strings(ids)
		d.model.Expose(invalidate.Exposure{ID: f.root, AffectsIDs: ids, UnknownOrder: true})
	}
	// Materialize precisely the existing native sequence/unknown-order facts.
	for _, source := range d.records {
		for _, r := range source.recalls {
			for _, x := range d.records {
				work++
				if work > 1048576 {
					return &projectionLimit{}
				}
				if !x.rec.Header.Type.IsControl() && source.rec.Header.Subj.SessionKey != "" && x.rec.Header.Subj.SessionKey == source.rec.Header.Subj.SessionKey && (!x.orderKnown || x.lastSeq > r.Seq) {
					if err := add(x.rec.ID, r.ID); err != nil {
						return err
					}
				}
			}
		}
	}
	native := map[string][]string{}
	for id, roots := range d.semantic {
		for root := range roots {
			native[root] = append(native[root], id)
		}
	}
	for root, ids := range native {
		sort.Strings(ids)
		d.model.Expose(invalidate.Exposure{ID: root, AffectsIDs: ids, UnknownOrder: true})
	}
	return nil
}
func (s *Store) commitProjectionHold(ctx context.Context) error {
	var g int64
	if s.conn.QueryRowContext(ctx, "SELECT generation FROM meta WHERE singleton=1").Scan(&g) != nil || g == math.MaxInt64 {
		s.poisoned = true
		return failure("unavailable")
	}
	s.barrierAttempt = true
	for _, q := range []struct {
		sql  string
		args []any
	}{{"INSERT OR IGNORE INTO projection_hold VALUES(?,?,'lineage_evaluation_required',?)", []any{s.opts.PinnedGenesisID, s.opts.LocalMachineID, g + 1}}, {"UPDATE meta SET generation=? WHERE singleton=1", []any{g + 1}}, {"DELETE FROM projection_job", nil}, {"DELETE FROM render_body", nil}} {
		if _, err := s.conn.ExecContext(ctx, q.sql, q.args...); err != nil {
			s.poisoned = true
			return failure("unavailable")
		}
	}
	return &postCommitRefusal{err: &Error{Code: "lineage_evaluation_required", OwnerBlocked: true}}
}
func (s *Store) persistLineage(ctx context.Context, d *databaseState) error {
	for _, f := range d.exposures {
		if !f.persisted {
			if _, err := s.conn.ExecContext(ctx, "INSERT INTO exposure VALUES(?,?,?,?,?,?,?,?,?,'local-admission-fence/1')", f.id, f.owner, f.machine, f.credential, f.scope, f.root, f.source, f.attempt, f.fence); err != nil {
				return failure("storage_error")
			}
		}
		for _, id := range f.evidence {
			if _, err := s.conn.ExecContext(ctx, "INSERT OR IGNORE INTO exposure_evidence VALUES(?,?)", f.id, id); err != nil {
				return failure("storage_error")
			}
		}
		for id := range f.affects {
			if _, err := s.conn.ExecContext(ctx, "INSERT OR IGNORE INTO exposure_affect VALUES(?,?)", f.id, id); err != nil {
				return failure("storage_error")
			}
		}
	}
	for id, tokens := range d.eval.HoldCauses {
		for _, token := range tokens {
			parts := strings.Split(token, "/")
			if len(parts) != 2 || !record.IsHex64(parts[0]) || !record.IsHex64(parts[1]) {
				return failure("corrupt_database")
			}
			if _, err := s.conn.ExecContext(ctx, "INSERT OR IGNORE INTO semantic_hold_cause VALUES(?,?,?,?)", s.opts.PinnedGenesisID, id, parts[0], parts[1]); err != nil {
				return failure("storage_error")
			}
		}
	}
	return nil
}
