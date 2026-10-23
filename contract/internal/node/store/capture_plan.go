package store

import (
	"context"
	"database/sql"

	"github.com/Telara-Labs/telara-memory/contract/record"
)

func (s *Store) validateCaptureMembership(d *databaseState, q CaptureRequest, p CaptureProgress, t *CaptureTxn, plan CommitPlan, allowed map[string]bool) error {
	n := plan.Next
	requested := map[string]bool{}
	for _, id := range q.EventIDs {
		requested[id] = true
	}
	sourceIDs := map[string]bool{}
	eventSeq := map[string]int64{}
	seqIDs := map[int64]string{}
	lastSeq := int64(-1)
	for _, id := range n.LastSourceRecordIDs {
		x := d.byID[id]
		if sourceIDs[id] || !allowed[id] || !candidateBody(x) || x.rec.Header.Type != record.KindChunk {
			return failure("invalid_source_refs")
		}
		sourceIDs[id] = true
		b := x.rec.Body.(*record.ChunkBody)
		for _, e := range b.Events {
			if !requested[e.ID] || eventSeqHas(eventSeq, e.ID) || e.Seq <= lastSeq || e.Seq < 0 || e.Seq >= n.Range.LastExclusive || seqIDs[e.Seq] != "" {
				return failure("invalid_source_refs")
			}
			lastSeq = e.Seq
			eventSeq[e.ID] = e.Seq
			seqIDs[e.Seq] = e.ID
		}
	}
	if int64(len(seqIDs)) != n.Range.LastExclusive || len(eventSeq) != len(requested) {
		return failure("source_regression")
	}
	// The source's admitted prefix remains complete even when some wrappers were
	// repacked. A corrected occurrence retains its original identity and ordinal.
	for _, r := range t.prior {
		x := d.byID[r.ID]
		if !available(x) {
			return failure("history_unavailable")
		}
		for _, e := range x.rec.Body.(*record.ChunkBody).Events {
			if v, ok := eventSeq[e.ID]; !ok || v != e.Seq {
				return failure("source_regression")
			}
		}
	}
	pages := map[int64]string{}
	membership := map[string]bool{}
	newPageIDs := map[string]bool{}
	for i, r := range n.SessionPageIDs {
		x := d.byID[r.ID]
		if r.Page != int64(i) || !allowed[r.ID] || !candidateBody(x) || x.rec.Header.Type != record.KindSession {
			return failure("invalid_page_refs")
		}
		b := x.rec.Body.(*record.SessionBody)
		if b.Page != r.Page || b.SettledThrough != n.SettledThrough {
			return failure("invalid_page_refs")
		}
		pages[r.Page] = r.ID
		newPageIDs[r.ID] = true
		for _, id := range b.Chunks {
			v := d.byID[id]
			if !candidateBody(v) || v.rec.Header.Type != record.KindChunk || v.owner != q.Occurrence.Owner || v.rec.Header.Subj.SessionKey != q.Occurrence.SessionKey {
				return failure("invalid_page_refs")
			}
			membership[id] = true
		}
	}
	for _, old := range t.pages {
		if old.Availability != "available" {
			return failure("history_unavailable")
		}
		id := pages[old.Page]
		if id == "" {
			return failure("invalid_page_refs")
		}
		if id == old.ID {
			continue
		}
		r := d.byID[id].rec
		if r.Header.Links.Prev != old.ID || len(r.Header.Links.Supersedes) != 1 || r.Header.Links.Supersedes[0] != old.ID {
			return failure("invalid_page_ancestry")
		}
		b := d.byID[old.ID].rec.Body.(*record.SessionBody)
		for _, cid := range b.Chunks {
			if available(d.byID[cid]) && !membership[cid] {
				return failure("page_membership_regression")
			}
		}
	}
	for _, r := range n.SessionPageIDs {
		if r.Page >= int64(len(t.pages)) {
			h := d.byID[r.ID].rec.Header
			if h.Links.Prev != "" || len(h.Links.Supersedes) != 0 {
				return failure("invalid_page_ancestry")
			}
		}
	}
	for id := range sourceIDs {
		if !membership[id] {
			return failure("invalid_page_refs")
		}
	}
	for id := range allowed {
		if !sourceIDs[id] && !newPageIDs[id] && !membership[id] {
			return failure("unused_plan_record")
		}
	}
	return nil
}
func eventSeqHas(m map[string]int64, k string) bool { _, ok := m[k]; return ok }
func (s *Store) persistCapture(ctx context.Context, q CaptureRequest, id string, p CaptureProgress, refs []RecordRef) error {
	if _, e := s.conn.ExecContext(ctx, "INSERT INTO capture_progress VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(source) DO UPDATE SET version=excluded.version,settled=excluded.settled,reader=excluded.reader,reader_version=excluded.reader_version,ruleset=excluded.ruleset,first=excluded.first,last_exclusive=excluded.last_exclusive", q.Occurrence.Source, q.Occurrence.SessionKey, p.Version, p.SettledThrough, p.Reader.Reader, p.Reader.ReaderVersion, p.RulesetFingerprint, p.Range.First, p.Range.LastExclusive); e != nil {
		return failure("storage_error")
	}
	if _, e := s.conn.ExecContext(ctx, "INSERT INTO capture_transition VALUES(?,?,?,?,?,?,?,?,?,?,?)", id, q.Occurrence.Source, q.Occurrence.SessionKey, q.ExpectedVersion, p.Version, p.SettledThrough, p.Reader.Reader, p.Reader.ReaderVersion, p.RulesetFingerprint, p.Range.First, p.Range.LastExclusive); e != nil {
		return failure("storage_error")
	}
	for _, table := range []string{"capture_source", "capture_page"} {
		if _, e := s.conn.ExecContext(ctx, "DELETE FROM "+table+" WHERE source=?", q.Occurrence.Source); e != nil {
			return failure("storage_error")
		}
	}
	for i, r := range refs {
		if _, e := s.conn.ExecContext(ctx, "INSERT INTO capture_transition_record VALUES(?,?,?,?)", id, i, r.ID, r.Sequence); e != nil {
			return failure("storage_error")
		}
	}
	for i, r := range p.LastSourceRecords {
		if _, e := s.conn.ExecContext(ctx, "INSERT INTO capture_source VALUES(?,?,?)", q.Occurrence.Source, i, r.ID); e != nil {
			return failure("storage_error")
		}
		if _, e := s.conn.ExecContext(ctx, "INSERT INTO capture_transition_source VALUES(?,?,?,?)", id, i, r.ID, r.Sequence); e != nil {
			return failure("storage_error")
		}
	}
	for _, r := range p.SessionPages {
		if _, e := s.conn.ExecContext(ctx, "INSERT INTO capture_page VALUES(?,?,?)", q.Occurrence.Source, r.Page, r.ID); e != nil {
			return failure("storage_error")
		}
		if _, e := s.conn.ExecContext(ctx, "INSERT INTO capture_transition_page VALUES(?,?,?)", id, r.Page, r.ID); e != nil {
			return failure("storage_error")
		}
	}
	return nil
}
func (s *Store) captureReceipt(ctx context.Context, d *databaseState, id string, q CaptureRequest) (CaptureReceipt, bool, error) {
	out := CaptureReceipt{Status: "prior_transition_committed", TransitionID: id}
	p := &out.ResultingProgress
	var source, session string
	var expected int64
	e := s.conn.QueryRowContext(ctx, "SELECT source,session,expected_version,resulting_version,settled,reader,reader_version,ruleset,first,last_exclusive FROM capture_transition WHERE id=?", id).Scan(&source, &session, &expected, &p.Version, &p.SettledThrough, &p.Reader.Reader, &p.Reader.ReaderVersion, &p.RulesetFingerprint, &p.Range.First, &p.Range.LastExclusive)
	if e == sql.ErrNoRows {
		return CaptureReceipt{}, false, nil
	}
	if e != nil {
		return out, false, failure("storage_error")
	}
	if source != q.Occurrence.Source || session != q.Occurrence.SessionKey || expected != q.ExpectedVersion || expected < 0 || p.Version <= expected || p.Version-expected != 1 || p.Range.First != 0 || p.Range.LastExclusive <= 0 || p.SettledThrough != p.Range.LastExclusive-1 || !readerValid(p.Reader) || !record.IsHex64(p.RulesetFingerprint) {
		return out, false, failure("corrupt_database")
	}
	for _, spec := range []struct {
		table  string
		target *[]RecordRef
	}{{"capture_transition_record", &out.ActualRecordRefs}, {"capture_transition_source", &p.LastSourceRecords}} {
		rows, e := s.conn.QueryContext(ctx, "SELECT record_id,sequence FROM "+spec.table+" WHERE transition_id=? ORDER BY position", id)
		if e != nil {
			return out, false, failure("storage_error")
		}
		for rows.Next() {
			var r RecordRef
			if rows.Scan(&r.ID, &r.Sequence) != nil {
				rows.Close()
				return out, false, failure("storage_error")
			}
			x := d.byID[r.ID]
			if x == nil || x.seq != r.Sequence {
				rows.Close()
				return out, false, failure("corrupt_database")
			}
			*spec.target = append(*spec.target, r)
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return out, false, failure("storage_error")
		}
	}
	rows, e := s.conn.QueryContext(ctx, "SELECT page,record_id FROM capture_transition_page WHERE transition_id=? ORDER BY page", id)
	if e != nil {
		return out, false, failure("storage_error")
	}
	for rows.Next() {
		var r PageRef
		if rows.Scan(&r.Page, &r.ID) != nil || d.byID[r.ID] == nil {
			rows.Close()
			return out, false, failure("corrupt_database")
		}
		p.SessionPages = append(p.SessionPages, r)
	}
	e = rows.Err()
	rows.Close()
	if e != nil || len(out.ActualRecordRefs) == 0 || len(out.ActualRecordRefs) > maxCaptureRecordRefs || len(p.LastSourceRecords) == 0 || len(p.LastSourceRecords) > 64 || len(p.SessionPages) == 0 || len(p.SessionPages) > 16 {
		return out, false, failure("corrupt_database")
	}
	out.CurrentAvailability = currentAvailability(d, out.ActualRecordRefs)
	return out, true, nil
}

func candidateBody(x *stored) bool { return x != nil && x.rec.Body != nil && x.sigStatus == "verified" }
