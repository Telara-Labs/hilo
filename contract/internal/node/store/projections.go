package store

import (
	"context"
	"github.com/Telara-Labs/telara-memory/contract/invalidate"
	"github.com/Telara-Labs/telara-memory/contract/record"
	"github.com/Telara-Labs/telara-memory/contract/sig"
	"strings"
)

// Policy authority changes suppress old projections in the SAME writer as the
// new authority. Normal operations rebuild from currently permitted normalized
// fields; stale passage/vector jobs must not survive until that later rebuild.
func (s *Store) policyProjectionFence(ctx context.Context) error {
	if err := s.clearSearch(ctx); err != nil {
		return err
	}
	for _, table := range []string{"vector", "projection_job", "record_field_projection"} {
		if _, err := s.conn.ExecContext(ctx, "DELETE FROM "+table); err != nil {
			return failure("storage_error")
		}
	}
	return s.bump(ctx)
}

func (s *Store) persistErasurePending(ctx context.Context, d *databaseState) error {
	if _, err := s.conn.ExecContext(ctx, "DELETE FROM erasure_pending"); err != nil {
		return failure("storage_error")
	}
	for _, x := range d.records {
		if x.rec.Header.Type == record.KindErasure && !d.eval.ControlComplete[x.rec.ID] {
			if _, err := s.conn.ExecContext(ctx, "INSERT INTO erasure_pending VALUES(?,?)", x.rec.ID, x.owner); err != nil {
				return failure("storage_error")
			}
		}
	}
	return nil
}

func (s *Store) persistState(ctx context.Context, d *databaseState) error {
	if err := s.persistErasurePending(ctx, d); err != nil {
		return err
	}
	if err := d.prepareRelations(); err != nil {
		return err
	}
	for _, x := range d.records {
		if err := s.persistEventMembership(ctx, x); err != nil {
			return err
		}
	}
	if err := s.persistLineage(ctx, d); err != nil {
		return err
	}
	if err := s.persistFieldProjection(ctx, d); err != nil {
		return err
	}
	if _, err := s.conn.ExecContext(ctx, "DELETE FROM render_body"); err != nil {
		return failure("storage_error")
	}
	for id, causes := range d.eval.Causes {
		for _, c := range causes {
			if _, err := s.conn.ExecContext(ctx, "INSERT OR IGNORE INTO tomb VALUES(?,?,?)", id, string(c.Kind), c.Cause); err != nil {
				return failure("storage_error")
			}
		}
	}
	// Persist occurrence fences by their opaque source identity, separately per cause.
	for _, x := range d.records {
		for _, cause := range d.eval.Causes[x.rec.ID] {
			if cause.Kind != invalidate.Erased {
				continue
			}
			for _, eventID := range x.events {
				if _, err := s.conn.ExecContext(ctx, "INSERT OR IGNORE INTO event_ban VALUES(?,?,?,?)", x.owner, x.rec.Header.Subj.SessionKey, eventID, cause.Cause); err != nil {
					return failure("storage_error")
				}
			}
		}
	}
	sessions := map[string]bool{}
	tasks := map[[2]string]bool{}
	for _, x := range d.records {
		if x.priorState != "" && x.priorState != x.state {
			x.generation = d.generation
		}
		if x.state == string(invalidate.Invalidated) {
			// Standalone comparator copies never outlive their signed call key.
			if _, err := s.conn.ExecContext(ctx, "UPDATE operation SET args_hash='' WHERE call_id=?", x.rec.ID); err != nil {
				return failure("storage_error")
			}
			if _, err := s.conn.ExecContext(ctx, "DELETE FROM outcome_query"); err != nil {
				return failure("storage_error")
			}
			if _, err := s.conn.ExecContext(ctx, "DELETE FROM selection_payload"); err != nil {
				return failure("storage_error")
			}
			if _, err := s.conn.ExecContext(ctx, "UPDATE query_cursor SET state='expired' WHERE state='ready'"); err != nil {
				return failure("storage_error")
			}
			if _, err := s.conn.ExecContext(ctx, "DELETE FROM record_body WHERE id=?", x.rec.ID); err != nil {
				return failure("storage_error")
			}
			x.rec = x.rec.WithoutBody()
			if _, err := s.conn.ExecContext(ctx, "INSERT INTO scrub_job VALUES(?,?,'pending',0) ON CONFLICT(control) DO UPDATE SET target_generation=excluded.target_generation,state='pending'", x.rec.ID, d.generation); err != nil {
				return failure("storage_error")
			}
			d.groups = nil
			if _, err := s.conn.ExecContext(ctx, "DELETE FROM field_completeness WHERE id=?", x.rec.ID); err != nil {
				return failure("storage_error")
			}
			if _, err := s.conn.ExecContext(ctx, "DELETE FROM vector WHERE id=?", x.rec.ID); err != nil {
				return failure("storage_error")
			}
			if _, err := s.conn.ExecContext(ctx, "DELETE FROM projection_job WHERE id=?", x.rec.ID); err != nil {
				return failure("storage_error")
			}
		}
		if x.state != string(invalidate.Live) || x.sigStatus != sig.StatusVerified {
			if _, err := s.conn.ExecContext(ctx, "DELETE FROM vector WHERE id=?", x.rec.ID); err != nil {
				return failure("storage_error")
			}
			if _, err := s.conn.ExecContext(ctx, "DELETE FROM projection_job WHERE id=?", x.rec.ID); err != nil {
				return failure("storage_error")
			}
		}
		if _, err := s.conn.ExecContext(ctx, "UPDATE record SET sig_status=?,state=?,generation=? WHERE id=?", string(x.sigStatus), x.state, x.generation, x.rec.ID); err != nil {
			return failure("storage_error")
		}
		if sk := x.rec.Header.Subj.SessionKey; sk != "" {
			sessions[sk] = true
		}
		if task := x.rec.Header.Subj.TaskID; task != "" {
			tasks[[2]string{x.owner, task}] = true
		}
	}
	if len(sessions) > 128 {
		return &projectionLimit{}
	}
	for sk := range sessions {
		if err := s.persistFacts(ctx, d.plannedFacts[sk]); err != nil {
			return err
		}
	}
	if _, err := s.conn.ExecContext(ctx, "DELETE FROM task_state"); err != nil {
		return failure("storage_error")
	}
	for task := range tasks {
		status := d.taskStatus(task[0], task[1])
		if _, err := s.conn.ExecContext(ctx, "INSERT INTO task_state VALUES(?,?,?)", task[0], task[1], status); err != nil {
			return failure("storage_error")
		}
	}
	if err := s.clearSearch(ctx); err != nil {
		return err
	}
	for _, x := range d.records {
		if x.state != string(invalidate.Live) || x.sigStatus != sig.StatusVerified || x.rec.Body == nil || x.rec.Header.Type.IsControl() {
			continue
		}
		text := freshText(d, x.rec.ID)
		if text == "" {
			if _, err := s.conn.ExecContext(ctx, "DELETE FROM vector WHERE id=?", x.rec.ID); err != nil {
				return failure("storage_error")
			}
			if _, err := s.conn.ExecContext(ctx, "DELETE FROM projection_job WHERE id=?", x.rec.ID); err != nil {
				return failure("storage_error")
			}
			continue
		}
		if text != "" {
			result, err := s.conn.ExecContext(ctx, "INSERT INTO passage(id,text) VALUES(?,?)", x.rec.ID, text)
			if err != nil {
				return failure("storage_error")
			}
			row, err := result.LastInsertId()
			if err != nil {
				return failure("storage_error")
			}
			if _, err = s.conn.ExecContext(ctx, "INSERT INTO search(rowid,text) VALUES(?,?)", row, text); err != nil {
				return failure("storage_error")
			}
		}
		if _, err := s.conn.ExecContext(ctx, "INSERT OR IGNORE INTO projection_job VALUES(?,?)", x.rec.ID, x.generation); err != nil {
			return failure("storage_error")
		}
	}
	for _, x := range d.records {
		if x.rec.Header.Type == record.KindErasure || x.rec.Header.Type == record.KindRetraction {
			if _, err := s.conn.ExecContext(ctx, "INSERT INTO scrub_job VALUES(?,?,'pending',0) ON CONFLICT(control) DO UPDATE SET target_generation=excluded.target_generation,state='pending'", x.rec.ID, d.generation); err != nil {
				return failure("storage_error")
			}
		}
	}
	return nil
}
func (s *Store) clearSearch(ctx context.Context) error {
	type old struct {
		id   int64
		text string
	}
	var all []old
	rows, err := s.conn.QueryContext(ctx, "SELECT rowid,text FROM passage")
	if err != nil {
		return failure("storage_error")
	}
	for rows.Next() {
		var x old
		if rows.Scan(&x.id, &x.text) != nil {
			rows.Close()
			return failure("storage_error")
		}
		all = append(all, x)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return failure("storage_error")
	}
	for _, x := range all {
		if _, err = s.conn.ExecContext(ctx, "INSERT INTO search(search,rowid,text) VALUES('delete',?,?)", x.id, x.text); err != nil {
			return failure("storage_error")
		}
	}
	if _, err = s.conn.ExecContext(ctx, "DELETE FROM passage"); err != nil {
		return failure("storage_error")
	}
	return nil
}
func searchText(body any) string {
	switch b := body.(type) {
	case *record.TaskBody:
		return b.Name + " " + b.Goal
	case *record.ConclusionBody:
		return b.Request + " " + b.Text
	case *record.SessionBody:
		return b.Title
	case *record.ChunkBody:
		var parts []string
		for _, e := range b.Events {
			if e.Text != nil {
				parts = append(parts, e.Text.Body)
			}
		}
		return strings.Join(parts, " ")
	case *record.CheckpointBody:
		return b.Milestone + " " + b.NextSteps
	case *record.PauseBody:
		return b.ResumeContext + " " + b.ProgressNotes + " " + b.HandoffHint
	case *record.DigestBody:
		return b.Outcome
	}
	return ""
}
