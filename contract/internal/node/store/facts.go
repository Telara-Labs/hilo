package store

import (
	"context"
	"github.com/Telara-Labs/telara-memory/contract/view"
)

func factKey(p view.RevisionPresence) [5]string {
	return [5]string{p.Owner, p.SessionKey, p.EventID, p.Revision, p.RecordID}
}
func (s *Store) loadFacts(ctx context.Context, d *databaseState) error {
	ps := map[[5]string]*view.RevisionPresence{}
	rows, err := s.conn.QueryContext(ctx, "SELECT owner,session,event_id,revision,source,seq FROM presence")
	if err != nil {
		return failure("storage_error")
	}
	for rows.Next() {
		p := &view.RevisionPresence{Admissible: true}
		if rows.Scan(&p.Owner, &p.SessionKey, &p.EventID, &p.Revision, &p.RecordID, &p.Seq) != nil {
			rows.Close()
			return failure("storage_error")
		}
		ps[factKey(*p)] = p
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return failure("storage_error")
	}
	for _, spec := range []struct {
		table, field string
		apply        func(*view.RevisionPresence, string)
	}{
		{"presence_parent", "predecessor", func(p *view.RevisionPresence, v string) { p.Replaces = append(p.Replaces, v) }},
		{"presence_taint", "tag", func(p *view.RevisionPresence, v string) { p.ObservedTaint = append(p.ObservedTaint, v) }},
	} {
		rows, err = s.conn.QueryContext(ctx, "SELECT owner,session,event_id,revision,source,"+spec.field+" FROM "+spec.table)
		if err != nil {
			return failure("storage_error")
		}
		for rows.Next() {
			var key [5]string
			var v string
			if rows.Scan(&key[0], &key[1], &key[2], &key[3], &key[4], &v) != nil || ps[key] == nil {
				rows.Close()
				return failure("corrupt_database")
			}
			spec.apply(ps[key], v)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return failure("storage_error")
		}
	}
	for _, p := range ps {
		f := d.facts[p.SessionKey]
		f.V = 2
		f.Presence = append(f.Presence, *p)
		d.facts[p.SessionKey] = f
	}
	rows, err = s.conn.QueryContext(ctx, "SELECT owner,session,event_id,a,b,source_a,source_b FROM witness")
	if err != nil {
		return failure("storage_error")
	}
	for rows.Next() {
		w := view.EqualityWitness{Admissible: true}
		if rows.Scan(&w.Owner, &w.SessionKey, &w.EventID, &w.A, &w.B, &w.RecordA, &w.RecordB) != nil {
			rows.Close()
			return failure("storage_error")
		}
		f := d.facts[w.SessionKey]
		f.V = 2
		f.Witnesses = append(f.Witnesses, w)
		d.facts[w.SessionKey] = f
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return failure("storage_error")
	}
	return nil
}
func (s *Store) persistFacts(ctx context.Context, f view.EventFacts) error {
	for _, p := range f.Presence {
		if !p.Admissible {
			continue
		}
		args := []any{p.Owner, p.SessionKey, p.EventID, p.Revision, p.RecordID}
		if _, err := s.conn.ExecContext(ctx, "INSERT OR IGNORE INTO presence VALUES(?,?,?,?,?,?)", append(args, p.Seq)...); err != nil {
			return failure("storage_error")
		}
		for _, v := range p.Replaces {
			if _, err := s.conn.ExecContext(ctx, "INSERT OR IGNORE INTO presence_parent VALUES(?,?,?,?,?,?)", append(args, v)...); err != nil {
				return failure("storage_error")
			}
		}
		for _, v := range p.ObservedTaint {
			if _, err := s.conn.ExecContext(ctx, "INSERT OR IGNORE INTO presence_taint VALUES(?,?,?,?,?,?)", append(args, v)...); err != nil {
				return failure("storage_error")
			}
		}
	}
	for _, w := range f.Witnesses {
		if !w.Admissible {
			continue
		}
		if _, err := s.conn.ExecContext(ctx, "INSERT OR IGNORE INTO witness VALUES(?,?,?,?,?,?,?)", w.Owner, w.SessionKey, w.EventID, w.A, w.B, w.RecordA, w.RecordB); err != nil {
			return failure("storage_error")
		}
	}
	return nil
}
