// Package view contains pure reducers over already verified records. Stores
// must preserve supersession facts and re-evaluate these views on late input.
package view

import (
	"github.com/Telara-Labs/telara-memory/contract/heads"
	"github.com/Telara-Labs/telara-memory/contract/record"
	"sort"
)

type Observed struct {
	Record        *record.Record
	Owner         string
	Live          bool
	Admissible    bool // current verified admission/signature provenance, separate from body availability
	ObservedTaint []string
}
type Session struct {
	Facts       EventFacts
	TaintEvents []EventTaint

	Events      []record.Event
	Conflicts   map[string][]record.Event
	Through     int64
	HasBoundary bool
	LastEventAt int64
	End         string
	seq         map[int64]string
	badSeq      map[int64]bool
}

// CoverageAt requires an actual gap-free verified sequence, not a timestamp.
func (s *Session) CoverageAt(boundary int64) bool {
	if s == nil || !s.HasBoundary || boundary < 0 || boundary > s.Through || boundary >= int64(len(s.seq)) {
		return false
	}
	for seq := int64(0); seq <= boundary; seq++ {
		if s.seq[seq] == "" || s.badSeq[seq] {
			return false
		}
	}
	return true
}

func SessionView(all []Observed, index []heads.Pair, eventIndex []EventPair, sessionKey string, history ...EventFacts) (*Session, error) {
	out := &Session{Conflicts: map[string][]record.Event{}, seq: map[int64]string{}, badSeq: map[int64]bool{}}
	records := map[string]Observed{}
	var versions []heads.Version
	lids := map[string]bool{}
	var eventCopies []EventVersion
	for _, o := range all {
		if o.Record == nil {
			continue
		}
		r := o.Record
		records[r.ID] = o
		if r.Header.Type == record.KindSession && r.Header.Subj.SessionKey == sessionKey {
			versions = append(versions, heads.FromHeader(r.ID, &r.Header, o.Owner, o.Live && o.Admissible))
			lids[r.Header.LID] = true
		}
	}
	type page struct {
		body  *record.SessionBody
		owner string
	}
	pages := map[string]map[int64]page{}
	members := map[string]bool{}
	allIdle := true
	snapshotCount := 0
	for lid := range lids {
		h, ok := heads.Head(versions, index, lid, record.KindSession)
		if !ok {
			continue
		}
		o := records[h.ID]
		b, ok := o.Record.Body.(*record.SessionBody)
		if !ok {
			continue
		}
		machine := o.Record.Header.Author.MachineID
		snapshotCount++
		if b.End != "idle" {
			allIdle = false
		}
		if pages[machine] == nil {
			pages[machine] = map[int64]page{}
		}
		pages[machine][b.Page] = page{b, o.Owner}
		for _, id := range b.Chunks {
			members[id] = true
		}
		if b.LastEventAt > out.LastEventAt {
			out.LastEventAt = b.LastEventAt
		}
		if b.End == "client-end" {
			out.End = "client-end"
		}
	}
	if out.End != "client-end" && allIdle && snapshotCount > 0 {
		out.End = "idle"
	}
	for _, ps := range pages {
		seen := map[int64]bool{}
		through := int64(0)
		for pageNum := int64(0); pageNum < int64(len(ps)); pageNum++ {
			p, ok := ps[pageNum]
			if !ok {
				break
			}
			prefixLive := true
			for _, cid := range p.body.Chunks {
				o, ok := records[cid]
				if !ok || !o.Live || !o.Admissible || o.Owner != p.owner || o.Record.Header.Subj.SessionKey != sessionKey {
					prefixLive = false
					break
				}
				b, ok := o.Record.Body.(*record.ChunkBody)
				if !ok {
					prefixLive = false
					break
				}
				for _, e := range b.Events {
					seen[e.Seq] = true
				}
			}
			if !prefixLive {
				break
			}
			if p.body.SettledThrough > through {
				through = p.body.SettledThrough
			}
			complete := through < int64(len(seen))
			for seq := int64(0); complete && seq <= through; seq++ {
				if !seen[seq] {
					complete = false
				}
			}
			if complete && (!out.HasBoundary || through > out.Through) {
				out.HasBoundary = true
				out.Through = through
			}
		}
	}
	for _, o := range all {
		if o.Record == nil || o.Record.Header.Type != record.KindChunk || o.Record.Header.Subj.SessionKey != sessionKey {
			continue
		}
		if b, ok := o.Record.Body.(*record.ChunkBody); ok {
			for _, e := range b.Events {
				eventCopies = append(eventCopies, EventVersion{Event: e, Live: o.Live && members[o.Record.ID], Admissible: o.Admissible, ObservedTaint: append(append([]string(nil), o.ObservedTaint...), o.Record.Header.Trust.Taint...), RecordID: o.Record.ID, Owner: o.Owner, SessionKey: sessionKey})
			}
		}
	}
	// Forward authoritative status for every source header, including bodyless
	// predecessors. Availability cannot leave stale historical admissibility active.
	sourceStatus := map[string]bool{}
	for _, o := range all {
		if o.Record != nil {
			if old, ok := sourceStatus[o.Record.ID]; ok {
				sourceStatus[o.Record.ID] = old && o.Admissible
			} else {
				sourceStatus[o.Record.ID] = o.Admissible
			}
		}
	}
	history = append(append([]EventFacts(nil), history...), EventFacts{V: record.Version, CurrentSources: sourceStatus})
	choices, err := EventHeads(eventCopies, eventIndex, history...)
	if err != nil {
		return nil, err
	}
	out.Facts = EventFacts{V: record.Version}
	for id, c := range choices {
		out.Facts.Presence = append(out.Facts.Presence, c.Facts.Presence...)
		out.Facts.Witnesses = append(out.Facts.Witnesses, c.Facts.Witnesses...)
		for _, p := range c.Facts.Presence {
			if len(p.ObservedTaint) > 0 {
				out.TaintEvents = append(out.TaintEvents, EventTaint{Seq: p.Seq, Tags: append([]string(nil), p.ObservedTaint...)})
			}
		}

		if len(c.Heads) == 0 || c.Conflict || c.Pending {
			if len(c.Heads) > 0 {
				out.Conflicts[id] = c.Heads
				for _, e := range c.Heads {
					out.badSeq[e.Seq] = true
				}
			}
			continue
		}
		e := c.Heads[0]
		if prior := out.seq[e.Seq]; prior != "" && prior != id {
			out.badSeq[e.Seq] = true
		}
		out.seq[e.Seq] = id
		out.Events = append(out.Events, e)
	}
	sort.Slice(out.Events, func(i, j int) bool {
		if out.Events[i].Seq != out.Events[j].Seq {
			return out.Events[i].Seq < out.Events[j].Seq
		}
		return out.Events[i].ID < out.Events[j].ID
	})
	return out, nil
}
