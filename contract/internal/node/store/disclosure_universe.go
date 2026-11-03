package store

import (
	"github.com/Telara-Labs/hilo/contract/record"
)

// Current native resource membership comes from actual reduced session/event
// views, rather than treating every retained chunk version as current activity.
func projectionUniverse(d *databaseState) (map[string]bool, map[string]map[string]bool, error) {
	head := map[string]bool{}
	for id, v := range currentHeads(d) {
		head[id] = v
	}
	events := map[string]map[string]bool{}
	sessions := map[string]bool{}
	for _, x := range d.records {
		if x.rec.Header.Type == record.KindChunk {
			delete(head, x.rec.ID)
			if x.rec.Header.Subj.SessionKey != "" {
				sessions[x.rec.Header.Subj.SessionKey] = true
			}
		}
	}
	if len(sessions) > 128 {
		return nil, nil, &projectionLimit{}
	}
	for sk := range sessions {
		v, err := d.reduceSession(sk)
		if err != nil {
			return nil, nil, err
		}
		current := map[string]bool{}
		for _, ev := range v.Events {
			current[ev.ID+"/"+ev.Revision] = true
		}
		members := map[string]bool{}
		for _, x := range d.records {
			if head[x.rec.ID] && x.rec.Header.Subj.SessionKey == sk {
				if b, ok := x.rec.Body.(*record.SessionBody); ok {
					for _, id := range b.Chunks {
						members[id] = true
					}
				}
			}
		}
		for _, x := range d.records {
			b, ok := x.rec.Body.(*record.ChunkBody)
			if !ok || !available(x) || !members[x.rec.ID] {
				continue
			}
			for _, ev := range b.Events {
				key := ev.ID + "/" + ev.Revision
				if current[key] {
					head[x.rec.ID] = true
					if events[x.rec.ID] == nil {
						events[x.rec.ID] = map[string]bool{}
					}
					events[x.rec.ID][key] = true
				}
			}
		}
	}
	return head, events, nil
}
func resourceMember(types map[string]bool, x *stored) bool {
	if x == nil || !types[string(x.rec.Header.Type)] {
		return false
	}
	if b, ok := x.rec.Body.(*record.ConclusionBody); ok {
		return b.Source == "explicit" && x.rec.Header.Prov == record.ProvMCPExplicit
	}
	return true
}
