package capture

import (
	"github.com/Telara-Labs/telara-memory/contract/record"
	"sort"
)

func runtimeErasureEvents(owner string, records map[string]*record.Record) []record.EventSelector {
	set := map[record.EventSelector]bool{}
	for _, r := range records {
		if b, ok := r.Body.(*record.ChunkBody); ok {
			for _, ev := range b.Events {
				set[record.EventSelector{Owner: owner, SessionKey: r.Header.Subj.SessionKey, EventID: ev.ID}] = true
			}
		}
	}
	out := []record.EventSelector{}
	for sel := range set {
		out = append(out, sel)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Owner+out[i].SessionKey+out[i].EventID < out[j].Owner+out[j].SessionKey+out[j].EventID
	})
	return out
}
