package store

import (
	"github.com/Telara-Labs/hilo/contract/invalidate"
	"github.com/Telara-Labs/hilo/contract/record"
)

func mutationKind(k record.Kind) bool {
	return k == record.KindTask || k == record.KindCheckpoint || k == record.KindPause || k == record.KindConclusion
}
func knownCallRoots(d *databaseState, call *record.Record) []string {
	var roots []string
	for _, x := range d.records {
		if x.rec.ID != call.ID && x.rec.Header.Op == call.Header.Op && x.rec.Header.Author == call.Header.Author && mutationKind(x.rec.Header.Type) {
			roots = append(roots, x.rec.ID)
		}
	}
	return roots
}
func (d *databaseState) enforceCallDependencies() error {
	byOp := map[string][]string{}
	for _, x := range d.records {
		if mutationKind(x.rec.Header.Type) {
			byOp[x.rec.Header.Op+"/"+x.rec.Header.Author.KeyID] = append(byOp[x.rec.Header.Op+"/"+x.rec.Header.Author.KeyID], x.rec.ID)
		}
	}
	for _, x := range d.records {
		if x.rec.Header.Type != record.KindCall || x.rec.Body == nil {
			continue
		}
		roots := byOp[x.rec.Header.Op+"/"+x.rec.Header.Author.KeyID]
		if err := record.ValidateCommitmentDependencies(x.rec, roots); err != nil {
			// A later verified root contradicts the transferred call. Permanently
			// invalidate the whole key-bearing body; preserve only opaque settlement.
			if d.retained == nil {
				d.retained = map[string][]invalidate.Tomb{}
			}
			tomb := invalidate.Tomb{Kind: invalidate.Retracted, Cause: x.rec.ID}
			found := false
			for _, old := range d.retained[x.rec.ID] {
				found = found || old == tomb
			}
			if !found {
				d.retained[x.rec.ID] = append(d.retained[x.rec.ID], tomb)
			}
		}
	}
	return nil
}
