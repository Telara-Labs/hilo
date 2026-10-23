package store

import (
	"context"
	"math"
)

// syntheticCompactionSignal is fixture-only owner administration, not a native
// signal, installed adapter or model-callable capability.
type syntheticCompactionSignal struct {
	engine     *DisclosureEngine
	id, scope  string
	generation int64
}

func (a *DisclosureAdministration) issueSyntheticCompaction(ctx context.Context, scope ScopeHandle) (syntheticCompactionSignal, error) {
	var out syntheticCompactionSignal
	if a == nil || a.engine == nil || scope.engine != a.engine {
		return out, failure("unauthorized")
	}
	e := a.engine
	p, err := newDisclosureEntropy()
	if err != nil {
		return out, err
	}
	defer p.clear()
	err = e.store.writeMode(ctx, true, func() error {
		if err := e.checkAuthority(ctx); err != nil {
			return err
		}
		var generation int64
		if err := e.store.conn.QueryRowContext(ctx, "SELECT generation FROM local_scope WHERE id=? AND owner=? AND machine=?", scope.id, e.config.OwnerGenesis, e.config.MachineID).Scan(&generation); err != nil {
			return failure("invalid_scope")
		}
		id, err := p.uuid(ctx, e.store, "scope", "synthetic_compaction_signal", "id")
		if err != nil {
			return err
		}
		if _, err = e.store.conn.ExecContext(ctx, "INSERT INTO synthetic_compaction_signal VALUES(?,?,?,'owner-fixture',0)", id, scope.id, generation); err != nil {
			return failure("storage_error")
		}
		if err = e.store.bump(ctx); err != nil {
			return err
		}
		out = syntheticCompactionSignal{e, id, scope.id, generation}
		return nil
	})
	if err != nil {
		return syntheticCompactionSignal{}, err
	}
	return out, nil
}
func (a *DisclosureAdministration) applySyntheticCompaction(ctx context.Context, signal syntheticCompactionSignal) error {
	if a == nil || a.engine == nil || signal.engine != a.engine {
		return failure("compaction_adapter_unavailable")
	}
	e := a.engine
	return e.store.writeMode(ctx, true, func() error {
		if err := e.checkAuthority(ctx); err != nil {
			return err
		}
		var scope, kind string
		var generation int64
		var consumed bool
		if err := e.store.conn.QueryRowContext(ctx, "SELECT scope,generation,kind,consumed FROM synthetic_compaction_signal WHERE id=?", signal.id).Scan(&scope, &generation, &kind, &consumed); err != nil {
			return failure("compaction_adapter_unavailable")
		}
		if scope != signal.scope || generation != signal.generation || kind != "owner-fixture" {
			return failure("compaction_adapter_unavailable")
		}
		if consumed {
			return nil
		}
		if generation == math.MaxInt64 {
			return failure("ordinal_limit")
		}
		result, err := e.store.conn.ExecContext(ctx, "UPDATE local_scope SET generation=generation+1 WHERE id=? AND generation=?", scope, generation)
		if err != nil {
			return failure("storage_error")
		}
		n, _ := result.RowsAffected()
		if n != 1 {
			return failure("stale_scope")
		}
		if _, err = e.store.conn.ExecContext(ctx, "UPDATE synthetic_compaction_signal SET consumed=1 WHERE id=?", signal.id); err != nil {
			return failure("storage_error")
		}
		if _, err = e.store.conn.ExecContext(ctx, "UPDATE query_cursor SET state='expired' WHERE selection IN(SELECT id FROM query_selection WHERE scope=?)", scope); err != nil {
			return failure("storage_error")
		}
		return e.store.bump(ctx)
	})
}
