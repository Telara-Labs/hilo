package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"

	"github.com/Telara-Labs/telara-memory/contract/record"
)

// Wire correlation exists only for the active connection. It is never hashed,
// logged, transferred, or retained in settlement. Receiver tokens are random.
type liveClient struct {
	rpc       map[string]string
	ephemeral bool
}

func receiptTool(tool string) string {
	switch tool {
	case "local.create_task":
		return "telara_task_create"
	case "local.checkpoint_task":
		return "telara_task_checkpoint"
	case "local.pause_task":
		return "telara_task_pause"
	case "local.complete_task":
		return "telara_task_complete"
	case "local.resume_task":
		return "telara_task_resume"
	case "local.list_tasks":
		return "telara_task_list"
	case "local.lookup_record":
		return "telara_get_context"
	case "local.lexical_search", "local.next_page":
		return "telara_knowledge_search"
	}
	return ""
}

// IssueOperationTokens is a trusted initialize seam. Only committed, credential
// bound tokens may be returned to a client; callers cannot bring their own entropy.
func (e *DisclosureEngine) IssueOperationTokens(ctx context.Context, h ClientHandle) ([]string, error) {
	var out []string
	if e == nil || e.store == nil {
		return nil, failure("unauthorized")
	}
	err := e.store.write(ctx, func() error {
		if _, err := e.client(ctx, h); err != nil {
			return err
		}
		pool, err := e.operationTokens(ctx, h.credential)
		if err != nil {
			return err
		}
		out, err = pool.Issue(h.credential)
		if err != nil {
			return failure("entropy_unavailable")
		}
		for _, r := range pool.Snapshot() {
			var credential string
			var consumed bool
			err = e.store.conn.QueryRowContext(ctx, "SELECT credential,consumed FROM operation_token WHERE token=?", r.Token).Scan(&credential, &consumed)
			if err == nil {
				if credential != r.Credential || consumed {
					return failure("entropy_collision")
				}
				continue
			}
			if err != sql.ErrNoRows {
				return failure("storage_error")
			}
			if _, err = e.store.conn.ExecContext(ctx, "INSERT INTO operation_token VALUES(?,?,?)", r.Token, r.Credential, boolInt(r.Consumed)); err != nil {
				return failure("storage_error")
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
func (e *DisclosureEngine) operationTokens(ctx context.Context, credential string) (*record.OperationTokens, error) {
	rows, err := e.store.conn.QueryContext(ctx, "SELECT token,credential,consumed FROM operation_token WHERE credential=? AND consumed=0 LIMIT 129", credential)
	if err != nil {
		return nil, failure("storage_error")
	}
	defer rows.Close()
	var entries []record.IssuedOperationToken
	for rows.Next() {
		var r record.IssuedOperationToken
		if rows.Scan(&r.Token, &r.Credential, &r.Consumed) != nil {
			return nil, failure("storage_error")
		}
		entries = append(entries, r)
	}
	if rows.Err() != nil {
		return nil, failure("storage_error")
	}
	p, err := record.RestoreOperationTokens(entries)
	if err != nil {
		return nil, failure("corrupt_database")
	}
	return p, nil
}
func (e *DisclosureEngine) suppliedOperation(ctx context.Context, h ClientHandle, token string) (string, error) {
	var credential string
	if err := e.store.conn.QueryRowContext(ctx, "SELECT credential FROM operation_token WHERE token=?", token).Scan(&credential); err != nil {
		if err != sql.ErrNoRows {
			return "", failure("storage_error")
		}
		return "", failure("unissued_operation")
	}
	if credential != h.credential {
		return "", failure("unissued_operation")
	}
	// Restore one authenticated local-ledger row, never a client snapshot.
	p, err := record.RestoreOperationTokens([]record.IssuedOperationToken{{Token: token, Credential: credential}})
	if err != nil {
		return "", failure("corrupt_database")
	}
	op, err := p.Resolve(credential, token)
	if err != nil {
		return "", failure("unissued_operation")
	}
	return op, nil
}
func (e *DisclosureEngine) fallbackOperation(h ClientHandle, sc scopeState, rpc []byte, tool string) (string, error) {
	live := e.clients[h.connection]
	if live == nil {
		return "", failure("unauthorized")
	}
	token := live.rpc[string(rpc)]
	if token == "" {
		if len(live.rpc) >= 4096 {
			return "", failure("request_limit")
		}
		var b [16]byte
		if _, err := rand.Read(b[:]); err != nil {
			return "", failure("entropy_unavailable")
		}
		token = hex.EncodeToString(b[:])
		clear(b[:])
		live.rpc[string(rpc)] = token
	}
	op, err := record.FallbackOpID(h.credential, sc.id, h.connection, token, receiptTool(tool))
	if err != nil {
		return "", failure("unsafe_identity")
	}
	return op, nil
}

func (e *DisclosureEngine) retireEphemeral(h ClientHandle) {
	e.store.mu.Lock()
	live := e.clients[h.connection]
	retire := live != nil && live.ephemeral
	e.store.mu.Unlock()
	if retire {
		e.CloseClient(h)
	}
}
