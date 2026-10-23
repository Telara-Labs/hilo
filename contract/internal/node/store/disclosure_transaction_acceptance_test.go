package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"
)

func disclosureTransactionState(t *testing.T, k *kernelWorld) map[string]string {
	t.Helper()
	ctx := context.Background()
	out := map[string]string{}
	for _, table := range []string{"record", "record_body", "operation", "outcome_member", "exposure", "exposure_affect", "render_attempt", "render_body", "delivery_confirmation", "attempt_ack", "projection_count_snapshot", "query_selection", "selection_item", "selection_payload", "query_cursor", "client_credential", "admin_outcome", "client_grant_repo", "client_grant_channel", "client_task_write", "client_task_write_repo", "local_scope", "task_write_scope", "record_observed_taint", "record_taint_evidence", "field_completeness", "record_field_projection", "projection_job", "vector", "passage"} {
		var n int64
		if err := k.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM "+table).Scan(&n); err != nil {
			t.Fatal(err)
		}
		out[table] = fmt.Sprint(n)
		rows, err := k.s.conn.QueryContext(ctx, "SELECT * FROM "+table+" ORDER BY rowid")
		if err != nil {
			t.Fatal(err)
		}
		columns, err := rows.Columns()
		if err != nil {
			t.Fatal(err)
		}
		hash := sha256.New()
		for rows.Next() {
			values := make([]any, len(columns))
			dest := make([]any, len(columns))
			for i := range values {
				dest[i] = &values[i]
			}
			if err := rows.Scan(dest...); err != nil {
				t.Fatal(err)
			}
			raw, err := json.Marshal(values)
			if err != nil {
				t.Fatal(err)
			}
			hash.Write(raw)
			hash.Write([]byte{0})
			clear(raw)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			t.Fatal(err)
		}
		out[table+"/contents"] = hex.EncodeToString(hash.Sum(nil))
	}
	for _, field := range []string{"generation", "next_seq", "authority_epoch"} {
		var n int64
		if err := k.s.conn.QueryRowContext(ctx, "SELECT "+field+" FROM meta").Scan(&n); err != nil {
			t.Fatal(err)
		}
		out[field] = fmt.Sprint(n)
	}
	return out
}
func requireSameDisclosureState(t *testing.T, k *kernelWorld, before map[string]string) {
	t.Helper()
	for key, n := range disclosureTransactionState(t, k) {
		if before[key] != n {
			t.Fatal("partial transaction changed private table or counter", key)
		}
	}
}
func installDisclosureFault(t *testing.T, k *kernelWorld, event, table string, commit bool) {
	t.Helper()
	ctx := context.Background()
	if commit {
		for _, q := range []string{"CREATE TABLE phase_parent(id INTEGER PRIMARY KEY)", "CREATE TABLE phase_child(id INTEGER REFERENCES phase_parent(id) DEFERRABLE INITIALLY DEFERRED)", "CREATE TRIGGER phase_fault AFTER " + event + " ON " + table + " BEGIN INSERT INTO phase_child VALUES(999); END"} {
			if _, err := k.s.conn.ExecContext(ctx, q); err != nil {
				t.Fatal(err)
			}
		}
	} else {
		if _, err := k.s.conn.ExecContext(ctx, "CREATE TRIGGER phase_fault BEFORE "+event+" ON "+table+" BEGIN SELECT RAISE(ABORT,'private phase failure'); END"); err != nil {
			t.Fatal(err)
		}
	}
}
func reopenDisclosureKernel(t *testing.T, k *kernelWorld) {
	t.Helper()
	ctx := context.Background()
	k.e.Close()
	k.s.Close()
	s, err := Open(ctx, k.o)
	if err != nil {
		t.Fatal(err)
	}
	k.s = s
	material, err := PreloadDisclosureAuthority(bytes.Repeat([]byte{9}, 32), k.key)
	if err != nil {
		t.Fatal(err)
	}
	k.e, err = NewDisclosureEngine(ctx, s, material, DisclosureConfig{OwnerGenesis: k.o.PinnedGenesisID, MachineID: testMachine, MaxReplyBytes: 16384})
	if err != nil {
		t.Fatal(err)
	}
	k.a, err = k.e.Administration(ctx)
	if err != nil {
		t.Fatal(err)
	}
	k.h, err = k.e.Authenticate(ctx, k.proof)
	if err != nil {
		t.Fatal(err)
	}
	k.sc, err = k.e.Resolve(ctx, k.h, IdentityInput{ConversationHandle: "kernel-conversation"})
	if err != nil {
		t.Fatal(err)
	}
}
func TestDisclosureTransactionPhaseFailuresNeverReleasePartialAuthority(t *testing.T) {
	cases := []struct{ name, event, table string }{{"register", "INSERT", "admin_outcome"}, {"rotate", "UPDATE", "client_credential"},
		{"replace_grant", "DELETE", "client_grant_channel"},
		{"replace_writes", "DELETE", "client_task_write"},
		{"revoke", "UPDATE", "client_credential"},
		{"resolve", "INSERT", "local_scope"},
		{"grant_render_cleanup", "DELETE", "render_body"}, {"release", "INSERT", "render_attempt"}, {"ack", "INSERT", "attempt_ack"}, {"next", "UPDATE", "query_cursor"}, {"count", "INSERT", "projection_count_snapshot"}}
	for _, c := range cases {
		for _, commit := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/commit=%v", c.name, commit), func(t *testing.T) {
				k := newKernel(t)
				ctx := context.Background()
				var reply CommittedReplyHandle
				var ack ACK
				var cursor string
				if c.name == "register" || c.name == "rotate" || c.name == "replace_grant" || c.name == "replace_writes" || c.name == "revoke" || c.name == "resolve" || c.name == "grant_render_cleanup" {
					seed := k.execute("phase-existing-render", "local.create_task", map[string]any{"goal": "existing rendered authority"})
					k.release(seed)
				}
				if c.name == "release" || c.name == "ack" {
					reply = k.execute("phase-task", "local.create_task", map[string]any{"goal": "phase authority"})
					if c.name == "ack" {
						k.release(reply)
						var attempt string
						k.s.conn.QueryRowContext(ctx, "SELECT id,nonce FROM render_attempt WHERE op=? ORDER BY db_generation DESC LIMIT 1", reply.op).Scan(&attempt, &ack.Nonce)
						rows, err := k.s.conn.QueryContext(ctx, "SELECT lid,id FROM render_item WHERE attempt=?", attempt)
						if err != nil {
							t.Fatal(err)
						}
						for rows.Next() {
							var m ItemMarker
							rows.Scan(&m.LID, &m.ID)
							ack.Items = append(ack.Items, m)
						}
						rows.Close()
					}
				}
				if c.name == "next" || c.name == "count" {
					task := k.execute("seed", "local.create_task", map[string]any{"goal": "phase seed"})
					id := k.taskID(task)
					for i := 0; i < 2; i++ {
						k.execute(fmt.Sprint("step", i), "local.checkpoint_task", map[string]any{"task_id": id, "milestone": "phase_search_canary"})
					}
					if c.name == "next" {
						search := k.execute("phase-search", "local.lexical_search", map[string]any{"query": "phase_search_canary", "resource_types": []string{"checkpoint"}, "limit": 1})
						k.release(search)
						k.s.conn.QueryRowContext(ctx, "SELECT cursor FROM outcome_continuation WHERE op=?", search.op).Scan(&cursor)
					}
				}
				before := disclosureTransactionState(t, k)
				var priorVerifier []byte
				k.s.conn.QueryRowContext(ctx, "SELECT verifier FROM client_credential WHERE id=?", k.proof.CredentialID).Scan(&priorVerifier)
				installDisclosureFault(t, k, c.event, c.table, commit)
				var err error
				switch c.name {
				case "register":
					var r RegisteredClient
					r, err = k.a.Register(ctx, RegisterClient{AdminOpID: "phase-register", ClientName: "Phase fixture", ReadGrant: Grant{Repos: AllLocalRepos(), Channels: []Channel{S}}})
					if r.Secret != nil || r.CredentialID != "" {
						t.Fatal("uncommitted credential escaped")
					}
				case "rotate":
					var r RegisteredClient
					r, err = k.a.RotateCredential(ctx, "phase-rotate", k.proof.CredentialID, 1)
					if r.Secret != nil || r.CredentialID != "" {
						t.Fatal("uncommitted rotated secret escaped")
					}
				case "replace_grant", "grant_render_cleanup":
					repos, er := ConcreteRepos([]string{"r1:" + fmt.Sprintf("%064x", 3)})
					if er != nil {
						t.Fatal(er)
					}
					var r GrantReceipt
					r, err = k.a.ReplaceGrant(ctx, "phase-grant", k.proof.CredentialID, 1, Grant{Repos: repos, Channels: []Channel{S, P}})
					if r.CredentialID != "" {
						t.Fatal("uncommitted grant receipt escaped")
					}
				case "replace_writes":
					var r GrantReceipt
					r, err = k.a.ReplaceTaskWrites(ctx, "phase-writes", k.proof.CredentialID, 1, TaskWriteGrant{Actions: []TaskMutation{Pause}, Repos: AllLocalRepos(), AllowUnscoped: true})
					if r.CredentialID != "" {
						t.Fatal("uncommitted write grant escaped")
					}
				case "revoke":
					var r GrantReceipt
					r, err = k.a.RevokeCredential(ctx, "phase-revoke", k.proof.CredentialID, 1)
					if r.CredentialID != "" {
						t.Fatal("uncommitted revoke escaped")
					}
				case "resolve":
					var r ScopeHandle
					r, err = k.e.Resolve(ctx, k.h, IdentityInput{ConversationHandle: "phase-new-conversation"})
					if r.engine != nil {
						t.Fatal("uncommitted scope escaped")
					}
				case "release":
					var r ReleasedText
					r, err = k.e.Release(ctx, k.h, reply)
					if r.Text() != "" {
						t.Fatal("uncommitted source escaped")
					}
				case "ack":
					var r ACKReceipt
					r, err = k.e.Acknowledge(ctx, k.h, ack)
					if r.Status != "" {
						t.Fatal("uncommitted ACK escaped")
					}
				case "next":
					var r CommittedReplyHandle
					r, err = k.e.Next(ctx, k.h, k.sc, CallIdentity{SuppliedOpID: "phase-next"}, cursor, ByteBudget{MaxBytes: 4096})
					if r.engine != nil {
						t.Fatal("uncommitted cursor/page escaped")
					}
				case "count":
					var r CommittedReplyHandle
					r, err = k.e.Execute(ctx, k.h, k.sc, CallIdentity{SuppliedOpID: "phase-count"}, commandFor(t, "local.lexical_search", map[string]any{"query": "phase_search_canary", "resource_types": []string{"checkpoint"}}), ByteBudget{MaxBytes: 4096})
					if r.engine != nil {
						t.Fatal("uncommitted count/page escaped")
					}
				}
				want := "storage_error"
				if commit {
					want = "outcome_unknown"
				}
				if Code(err) != want {
					t.Fatal("incorrect settlement", c.name, err)
				}
				requireSameDisclosureState(t, k, before)
				var afterVerifier []byte
				k.s.conn.QueryRowContext(ctx, "SELECT verifier FROM client_credential WHERE id=?", k.proof.CredentialID).Scan(&afterVerifier)
				if !bytes.Equal(priorVerifier, afterVerifier) {
					t.Fatal("failed credential rotation changed current auth")
				}
				if commit {
					if _, err = k.e.Authenticate(ctx, k.proof); Code(err) != "outcome_unknown" {
						t.Fatal("unknown settlement handle still usable", err)
					}
					reopenDisclosureKernel(t, k)
				}
				if _, err = k.s.conn.ExecContext(ctx, "DROP TRIGGER phase_fault"); err != nil {
					t.Fatal(err)
				}
				if c.name == "ack" {
					if r, err := k.e.Acknowledge(ctx, k.h, ack); err != nil || r.Status != "confirmed" {
						t.Fatal("rollback consumed ACK", r, err)
					}
				}
				if c.name == "next" {
					var state string
					k.s.conn.QueryRowContext(ctx, "SELECT state FROM query_cursor WHERE id=?", cursor).Scan(&state)
					if state != "ready" {
						t.Fatal("rollback consumed input cursor", state)
					}
					if !commit {
						if _, err = k.e.Next(ctx, k.h, k.sc, CallIdentity{SuppliedOpID: "phase-next"}, cursor, ByteBudget{MaxBytes: 4096}); err != nil {
							t.Fatal("known rollback blocked safe Next retry", err)
						}
					} else {
						if _, err = k.e.Next(ctx, k.h, k.sc, CallIdentity{SuppliedOpID: "phase-next"}, cursor, ByteBudget{MaxBytes: 4096}); Code(err) != "cursor_expired" {
							t.Fatal("new engine revived monotonic cursor", err)
						}
					}
				}
			})
		}
	}
}
