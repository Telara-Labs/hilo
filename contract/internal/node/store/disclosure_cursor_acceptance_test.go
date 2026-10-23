package store

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

func cursorAcceptance(t *testing.T) (*kernelWorld, CommittedReplyHandle, string) {
	t.Helper()
	k := newKernel(t)
	ctx := context.Background()
	root := k.execute("cursor-root", "local.create_task", map[string]any{"goal": "cursor root"})
	task := k.taskID(root)
	for i := 0; i < 3; i++ {
		k.execute(fmt.Sprint("cursor-step", i), "local.checkpoint_task", map[string]any{"task_id": task, "milestone": "cursor_lifetime_source"})
	}
	r := k.execute("cursor-search", "local.lexical_search", map[string]any{"query": "cursor_lifetime_source", "resource_types": []string{"checkpoint"}, "limit": 1})
	var cursor string
	if err := k.s.conn.QueryRowContext(ctx, "SELECT cursor FROM outcome_continuation WHERE op=?", r.op).Scan(&cursor); err != nil {
		t.Fatal(err)
	}
	return k, r, cursor
}
func TestDisclosureCursorUnrelatedWriteAndMonotonicLeaseRefuse(t *testing.T) {
	for _, change := range []string{"unrelated_write", "elapsed_monotonic", "missing_deadline"} {
		t.Run(change, func(t *testing.T) {
			k, r, cursor := cursorAcceptance(t)
			ctx := context.Background()
			switch change {
			case "unrelated_write":
				k.append(k.task(4400, "independent ordinary source"))
			case "elapsed_monotonic":
				k.s.mu.Lock()
				for id := range k.e.deadlines {
					k.e.deadlines[id] = time.Now().Add(-time.Second)
				}
				k.s.mu.Unlock()
			case "missing_deadline":
				k.s.mu.Lock()
				clear(k.e.deadlines)
				k.s.mu.Unlock()
			}
			text := k.release(r)
			if !strings.Contains(text, "cursor") || !strings.Contains(text, "expired") {
				t.Fatal("invalid continuation appeared usable", text)
			}
			var state string
			k.s.conn.QueryRowContext(ctx, "SELECT state FROM query_cursor WHERE id=?", cursor).Scan(&state)
			if state != "expired" {
				t.Fatal("expired cursor silently rebased", state)
			}
			if _, err := k.e.Next(ctx, k.h, k.sc, CallIdentity{SuppliedOpID: "expired-next"}, cursor, ByteBudget{MaxBytes: 4096}); Code(err) != "cursor_expired" {
				t.Fatal(err)
			}
		})
	}
}
func TestDisclosureConcurrentNextAndFallbackIdentity(t *testing.T) {
	t.Run("single_winner", func(t *testing.T) {
		k, r, cursor := cursorAcceptance(t)
		k.release(r)
		ctx := context.Background()
		var wg sync.WaitGroup
		codes := make([]string, 2)
		for i := range codes {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				_, err := k.e.Next(ctx, k.h, k.sc, CallIdentity{SuppliedOpID: fmt.Sprint("concurrent-next", i)}, cursor, ByteBudget{MaxBytes: 4096})
				codes[i] = Code(err)
			}(i)
		}
		wg.Wait()
		if !((codes[0] == "" && codes[1] == "cursor_consumed") || (codes[1] == "" && codes[0] == "cursor_consumed")) {
			t.Fatal("cursor had two winners", codes)
		}
	})
	t.Run("live_fallback_retry_reconnect_limit", func(t *testing.T) {
		k, r, cursor := cursorAcceptance(t)
		k.release(r)
		ctx := context.Background()
		call := CallIdentity{JSONRPCID: []byte(`73`)}
		first, err := k.e.Next(ctx, k.h, k.sc, call, cursor, ByteBudget{MaxBytes: 4096})
		if err != nil {
			t.Fatal(err)
		}
		second, err := k.e.Next(ctx, k.h, k.sc, call, cursor, ByteBudget{MaxBytes: 4096})
		if err != nil || first.op != second.op {
			t.Fatal("same live fallback resealed", err)
		}
		newer, err := k.e.Authenticate(ctx, k.proof)
		if err != nil {
			t.Fatal(err)
		}
		sc, err := k.e.Resolve(ctx, newer, IdentityInput{ConversationHandle: "kernel-conversation"})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = k.e.Next(ctx, newer, sc, call, cursor, ByteBudget{MaxBytes: 4096}); Code(err) != "cursor_consumed" {
			t.Fatal("reconnect fallback inherited live connection op", err)
		}
		if _, err = k.e.Next(ctx, k.h, k.sc, CallIdentity{SuppliedOpID: "cursor-search"}, cursor, ByteBudget{MaxBytes: 4096}); Code(err) != "op_conflict" {
			t.Fatal("Next reused search operation identity", err)
		}
	})
}
func TestDisclosureACKRejectsWrongNonceCredentialAndNonexactSet(t *testing.T) {
	k := newKernel(t)
	ctx := context.Background()
	r := k.execute("ack-source", "local.create_task", map[string]any{"goal": "ACK exact source"})
	k.release(r)
	var ack ACK
	var attempt string
	k.s.conn.QueryRowContext(ctx, "SELECT id,nonce FROM render_attempt WHERE op=? ORDER BY db_generation DESC LIMIT 1", r.op).Scan(&attempt, &ack.Nonce)
	rows, err := k.s.conn.QueryContext(ctx, "SELECT lid,id FROM render_item WHERE attempt=?", attempt)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var item ItemMarker
		rows.Scan(&item.LID, &item.ID)
		ack.Items = append(ack.Items, item)
	}
	rows.Close()
	other, err := k.a.Register(ctx, RegisterClient{AdminOpID: "ack-second-client", ClientName: "Other ACK client", ReadGrant: Grant{Repos: AllLocalRepos(), Channels: []Channel{S}}})
	if err != nil {
		t.Fatal(err)
	}
	token, err := other.Secret.Take()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(token)
	h, err := k.e.Authenticate(ctx, CredentialProof{other.CredentialID, token})
	if err != nil {
		t.Fatal(err)
	}
	variants := []struct {
		name string
		h    ClientHandle
		a    ACK
	}{{"unknown_nonce", k.h, ACK{Nonce: "00000000000000000000", Items: ack.Items}}, {"other_credential", h, ack}, {"duplicate_item", k.h, ACK{Nonce: ack.Nonce, Items: append(append([]ItemMarker(nil), ack.Items...), ack.Items[0])}}, {"extra_item", k.h, ACK{Nonce: ack.Nonce, Items: append(append([]ItemMarker(nil), ack.Items...), ItemMarker{strings.Repeat("a", 64), strings.Repeat("b", 64)})}}}
	for _, v := range variants {
		if _, err = k.e.Acknowledge(ctx, v.h, v.a); Code(err) != "invalid_ack" {
			t.Fatal(v.name, err)
		}
	}
	var n int
	k.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM attempt_ack WHERE attempt=?", attempt).Scan(&n)
	if n != 0 {
		t.Fatal("forged ACK wrote confirmation")
	}
	if _, err = k.a.RotateCredential(ctx, "rotate-before-ack", k.proof.CredentialID, 1); err != nil {
		t.Fatal(err)
	}
	if _, err = k.e.Acknowledge(ctx, k.h, ack); Code(err) != "unauthorized" {
		t.Fatal("stale credential confirmed delivery", err)
	}
}
