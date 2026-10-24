package mcp_test

import (
	"context"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/ipc"
	mcp "github.com/Telara-Labs/telara-memory/contract/internal/node/mcp/internal/fixture"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/mcp/internal/teststore"
	"github.com/Telara-Labs/telara-memory/contract/record"
	"testing"
)

func native(id string) mcp.Native {
	return mcp.Native{Client: "fixture", ID: id, Kind: "local", Origin: "local"}
}
func TestPerRequestIdentityPrecedenceAndRotation(t *testing.T) {
	p := ipc.Proc{PID: 123, StartMS: 1000}
	n := native("first")
	s := &teststore.Source{Access: teststore.Access(), Signals: []mcp.Announcement{{Native: n, Ancestor: p}}}
	r := mcp.IdentityResolver{Source: s, LegacySupported: true}
	h := ipc.Hello{Client: "ignored-clientInfo", Shim: "shim", Ancestry: []ipc.Proc{p}}
	a, e := r.Resolve(context.Background(), h, mcp.Metadata{Legacy: "old"})
	if e != nil || a.Confidence != "process-matched" || a.SessionKey == "" || s.Drains != 1 {
		t.Fatal(a, e)
	}
	first := a.SessionKey
	s.Signals = []mcp.Announcement{{Native: native("second"), Ancestor: p}}
	a, e = r.Resolve(context.Background(), h, mcp.Metadata{})
	if e != nil || a.SessionKey == first {
		t.Fatal("old scope transferred", a, e)
	}
	explicit := native("explicit")
	a, e = r.Resolve(context.Background(), h, mcp.Metadata{Native: &explicit, Handle: "handle"})
	if e != nil || a.Confidence != "stated" || !a.Disagreement {
		t.Fatal(a, e)
	}
	a, e = r.Resolve(context.Background(), h, mcp.Metadata{Handle: "handle"})
	if e != nil || a.Confidence != "handle-only" || a.SessionKey != "" {
		t.Fatal(a, e)
	}
	// A reused PID with a different start time is not an ancestry match.
	h.Ancestry = []ipc.Proc{{PID: 123, StartMS: 2000}}
	a, e = r.Resolve(context.Background(), h, mcp.Metadata{Legacy: "old"})
	if e != nil || a.Confidence != "inferred" || a.SessionKey != "" {
		t.Fatal("PID reused", a, e)
	}
	h.Ancestry = []ipc.Proc{p}
	s.Dead = map[ipc.Proc]bool{p: true}
	a, e = r.Resolve(context.Background(), h, mcp.Metadata{})
	if e != nil || a.SessionKey != "" {
		t.Fatal("dead announcement", a, e)
	}
	s.Dead = nil
	s.Signals = nil
	a, e = r.Resolve(context.Background(), ipc.Hello{}, mcp.Metadata{})
	if e != nil || a.ScopeID != "" || a.SessionKey != "" {
		t.Fatal("anonymous state restored", a, e)
	}
	// Global identities omit machine id, local identities include it.
	x, _ := record.SessionKey("fixture", "local", "global", taskID, teststore.Machine)
	y, _ := record.SessionKey("fixture", "local", "global", taskID, "22345678-1234-4234-8234-123456789abc")
	if x != y {
		t.Fatal("global key machine-scoped")
	}
}
func TestIdentityAmbiguityMalformedAndSpoolLag(t *testing.T) {
	p := ipc.Proc{PID: 123, StartMS: 1000}
	s := &teststore.Source{Access: teststore.Access(), Signals: []mcp.Announcement{{Native: native("a"), Ancestor: p}, {Native: native("b"), Ancestor: p}}}
	r := mcp.IdentityResolver{Source: s, LegacySupported: true}
	h := ipc.Hello{Shim: "shared", Ancestry: []ipc.Proc{p}}
	a, e := r.Resolve(context.Background(), h, mcp.Metadata{Legacy: "old"})
	if e != nil || !a.Ambiguous || a.SessionKey != "" {
		t.Fatal("ambiguous bound", a, e)
	}
	for _, m := range []mcp.Metadata{{Handle: "bad handle"}, {Legacy: "bad\nlegacy"}, {OpID: "bad/op"}, {Native: &mcp.Native{Client: "fixture", ID: "notuuid", Kind: "global", Origin: "local"}}, {Native: &mcp.Native{Client: "fixture", ID: "x", Kind: "local", Origin: "bad"}}, {Native: &mcp.Native{Client: "other", ID: "x", Kind: "local", Origin: "local"}}} {
		if _, e = r.Resolve(context.Background(), h, m); e == nil {
			t.Fatal("malformed identity fallback", m)
		}
	}
	s.DrainError = true
	if _, e = r.Resolve(context.Background(), h, mcp.Metadata{}); e == nil {
		t.Fatal("spool failure silently stale")
	}
	if _, e = (mcp.IdentityResolver{}).Resolve(context.Background(), h, mcp.Metadata{}); e == nil {
		t.Fatal("missing credential source")
	}
	s.DrainError = false
	s.Access.CredentialID = ""
	if _, e = r.Resolve(context.Background(), h, mcp.Metadata{}); e == nil {
		t.Fatal("clientInfo was credential")
	}
}
