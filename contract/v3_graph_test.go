package contract_test

import (
	"encoding/json"
	"github.com/Telara-Labs/hilo/contract/invalidate"
	"github.com/Telara-Labs/hilo/contract/record"
	"github.com/Telara-Labs/hilo/contract/sig"
	"testing"
)

func TestV3SignedCommitmentGraph(t *testing.T) {
	var f struct {
		Args, Result any
		Records      []struct {
			Name, ID  string
			HeaderJCS string `json:"header_jcs"`
			BodyJCS   string `json:"body_jcs"`
			Signature record.Signature
		}
	}
	if err := json.Unmarshal(mustRead(t, "testdata/oracle-history/v3/commitment-graph.json"), &f); err != nil {
		t.Fatal(err)
	}
	kr := sig.NewKeyring("")
	rs := map[string]*record.Record{}
	owner := ""
	for _, wire := range f.Records {
		r, err := record.Parse([]byte(wire.HeaderJCS), []byte(wire.BodyJCS), wire.ID)
		if err != nil {
			t.Fatal(wire.Name, err)
		}
		rs[wire.Name] = r
		if r.Header.Type == record.KindKeyOp {
			b := r.Body.(*record.KeyOpBody)
			if got := sig.VerifyKeyOp(kr, &sig.KeyOp{Rec: r, Body: b, Sigs: []record.Signature{wire.Signature}}); got.Status != sig.OpAuthorized {
				t.Fatal(got)
			}
			owner = b.Subject.KeyID
			continue
		}
		if got := sig.VerifyRecord(r, []record.Signature{wire.Signature}, kr.State(), sig.Context{Route: record.RouteBundleImport}); got.Status != sig.StatusVerified {
			t.Fatal(wire.Name, got)
		}
	}
	c := rs["call"]
	b := c.Body.(*record.CallBody)
	cp := rs["checkpoint"]
	erasure := rs["erasure"]
	if len(b.CommitmentDeps) != 1 || b.CommitmentDeps[0] != cp.ID {
		t.Fatal("signed mutation root")
	}
	ah, err := record.CallCommitment(b.Salt, "args", b.Tool, mustJSONV3(t, f.Args))
	if err != nil || ah != b.ArgsHash {
		t.Fatal("args fixture", err)
	}
	rh, err := record.CallCommitment(b.Salt, "result", b.Tool, mustJSONV3(t, f.Result))
	if err != nil || rh != b.ResultHash {
		t.Fatal("result fixture", err)
	}
	for _, order := range [][]int{{0, 1, 2}, {2, 1, 0}, {1, 2, 0}} {
		m := invalidate.NewModel()
		for _, n := range order {
			switch n {
			case 0:
				m.Admit(invalidate.Item{ID: cp.ID, Kind: cp.Header.Type, Owner: owner})
			case 1:
				m.Admit(invalidate.Item{ID: c.ID, Kind: record.KindCall, Owner: owner, Deps: c.Header.Links.DerivedFrom})
			case 2:
				if err := m.Apply(invalidate.Control{ID: erasure.ID, Kind: record.KindErasure, Owner: owner, Erasure: erasure.Body.(*record.ErasureBody)}); err != nil {
					t.Fatal(err)
				}
			}
		}
		if m.Evaluate().StatusOf(c.ID) != invalidate.Invalidated {
			t.Fatal("exact source erasure lost call-key closure", order)
		}
	}
	// A bodyless receipt never restores the secret or an empty dependency set.
	gone := c.WithoutBody()
	if gone.Body != nil || gone.BodyJCS != nil {
		t.Fatal("call key survived body purge")
	}
	for _, guess := range []any{f.Args, map[string]any{"milestone": "different"}} {
		if _, err := record.CallCommitment("", "args", b.Tool, mustJSONV3(t, guess)); err == nil {
			t.Fatal("keyless candidate comparison")
		}
	}
}

func mustJSONV3(t *testing.T, v any) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
