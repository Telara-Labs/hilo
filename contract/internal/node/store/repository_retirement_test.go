package store

import (
	"errors"
	"fmt"
	"testing"

	"github.com/Telara-Labs/hilo/contract/record"
	"github.com/Telara-Labs/hilo/contract/sig"
)

func TestRepositoryRetirementClosureBoundsAndOwnerEdges(t *testing.T) {
	const owner = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	seed := record.H("closure-seed")
	for _, mode := range []string{"deep-limit", "wide-limit", "deep-allowed", "work-limit", "foreign", "historical-signer", "cycle"} {
		t.Run(mode, func(t *testing.T) {
			var records []*stored
			count := 8192
			if mode == "deep-allowed" {
				count = 8191
			}
			if mode == "work-limit" || mode == "foreign" || mode == "historical-signer" || mode == "cycle" {
				count = 3
			}
			parent := seed
			for i := 0; i < count; i++ {
				id := record.H("closure-child", fmt.Sprint(i))
				if mode == "wide-limit" {
					parent = seed
				}
				records = append(records, &stored{owner: owner, rec: &record.Record{ID: id, Header: record.Header{Type: record.KindDigest}}, deps: []string{parent}, sigStatus: sig.StatusVerified})
				parent = id
			}
			budget := newReductionContext()
			if mode == "work-limit" {
				budget.work = reductionWorkLimit - 1
			}
			if mode == "foreign" {
				records[0].owner = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
			}
			if mode == "historical-signer" {
				records[0].sigStatus = sig.StatusSignerRevoked
			}
			if mode == "cycle" {
				records[0].deps = append(records[0].deps, records[len(records)-1].rec.ID)
			}
			got, err := repositoryRetirementClosure(records, map[string]bool{seed: true}, owner, budget)
			switch mode {
			case "deep-limit", "wide-limit":
				if Code(err) != "repository_binding_limit" || got != nil {
					t.Fatal("oversized closure escaped bounded refusal", len(got), err)
				}
			case "work-limit":
				if _, ok := err.(*projectionLimit); !ok || got != nil {
					t.Fatal("work bound allocated graph", err)
				}
			case "foreign":
				if err != nil || len(got) != 1 || got[0] != seed {
					t.Fatal("cross-owner dependency became a retirement target", got, err)
				}
			default:
				if err != nil || len(got) != count+1 {
					t.Fatal("bounded owned closure", len(got), err)
				}
			}
		})
	}
}

type repositoryInterruptedSigner struct {
	worldSigner
	remaining int
}

func (s *repositoryInterruptedSigner) SignRecordID(id string) (record.Signature, error) {
	if s.remaining == 0 {
		return record.Signature{}, errors.New("synthetic_signer_failure")
	}
	s.remaining--
	return s.worldSigner.SignRecordID(id)
}
