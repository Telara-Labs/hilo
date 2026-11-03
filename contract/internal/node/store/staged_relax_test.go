package store

import (
	"testing"

	"github.com/Telara-Labs/hilo/contract/record"
)

// Only a successor at least as restrictive everywhere is not a relaxation.
func TestPolicyRelaxesComparesEveryAuthorityField(t *testing.T) {
	head := record.PolicyBody{NotAfter: 100, Applies: record.PolicyApplies{Users: []string{"u"}}, Kill: record.PolicyKill{Sync: true, CaptureTenantRepos: true, WithdrawPulled: true}, BlockedRepos: []record.BlockedRepo{{RemoteGlob: "a/*", Effect: "no-push"}}, Redaction: record.PolicyRedact{MinEpoch: 2, Shapes: []record.Shape{{Name: "s", RE2: "x"}}}, Push: record.PolicyPush{MaxProfile: record.ProfilePushMetadata, AllowRepos: []string{"r1"}, RequirePreview: true}, Readback: record.PolicyReadback{CloudPull: true}}
	tighter := head
	tighter.NotAfter = 90
	tighter.BlockedRepos = append([]record.BlockedRepo{{RemoteGlob: "b/*", Effect: "no-capture"}}, head.BlockedRepos...)
	tighter.Redaction.MinEpoch = 3
	tighter.Push.AllowRepos = nil
	tighter.Readback = record.PolicyReadback{}
	if policyRelaxes(&head, &tighter, "u") {
		t.Fatal("restriction reported as relaxation")
	}
	for name, mutate := range map[string]func(*record.PolicyBody){
		"not_after":       func(b *record.PolicyBody) { b.NotAfter = 101 },
		"kill_sync":       func(b *record.PolicyBody) { b.Kill.Sync = false },
		"kill_capture":    func(b *record.PolicyBody) { b.Kill.CaptureTenantRepos = false },
		"kill_withdraw":   func(b *record.PolicyBody) { b.Kill.WithdrawPulled = false },
		"blocked_repo":    func(b *record.PolicyBody) { b.BlockedRepos = nil },
		"min_epoch":       func(b *record.PolicyBody) { b.Redaction.MinEpoch = 1 },
		"shape":           func(b *record.PolicyBody) { b.Redaction.Shapes = nil },
		"require_preview": func(b *record.PolicyBody) { b.Push.RequirePreview = false },
		"allow_repo":      func(b *record.PolicyBody) { b.Push.AllowRepos = []string{"r1", "r2"} },
		"readback":        func(b *record.PolicyBody) { b.Readback.HookInjection = true },
	} {
		next := head
		next.Applies.Users = append([]string(nil), head.Applies.Users...)
		mutate(&next)
		if !policyRelaxes(&head, &next, "u") {
			t.Fatal("relaxation not detected:", name)
		}
	}
	other := head
	other.Applies.Users = []string{"v"}
	if !policyRelaxes(&other, &head, "u") || policyRelaxes(&head, &other, "u") {
		t.Fatal("applies comparison")
	}
	noPush := head
	noPush.Push.MaxProfile = ""
	if !policyRelaxes(&noPush, &head, "u") {
		t.Fatal("enabling push not detected")
	}
}
