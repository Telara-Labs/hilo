package syncnode

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func hostedInspectionTestBinding() HostedEnrollmentInspection {
	return HostedEnrollmentInspection{Version: 1, Origin: "https://example.invalid", Tenant: "0123456789abcdef0123456789abcdef", User: "11111111-1111-4111-8111-111111111111", Config: "22222222-2222-4222-8222-222222222222", BootstrapID: "33333333-3333-4333-8333-333333333333", ScopeType: "user", ScopeID: "11111111-1111-4111-8111-111111111111", UserEpoch: 2, TenantEpoch: 3, ConfigVersion: 4}
}

func hostedInspectionTestInput() HostedEnrollmentInput {
	return HostedEnrollmentInput{Server: "https://example.invalid", UserToken: "synthetic-human", Bootstrap: "telara_mcp_synthetic", Consent: true, MemoryOnly: true, Ops: []string{"push"}, Repos: []string{"r1:" + strings.Repeat("1", 64)}, ExpiresAt: time.Now().Add(time.Hour).Unix()}
}

func TestHostedInspectionResponseHasClosedExactIdentity(t *testing.T) {
	good := hostedInspectionTestBinding()
	raw, err := json.Marshal(good)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseHostedInspectionResponse(strings.NewReader(string(raw)))
	if err != nil || !got.Matches(good) {
		t.Fatal("valid inspection refused", err)
	}
	for _, invalid := range []string{
		`null`, `{}`, string(raw) + `{}`,
		string(raw[:len(raw)-1]) + `,"version":1}`,
		string(raw[:len(raw)-1]) + `,"vers\u0069on":1}`,
		string(raw[:len(raw)-1]) + `,"session_token":"synthetic"}`,
		strings.Repeat(" ", 8193),
	} {
		if _, err := ParseHostedInspectionResponse(strings.NewReader(invalid)); !errors.Is(err, ErrLoginUnverified) {
			t.Fatal("ambiguous or expanded inspection accepted")
		}
	}
	mutations := []func(*HostedEnrollmentInspection){
		func(s *HostedEnrollmentInspection) { s.Origin = "https://other.invalid" },
		func(s *HostedEnrollmentInspection) { s.Tenant = "11111111111111111111111111111111" },
		func(s *HostedEnrollmentInspection) { s.User = "44444444-4444-4444-8444-444444444444" },
		func(s *HostedEnrollmentInspection) { s.Config = "44444444-4444-4444-8444-444444444444" },
		func(s *HostedEnrollmentInspection) { s.BootstrapID = "44444444-4444-4444-8444-444444444444" },
		func(s *HostedEnrollmentInspection) { s.ScopeType = "tenant" },
		func(s *HostedEnrollmentInspection) { s.ScopeID = "44444444-4444-4444-8444-444444444444" },
		func(s *HostedEnrollmentInspection) { s.UserEpoch++ },
		func(s *HostedEnrollmentInspection) { s.TenantEpoch++ },
		func(s *HostedEnrollmentInspection) { s.ConfigVersion++ },
	}
	for _, mutate := range mutations {
		changed := good
		mutate(&changed)
		if changed.Matches(good) || good.Matches(changed) {
			t.Fatal("changed identity matched")
		}
	}
}

func TestHostedBoundInputNeverFallsBackToLegacy(t *testing.T) {
	good := HostedBoundEnrollmentInput{HostedEnrollmentInput: hostedInspectionTestInput(), Expected: hostedInspectionTestBinding()}
	raw, err := json.Marshal(good)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseHostedBoundEnrollment(strings.NewReader(string(raw))); err != nil {
		t.Fatal(err)
	}
	legacy, err := json.Marshal(good.HostedEnrollmentInput)
	if err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []string{
		string(legacy),
		string(legacy[:len(legacy)-1]) + `,"expected":null}`,
		string(raw[:len(raw)-1]) + `,"expected":null}`,
		string(raw[:len(raw)-1]) + `,"exp\u0065cted":null}`,
		string(raw) + `{}`,
	} {
		if _, err := ParseHostedBoundEnrollment(strings.NewReader(invalid)); !errors.Is(err, ErrEnrollment) {
			t.Fatal("unbound or ambiguous input accepted")
		}
	}
	if _, err := ParseHostedEnrollment(strings.NewReader(string(legacy))); err != nil {
		t.Fatal("legacy input changed", err)
	}
	if _, err := ParseHostedEnrollment(strings.NewReader(string(raw))); err == nil {
		t.Fatal("legacy parser accepted new bound schema")
	}
	if _, err := ParseHostedInspectionInput(strings.NewReader(string(legacy))); err != nil {
		t.Fatal(err)
	}
	duplicate := string(legacy[:len(legacy)-1]) + `,"bootstr\u0061p":"telara_mcp_other"}`
	if _, err := ParseHostedInspectionInput(strings.NewReader(duplicate)); err == nil {
		t.Fatal("ambiguous diagnostic input accepted")
	}
}

func TestHostedBoundRefusalDoesNotProvisionLocalArtifacts(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "must-remain-absent")
	in := HostedBoundEnrollmentInput{HostedEnrollmentInput: hostedInspectionTestInput(), Expected: hostedInspectionTestBinding()}
	in.Expected.ConfigVersion = 0
	// Nil vault is intentional. A refusal must precede every vault operation.
	if _, err := EnrollHostedBound(context.Background(), dir, nil, nil, in); !errors.Is(err, ErrEnrollment) {
		t.Fatal(err)
	}
	if _, err := os.Lstat(dir); !os.IsNotExist(err) {
		t.Fatal("refusal touched local profile")
	}
	in.Expected = hostedInspectionTestBinding()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := EnrollHostedBound(ctx, dir, nil, nil, in); !errors.Is(err, ErrLoginUnverified) {
		t.Fatal(err)
	}
	if _, err := os.Lstat(dir); !os.IsNotExist(err) {
		t.Fatal("failed inspection touched local profile")
	}
}

func TestHostedInspectionRequiresExactCompleteZeroEpochSnapshot(t *testing.T) {
	good := hostedInspectionTestBinding()
	good.UserEpoch, good.TenantEpoch = 0, 0
	valid, err := json.Marshal(good)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseHostedInspectionResponse(strings.NewReader(string(valid))); err != nil {
		t.Fatal("explicit zero snapshot rejected", err)
	}
	for _, alias := range []string{`"Tenant"`, `"\u0054enant"`, `"User_Epoch"`, `"\u0055ser_Epoch"`} {
		value := "0"
		if strings.Contains(alias, "enant") {
			value = `"0123456789abcdef0123456789abcdef"`
		}
		raw := string(valid[:len(valid)-1]) + "," + alias + ":" + value + "}"
		if _, err := ParseHostedInspectionResponse(strings.NewReader(raw)); !errors.Is(err, ErrLoginUnverified) {
			t.Fatal("response alias accepted")
		}
	}
	for _, field := range hostedInspectionSnapshotMembers {
		for _, mode := range []string{"absent", "null"} {
			var members map[string]json.RawMessage
			if json.Unmarshal(valid, &members) != nil {
				t.Fatal("unit fixture")
			}
			if mode == "absent" {
				delete(members, field)
			} else {
				members[field] = json.RawMessage(`null`)
			}
			raw, err := json.Marshal(members)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ParseHostedInspectionResponse(strings.NewReader(string(raw))); !errors.Is(err, ErrLoginUnverified) {
				t.Fatal("missing/null response fact accepted", field, mode)
			}
		}
	}
}

func TestHostedNewInputsRejectCaseAliasesAndMissingEpochFacts(t *testing.T) {
	input := HostedBoundEnrollmentInput{HostedEnrollmentInput: hostedInspectionTestInput(), Expected: hostedInspectionTestBinding()}
	input.Expected.UserEpoch, input.Expected.TenantEpoch = 0, 0
	valid, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseHostedBoundEnrollment(strings.NewReader(string(valid))); err != nil {
		t.Fatal(err)
	}
	for _, alias := range []string{`"Expected"`, `"\u0045xpected"`} {
		raw := string(valid[:len(valid)-1]) + "," + alias + ":null}"
		if _, err := ParseHostedBoundEnrollment(strings.NewReader(raw)); !errors.Is(err, ErrEnrollment) {
			t.Fatal("input alias accepted")
		}
	}
	for _, alias := range []string{`"Tenant"`, `"\u0054enant"`, `"User_Epoch"`, `"\u0055ser_Epoch"`} {
		var top map[string]json.RawMessage
		if json.Unmarshal(valid, &top) != nil {
			t.Fatal("unit fixture")
		}
		expected := top["expected"]
		value := "0"
		if strings.Contains(alias, "enant") {
			value = `"0123456789abcdef0123456789abcdef"`
		}
		top["expected"] = json.RawMessage(string(expected[:len(expected)-1]) + "," + alias + ":" + value + "}")
		raw, err := json.Marshal(top)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ParseHostedBoundEnrollment(strings.NewReader(string(raw))); !errors.Is(err, ErrEnrollment) {
			t.Fatal("nested input alias accepted")
		}
	}
	for _, field := range hostedInspectionSnapshotMembers {
		for _, mode := range []string{"absent", "null"} {
			var top map[string]json.RawMessage
			if json.Unmarshal(valid, &top) != nil {
				t.Fatal("unit fixture")
			}
			var snapshot map[string]json.RawMessage
			if json.Unmarshal(top["expected"], &snapshot) != nil {
				t.Fatal("unit fixture")
			}
			if mode == "absent" {
				delete(snapshot, field)
			} else {
				snapshot[field] = json.RawMessage(`null`)
			}
			top["expected"], err = json.Marshal(snapshot)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := json.Marshal(top)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ParseHostedBoundEnrollment(strings.NewReader(string(raw))); !errors.Is(err, ErrEnrollment) {
				t.Fatal("incomplete input fact accepted", field, mode)
			}
		}
	}
	inspect, err := json.Marshal(input.HostedEnrollmentInput)
	if err != nil {
		t.Fatal(err)
	}
	for _, alias := range []string{`"Bootstrap"`, `"\u0042ootstrap"`} {
		raw := string(inspect[:len(inspect)-1]) + "," + alias + `:"telara_mcp_other"}`
		if _, err := ParseHostedInspectionInput(strings.NewReader(raw)); !errors.Is(err, ErrEnrollment) {
			t.Fatal("diagnostic input alias accepted")
		}
	}
}
