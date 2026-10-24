package transport

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"github.com/Telara-Labs/telara-memory/contract/jcs"
	"github.com/Telara-Labs/telara-memory/contract/policy"
	"github.com/Telara-Labs/telara-memory/contract/record"
	"github.com/Telara-Labs/telara-memory/contract/sig"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestV3ExposureFixturesAndManifest(t *testing.T) {
	var f struct {
		Manifest string   `json:"manifest_jcs"`
		Facts    []string `json:"facts_jcs"`
	}
	raw, err := os.ReadFile("../testdata/v20-exposures.json")
	if err != nil || json.Unmarshal(raw, &f) != nil {
		t.Fatal(err)
	}
	var m Manifest
	if json.Unmarshal([]byte(f.Manifest), &m) != nil {
		t.Fatal("manifest")
	}
	lines := [][]byte{}
	for _, fact := range f.Facts {
		lines = append(lines, []byte(fact))
	}
	facts, err := ValidateBundleLines(m, lines)
	if err != nil || len(facts) != 3 || facts[1].Boundary.Seq == nil || *facts[1].Boundary.Seq != 0 || facts[1].PendingAttribution {
		t.Fatal("required seq0/false", err)
	}
	var unsigned map[string]any
	json.Unmarshal([]byte(f.Manifest), &unsigned)
	delete(unsigned, "sigs")
	canonical, _ := jcs.MarshalRecord(unsigned)
	msg := sig.BundleMessage(canonical)
	pub := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, 32)).Public().(ed25519.PublicKey)
	if sig.Verify(pub, sig.CtxBundle, msg, m.Sigs[0]) != nil {
		t.Fatal("worked manifest signature")
	}
	for _, mutate := range []func(map[string]any){
		func(o map[string]any) { delete(o, "pending_attribution") }, func(o map[string]any) { o["prose"] = "secret" }, func(o map[string]any) { o["origin_machine"] = "11111111-1111-4111-8111-111111111111" }, func(o map[string]any) { o["boundary"].(map[string]any)["seq"] = 0 }, func(o map[string]any) { o["scope_id"] = "native prose" }, func(o map[string]any) { o["pending_attribution"] = false }, func(o map[string]any) { o["boundary"].(map[string]any)["ordinal"] = 0 }, func(o map[string]any) { o["source_call_or_event"].(map[string]any)["unknown"] = "prose" },
	} {
		var o map[string]any
		json.Unmarshal(lines[0], &o)
		mutate(o)
		bad, _ := jcs.MarshalRecord(o)
		if _, err := ParseExposure(bad); err == nil {
			t.Fatal("invalid tagged fact accepted", string(bad))
		}
	}
	for _, mutate := range []func(*Manifest){func(m *Manifest) { m.Exposures++ }, func(m *Manifest) { m.ItemsDigest = record.H("wrong") }, func(m *Manifest) { m.Bundle = "mnc/2" }, func(m *Manifest) { m.Control = -1 }} {
		bad := m
		mutate(&bad)
		if _, err := ValidateBundleLines(bad, lines); err == nil {
			t.Fatal("invalid manifest accepted")
		}
	}
	if _, err := ValidateBundleLines(m, append(lines, []byte(`{}`))); err == nil {
		t.Fatal("extra line accepted")
	}
}
func TestV3BundlePolicyBothDirections(t *testing.T) {
	r := bundleTestRecord(t, "standalone", nil)
	if !BundleEligible(r.ID, map[string]BundleRecord{r.ID: r}) {
		t.Fatal("standalone full body denied")
	}
	b := &record.PolicyBody{Push: record.PolicyPush{MaxProfile: record.ProfilePushMetadata, AllowRepos: []string{"*"}}}
	governed := r
	governed.Authorization = BundleAuthorization{ProvenanceKnown: true, ActivePolicy: true, Policy: b, LoggedIn: true, Applicable: true, ShapesSatisfied: true, Freshness: policy.Fresh, Repo: "github.com/acme/api"}
	if BundleEligible(governed.ID, map[string]BundleRecord{governed.ID: governed}) {
		t.Fatal("policy ceiling licensed full-body bundle")
	}
	h := r.Record.Header
	h.Prov = record.ProvDerived
	h.Op = ""
	h.Red.Profile = record.ProfilePushMetadata
	h.Links.Origin = r.ID
	h.Pol = record.H("policy")
	meta, err := record.Build(h, &record.TaskMetaBody{Status: "active"})
	if err != nil {
		t.Fatal(err)
	}
	if !BundlePolicyAllowed(meta, governed.Authorization) {
		t.Fatal("currently authorized metadata denied")
	}
	for _, mutate := range []func(*BundleAuthorization){func(a *BundleAuthorization) { a.LoggedIn = false }, func(a *BundleAuthorization) { a.Freshness = policy.TamperedHead }, func(a *BundleAuthorization) { a.Freshness = policy.Expired }, func(a *BundleAuthorization) { a.Freshness = policy.RolledBack }, func(a *BundleAuthorization) { a.ShapesSatisfied = false }, func(a *BundleAuthorization) { a.ProvenanceKnown = false }, func(a *BundleAuthorization) { a.Applicable = false }} {
		a := governed.Authorization
		mutate(&a)
		if BundlePolicyAllowed(meta, a) {
			t.Fatal("governed authorization bypass")
		}
	}
	b.Push.MaxProfile = ""
	if BundlePolicyAllowed(meta, governed.Authorization) {
		t.Fatal("omitted ceiling")
	}
	b.Push.MaxProfile = record.ProfilePushMetadata
	b.Kill.Sync = true
	if BundlePolicyAllowed(meta, governed.Authorization) {
		t.Fatal("kill bypass")
	}
	b.Kill.Sync = false
	b.Push.RequirePreview = true
	if BundlePolicyAllowed(meta, governed.Authorization) {
		t.Fatal("preview bypass")
	}
}
func controlFixture(t *testing.T, kind record.Kind, seq int64) LogItem {
	t.Helper()
	h := record.Header{Type: kind, LID: record.H("control", string(kind), string(rune(seq))), Author: record.Author{KeyID: "11111111111111111111111111111111", MachineID: "6f1d2c3b-4a59-4e6f-8a7b-9c0d1e2f3a4b"}, At: 1, Prov: record.ProvUser, Red: record.Redact{Profile: record.ProfileLocal}}
	var body any
	switch kind {
	case record.KindErasure:
		body = &record.ErasureBody{EventCoverage: "complete", Reason: "user_request", Selectors: record.Selectors{IDs: []string{record.H("root")}}}
	}
	r, err := record.Build(h, body)
	if err != nil {
		t.Fatal(err)
	}
	return LogItem{HSeq: seq, Class: "control", DecodedBody: r.BodyJCS, Envelope: record.Envelope{V: 3, ID: r.ID, Header: base64.RawURLEncoding.EncodeToString(r.HeaderJCS), Body: &record.EnvelopeBody{Codec: "zstd", Bytes: "adapter supplied bounded decoded bytes"}}}
}
func TestV3SupplementalControlScanDoesNotACKAhead(t *testing.T) {
	c1, c2 := controlFixture(t, record.KindErasure, 2), controlFixture(t, record.KindErasure, 6)
	c := NewControlProgress(0)
	if c.Stage(Page{Items: []LogItem{c1}, NextAfter: 2, ScannedThrough: 2, More: true}, 6) != nil {
		t.Fatal("page1")
	}
	supplemented := false
	verify := func(x LogItem, staged bool) ControlDecision {
		if x.HSeq == 2 {
			return ControlDecision{Verified: true, RestrictionsApplied: true, Complete: supplemented, CoveragePending: !supplemented}
		}
		if x.HSeq == 6 {
			if staged {
				supplemented = true
			}
			return ControlDecision{Verified: true, RestrictionsApplied: true, Complete: true}
		}
		return ControlDecision{}
	}
	if c.Enforce(verify) || c.Cursor != 0 || c.Scan != 2 {
		t.Fatal("pending c1 advanced ACK")
	}
	if c.Stage(Page{Items: []LogItem{c2}, NextAfter: 6, ScannedThrough: 6}, 6) != nil {
		t.Fatal("page2")
	}
	// Restart rescans from completed cursor; no third durable cursor survives.
	restarted := NewControlProgress(c.Cursor)
	if restarted.Stage(Page{Items: c.Pending(), NextAfter: 6, ScannedThrough: 6}, 6) != nil || !restarted.Enforce(verify) || restarted.Cursor != 6 {
		t.Fatal("supplement did not recover contiguous prefix")
	}
	bad := c2
	bad.Envelope.V = 2
	c = NewControlProgress(0)
	c.Stage(Page{Items: []LogItem{c1, bad}, NextAfter: 6, ScannedThrough: 6}, 6)
	supplemented = false
	if c.Enforce(verify) || c.Cursor != 0 {
		t.Fatal("unknown/invalid major skipped to supplement")
	}
}

func TestV3SelfReviewLogoutFenceSurvivesRelogin(t *testing.T) {
	source := bundleTestRecord(t, "source", nil)
	h := source.Record.Header
	h.Prov = record.ProvDerived
	h.Op = ""
	h.Red.Profile = record.ProfilePushMetadata
	h.Links.Origin = source.ID
	h.Pol = record.H("old-policy")
	meta, err := record.Build(h, &record.TaskMetaBody{Status: "active"})
	if err != nil {
		t.Fatal(err)
	}
	a := BundleAuthorization{ProvenanceKnown: true, ActivePolicy: true, LoggedIn: true, Applicable: true, ShapesSatisfied: true, Freshness: policy.Fresh, Policy: &record.PolicyBody{Push: record.PolicyPush{MaxProfile: record.ProfilePushMetadata, AllowRepos: []string{"*"}}}, Repo: "github.com/acme/api"}
	// A logged-out provenance marker must remain restrictive after a new login.
	field := reflect.ValueOf(&a).Elem().FieldByName("LogoutRestricted")
	if !field.IsValid() {
		t.Fatal("no retained logout fence in bundle authorization")
	}
	field.SetBool(true)
	if BundlePolicyAllowed(meta, a) {
		t.Fatal("relogin laundered non-bundleable policy provenance")
	}
}

func TestV3EnvelopeBoundsBeforeDecode(t *testing.T) {
	for _, e := range []record.Envelope{{V: 3, ID: record.H("id"), Header: strings.Repeat("A", base64.RawURLEncoding.EncodedLen(record.MaxHeaderBytes)+1)}, {V: 3, ID: "", Header: "e30"}} {
		if _, err := CheckEnvelope(e, nil); err == nil {
			t.Fatal("envelope bounds/advisory shape bypass")
		}
	}
}

func TestV3BodylessControlCannotCompletePrefix(t *testing.T) {
	item := controlFixture(t, record.KindErasure, 2)
	item.Envelope.Body = nil
	item.DecodedBody = nil
	progress := NewControlProgress(0)
	if progress.Stage(Page{Items: []LogItem{item}, NextAfter: 2, ScannedThrough: 2}, 2) != nil {
		t.Fatal("stage")
	}
	if progress.Enforce(func(LogItem, bool) ControlDecision {
		return ControlDecision{Verified: true, Complete: true, RestrictionsApplied: true}
	}) || progress.Cursor != 0 {
		t.Fatal("bodyless control acknowledged without enforcement")
	}
}
