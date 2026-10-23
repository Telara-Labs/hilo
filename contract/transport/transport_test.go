package transport

import (
	"encoding/base64"
	"encoding/json"
	"github.com/Telara-Labs/telara-memory/contract/jcs"
	"github.com/Telara-Labs/telara-memory/contract/record"
	"os"
	"testing"
)

func TestInterleavedCursorSnapshots(t *testing.T) {
	log := []LogItem{{HSeq: 1, Class: "data"}, {HSeq: 2, Class: "control"}, {HSeq: 3, Class: "data", Own: true}, {HSeq: 4, Class: "control"}}
	ctl := int64(0)
	for ctl < 4 {
		p, err := ScanPage(log, "control", ctl, 4, 1, false)
		if err != nil {
			t.Fatal(err)
		}
		next, halt, err := ApplyPage(p, "control", ctl, 4, func(x LogItem) bool { return x.HSeq != 4 })
		if err != nil {
			t.Fatal(err)
		}
		if halt {
			if next != 2 {
				t.Fatal(next)
			}
			break
		}
		ctl = next
	}
	data, err := ScanPage(log, "data", 0, 3, 1, true)
	if err != nil || len(data.Items) != 1 || data.Items[0].HSeq != 1 || data.NextAfter != 3 || data.More {
		t.Fatalf("own tail must advance without skipping d1: %+v %v", data, err)
	}
	next, halt, err := ApplyPage(data, "data", 0, 3, func(LogItem) bool { return false })
	if err != nil || halt || next != 3 {
		t.Fatal("unknown data quarantines and advances")
	}
	if _, _, err = ApplyPage(Page{Items: []LogItem{{HSeq: 2, Class: "control"}}, NextAfter: 3, ScannedThrough: 3}, "data", 0, 3, func(LogItem) bool { return true }); err == nil {
		t.Fatal("cross-class cursor accepted")
	}
}
func TestOutboxRevalidatesExplicitAuthority(t *testing.T) {
	a := Authority{ExplicitOp: record.H("op"), Profile: record.ProfilePushMetadata}
	s := SendState{Kind: record.KindTask, Live: true, AncestryResolved: true, PolicyAllowed: true, Profile: a.Profile}
	if !MaySend(a, s) {
		t.Fatal("eligible explicit send")
	}
	s.Grants = []record.GrantRef{{Tenant: "t", Generation: 1}}
	if MaySend(a, s) {
		t.Fatal("explicit confirmation bypassed grant")
	}
	s.Grants = nil
	s.Live = false
	if MaySend(a, s) {
		t.Fatal("held row sent")
	}
	s.Live = true
	a = Authority{RuleID: "r", RuleVersion: 1, Profile: s.Profile}
	s.RuleID = "r"
	s.RuleVersion = 2
	s.RuleMatches = true
	if MaySend(a, s) {
		t.Fatal("edited rule queued row sent")
	}
}
func TestBundleCuts(t *testing.T) {
	gen := "11111111111111111111111111111111"
	if ValidateBundleMode(gen, gen, "plaintext", nil) == nil || ValidateBundleMode(gen, gen, "backup", []string{"scrypt", "x25519"}) == nil || ValidateBundleMode(gen, "22222222222222222222222222222222", "transfer", []string{"x25519"}) == nil {
		t.Fatal("unsafe bundle accepted")
	}
	if ValidateBundleMode(gen, gen, "transfer", []string{"x25519"}) != nil {
		t.Fatal("transfer refused")
	}
	root := BundleRecord{ID: "r", Selected: true, CompleteSigned: true, SelectorIdentity: true, Live: true}
	leaf := root
	leaf.ID = "l"
	leaf.RecalledRoots = []string{"r"}
	rs := map[string]BundleRecord{"r": root, "l": leaf}
	if !BundleEligible("l", rs) {
		t.Fatal("complete closure refused")
	}
	root.Selected = false
	rs["r"] = root
	if BundleEligible("l", rs) {
		t.Fatal("unselected private root accepted")
	}
	root.Selected = true
	root.Grants = []record.GrantRef{{Tenant: "t", Generation: 1}}
	rs["r"] = root
	if BundleEligible("l", rs) {
		t.Fatal("granted root accepted")
	}
}
func TestHookIdentityOnly(t *testing.T) {
	h := HookSignal{V: 3, At: 1, Client: "c", Event: "Stop", HookPID: 1, TranscriptPath: "/root/transcripts/a"}
	rules := HookRules{Client: "c", TranscriptRoot: "/root/transcripts", ValidateTranscriptPath: func(s string) bool { return s == "/root/transcripts/a" }, Events: map[string]bool{"Stop": true}}
	raw, _ := json.Marshal(h)
	if _, err := ParseHook(raw, rules); err != nil {
		t.Fatal(err)
	}
	var object map[string]any
	json.Unmarshal(raw, &object)
	object["final_text"] = "never spool"
	raw, _ = json.Marshal(object)
	if _, err := ParseHook(raw, rules); err == nil {
		t.Fatal("body-bearing signal accepted")
	}
	delete(object, "final_text")
	object["transcript_path"] = "/root/other/a"
	raw, _ = json.Marshal(object)
	if _, err := ParseHook(raw, rules); err == nil {
		t.Fatal("escaped client root")
	}
}
func TestPushRequiresReceipt(t *testing.T) {
	p := PushResult{ID: record.H("id"), Status: "accepted", HSeq: 1}
	if CheckPushResult(p) == nil {
		t.Fatal("no receipt")
	}
	p.Receipt = &record.Receipt{ID: p.ID, HSeq: 1}
	if CheckPushResult(p) != nil {
		t.Fatal("structural receipt rejected")
	}
}

func TestOwnControlCannotBeFiltered(t *testing.T) {
	log := []LogItem{{HSeq: 1, Class: "control", Own: true}}
	if _, err := ScanPage(log, "control", 0, 1, 1, true); err == nil {
		t.Fatal("own erasure skipped enforcement")
	}
	page, err := ScanPage(log, "control", 0, 1, 1, false)
	if err != nil || len(page.Items) != 1 {
		t.Fatal("own erasure missing")
	}
}
func TestHookRejectsProseInIdentityFields(t *testing.T) {
	h := HookSignal{V: 3, At: 1, Client: "c", Event: "Stop", HookPID: 1, NativeSession: "prompt text\nsecret"}
	rules := HookRules{Client: "c", Events: map[string]bool{"Stop": true}, ValidateNativeSession: func(string) bool { return true }}
	raw, _ := json.Marshal(h)
	if _, err := ParseHook(raw, rules); err == nil {
		t.Fatal("multiline raw content accepted")
	}
	h.NativeSession = "unvalidated-native-token"
	rules.ValidateNativeSession = nil
	raw, _ = json.Marshal(h)
	if _, err := ParseHook(raw, rules); err == nil {
		t.Fatal("unvalidated client identity accepted")
	}
}

func TestContractMajorGates(t *testing.T) {
	h := Hello{DeviceID: "11111111-1111-4111-8111-111111111111", Contract: record.ContractVersion}
	r := HelloReply{ContractMin: record.ContractVersion, ServerTime: 1}
	if CheckHello(h, r) != nil {
		t.Fatal("current hello refused")
	}
	h.Contract = "mnc/1.7"
	if CheckHello(h, r) == nil {
		t.Fatal("legacy hello accepted")
	}
	if CheckManifestVersion(Manifest{Bundle: "mnc/1"}) == nil || CheckManifestVersion(Manifest{Bundle: "mnc/2"}) != nil {
		t.Fatal("bundle major gate")
	}
	if _, err := CheckEnvelope(record.Envelope{V: 1}, nil); err == nil {
		t.Fatal("legacy envelope accepted")
	}
}

func TestVersionGatesCannotOverrideSignedHeader(t *testing.T) {
	var fs []struct{ Name, HeaderJCS, BodyJCS, ID string }
	raw, err := os.ReadFile("../testdata/v03-records.json")
	if err != nil || json.Unmarshal(raw, &fs) != nil {
		t.Fatal("fixture")
	}
	var chunk record.Envelope
	for _, f := range fs {
		if f.Name == "chunk" {
			chunk = record.Envelope{V: record.Version, ID: f.ID, Header: base64.RawURLEncoding.EncodeToString([]byte(f.HeaderJCS))}
		}
	}
	parsed, err := CheckEnvelope(chunk, nil)
	if err != nil || parsed.Body != nil {
		t.Fatal("current bodyless envelope", err)
	}
	header, _ := base64.RawURLEncoding.DecodeString(chunk.Header)
	var object map[string]any
	json.Unmarshal(header, &object)
	object["v"] = 1
	oldHeader, _ := jcs.MarshalRecord(object)
	legacy := chunk
	legacy.Header = base64.RawURLEncoding.EncodeToString(oldHeader)
	legacy.ID = record.ContentID(oldHeader)
	if _, err = CheckEnvelope(legacy, nil); err == nil {
		t.Fatal("v2 envelope overrode legacy signed header")
	}
	future := chunk
	future.V = 3
	if _, err = CheckEnvelope(future, nil); err == nil {
		t.Fatal("future envelope accepted")
	}
	object["v"] = 3
	futureHeader, _ := jcs.MarshalRecord(object)
	future = chunk
	future.Header = base64.RawURLEncoding.EncodeToString(futureHeader)
	future.ID = record.ContentID(futureHeader)
	if _, err = CheckEnvelope(future, nil); err == nil {
		t.Fatal("future signed header accepted")
	}
	h := Hello{DeviceID: "11111111-1111-4111-8111-111111111111", Contract: record.ContractVersion}
	for _, version := range []string{"mnc/1.7", "mnc/3.0", ""} {
		if CheckHello(h, HelloReply{ContractMin: version, ServerTime: 1}) == nil {
			t.Fatal("server hello gate bypass")
		}
		if CheckManifestVersion(Manifest{Bundle: version}) == nil {
			t.Fatal("bundle gate bypass")
		}
	}
}
