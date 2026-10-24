package disclosuretext

import (
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/Telara-Labs/telara-memory/contract/record"
)

func fittedInput(value string) RenderInput {
	return RenderInput{CallRef: "m1.abcdefghij", Nonce: strings.Repeat("a", 20), Budget: ByteBudget{2048}, Items: []RenderItem{{LID: strings.Repeat("b", 64), ID: strings.Repeat("c", 64), Fields: []RenderField{{Family: "goal", Value: value}}}}}
}
func fittedPolicy(t *testing.T, shape string) AssemblyPolicy {
	t.Helper()
	p, err := NewAssemblyPolicy(&record.PolicyBody{Redaction: record.PolicyRedact{Shapes: []record.Shape{{Name: "fitted", RE2: shape}}}})
	if err != nil {
		t.Fatal(err)
	}
	return p
}
func TestFittedReplyCreatedMatches(t *testing.T) {
	for _, shape := range []string{`START(?s:.{0,100})END`, `tenantsecret\b`} {
		t.Run(shape, func(t *testing.T) {
			value := strings.Repeat("x", 702) + "START" + strings.Repeat("z", 4096) + "END" + strings.Repeat("x", 710)
			if shape == `tenantsecret\b` {
				probe, err := Render(fittedInput(strings.Repeat("x", 6000)))
				if err != nil {
					t.Fatal(err)
				}
				h := len(regexp.MustCompile(`x{20,}`).FindString(probe.Text))
				value = strings.Repeat("x", h-len("tenantsecret")) + "tenantsecretTAIL" + strings.Repeat("x", 5000)
			}
			in := fittedInput(value)
			positive, err := Render(in)
			if err != nil {
				t.Fatal(err)
			}
			re := regexp.MustCompile(shape)
			if re.MatchString(value) || !re.MatchString(positive.Text) {
				t.Fatal("missing fitting-only positive control", positive.Text)
			}
			in.Overlay = fittedPolicy(t, shape)
			got, err := Render(in)
			if err != nil || re.MatchString(got.Text) || len(got.ShownUnits) != 0 || !strings.Contains(got.Text, "withheld") {
				t.Fatal(got, err)
			}
		})
	}
}
func TestFittedReplyFormattingLabelsAndRebuild(t *testing.T) {
	for _, tc := range []struct {
		shape, value string
		label        bool
	}{
		{`&lt;`, "<", false}, {`tenantsecret\b`, strings.Repeat("x", 244) + "tenantsecretTAIL", true},
		{`first\n    \| second`, "first\nsecond", false},
	} {
		t.Run(tc.shape+tc.value, func(t *testing.T) {
			in := fittedInput(tc.value)
			if tc.label {
				in.Items[0].Labels.Source = tc.value
				in.Items[0].Fields = nil
			}
			in.Items[0].Fields = append(in.Items[0].Fields, RenderField{Family: "goal", Ordinal: 1, Value: "safecontrol"})
			positive, err := Render(in)
			if err != nil || !regexp.MustCompile(tc.shape).MatchString(positive.Text) {
				t.Fatal(positive, err)
			}
			in.Overlay = fittedPolicy(t, tc.shape)
			got, err := Render(in)
			if err != nil || regexp.MustCompile(tc.shape).MatchString(got.Text) || !strings.Contains(got.Text, "safecontrol") || len(got.ShownUnits) != 1 {
				t.Fatal(got, err)
			}
		})
	}
	// Removing an escaped first field shifts the head cut onto a word boundary
	// in the next field. A second final-text pass must remove that field too.
	in := fittedInput("")
	in.Items[0].Fields = append(in.Items[0].Fields, RenderField{Family: "goal", Ordinal: 1, Value: strings.Repeat("x", 6000)})
	probe, err := Render(in)
	if err != nil {
		t.Fatal(err)
	}
	h := len(regexp.MustCompile(`x{20,}`).FindString(probe.Text)) - len("    | Content withheld by current policy.\n")
	in.Items[0].Fields[0].Value = "<"
	in.Items[0].Fields[1].Value = strings.Repeat("x", h-len("tenantsecret")) + "tenantsecretTAIL" + strings.Repeat("x", 5000)
	in.Overlay = fittedPolicy(t, `&lt;|tenantsecret\b`)
	got, err := Render(in)
	if err != nil || strings.Contains(got.Text, "tenantsecret") || strings.Contains(got.Text, "&lt;") || len(got.ShownUnits) != 0 {
		t.Fatal(got, err)
	}
}
func TestFittedReplyAttributionAndBounds(t *testing.T) {
	src := renderSource{0, 0, false}
	tests := []struct {
		text, shape string
		spans       []renderSpan
		work        *WorkBudget
		code        string
	}{
		{"abc!", "abc|!", []renderSpan{{0, 3, src}}, &WorkBudget{}, "assembled_policy_unavailable"},
		{"abc", "^", []renderSpan{{0, 3, src}}, &WorkBudget{}, "assembled_policy_unavailable"},
		{"abc", "abc", []renderSpan{{-1, 3, src}}, &WorkBudget{}, "assembled_policy_unavailable"},
		{"abc", "abc", []renderSpan{{0, 3, src}, {1, 2, src}}, &WorkBudget{}, "assembled_policy_unavailable"},
		{"abc", "abc", []renderSpan{{0, 3, src}}, nil, "render_limit"},
		{"abc", "abc", []renderSpan{{0, 3, src}}, &WorkBudget{bytes: MaxViewOperation - 3}, "render_limit"},
		{strings.Repeat("a", 8193), "a", nil, &WorkBudget{}, "render_limit"},
	}
	for _, tc := range tests {
		got, err := fittedReplyMatches(tc.text, tc.spans, fittedPolicy(t, tc.shape), tc.work)
		if Code(err) != tc.code || len(got) != 0 {
			t.Fatalf("%q %v %v", tc.shape, got, err)
		}
	}
	got, err := fittedReplyMatches("é<", []renderSpan{{0, 2, src}, {2, 3, renderSource{0, 1, true}}}, fittedPolicy(t, "é<"), &WorkBudget{})
	if err != nil || !reflect.DeepEqual(got, []renderSource{src, {0, 1, true}}) {
		t.Fatal(got, err)
	}
	in := fittedInput("safecontrol")
	in.Overlay = fittedPolicy(t, "Evidence only")
	out, err := Render(in)
	if Code(err) != "assembled_policy_unavailable" || out.Text != "" || len(out.ShownIndices) != 0 {
		t.Fatal(out, err)
	}
}
