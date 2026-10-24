package disclosuretext

import (
	"reflect"
	"strings"
	"testing"

	"github.com/Telara-Labs/telara-memory/contract/record"
)

func assemblyOverlay(t *testing.T) AssemblyPolicy {
	t.Helper()
	o, err := NewAssemblyPolicy(&record.PolicyBody{Redaction: record.PolicyRedact{Shapes: []record.Shape{{Name: "split", RE2: `tenant-\s*secret-\s*123`}}}})
	if err != nil {
		t.Fatal(err)
	}
	return o
}

func TestAssemblySourceSpansAndBounds(t *testing.T) {
	o := assemblyOverlay(t)
	a, err := CheckAssembly([]string{"é", "", "safe"}, o, &WorkBudget{})
	if err != nil || a.Restricted || a.Text != "é\nsafe" || !reflect.DeepEqual(a.Spans, []ProjectionSpan{{0, 2, 0}, {3, 7, 2}}) {
		t.Fatal(a, err)
	}
	a, err = CheckAssembly(nil, o, &WorkBudget{})
	if err != nil || a.Text != "" || a.Restricted || len(a.Spans) != 0 {
		t.Fatal(a, err)
	}
	for _, values := range [][]string{{"tenant-secret-", "123"}, {"tenant-", "secret-", "123"}, {"tenant-secret-", "", "123"}} {
		a, err := CheckAssembly(values, o, &WorkBudget{})
		if err != nil || !a.Restricted || a.Text != "" {
			t.Fatal(a, err)
		}
		for _, span := range a.Spans {
			if span.End-span.Start != len(values[span.Field]) {
				t.Fatal("bad source mapping", a)
			}
		}
	}
	for _, tc := range []struct {
		values []string
		work   *WorkBudget
	}{
		{[]string{"abc"}, nil}, {[]string{"abc"}, &WorkBudget{bytes: MaxViewOperation - 2}},
		{[]string{strings.Repeat("x", MaxViewValue), "x"}, &WorkBudget{}},
	} {
		if _, err := CheckAssembly(tc.values, o, tc.work); Code(err) != "render_limit" {
			t.Fatal(err)
		}
	}
}

func TestRenderSuppressesAssembledPolicyBeforeFitting(t *testing.T) {
	for name, values := range map[string][]string{
		"checkpoint": {"tenant-secret-", "１２３"}, "title-goal": {"tenant-secret-", "１２３"},
		"three-way": {"tenant-", "secret-", "１２３"}, "normalization": {"tenant-\x01", "sec\u200bret-", "１２３"},
		"fitted": {"safe " + strings.Repeat("x", 4000) + " tenant-secret-", "１２３" + strings.Repeat(" tail", 1000)},
	} {
		t.Run(name, func(t *testing.T) {
			families := []string{"milestone", "next_steps", "step_title"}
			if name == "title-goal" {
				families = []string{"name", "goal"}
			}
			fields := make([]RenderField, len(values))
			for i, v := range values {
				fields[i] = RenderField{Family: families[i], Value: v}
			}
			out, err := Render(RenderInput{Overlay: assemblyOverlay(t), CallRef: "m1.abcdefghij", Nonce: strings.Repeat("a", 20), Budget: ByteBudget{MaxBytes: 2048}, Items: []RenderItem{
				{LID: strings.Repeat("b", 64), ID: strings.Repeat("c", 64), Fields: fields},
				{LID: strings.Repeat("d", 64), ID: strings.Repeat("e", 64), Fields: []RenderField{{Family: "goal", Value: "safecontrol"}}},
			}})
			if err != nil || !strings.Contains(out.Text, "Content withheld by current policy.") || strings.Contains(out.Text, "tenant") || strings.Contains(out.Text, "123") || !strings.Contains(out.Text, "safecontrol") {
				t.Fatal(out, err)
			}
			if !reflect.DeepEqual(out.ShownUnits, []ShownUnit{{1, 0}}) {
				t.Fatal("suppressed source marked shown", out.ShownUnits)
			}
		})
	}
}

func TestRenderAssemblySkipsNormalizedEmptyFields(t *testing.T) {
	o, err := NewAssemblyPolicy(&record.PolicyBody{Redaction: record.PolicyRedact{Shapes: []record.Shape{{Name: "exact", RE2: "tenant-secret-\\n123"}}}})
	if err != nil {
		t.Fatal(err)
	}
	out, err := Render(RenderInput{Overlay: o, CallRef: "m1.abcdefghij", Nonce: strings.Repeat("a", 20), Budget: ByteBudget{MaxBytes: 2048}, Items: []RenderItem{{LID: strings.Repeat("b", 64), ID: strings.Repeat("c", 64), Fields: []RenderField{
		{Family: "resume_context", Value: "tenant-secret-"}, {Family: "progress_notes", Value: "\u200b"}, {Family: "handoff_hint", Value: "１２３"},
	}}}})
	if err != nil || !strings.Contains(out.Text, "Content withheld by current policy.") || len(out.ShownUnits) != 0 {
		t.Fatal(out, err)
	}
}

func TestAssemblySelectiveIntervalsAndRemovalRecheck(t *testing.T) {
	p, err := NewAssemblyPolicy(&record.PolicyBody{Redaction: record.PolicyRedact{Shapes: []record.Shape{
		{Name: "first", RE2: "x\\ny"}, {Name: "second", RE2: "a\\nz"},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	values := []string{"é", "a", "x", "y", "z", "safecontrol"}
	a, err := CheckAssembly(values, p, &WorkBudget{})
	if err != nil || !a.Restricted || a.Text != "é\nsafecontrol" || !reflect.DeepEqual(a.Suppressed, []int{2, 3, 1, 4}) {
		t.Fatal(a, err)
	}
	if values[2] != "x" || len(a.Spans) != len(values) || a.Spans[0] != (ProjectionSpan{0, 2, 0}) {
		t.Fatal("source map or input changed", a, values)
	}
	p, err = NewAssemblyPolicy(&record.PolicyBody{Redaction: record.PolicyRedact{Shapes: []record.Shape{{Name: "multiple", RE2: "x|z"}}}})
	if err != nil {
		t.Fatal(err)
	}
	a, err = CheckAssembly([]string{"x", "safecontrol", "z"}, p, &WorkBudget{})
	if err != nil || a.Text != "safecontrol" || !reflect.DeepEqual(a.Suppressed, []int{0, 2}) {
		t.Fatal(a, err)
	}
}

func TestAssemblyUnattributableAndWorkBounds(t *testing.T) {
	if _, err := NewAssemblyPolicy(&record.PolicyBody{Redaction: record.PolicyRedact{Shapes: []record.Shape{{RE2: "["}}}}); err == nil {
		t.Fatal("invalid policy accepted")
	}
	if _, err := CheckAssembly([]string{"bearer", "abcdefghijklmnop"}, AssemblyPolicy{}, &WorkBudget{}); Code(err) != "assembled_policy_unavailable" {
		t.Fatal(err)
	}
	for _, pattern := range []string{"^", "\\n"} {
		p, err := NewAssemblyPolicy(&record.PolicyBody{Redaction: record.PolicyRedact{Shapes: []record.Shape{{RE2: pattern}}}})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := CheckAssembly([]string{"a", "b"}, p, &WorkBudget{}); Code(err) != "assembled_policy_unavailable" {
			t.Fatal(pattern, err)
		}
	}
	p, _ := NewAssemblyPolicy(&record.PolicyBody{Redaction: record.PolicyRedact{Shapes: []record.Shape{{RE2: "x"}}}})
	if _, err := CheckAssembly([]string{strings.Repeat("x", 8193)}, p, &WorkBudget{}); Code(err) != "render_limit" {
		t.Fatal(err)
	}
	if _, err := CheckAssembly([]string{"x"}, p, &WorkBudget{assemblyMatches: 8192}); Code(err) != "render_limit" {
		t.Fatal(err)
	}
	if _, err := CheckAssembly(make([]string, 64*(4096+6)+1), p, &WorkBudget{}); Code(err) != "render_limit" {
		t.Fatal(err)
	}
}

func TestRenderCompleteReplySelectiveSourceMap(t *testing.T) {
	p, err := NewAssemblyPolicy(&record.PolicyBody{Redaction: record.PolicyRedact{Shapes: []record.Shape{{RE2: `tenantsecret(?s:.*)parttwo(?s:.*)123`}}}})
	if err != nil {
		t.Fatal(err)
	}
	in := RenderInput{Overlay: p, CallRef: "m1.abcdefghij", Nonce: strings.Repeat("a", 20), Budget: ByteBudget{MaxBytes: 4096}, Items: []RenderItem{
		{LID: strings.Repeat("b", 64), ID: strings.Repeat("c", 64), Fields: []RenderField{{Family: "goal", Value: "tenantsecret"}}},
		{LID: strings.Repeat("d", 64), ID: strings.Repeat("e", 64), Fields: []RenderField{{Family: "milestone", Value: "parttwo"}}},
		{LID: strings.Repeat("f", 64), ID: strings.Repeat("a", 64), Fields: []RenderField{{Family: "milestone", Value: "１２３"}, {Family: "next_steps", Value: "safecontrol"}}},
	}}
	out, err := Render(in)
	if err != nil || strings.Contains(out.Text, "tenantsecret") || strings.Contains(out.Text, "parttwo") || strings.Contains(out.Text, "| 123") || !strings.Contains(out.Text, "safecontrol") || !reflect.DeepEqual(out.ShownUnits, []ShownUnit{{2, 1}}) {
		t.Fatal(out, err)
	}
	// Labels participate at their release position too; source units only count content.
	in.Items[1].Fields = nil
	in.Items[1].Labels.Source = "parttwo"
	out, err = Render(in)
	if err != nil || strings.Contains(out.Text, "parttwo") || !reflect.DeepEqual(out.ShownUnits, []ShownUnit{{2, 1}}) {
		t.Fatal(out, err)
	}
}
