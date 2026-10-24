package disclosuretext

import (
	"reflect"
	"strings"
	"testing"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/localpolicy"
	"github.com/Telara-Labs/telara-memory/contract/record"
)

func assemblyOverlay(t *testing.T) localpolicy.Overlay {
	t.Helper()
	o, err := localpolicy.TenantOverlay(&record.PolicyBody{Redaction: record.PolicyRedact{Shapes: []record.Shape{{Name: "split", RE2: `tenant-\s*secret-\s*123`}}}})
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
	o, err := localpolicy.TenantOverlay(&record.PolicyBody{Redaction: record.PolicyRedact{Shapes: []record.Shape{{Name: "exact", RE2: "tenant-secret-\\n123"}}}})
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
