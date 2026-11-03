package disclosuretext

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Telara-Labs/hilo/contract/internal/node/localpolicy"
	"github.com/Telara-Labs/hilo/contract/record"
)

func TestTenantOverlayAfterCompleteDisplayNormalization(t *testing.T) {
	policy := &record.PolicyBody{Redaction: record.PolicyRedact{Shapes: []record.Shape{{Name: "secret", RE2: `tenant-secret-(123|office|café)`}}}}
	overlay, err := NewAssemblyPolicy(policy)
	if err != nil {
		t.Fatal(err)
	}
	rules, err := localpolicy.Ruleset()
	if err != nil {
		t.Fatal(err)
	}
	for name, input := range map[string]string{
		"recomposition": "tenant-secret-cafe\u200b\u0301", "fullwidth": "tenant-secret-１２３", "ligature": "tenant-secret-oﬃce",
		"zero-width": "tenant-secret-\u200b123", "control": "tenant-\x01secret-123",
		"terminal": "tenant-secret-\x1b[31m123\x1b[0m",
	} {
		t.Run(name, func(t *testing.T) {
			raw, _, err := NormalizePolicyValue(input, &WorkBudget{})
			if err != nil || overlay.Text(raw) == raw {
				t.Fatal("fixture did not reconstruct policy match", raw, err)
			}
			p, err := PrepareField(FieldInput{Family: "goal", Value: input, Overlay: overlay.FieldOverlay()}, &WorkBudget{})
			if err != nil || p.ProjectionValue() != "[REDACTED]" {
				t.Fatal("unsafe projection", p.ProjectionValue(), err)
			}
			in := RenderInput{CallRef: "m1.abcdefghij", Nonce: strings.Repeat("a", 20), Budget: ByteBudget{MaxBytes: 2048}, Overlay: overlay,
				Items: []RenderItem{{LID: strings.Repeat("b", 64), ID: strings.Repeat("c", 64), Labels: Labels{Source: input}, Fields: []RenderField{{Family: "goal", Value: strings.Repeat("safe ", 500) + input + strings.Repeat(" tail", 500)}}}}}
			out, err := Render(in)
			if err != nil || strings.Contains(out.Text, escape(raw)) || !strings.Contains(out.Text, "REDACTED") {
				t.Fatal("unsafe fitted render", out.Text, err)
			}
			for _, tc := range []struct {
				tool string
				args any
			}{
				{"local.create_task", map[string]any{"goal": input, "file_paths": []string{input}}},
				{"local.checkpoint_task", map[string]any{"task_id": taskID, "milestone": input, "task_tree": []map[string]string{{"step": input, "status": "done"}}}},
			} {
				b, _ := json.Marshal(tc.args)
				c, err := DecodeCommand(tc.tool, b)
				if err != nil {
					t.Fatal(err)
				}
				n, err := NormalizeTenantCommand(c, ByteBudget{4096}, CurrentSchema(tc.tool), rules.Fingerprint(), policy)
				if err != nil || strings.Contains(string(n.Canonical), input) || strings.Contains(string(n.Canonical), raw) || !strings.Contains(string(n.Canonical), "REDACTED") {
					t.Fatal("unsafe governed command", string(n.Canonical), err)
				}
			}
		})
	}
	// Ordinary Unicode stays part of the original argument identity under policy.
	c, _ := DecodeCommand("local.create_task", []byte(`{"goal":"① café"}`))
	n, err := NormalizeTenantCommand(c, ByteBudget{4096}, CurrentSchema(c.Tool()), rules.Fingerprint(), policy)
	if err != nil || n.Args.Goal != "① café" {
		t.Fatal("safe Unicode identity changed", err)
	}
}

func TestTenantNormalizationFailsClosedAtSharedBounds(t *testing.T) {
	if _, _, err := NormalizePolicyValue("abc", &WorkBudget{bytes: MaxViewOperation - 2}); Code(err) != "render_limit" {
		t.Fatal(err)
	}
	if _, _, err := NormalizePolicyValue(string([]byte{0xff}), &WorkBudget{}); Code(err) != "render_limit" {
		t.Fatal(err)
	}
	if _, _, err := NormalizePolicyValue("abc", nil); Code(err) != "render_limit" {
		t.Fatal(err)
	}
}
