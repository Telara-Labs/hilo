package mcpcatalog

import (
	"encoding/json"
	"testing"
)

func TestCatalogDetachedAndComplete(t *testing.T) {
	first := Tools()
	if len(first) != 8 {
		t.Fatal("missing tools")
	}
	names := map[string]bool{}
	for _, tool := range first {
		if names[tool.Name] || tool.Description == "" || !json.Valid(tool.InputSchema) {
			t.Fatal("invalid catalog")
		}
		names[tool.Name] = true
	}
	first[0].InputSchema[0] = '!'
	first[1].Name = "changed"
	fresh := Tools()
	if fresh[0].InputSchema[0] != '{' || fresh[1].Name == "changed" {
		t.Fatal("caller mutated compiled catalog")
	}
}
