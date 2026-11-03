package mcp_test

import (
	"context"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/Telara-Labs/hilo/contract/internal/node/mcp"
)

// Read git objects, never a sibling stream's possibly dirty source file. A
// standalone checkout still runs TestHostedFixtures; this workspace gate is
// explicit about missing source and fails on every extraction/git/schema error.
func TestCurrentGatewaySourceSchemas(t *testing.T) {
	repo := filepath.Join("..", "..", "..", "..", "..", "telara-inference")
	if _, err := os.Stat(filepath.Join(repo, ".git")); os.IsNotExist(err) {
		t.Skip("UNVERIFIED current gateway compatibility; sibling checkout absent")
	} else if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	source, err := exec.CommandContext(ctx, "git", "-C", repo, "show", "origin/main:services/mcp-gateway/src/internal/engine/capabilities.go").Output()
	if err != nil {
		t.Fatalf("read gateway origin/main: %v", err)
	}
	got := gatewaySchemas(t, source)
	want := map[string]any{}
	for _, tool := range mcp.Tools() {
		var schema any
		if err := json.Unmarshal(tool.InputSchema, &schema); err != nil {
			t.Fatal(err)
		}
		want[tool.Name] = schema
	}
	if !reflect.DeepEqual(got, want) {
		for name, schema := range got {
			if !reflect.DeepEqual(schema, want[name]) {
				t.Errorf("current gateway schema drift for %s; refresh hosted fixtures", name)
			}
		}
		t.Fatal("current gateway schema set differs from compiled catalog")
	}
}

func gatewaySchemas(t *testing.T, source []byte) map[string]any {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), "capabilities.go", source, 0)
	if err != nil {
		t.Fatal(err)
	}
	functions := map[string]bool{"taskListDef": true, "taskCreateDef": true, "taskResumeDef": true, "taskCheckpointDef": true, "taskPauseDef": true, "taskCompleteDef": true, "knowledgeSearchDef": true, "knowledgeGetContextDef": true}
	out := map[string]any{}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || !functions[fn.Name.Name] {
			continue
		}
		if fn.Body == nil || len(fn.Body.List) != 1 {
			t.Fatalf("%s is no longer a static tool definition", fn.Name.Name)
		}
		ret, ok := fn.Body.List[0].(*ast.ReturnStmt)
		if !ok || len(ret.Results) != 1 {
			t.Fatal("nonliteral tool definition")
		}
		lit, ok := ret.Results[0].(*ast.CompositeLit)
		if !ok {
			t.Fatal("nonliteral ToolDef")
		}
		var name string
		var schema any
		for _, field := range lit.Elts {
			kv, ok := field.(*ast.KeyValueExpr)
			if !ok {
				t.Fatal("unkeyed ToolDef")
			}
			key, ok := kv.Key.(*ast.Ident)
			if !ok {
				t.Fatal("unexpected ToolDef key")
			}
			switch key.Name {
			case "Name":
				name, ok = gatewayLiteral(t, kv.Value).(string)
				if !ok {
					t.Fatal("invalid tool name")
				}
			case "InputSchema":
				schema = gatewayLiteral(t, kv.Value)
			}
		}
		if name == "" || schema == nil || out[name] != nil {
			t.Fatal("missing/duplicate schema")
		}
		// Match JSON's value types, including future numeric schema constraints.
		encoded, err := json.Marshal(schema)
		if err != nil {
			t.Fatal(err)
		}
		if err = json.Unmarshal(encoded, &schema); err != nil {
			t.Fatal(err)
		}
		out[name] = schema
	}
	if len(out) != len(functions) {
		t.Fatalf("extracted %d of %d tool schemas", len(out), len(functions))
	}
	return out
}

// Evaluate only static syntax. No gateway code, imports or package init runs.
func gatewayLiteral(t *testing.T, expr ast.Expr) any {
	t.Helper()
	switch x := expr.(type) {
	case *ast.BasicLit:
		switch x.Kind {
		case token.STRING:
			s, err := strconv.Unquote(x.Value)
			if err != nil {
				t.Fatal(err)
			}
			return s
		case token.INT, token.FLOAT:
			n, err := strconv.ParseFloat(x.Value, 64)
			if err != nil {
				t.Fatal(err)
			}
			return n
		}
	case *ast.Ident:
		switch x.Name {
		case "true":
			return true
		case "false":
			return false
		case "ToolPrefix":
			return "telara_"
		}
	case *ast.BinaryExpr:
		if x.Op == token.ADD {
			a, aok := gatewayLiteral(t, x.X).(string)
			b, bok := gatewayLiteral(t, x.Y).(string)
			if aok && bok {
				return a + b
			}
		}
	case *ast.CompositeLit:
		switch x.Type.(type) {
		case *ast.MapType:
			m := map[string]any{}
			for _, field := range x.Elts {
				kv, ok := field.(*ast.KeyValueExpr)
				if !ok {
					t.Fatal("unkeyed schema map")
				}
				key, ok := gatewayLiteral(t, kv.Key).(string)
				if !ok {
					t.Fatal("nonstring schema key")
				}
				if _, exists := m[key]; exists {
					t.Fatal("duplicate schema key")
				}
				m[key] = gatewayLiteral(t, kv.Value)
			}
			return m
		case *ast.ArrayType:
			a := make([]any, 0, len(x.Elts))
			for _, v := range x.Elts {
				a = append(a, gatewayLiteral(t, v))
			}
			return a
		}
	}
	t.Fatalf("unsupported gateway schema expression %T", expr)
	return nil
}
