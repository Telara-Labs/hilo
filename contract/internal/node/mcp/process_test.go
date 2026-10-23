//go:build darwin || linux

package mcp_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/daemon"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/ipc"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

func buildBinary(t *testing.T, name, path string) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), name)
	cmd := exec.Command("go", "build", "-p", "2", "-o", bin, path)
	cmd.Env = append(os.Environ(), "GOWORK=off")
	if out, e := cmd.CombinedOutput(); e != nil {
		t.Fatalf("build %v %s", e, out)
	}
	return bin
}
func TestBuiltProcessShimDaemonMCP(t *testing.T) {
	// Actual shipped CLI shim and actual daemon in a separately built driver.
	// Only the explicitly authorized store/credential boundary is a fake.
	binary := buildBinary(t, "telara-memory", "../../../cmd/telara-memory")
	driver := buildBinary(t, "mcp-fixture-daemon", "./testdata/process")
	base := t.TempDir()
	if e := os.Chmod(base, 0700); e != nil {
		t.Fatal(e)
	}
	p, e := ipc.Resolve(filepath.Join(base, "data"), filepath.Join(base, "run"))
	if e != nil {
		t.Fatal(e)
	}
	if e = p.Prepare(); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { os.RemoveAll(p.Run) })
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	d := exec.CommandContext(ctx, driver, "daemon", p.Data, p.Run)
	var diagnostic bytes.Buffer
	d.Stderr = &diagnostic
	if e = d.Start(); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { d.Process.Kill(); d.Wait() })
	ready := false
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		probe, stop := context.WithTimeout(ctx, 100*time.Millisecond)
		_, e = daemon.Probe(probe, p)
		stop()
		if e == nil {
			ready = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !ready {
		t.Fatal("fixture daemon not ready", diagnostic.String())
	}
	cmd := exec.CommandContext(ctx, binary, "shim", "--data-dir", p.Data, "--run-dir", p.Run)
	input, e := cmd.StdinPipe()
	if e != nil {
		t.Fatal(e)
	}
	output, e := cmd.StdoutPipe()
	if e != nil {
		t.Fatal(e)
	}
	if e = cmd.Start(); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { input.Close(); output.Close(); cmd.Process.Kill(); cmd.Wait() })
	reader := bufio.NewReader(output)
	id := 0
	send := func(method string, params any) map[string]any {
		t.Helper()
		id++
		request := map[string]any{"jsonrpc": "2.0", "id": id, "method": method}
		if params != nil {
			request["params"] = params
		}
		if e := json.NewEncoder(input).Encode(request); e != nil {
			t.Fatal(e)
		}
		raw, e := reader.ReadBytes('\n')
		if e != nil {
			t.Fatal(e)
		}
		var response map[string]any
		if json.Unmarshal(raw, &response) != nil {
			t.Fatalf("invalid reply %s", raw)
		}
		if response["error"] != nil {
			t.Fatalf("RPC error %s", raw)
		}
		return response["result"].(map[string]any)
	}
	initialized := send("initialize", map[string]any{"protocolVersion": "2024-11-05", "clientInfo": map[string]any{"name": "fixture", "version": "1"}, "capabilities": map[string]any{}})
	if initialized["protocolVersion"] != "2024-11-05" {
		t.Fatal(initialized)
	}
	tools := send("tools/list", nil)["tools"].([]any)
	if len(tools) != 8 {
		t.Fatalf("daemon tool catalog %v", tools)
	}
	do := func(name string, args any, op string) string {
		t.Helper()
		reply := send("tools/call", map[string]any{"name": name, "arguments": args, "_meta": map[string]any{"com.telara/op-id": op}})
		if reply["isError"] == true {
			t.Fatalf("tool error %v", reply)
		}
		if _, ok := reply["structuredContent"]; ok {
			t.Fatal("raw structured representation")
		}
		return reply["content"].([]any)[0].(map[string]any)["text"].(string)
	}
	created := do("telara_task_create", map[string]any{"goal": "Process roundtrip"}, "process-create")
	idRe := regexp.MustCompile(`[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}`)
	task := idRe.FindString(strings.ReplaceAll(created, `\u002d`, "-"))
	if task == "" {
		t.Fatal("no task UUID in framed reply", created)
	}
	do("telara_task_checkpoint", map[string]any{"task_id": task, "milestone": "Built-process checkpoint", "next_steps": "Resume"}, "process-checkpoint")
	resumed := do("telara_task_resume", map[string]any{"task_id": task}, "process-resume")
	if !strings.Contains(resumed, `Built\u002dprocess checkpoint`) {
		t.Fatal("checkpoint absent", resumed)
	}
	repeated := do("telara_task_create", map[string]any{"goal": "Process roundtrip"}, "process-create")
	if repeated != created {
		t.Fatal("op replay reran mutation")
	}
	input.Close()
	io.Copy(io.Discard, output)
	if e = cmd.Wait(); e != nil {
		t.Fatal(e)
	}
	next := exec.CommandContext(ctx, binary, "shim", "--data-dir", p.Data, "--run-dir", p.Run)
	next.Stdin = strings.NewReader("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"telara_task_create\",\"arguments\":{\"goal\":\"Process roundtrip\"},\"_meta\":{\"com.telara/op-id\":\"process-create\"}}}\n")
	raw, e := next.CombinedOutput()
	if e != nil {
		t.Fatal(e, string(raw))
	}
	var replayed map[string]any
	if json.Unmarshal(raw, &replayed) != nil {
		t.Fatal(string(raw))
	}
	if replayed["result"].(map[string]any)["content"].([]any)[0].(map[string]any)["text"] != created {
		t.Fatal("reconnect duplicated")
	}
}
