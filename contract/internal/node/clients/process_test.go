package clients

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

type processResult struct {
	output  []byte
	err     error
	elapsed time.Duration
}

func isolatedEnv(home string) []string {
	// Keep only existing non-secret OS variables. No credentials, client config
	// overrides, session identifiers or real-home settings are inherited.
	allow := map[string]bool{"PATH": true, "USER": true, "LOGNAME": true, "SHELL": true, "LANG": true, "LC_ALL": true, "SYSTEMROOT": true, "WINDIR": true, "COMSPEC": true, "PATHEXT": true}
	var out []string
	for _, pair := range os.Environ() {
		key, _, _ := strings.Cut(pair, "=")
		if allow[strings.ToUpper(key)] {
			out = append(out, pair)
		}
	}
	// HOME is the explicit test profile requested by the owner. Existing platform
	// home/temp variables are redirected as well; no product switch is introduced.
	out = append(out, "HOME="+home)
	for _, k := range []string{"USERPROFILE", "TMPDIR", "TMP", "TEMP", "CFFIXED_USER_HOME"} {
		if _, ok := os.LookupEnv(k); ok {
			out = append(out, k+"="+home)
		}
	}
	return out
}
func runIsolated(t *testing.T, home, exe string, args []string, in []byte) processResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, args...)
	cmd.Dir = home
	cmd.Env = isolatedEnv(home)
	cmd.Stdin = bytes.NewReader(in)
	cmd.WaitDelay = time.Second
	start := time.Now()
	b, e := cmd.CombinedOutput()
	return processResult{b, e, time.Since(start)}
}

func TestInstalledMacClientsInTemporaryHomes(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("actual installed-client check is Mac only")
	}
	for _, c := range []Client{Claude, Codex, Cursor, Pi} {
		t.Run(string(c), func(t *testing.T) {
			o := options(t, c)
			d, e := Detect(o)
			if e != nil {
				t.Fatal(e)
			}
			if len(d.Executables) == 0 {
				t.Skip("not installed, native runtime UNVERIFIED")
			}
			exe := d.Executables[0]
			version := runIsolated(t, o.Home, exe, []string{"--version"}, nil)
			t.Logf("executable %s version %q exit %v elapsed %s", exe, strings.TrimSpace(string(version.output)), version.err, version.elapsed)
			if version.err != nil {
				t.Fatalf("installed client cannot start in isolated home %v", version.err)
			}
			l, _ := Locations(o)
			switch c {
			case Claude:
				before := []byte("{\n  \"unrelated\": \"fixture\", \"mcpServers\": {\"other\":{\"command\":\"fixture-other\",\"args\":[]}}\n}\n")
				put(t, l.MCP, before)
				add := runIsolated(t, o.Home, exe, []string{"mcp", "add", "--scope", "user", ServerName, "--", o.Executable, "shim", "--data-dir", o.StateDir}, nil)
				if add.err != nil {
					t.Fatalf("vendor add %v %s", add.err, add.output)
				}
				var cfg struct {
					Unrelated string `json:"unrelated"`
					Servers   map[string]struct {
						Command string   `json:"command"`
						Args    []string `json:"args"`
					} `json:"mcpServers"`
				}
				if e = json.Unmarshal(mustRead(t, l.MCP), &cfg); e != nil || cfg.Unrelated != "fixture" || cfg.Servers[ServerName].Command != o.Executable || cfg.Servers["other"].Command != "fixture-other" {
					t.Fatalf("vendor config %v %+v", e, cfg)
				}
				remove := runIsolated(t, o.Home, exe, []string{"mcp", "remove", "--scope", "user", ServerName}, nil)
				if remove.err != nil {
					t.Fatalf("vendor remove %v %s", remove.err, remove.output)
				}
				t.Logf("vendor MCP registration/remove validated in temporary home, add %s remove %s; shared-writer transaction NOT proven", add.elapsed, remove.elapsed)
				o, _, _ = resolve(o)
				changes := plan(o, l)
				put(t, l.Hooks, []byte(changes[1].Snippet))
				hook := runIsolated(t, o.Home, exe, []string{"--init-only", "--session-id", sessionFixture}, nil)
				if hook.err != nil {
					t.Fatalf("native init-only %v %s", hook.err, hook.output)
				}
				if len(spoolFiles(t, o)) == 0 {
					t.Fatal("native SessionStart did not publish a signal")
				}
				t.Logf("native Claude SessionStart dispatched without model or daemon in %s", hook.elapsed)
			case Codex:
				before := []byte("# untouched vendor fixture\nmodel = 'fixture'\n[mcp_servers.other]\ncommand = 'fixture-other'\n")
				put(t, l.MCP, before)
				add := runIsolated(t, o.Home, exe, []string{"mcp", "add", ServerName, "--", o.Executable, "shim", "--data-dir", o.StateDir}, nil)
				if add.err != nil {
					t.Fatalf("vendor add %v %s", add.err, add.output)
				}
				get := runIsolated(t, o.Home, exe, []string{"mcp", "get", ServerName, "--json"}, nil)
				if get.err != nil || !bytes.Contains(get.output, []byte(o.Executable)) {
					t.Fatalf("vendor get %v %s", get.err, get.output)
				}
				if !bytes.Contains(mustRead(t, l.MCP), []byte("mcp_servers.other")) {
					t.Fatal("vendor dropped unrelated entry")
				}
				remove := runIsolated(t, o.Home, exe, []string{"mcp", "remove", ServerName}, nil)
				if remove.err != nil {
					t.Fatalf("vendor remove %v %s", remove.err, remove.output)
				}
				t.Logf("vendor MCP registration/get/remove validated in temporary home, add %s get %s remove %s; shared-writer transaction NOT proven", add.elapsed, get.elapsed, remove.elapsed)
			case Pi:
				if _, e = Install(context.Background(), o); e != nil {
					t.Fatal(e)
				}
				proc := runIsolated(t, o.Home, exe, []string{"--offline", "--mode", "rpc", "--no-session", "--no-context-files"}, []byte("{\"type\":\"get_state\",\"id\":\"fixture\"}\n"))
				if proc.err != nil {
					t.Fatalf("native Pi RPC %v %s", proc.err, proc.output)
				}
				files := spoolFiles(t, o)
				if len(files) < 2 {
					t.Fatalf("native Pi start/shutdown signals missing, got %d, output %s", len(files), proc.output)
				}
				t.Logf("native Pi extension loaded and start/shutdown hooks dispatched in %s; agent_end and live MCP tools UNVERIFIED", proc.elapsed)
			case Cursor:
				o, _, _ = resolve(o)
				changes := plan(o, l)
				put(t, l.MCP, []byte(changes[0].Snippet))
				list := runIsolated(t, o.Home, exe, []string{"mcp", "list"}, nil)
				if !bytes.Contains(list.output, []byte(ServerName)) {
					t.Fatalf("native Cursor did not read MCP registration %v %s", list.err, list.output)
				}
				t.Logf("native Cursor parsed MCP entry with unavailable real shim in %s; hook dispatch and live MCP tools UNVERIFIED", list.elapsed)
			}
		})
	}
}

func TestPiExtensionNodeAPIFixtureRealSubprocess(t *testing.T) {
	node, e := exec.LookPath("node")
	if e != nil {
		t.Skip("node unavailable, JS API fixture UNVERIFIED")
	}
	o := options(t, Pi)
	l, _ := Locations(o)
	if _, e = Install(context.Background(), o); e != nil {
		t.Fatal(e)
	}
	transcript := filepath.Join(l.Transcripts, "fixture.jsonl")
	put(t, transcript, []byte("synthetic transcript\n"))
	// This is a vendor API-shape fixture, not a mocked Telara service and not
	// a native Pi acceptance claim. It launches actual Go hook child processes.
	js := fmt.Sprintf(`import { readFileSync } from 'node:fs';
const source=readFileSync(%s,'utf8');
const mod=await import('data:text/javascript;base64,'+Buffer.from(source).toString('base64'));
const handlers=new Map(); let registered;
mod.default({registerMcpServer:(name,config)=>{registered={name,config}},on:(name,fn)=>handlers.set(name,fn)});
if(registered.name!=='telara-memory'||registered.config.args[0]!=='shim') throw Error('registration');
const ctx={cwd:%s,sessionManager:{getSessionId:()=>%s,getSessionFile:()=>%s}};
for(const event of ['session_start','agent_end','session_shutdown']) await handlers.get(event)({secret:'never persisted'},ctx);
if(handlers.size!==3) throw Error('events');
`, quoted(l.Extension), quoted(o.Home), quoted(sessionFixture), quoted(transcript))
	r := runIsolated(t, o.Home, node, []string{"--input-type=module", "-e", js}, nil)
	if r.err != nil {
		t.Fatalf("JS fixture %v %s", r.err, r.output)
	}
	if len(spoolFiles(t, o)) != 3 {
		t.Fatalf("expected three real hook subprocess signals, got %d", len(spoolFiles(t, o)))
	}
	t.Logf("Pi API fixture with real Node/Go subprocesses passed in %s; native Pi UNVERIFIED", r.elapsed)
}
