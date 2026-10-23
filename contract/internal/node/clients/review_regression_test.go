package clients

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestStatusReturnsTypedReviewCaptureGaps(t *testing.T) {
	common := []CaptureGapCode{DaemonCaptureUnverified, CompleteCaptureUnverified, ProductionHookUnverified, ConnectedMCPUnverified}
	for c, codes := range map[Client][]CaptureGapCode{
		Claude: {SharedMCPMergeRequired, SharedHooksMergeRequired, NativeLifecycleUnverified},
		Codex:  {SharedMCPMergeRequired, SharedHooksMergeRequired, HookTrustReviewRequired, ExistingTOMLUnvalidated, NativeLifecycleUnverified},
		Cursor: {SharedMCPMergeRequired, SharedHooksMergeRequired, AssistantDecoderMissing, NativeLifecycleUnverified, PromptIdentityUnverified},
		Pi:     {ExtensionReloadRequired, NativeAgentEndUnverified},
	} {
		t.Run(string(c), func(t *testing.T) {
			o := options(t, c)
			for _, installed := range []bool{false, true} {
				if installed {
					if _, e := Install(context.Background(), o); e != nil {
						t.Fatal(e)
					}
				}
				r, e := Status(context.Background(), o)
				if e != nil {
					t.Fatal(e)
				}
				want := append(append([]CaptureGapCode{}, common...), codes...)
				if len(r.CaptureGaps) != len(want) {
					t.Fatalf("typed gaps %+v", r.CaptureGaps)
				}
				seen := map[CaptureGapCode]bool{}
				for _, g := range r.CaptureGaps {
					state := Unverified
					switch g.Code {
					case SharedMCPMergeRequired, SharedHooksMergeRequired, HookTrustReviewRequired, ExtensionReloadRequired:
						state = ManualRequired
					case AssistantDecoderMissing:
						state = Missing
					}
					if seen[g.Code] || g.State != state || g.Detail == "" {
						t.Fatalf("invalid typed gap %+v", g)
					}
					seen[g.Code] = true
				}
				for _, code := range want {
					if !seen[code] {
						t.Fatalf("missing %s", code)
					}
				}
			}
		})
	}
}

func TestHookDeadlineIncludesStalledFilesystem(t *testing.T) {
	o := options(t, Pi)
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	releaseWorker := func() { releaseOnce.Do(func() { close(release) }) }
	defer releaseWorker()
	// Return only after the simulated kernel stall is released. The result must
	// still meet its bound, and the worker must not publish after cancellation.
	writer := func(ctx context.Context, _ Options, _ []byte) error {
		close(entered)
		<-release
		defer close(done)
		return ctx.Err()
	}
	start := time.Now()
	r := runHookBounded(context.Background(), o, bytes.NewReader(encoded(payload(o, "agent_end"))), writer)
	select {
	case <-entered:
	default:
		t.Fatal("filesystem boundary not reached")
	}
	if r.Published || !r.PublicationUnknown || r.Code != "hook_timeout" || time.Since(start) > time.Second {
		t.Fatalf("%+v in %s", r, time.Since(start))
	}
	// No blocked worker survives this test.
	releaseWorker()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("worker did not finish")
	}
}

func TestPiDeadlineIndependentOfChildEvents(t *testing.T) {
	node, e := exec.LookPath("node")
	if e != nil {
		t.Skip("Node unavailable, deadline runtime UNVERIFIED")
	}
	o := options(t, Pi)
	o, _, _ = resolve(o)
	// No error or close event is emitted, even when kill is called. This catches
	// any implementation that merely changes the spawn timeout or kill signal.
	source := strings.Replace(piExtension(o), `import { spawn } from "node:child_process";`,
		`let kills=[];function spawn(){return {once(){},stdin:{on(){},end(){}},kill(signal){kills.push(signal)}}}`, 1)
	source += "\nexport {kills};\n"
	js := fmt.Sprintf(`const mod=await import('data:text/javascript;base64,'+Buffer.from(%s).toString('base64'));
 const handlers=new Map();mod.default({on:(name,fn)=>handlers.set(name,fn)});
 const ctx={cwd:%s,sessionManager:{getSessionId:()=>%s,getSessionFile:()=>''}};
 for(const event of ['session_start','agent_end','session_shutdown']) {
 const start=performance.now();await handlers.get(event)({},ctx);
 if(performance.now()-start>500)throw Error('callback exceeded bound');
 }
 `, quoted(source), quoted(o.Home), quoted(sessionFixture))
	js += "if(mod.kills.length!==3||mod.kills.some(x=>x!=='SIGKILL'))throw Error('forced cleanup missing');\n"
	r := runIsolated(t, o.Home, node, []string{"--input-type=module", "-e", js}, nil)
	if r.err != nil {
		t.Fatalf("deadline regression %v %s", r.err, r.output)
	}
}

func TestPiDeadlineWithRealChildIgnoringSIGTERM(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX signal regression; Windows runtime UNVERIFIED")
	}
	node, e := exec.LookPath("node")
	if e != nil {
		t.Skip("Node unavailable, deadline runtime UNVERIFIED")
	}
	o := options(t, Pi)
	o, _, _ = resolve(o)
	// A real OS child is made ready and proven to ignore SIGTERM before invoking
	// the generated handler. Only the spawn seam is replaced, never its deadline.
	source := strings.Replace(piExtension(o), `import { spawn } from "node:child_process";`,
		`const spawn=()=>globalThis.advisoryChild;`, 1)
	js := fmt.Sprintf(`import {spawn} from 'node:child_process';
 const child=spawn(process.execPath,['-e',"process.on('SIGTERM',()=>process.stdout.write('ignored\\n'));process.stdout.write('ready\\n');setInterval(()=>{},1000)"],{stdio:['pipe','pipe','ignore']});
 globalThis.advisoryChild=child;
 const waitLine=(line)=>new Promise((resolve,reject)=>{
 const timer=setTimeout(()=>reject(Error('child readiness timeout')),2000);
 const onData=(b)=>{if(b.toString().includes(line)){clearTimeout(timer);child.stdout.off('data',onData);resolve()}};
 child.stdout.on('data',onData);
 });
 try {
 await waitLine('ready');const ignored=waitLine('ignored');child.kill('SIGTERM');await ignored;
 if(child.exitCode!==null||child.signalCode!==null)throw Error('child did not ignore SIGTERM');
 const exited=new Promise(resolve=>child.once('exit',(_code,signal)=>resolve(signal)));
 const mod=await import('data:text/javascript;base64,'+Buffer.from(%s).toString('base64'));
 const handlers=new Map();mod.default({on:(name,fn)=>handlers.set(name,fn)});
 const ctx={cwd:%s,sessionManager:{getSessionId:()=>%s,getSessionFile:()=>''}};
 const start=performance.now();await handlers.get('agent_end')({},ctx);
 if(performance.now()-start>500)throw Error('advisory callback exceeded bound');
 const signal=await Promise.race([exited,new Promise(resolve=>setTimeout(()=>resolve('timeout'),1000))]);
 if(signal!=='SIGKILL')throw Error('forced cleanup missing '+signal);
 } finally {child.kill('SIGKILL');}
 `, quoted(source), quoted(o.Home), quoted(sessionFixture))
	r := runIsolated(t, o.Home, node, []string{"--input-type=module", "-e", js}, nil)
	if r.err != nil {
		t.Fatalf("real child regression %v %s", r.err, r.output)
	}
}

func TestSpoolExpiredContextDoesNotPublish(t *testing.T) {
	o := options(t, Pi)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if e := writeSpool(ctx, o, []byte("{}")); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	if len(spoolFiles(t, o)) != 0 {
		t.Fatal("expired context published")
	}
}

func TestPiDeadlineHandlesChildFailures(t *testing.T) {
	node, e := exec.LookPath("node")
	if e != nil {
		t.Skip("Node unavailable, failure runtime UNVERIFIED")
	}
	o := options(t, Pi)
	o, _, _ = resolve(o)
	for _, tc := range []struct {
		name, spawn string
		wantKills   int
	}{
		{"spawn_throws", `throw Error('unavailable');`, 0},
		{"error_event", `return {once(event,fn){if(event==='error')queueMicrotask(fn)},stdin:{on(){},end(){}},kill(){kills++}};`, 0},
		{"close_event", `return {once(event,fn){if(event==='close')queueMicrotask(fn)},stdin:{on(){},end(){}},kill(){kills++}};`, 0},
		{"stdin_throws", `return {once(){},stdin:{on(){},end(){throw Error('closed')}},kill(){kills++}};`, 1},
		{"kill_throws", `return {once(){},stdin:{on(){},end(){}},kill(){kills++;throw Error('cleanup failed')}};`, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := strings.Replace(piExtension(o), `import { spawn } from "node:child_process";`, `let kills=0;function spawn(){`+tc.spawn+`}`, 1) + "\nexport {kills};\n"
			js := fmt.Sprintf(`const mod=await import('data:text/javascript;base64,'+Buffer.from(%s).toString('base64'));
const handlers=new Map();mod.default({on:(name,fn)=>handlers.set(name,fn)});
const ctx={cwd:%s,sessionManager:{getSessionId:()=>%s,getSessionFile:()=>''}};
const start=performance.now();await handlers.get('agent_end')({},ctx);
if(performance.now()-start>500||mod.kills!==%d)throw Error('unbounded or incorrect cleanup');
`, quoted(source), quoted(o.Home), quoted(sessionFixture), tc.wantKills)
			r := runIsolated(t, o.Home, node, []string{"--input-type=module", "-e", js}, nil)
			if r.err != nil {
				t.Fatalf("child failure %v %s", r.err, r.output)
			}
		})
	}
}

type stalledHookReader struct{ release, closing, readDone, closeDone chan struct{} }

func (r *stalledHookReader) Read(_ []byte) (int, error) {
	defer close(r.readDone)
	<-r.release
	return 0, io.EOF
}
func (r *stalledHookReader) Close() error {
	defer close(r.closeDone)
	close(r.closing)
	<-r.release
	return nil
}
func TestHookDeadlineDoesNotWaitForReaderClose(t *testing.T) {
	o := options(t, Pi)
	r := &stalledHookReader{make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})}
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(r.release) }) }
	defer release()
	start := time.Now()
	result := RunHook(context.Background(), o, r)
	if result.Published || result.Code != "hook_timeout" || time.Since(start) > time.Second {
		t.Fatalf("%+v after %s", result, time.Since(start))
	}
	select {
	case <-r.closing:
	case <-time.After(time.Second):
		t.Fatal("timed-out input not closed")
	}
	release()
	for _, done := range []chan struct{}{r.readDone, r.closeDone} {
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("cleanup did not finish")
		}
	}
}
