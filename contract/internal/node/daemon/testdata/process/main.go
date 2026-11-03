// Local transport test driver. Uses the actual daemon and real filesystem locks.
// It is excluded from shipped packages. No Telara service is substituted.
package main

import (
	"context"
	"encoding/json"
	"os"
	"os/signal"
	"path/filepath"
	"time"

	"github.com/Telara-Labs/hilo/contract/internal/node/daemon"
	"github.com/Telara-Labs/hilo/contract/internal/node/ipc"
)

type backend struct{ dir string }

func (b *backend) Close() error {
	if _, e := os.Stat(filepath.Join(b.dir, "fail-close")); e == nil {
		os.WriteFile(filepath.Join(b.dir, "closing"), []byte("closing"), 0600)
		if _, e := os.Stat(filepath.Join(b.dir, "allow-close")); e != nil {
			return daemon.ErrSettlement
		}
	}

	if lock, e := ipc.Lock(filepath.Join(b.dir, "db.lock")); e == nil {
		lock.Close()
		panic("close after lock release")
	}
	f, e := os.OpenFile(filepath.Join(b.dir, "checkpoint"), os.O_CREATE|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	if _, e = f.WriteString("closed"); e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil {
		return e
	}
	return ce
}
func (b *backend) Handle(ctx context.Context, h ipc.Hello, r daemon.Request) daemon.Response {
	var params struct {
		Name string `json:"name"`
	}
	json.Unmarshal(r.Params, &params)
	if r.Method == "tools/call" && params.Name == "fixture_write" {
		r.Method = "commit_then_die"
	}
	switch r.Method {
	case "settle":
		os.WriteFile(filepath.Join(b.dir, "entered"), []byte("entered"), 0600)
		for {
			if _, e := os.Stat(filepath.Join(b.dir, "release")); e == nil {
				break
			}
			select {
			case <-ctx.Done():
				os.WriteFile(filepath.Join(b.dir, "premature-cancel"), []byte("cancelled"), 0600)
				return daemon.Error(r.ID, "premature_cancel")
			case <-time.After(5 * time.Millisecond):
			}
		}
		os.WriteFile(filepath.Join(b.dir, "settled"), []byte("settled"), 0600)
		return daemon.Response{JSONRPC: "2.0", ID: r.ID, Result: map[string]bool{"settled": true}}

	case "hold":
		<-ctx.Done()
		return daemon.Error(r.ID, "canceled")
	case "commit_then_die":
		f, e := os.OpenFile(filepath.Join(b.dir, "committed"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if e != nil {
			panic(e)
		}
		f.WriteString("one\n")
		f.Sync()
		f.Close()
		os.Exit(23)
	case "tools/call":
		out := daemon.Response{JSONRPC: "2.0", ID: r.ID, Result: json.RawMessage(`{"ok":true}`)}
		return out
	}
	return daemon.Error(r.ID, "unknown")
}
func main() {
	p, e := ipc.Resolve(os.Args[1], os.Args[2])
	if e != nil {
		panic(e)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	e = daemon.Run(ctx, daemon.Config{Paths: p, Open: func(context.Context) (daemon.Backend, error) { return &backend{p.Data}, nil }})
	if len(os.Args) > 3 && os.Args[3] == "linger" {
		select {}
	}
	if e != nil && e != context.Canceled {
		time.Sleep(time.Millisecond)
		os.Exit(1)
	}
}
