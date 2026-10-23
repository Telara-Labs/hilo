// Test driver only. The shipped command never imports or selects teststore.
package main

import (
	"context"
	"fmt"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/daemon"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/ipc"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/mcp"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/mcp/internal/teststore"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/shim"
	"os"
	"os/signal"
)

func main() {
	if len(os.Args) != 4 {
		os.Exit(2)
	}
	p, e := ipc.Resolve(os.Args[2], os.Args[3])
	if e != nil {
		os.Exit(2)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	if os.Args[1] == "daemon" {
		e = daemon.Run(ctx, daemon.Config{Paths: p, Open: func(context.Context) (daemon.Backend, error) {
			return mcp.New(teststore.New(), teststore.Resolver{}), nil
		}})
	} else {
		e = shim.Run(ctx, os.Stdin, os.Stdout, shim.Config{Paths: p, Hello: ipc.Hello{Shim: "fixture-shim", Client: "fixture"}})
	}
	if e != nil && ctx.Err() == nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
