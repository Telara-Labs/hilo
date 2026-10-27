package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/daemon"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/install"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/ipc"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/mcp"
)

// publicError is a fixed, content-free code reported verbatim.
type publicError string

func (e publicError) Error() string { return string(e) }

// eraseTimeout bounds one erase request, including the daemon's bounded
// physical scrub retries.
const eraseTimeout = mcp.ScrubWait + 45*time.Second

// notReachable is the fixed list of copies an erasure cannot reach.
var notReachable = []string{
	"vendor transcripts and vendor-side copies; the node cannot delete them",
	"text already in a model context or an agent transcript",
	"operating system and filesystem snapshots and backups",
	"hosted backups until their lifecycle ends",
	"a hosted embedding provider",
	"devices that have not synced this erasure",
	"a node restored from a backup older than this erasure, until it pulls the control",
	"bundle and backup files exported before this erasure, until they are deleted",
}

// profilePaths uses explicit paths, else the verified installation receipt.
func profilePaths(ctx context.Context, data, run, installDir string) (ipc.Paths, error) {
	if data != "" || run != "" {
		p, err := ipc.Resolve(data, run)
		if err != nil {
			return ipc.Paths{}, errors.New("invalid_paths")
		}
		return p, nil
	}
	dir := installDir
	if dir == "" {
		var err error
		if dir, err = install.DefaultDir(); err != nil {
			return ipc.Paths{}, err
		}
	}
	r := install.Inspect(ctx, dir)
	if r.State != "verified" && r.State != "stopped" {
		return ipc.Paths{}, publicError("install_" + r.State)
	}
	p, err := ipc.Resolve(r.DataDir, r.RunDir)
	if err != nil {
		return ipc.Paths{}, errors.New("invalid_paths")
	}
	return p, nil
}

func runErase(ctx context.Context, args []string, in io.Reader, out io.Writer) error {
	fs := flag.NewFlagSet("erase", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var ids repeated
	fs.Var(&ids, "id", "Exact record id to erase (repeatable)")
	reason := fs.String("reason", "user_request", "user_request, redaction_miss, device_compromise or retention_policy")
	yes := fs.Bool("yes", false, "Skip the interactive confirmation")
	asJSON := fs.Bool("json", false, "Print the receipt as JSON")
	scrubOnly := fs.Bool("scrub-pending", false, "Retry every pending physical scrub without erasing")
	data := fs.String("data-dir", "", "Owner-only data directory")
	run := fs.String("run-dir", "", "Owner-only runtime directory")
	installDir := fs.String("install-dir", "", "Owner-only installation directory")
	if fs.Parse(args) != nil || fs.NArg() != 0 {
		return errors.New("invalid_arguments")
	}
	if *scrubOnly == (len(ids) > 0) {
		return errors.New("invalid_arguments")
	}
	ctx, cancel := context.WithTimeout(ctx, eraseTimeout)
	defer cancel()
	p, err := profilePaths(ctx, *data, *run, *installDir)
	if err != nil {
		return err
	}
	if *scrubOnly {
		return scrubPending(ctx, p, *asJSON, out)
	}
	if !*yes {
		if err = confirm(in, out, len(ids)); err != nil {
			return err
		}
	}
	res, err := daemon.Call(ctx, p, "erase", "erase", map[string]any{"ids": []string(ids), "reason": *reason})
	if err != nil {
		return errors.New("daemon_unavailable")
	}
	if res.Error != nil {
		return publicError(res.Error.Message)
	}
	raw, _ := res.Result.(json.RawMessage)
	var result mcp.EraseResult
	if err = json.Unmarshal(raw, &result); err != nil {
		return ipc.ErrFrame
	}
	if *asJSON {
		if err = ipc.WriteFrame(out, map[string]any{"receipt": result.Receipt, "scrub": result.Scrub, "not_reachable": notReachable}); err != nil {
			return err
		}
	} else if err = writeReceipt(out, result); err != nil {
		return err
	}
	switch result.Scrub.State {
	case "complete":
		return nil
	case "blocked":
		return publicError("scrub_blocked")
	}
	return publicError("scrub_pending")
}

// confirm requires the owner to type the confirmation word. A closed or
// non-interactive input without --yes is a refusal, never consent.
func confirm(in io.Reader, out io.Writer, n int) error {
	fmt.Fprintf(out, "Permanently erase %d record(s) and every copy derived from them. This cannot be undone.\nType erase to confirm. ", n)
	line, err := bufio.NewReader(io.LimitReader(in, 64)).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return publicError("confirmation_required")
	}
	if strings.TrimSpace(line) != "erase" {
		return publicError("confirmation_required")
	}
	return nil
}

func scrubPending(ctx context.Context, p ipc.Paths, asJSON bool, out io.Writer) error {
	res, err := daemon.Call(ctx, p, "erase", "scrub", struct{}{})
	if err != nil {
		return errors.New("daemon_unavailable")
	}
	if res.Error != nil {
		return publicError(res.Error.Message)
	}
	raw, _ := res.Result.(json.RawMessage)
	var result struct {
		Jobs []mcp.ScrubState `json:"jobs"`
	}
	if err = json.Unmarshal(raw, &result); err != nil {
		return ipc.ErrFrame
	}
	if asJSON {
		if err = ipc.WriteFrame(out, result); err != nil {
			return err
		}
	} else {
		var b strings.Builder
		fmt.Fprintf(&b, "Physical scrub\n  %-22s %d\n", "pending jobs retried", len(result.Jobs))
		for _, j := range result.Jobs {
			fmt.Fprintf(&b, "  %-22s %s\n", j.Control, j.State)
		}
		if _, err = io.WriteString(out, b.String()); err != nil {
			return err
		}
	}
	for _, j := range result.Jobs {
		if j.State != "complete" {
			return publicError("scrub_pending")
		}
	}
	return nil
}

func writeReceipt(out io.Writer, r mcp.EraseResult) error {
	var b strings.Builder
	line := func(key, value string) { fmt.Fprintf(&b, "  %-22s %s\n", key, value) }
	if r.Receipt.Reason == "redaction_miss" {
		b.WriteString("Rotate this credential now.\n")
	}
	b.WriteString("Erasure receipt\n")
	line("control", r.Receipt.Control)
	line("sequence", fmt.Sprint(r.Receipt.Sequence))
	line("reason", r.Receipt.Reason)
	line("event bans", fmt.Sprint(r.Receipt.EventBans))
	if r.Receipt.Pending {
		line("coverage", "pending, disclosure for this owner stays blocked until resolved")
	} else {
		line("coverage", "complete")
	}
	scrub := r.Scrub.State
	if r.Scrub.State == "complete" {
		scrub = fmt.Sprintf("complete at generation %d", r.Scrub.Generation)
	} else if r.Scrub.State != "blocked" {
		scrub = "pending, retry with erase --scrub-pending"
	}
	line("physical scrub", scrub)
	b.WriteString("\nRequested records\n")
	for _, t := range r.Receipt.Requested {
		line(t.ID, describe(t.Kind, t.Status))
	}
	if len(r.Receipt.Closure) > 0 {
		b.WriteString("\nDerived records erased with them\n")
		for _, t := range r.Receipt.Closure {
			line(t.ID, describe(t.Kind, t.Status))
		}
	}
	b.WriteString("\nNot reachable by this erasure\n")
	for _, s := range notReachable {
		b.WriteString("  - " + s + "\n")
	}
	_, err := io.WriteString(out, b.String())
	return err
}

func describe(kind, status string) string {
	switch status {
	case "not_present":
		return "not present here, banned if it arrives later"
	case "control_unaffected":
		return "control record, not erasable"
	}
	if kind == "" {
		return status
	}
	return status + " (" + kind + ")"
}
