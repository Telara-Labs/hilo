package doctor

import (
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
)

// WriteText renders the report as aligned sections for a terminal.
func WriteText(w io.Writer, r Report) error {
	var b strings.Builder
	line := func(key, value string) { fmt.Fprintf(&b, "  %-22s %s\n", key, value) }
	section := func(name string) { fmt.Fprintf(&b, "\n%s\n", name) }
	yes := func(v bool) string { return strconv.FormatBool(v) }
	list := func(xs []string) string {
		if len(xs) == 0 {
			return "none"
		}
		return strings.Join(xs, ", ")
	}

	b.WriteString("hilo doctor\n")
	line("data directory", r.DataDir)
	line("problems", list(r.Problems))

	section("Install receipt")
	if r.Install == nil {
		line("receipt", "not checked")
	} else {
		line("receipt", r.Install.State)
		line("digest verified", yes(r.Install.Verified))
		if r.Install.Version != "" {
			line("version", r.Install.Version)
		}
		if r.Install.Manager != "" {
			line("service manager", r.Install.Manager)
		}
		if r.Install.Error != "" {
			line("error", r.Install.Error)
		}
	}

	section("Daemon")
	line("reachable", yes(r.Daemon.Reachable))
	if r.Daemon.Reachable {
		line("pid", strconv.Itoa(r.Daemon.PID))
		line("store wired", yes(r.Daemon.StoreWired))
	} else if r.Daemon.Error != "" {
		line("error", r.Daemon.Error)
	}

	section("Key store")
	line("backend", r.KeyStore.Backend)
	line("location", r.KeyStore.Location)
	line("custody record", r.KeyStore.CustodyRecord)
	line("installed identity", r.KeyStore.InstalledProfile)
	line("runtime authority", r.KeyStore.RuntimeAuthority)

	section("Signing")
	line("backlog", strconv.FormatInt(r.Signing.Backlog, 10))
	line("signature states", counts(r.Signing.SignatureStates))

	section("Hooks")
	for _, h := range r.Hooks {
		value := fmt.Sprintf("client %s, mcp %s, hooks %s, trust %s", h.Installation, h.MCP, h.Hooks, h.Trust)
		if h.Error != "" {
			value += ", error " + h.Error
		}
		line(h.Client, value)
		var gaps []string
		for _, g := range h.CaptureGaps {
			gaps = append(gaps, g.Code+" ("+g.State+")")
		}
		line("  capture gaps", list(gaps))
	}

	section("Capture")
	line("incomplete", yes(r.Capture.Incomplete))
	line("reasons", list(r.Capture.Reasons))
	line("pending spool", strconv.Itoa(r.Capture.PendingSpool))
	line("spool gaps", counts(r.Capture.SpoolGaps))
	clients := make([]string, 0, len(r.Capture.Spool))
	for c := range r.Capture.Spool {
		clients = append(clients, c)
	}
	sort.Strings(clients)
	for _, c := range clients {
		s := r.Capture.Spool[c]
		line("  spool "+c, fmt.Sprintf("%d new, %d tmp", s.New, s.Tmp))
	}
	if len(r.Daemon.Capture) > 0 {
		keys := make([]string, 0, len(r.Daemon.Capture))
		for k := range r.Daemon.Capture {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var parts []string
		for _, k := range keys {
			parts = append(parts, fmt.Sprintf("%s %d", k, r.Daemon.Capture[k]))
		}
		line("daemon counters", strings.Join(parts, ", "))
	}

	section("Store")
	line("state", r.Store.State)
	if r.Store.State == "ok" {
		line("generation", strconv.FormatInt(r.Store.Generation, 10))
		line("records", strconv.FormatInt(r.Store.Records, 10))
	}
	if r.Store.Error != "" {
		line("error", r.Store.Error)
	}

	section("Policy")
	line("installed", yes(r.Policy.Installed))
	line("freshness", r.Policy.Freshness)
	if r.Policy.Installed {
		line("sequence", strconv.FormatInt(r.Policy.Seq, 10))
		line("stale", yes(r.Policy.Stale))
		line("fail closed", yes(r.Policy.FailClosed))
		line("kill sync", yes(r.Policy.KillSync))
		line("kill capture", yes(r.Policy.KillCapture))
		line("kill withdraw pulled", yes(r.Policy.KillWithdraw))
	}
	if r.Policy.EvaluationCode != "" {
		line("error", r.Policy.EvaluationCode)
	}

	section("Scrub")
	line("pending jobs", strconv.FormatInt(r.Scrub.Pending, 10))
	line("complete jobs", strconv.FormatInt(r.Scrub.Complete, 10))
	line("erasure pending", strconv.FormatInt(r.Scrub.ErasurePending, 10))
	line("privacy holds", strconv.FormatInt(r.Scrub.ProjectionHolds+r.Scrub.PrivacyBarriers, 10))
	line("wal bytes", strconv.FormatInt(r.Scrub.WALBytes, 10))
	for _, j := range r.Scrub.Jobs {
		line("  job "+short(j.Control), fmt.Sprintf("%s after %d attempts", j.State, j.Attempts))
	}

	section("Sync")
	line("configured", yes(r.Sync.Configured))
	if r.Sync.Configured {
		line("enabled", yes(r.Sync.Enabled))
		line("enrolled", yes(r.Sync.Enrolled))
		line("sync database", r.Sync.State)
		line("outbox", counts(r.Sync.Outbox))
	}
	line("blockers", list(r.Sync.Blockers))
	_, err := io.WriteString(w, b.String())
	return err
}

func counts(m map[string]int64) string {
	if len(m) == 0 {
		return "none"
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s %d", k, m[k]))
	}
	return strings.Join(parts, ", ")
}

func short(id string) string {
	if len(id) > 16 {
		return id[:16]
	}
	return id
}
