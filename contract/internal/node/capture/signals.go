package capture

import (
	"context"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/clients"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/store"
	"github.com/Telara-Labs/telara-memory/contract/transport"
)

// SignalStore is the durable boundary required by the spool protocol. Implement
// on the same SQLite store: CaptureSignal must commit its client/ULID receipt
// and announcement in the SAME FULL transaction as the capture plan, including
// no-change/recovered-transition cases. AdmitSignal handles identity-only hints.
// There is intentionally no post-Capture ACK fallback.
// These methods accept trusted in-process validated hints, never raw hook JSON.
type SignalStore interface {
	SignalDone(context.Context, string, string) (bool, error)
	CaptureSignal(context.Context, transport.HookSignal, string, store.CaptureRequest, func(*store.CaptureTxn) (store.CommitPlan, error)) (store.CaptureReceipt, error)
	AdmitSignal(context.Context, transport.HookSignal, string) error
}

// PendingSignalStore applies a validated announcement without acknowledging its
// transcript. It retains identity/path metadata only. A later CaptureSignal for
// the exact same immutable hint must atomically complete its output and receipt.
type PendingSignalStore interface {
	ObserveSignal(context.Context, transport.HookSignal, string) error
}

// SuppressedSignalStore acknowledges a transcript hint whose unit erasure has
// suppressed. It must recheck suppression under its writer and record the hint
// as done in one durable transaction, without reading, sealing or advancing
// capture progress. A suppressed unit is skipped; it never holds the drain.
type SuppressedSignalStore interface {
	SkipSuppressedSignal(context.Context, transport.HookSignal, string, store.SourceOccurrence) error
}

type signalAdmission struct {
	signal transport.HookSignal
	ulid   string
	store  SignalStore
}
type signalAdmissionKey struct{}

// CaptureSignal retains the ordinary source/policy/erasure gates while binding
// the atomically committed output to one immutable spool identity. A unit that
// erasure suppressed is skipped: when the backend durably acknowledges the
// hint, the result is Status "suppressed" with no error and no records.
func (p *Pipeline) CaptureSignal(ctx context.Context, unit Unit, signal transport.HookSignal, ulid string) (Result, error) {
	if p == nil || ctx == nil || ctx.Err() != nil || !signalID(ulid) {
		return refused(hold("invalid_signal"))
	}
	backend := p.signals
	if backend == nil {
		return refused(hold("spool_receipts_unavailable"))
	}
	return p.Capture(context.WithValue(ctx, signalAdmissionKey{}, signalAdmission{signal, ulid, backend}), unit)
}

func signalID(s string) bool {
	if len(s) != 26 || s[0] > '7' {
		return false
	}
	for _, r := range s {
		if !strings.ContainsRune("0123456789ABCDEFGHJKMNPQRSTVWXYZ", r) {
			return false
		}
	}
	return true
}

type SpoolStats struct{ Done, Dropped, Abandoned, Gap uint64 }
type Collector struct {
	mu                       sync.Mutex
	pipeline                 *Pipeline
	dir                      string
	rules                    map[string]transport.HookRules
	rootIDs                  map[string]string
	done, dropped, abandoned atomic.Uint64
	gap                      atomic.Uint64
	closed                   bool
}

// NewCollector uses only immutable trusted roots and the installed adapters'
// finite hook vocabulary. Creation does not inspect transcript contents.
// The caller must already hold the daemon's exclusive writer admission.
func NewCollector(p *Pipeline, data string) (*Collector, error) {
	if p == nil || !filepath.IsAbs(data) || filepath.Clean(data) != data {
		return nil, hold("invalid_config")
	}
	c := &Collector{pipeline: p, dir: data, rules: map[string]transport.HookRules{}, rootIDs: map[string]string{}}
	for id, root := range p.config.Roots {
		client := root.Client
		switch client {
		case "claude-code":
			client = "claude"
		case "cursor-agent":
			client = "cursor"
		}
		if _, dup := c.rules[client]; dup {
			return nil, hold("ambiguous_root")
		}
		rules, err := clients.HookRules(clients.Options{Client: clients.Client(client), Home: p.config.Home})
		if err != nil {
			return nil, hold("invalid_config")
		}
		// A root override comes only from trusted pipeline configuration, not hints.
		rules.TranscriptRoot = root.AbsPath
		c.rules[client] = rules
		c.rootIDs[client] = id
	}
	return c, nil
}

func (c *Collector) Stats() SpoolStats {
	return SpoolStats{Done: c.done.Load(), Dropped: c.dropped.Load(), Abandoned: c.abandoned.Load(), Gap: c.gap.Load()}
}
func (c *Collector) Close() error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	return c.pipeline.Close()
}

// Drain is synchronous. Each client's spool is drained independently, in ULID
// order, so one client's refusal never holds another client's hints. Every
// file has one explicit outcome (see drainClasses): pending files stay and are
// retried, gap and dropped files are acknowledged or deleted and counted, and
// only a fatal store, spool or configuration failure is returned. A fatal
// failure stops that client's remaining files only. New renames after a
// directory snapshot are observed on the next request.
func (c *Collector) Drain(ctx context.Context, credential string) error {
	if c == nil || ctx == nil || ctx.Err() != nil || credential == "" {
		return hold("invalid_signal")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return hold("closed")
	}
	names := make([]string, 0, len(c.rules))
	for client := range c.rules {
		names = append(names, client)
	}
	sort.Strings(names)
	var first error
	for _, client := range names {
		if ctx.Err() != nil {
			return hold("cancelled")
		}
		if err := c.drainClient(ctx, client); err != nil && first == nil {
			first = err
		}
	}
	return first
}

func (c *Collector) drainClient(ctx context.Context, client string) error {
	// Announcements come first; abandoned-write cleanup cannot delay them.
	err := c.drainNew(ctx, client)
	if e := c.abandonTmp(ctx, client); err == nil {
		err = e
	}
	return err
}

func (c *Collector) drainNew(ctx context.Context, client string) error {
	d, err := openSignalDirectory(c.dir, filepath.Join("spool", client, "new"))
	if err != nil || d == nil {
		return err
	}
	defer d.close()
	entries, err := d.names()
	if err != nil {
		return err
	}
	sort.Strings(entries)
	for _, name := range entries {
		if ctx.Err() != nil {
			return hold("cancelled")
		}
		if err := c.drainOne(ctx, client, d, name); err != nil {
			return err
		}
	}
	return nil
}

func (c *Collector) abandonTmp(ctx context.Context, client string) error {
	tmp, err := openSignalDirectory(c.dir, filepath.Join("spool", client, "tmp"))
	if err != nil || tmp == nil {
		return err
	}
	defer tmp.close()
	entries, err := tmp.names()
	if err != nil {
		return err
	}
	for _, name := range entries {
		if ctx.Err() != nil {
			return hold("cancelled")
		}
		removed, err := tmp.abandon(name, time.Now().Add(-time.Hour))
		if err != nil {
			return err
		}
		if removed {
			c.abandoned.Add(1)
		}
	}
	return nil
}

// drainOne returns an error only for a fatal outcome.
func (c *Collector) drainOne(ctx context.Context, client string, d *signalDirectory, name string) error {
	backend := c.pipeline.signals
	ulid := strings.TrimSuffix(name, ".json")
	validName := strings.HasSuffix(name, ".json") && signalID(ulid)
	// Check durable completion before reading a possibly changed transcript.
	if validName && backend != nil {
		done, err := backend.SignalDone(ctx, client, ulid)
		if err != nil {
			return hold("spool_receipt_failed")
		}
		if done {
			return c.finish(d, name, &c.done)
		}
	}
	raw, err := d.read(name)
	if err != nil {
		return err
	}
	var signal *transport.HookSignal
	parseErr := strictJSON(raw)
	if parseErr == nil {
		signal, parseErr = transport.ParseHook(raw, c.rules[client])
	}
	clear(raw)
	if !validName || parseErr != nil || signal.NativeSession == "" {
		// Malformed files are deleted and counted, never archived (07 7.2).
		return c.finish(d, name, &c.dropped)
	}
	if backend == nil {
		return hold("spool_receipts_unavailable")
	}
	if signal.TranscriptPath == "" {
		if err = backend.AdmitSignal(ctx, *signal, ulid); err != nil {
			if _, fatal := classifySpoolStore(err, "spool_admission_failed"); fatal != nil {
				return fatal
			}
			return c.finish(d, name, &c.dropped)
		}
		return c.finish(d, name, &c.done)
	}
	rootID := c.rootIDs[client]
	root := c.pipeline.config.Roots[rootID]
	relative, err := filepath.Rel(root.AbsPath, signal.TranscriptPath)
	if err != nil {
		return c.finish(d, name, &c.dropped)
	}
	native, err := resolve(preparationConfig{root: root.AbsPath, home: c.pipeline.config.Home, owner: c.pipeline.config.OwnerGenesis, machine: c.pipeline.config.MachineID}, unitLocator{client: root.Client, relative: relative, source: strings.Repeat("0", 64), session: "sk1:" + strings.Repeat("0", 64)})
	if err != nil || native != signal.NativeSession {
		// The hint names a session its own path contradicts.
		return c.finish(d, name, &c.dropped)
	}
	if _, err = c.pipeline.CaptureSignal(ctx, Unit{rootID, relative}, *signal, ulid); err == nil {
		// The backend only returns success after its FULL transaction is durable.
		// Crash before unlink reuses SignalDone and never reopens erased source text.
		return c.finish(d, name, &c.done)
	}
	class, code := classify(err)
	switch class {
	case drainPending:
		observer, ok := backend.(PendingSignalStore)
		if !ok {
			return hold("spool_observation_unavailable")
		}
		if e := observer.ObserveSignal(ctx, *signal, ulid); e != nil {
			if _, fatal := classifySpoolStore(e, "spool_admission_failed"); fatal != nil {
				return fatal
			}
			return c.finish(d, name, &c.dropped)
		}
		// No spool_done and no unlink until transcript admission.
		return nil
	case drainGap:
		gaps, ok := backend.(GapSignalStore)
		if !ok {
			// Without a durable gap receipt the hint cannot be acknowledged.
			return err
		}
		if e := gaps.SkipSignalWithGap(ctx, *signal, ulid, code); e != nil {
			if _, fatal := classifySpoolStore(e, "spool_gap_failed"); fatal != nil {
				return fatal
			}
			return c.finish(d, name, &c.dropped)
		}
		return c.finish(d, name, &c.gap)
	case drainDrop:
		return c.finish(d, name, &c.dropped)
	}
	return err
}

func (c *Collector) finish(d *signalDirectory, name string, counter *atomic.Uint64) error {
	if err := d.remove(name); err != nil {
		return err
	}
	counter.Add(1)
	return nil
}

// Recover removes already admitted hints at startup, without reopening source
// text or repeating a seal. Missing atomic receipt support leaves hints pending.
// The caller holds the daemon writer lifetime before exposing a listener.
func (c *Collector) Recover(ctx context.Context) error {
	if c == nil || ctx == nil || ctx.Err() != nil {
		return hold("cancelled")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return hold("closed")
	}
	backend := c.pipeline.signals
	if backend == nil {
		return nil
	}
	clients := make([]string, 0, len(c.rules))
	for client := range c.rules {
		clients = append(clients, client)
	}
	sort.Strings(clients)
	// Each client recovers independently; the first failure is reported.
	var first error
	for _, client := range clients {
		if ctx.Err() != nil {
			return hold("cancelled")
		}
		err := func() error {
			d, err := openSignalDirectory(c.dir, filepath.Join("spool", client, "new"))
			if err != nil {
				return err
			}
			if d == nil {
				return nil
			}
			defer d.close()
			names, err := d.names()
			if err != nil {
				return err
			}
			sort.Strings(names)
			for _, name := range names {
				if ctx.Err() != nil {
					return hold("cancelled")
				}
				ulid := strings.TrimSuffix(name, ".json")
				if !strings.HasSuffix(name, ".json") || !signalID(ulid) {
					continue
				}
				done, err := backend.SignalDone(ctx, client, ulid)
				if err != nil {
					return hold("spool_receipt_failed")
				}
				if done {
					if err = d.remove(name); err != nil {
						return err
					}
					c.done.Add(1)
				}
			}
			return nil
		}()
		if err != nil && first == nil {
			first = err
		}
	}
	return first
}
