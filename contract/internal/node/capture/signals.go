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

type signalAdmission struct {
	signal transport.HookSignal
	ulid   string
	store  SignalStore
}
type signalAdmissionKey struct{}

// CaptureSignal retains the ordinary source/policy/erasure gates while binding
// the atomically committed output to one immutable spool identity.
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

type SpoolStats struct{ Done, Dropped, Abandoned uint64 }
type Collector struct {
	mu                       sync.Mutex
	pipeline                 *Pipeline
	dir                      string
	rules                    map[string]transport.HookRules
	rootIDs                  map[string]string
	done, dropped, abandoned atomic.Uint64
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
	return SpoolStats{Done: c.done.Load(), Dropped: c.dropped.Load(), Abandoned: c.abandoned.Load()}
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

// Drain is synchronous. Snapshot each new directory before processing, then
// merge-sort globally by ULID. New renames after that snapshot are observed on
// the next request. Pending valid signals never become a successful empty drain
// if source sealing/admission is unavailable or its outcome is unknown.
func (c *Collector) Drain(ctx context.Context, credential string) error {
	if c == nil || ctx == nil || ctx.Err() != nil || credential == "" {
		return hold("invalid_signal")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return hold("closed")
	}
	if ctx.Err() != nil {
		return hold("cancelled")
	}
	type pending struct {
		client, name string
		dir          *signalDirectory
	}
	var items []pending
	var dirs []*signalDirectory
	defer func() {
		for _, d := range dirs {
			d.close()
		}
	}()
	names := make([]string, 0, len(c.rules))
	for client := range c.rules {
		names = append(names, client)
	}
	sort.Strings(names)
	for _, client := range names {
		for _, sub := range []string{"tmp", "new"} {
			d, err := openSignalDirectory(c.dir, filepath.Join("spool", client, sub))
			if err != nil {
				return err
			}
			if d == nil {
				continue
			}
			dirs = append(dirs, d)
			entries, err := d.names()
			if err != nil {
				return err
			}
			for _, name := range entries {
				if ctx.Err() != nil {
					return hold("cancelled")
				}
				if sub == "tmp" {
					removed, err := d.abandon(name, time.Now().Add(-time.Hour))
					if err != nil {
						return err
					}
					if removed {
						c.abandoned.Add(1)
					}
				} else {
					if len(items) >= 65536 {
						return hold("spool_limit")
					}
					items = append(items, pending{client, name, d})
				}
			}
		}
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].name != items[j].name {
			return items[i].name < items[j].name
		}
		return items[i].client < items[j].client
	})
	backend := c.pipeline.signals
	for _, item := range items {
		if ctx.Err() != nil {
			return hold("cancelled")
		}
		ulid := strings.TrimSuffix(item.name, ".json")
		validName := strings.HasSuffix(item.name, ".json") && signalID(ulid)
		// Check durable completion before reading a possibly changed transcript.
		if validName && backend != nil {
			done, err := backend.SignalDone(ctx, item.client, ulid)
			if err != nil {
				return hold("spool_receipt_failed")
			}
			if done {
				if err = item.dir.remove(item.name); err != nil {
					return err
				}
				c.done.Add(1)
				continue
			}
		}
		raw, err := item.dir.read(item.name)
		if err != nil {
			return err
		}
		var signal *transport.HookSignal
		parseErr := strictJSON(raw)
		if parseErr == nil {
			signal, parseErr = transport.ParseHook(raw, c.rules[item.client])
		}
		clear(raw)
		if !validName || parseErr != nil || signal.NativeSession == "" {
			if err = item.dir.remove(item.name); err != nil {
				return err
			}
			c.dropped.Add(1)
			continue
		}
		if backend == nil {
			return hold("spool_receipts_unavailable")
		}
		if signal.TranscriptPath == "" {
			if err = backend.AdmitSignal(ctx, *signal, ulid); err != nil {
				return hold("spool_admission_failed")
			}
		} else {
			rootID := c.rootIDs[item.client]
			root := c.pipeline.config.Roots[rootID]
			relative, err := filepath.Rel(root.AbsPath, signal.TranscriptPath)
			if err != nil {
				return hold("unsafe_path")
			}
			native, err := resolve(preparationConfig{root: root.AbsPath, home: c.pipeline.config.Home, owner: c.pipeline.config.OwnerGenesis, machine: c.pipeline.config.MachineID}, unitLocator{client: root.Client, relative: relative, source: strings.Repeat("0", 64), session: "sk1:" + strings.Repeat("0", 64)})
			if err != nil || native != signal.NativeSession {
				return hold("signal_session_mismatch")
			}
			if _, err = c.pipeline.CaptureSignal(ctx, Unit{rootID, relative}, *signal, ulid); err != nil {
				return err
			}
		}
		// The backend only returns success after its FULL transaction is durable.
		// Crash before unlink reuses SignalDone and never reopens erased source text.
		if err = item.dir.remove(item.name); err != nil {
			return err
		}
		c.done.Add(1)
	}
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
		if err != nil {
			return err
		}
	}
	return nil
}
