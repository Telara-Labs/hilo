package daemon

import (
	"context"
	"encoding/json"
	"sync"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/ipc"
)

// CancellationID ignores malformed and unrelated notifications without replying.
func CancellationID(r Request) (json.RawMessage, bool) {
	if r.Method != "notifications/cancelled" || len(r.ID) != 0 {
		return nil, false
	}
	raw, _, err := RequestParams(r.Params)
	if err != nil {
		return nil, false
	}
	var p struct {
		RequestID json.RawMessage `json:"requestId"`
		Reason    string          `json:"reason,omitempty"`
	}
	if ipc.DecodeStrict(raw, &p) != nil || !ValidRPCID(p.RequestID) {
		return nil, false
	}
	return p.RequestID, true
}

// Inflight serializes cancellation with the last reply check. Its lifetime and
// size are bounded by one transport connection and that transport's call slots.
type Inflight struct {
	mu    sync.Mutex
	calls map[string]*Flight
}
type Flight struct {
	Context context.Context
	cancel  context.CancelFunc
	owner   *Inflight
	key     string
}

func correlationKey(id json.RawMessage) string {
	key, err := RPCIDKey(id)
	if err != nil {
		// Very large exponents still correlate as opaque tokens. Operation hashing
		// independently refuses them; never expand an exponent to allocate a key.
		return "raw:" + string(id)
	}
	return key
}
func (p *Inflight) Begin(ctx context.Context, id json.RawMessage) (*Flight, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	key := correlationKey(id)
	if p.calls[key] != nil {
		return nil, false
	}
	if p.calls == nil {
		p.calls = make(map[string]*Flight)
	}
	ctx, cancel := context.WithCancel(ctx)
	f := &Flight{Context: ctx, cancel: cancel, owner: p, key: key}
	p.calls[key] = f
	return f, true
}
func (p *Inflight) Cancel(id json.RawMessage) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if f := p.calls[correlationKey(id)]; f != nil {
		f.cancel()
	}
}
func (f *Flight) Reply(write func()) {
	f.owner.mu.Lock()
	defer f.owner.mu.Unlock()
	if f.Context.Err() == nil {
		write()
	}
	if f.owner.calls[f.key] == f {
		delete(f.owner.calls, f.key)
	}
}
func (f *Flight) Finish() {
	f.owner.mu.Lock()
	defer f.owner.mu.Unlock()
	if f.owner.calls[f.key] == f {
		delete(f.owner.calls, f.key)
	}
	f.cancel()
}
