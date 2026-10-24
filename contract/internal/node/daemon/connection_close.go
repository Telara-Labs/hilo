package daemon

import (
	"context"
	"sync"
)

type closeKey struct{}
type peerPIDKey struct{}

// AuthenticatedPeerPID comes from the kernel credential check, never Hello.
func AuthenticatedPeerPID(ctx context.Context) int {
	if ctx == nil {
		return 0
	}
	pid, _ := ctx.Value(peerPIDKey{}).(int)
	return pid
}

type connectionClose struct {
	mu        sync.Mutex
	closed    bool
	next      uint64
	callbacks map[uint64]func()
}

// OnConnectionClose registers trusted cleanup after every in-flight Handle has
// settled. A request context's cancellation is deliberately not a lifetime.
// It returns false outside a daemon-owned connection or at the fixed bound.
func OnConnectionClose(ctx context.Context, fn func()) bool {
	_, ok := RegisterConnectionClose(ctx, fn)
	return ok
}

// RegisterConnectionClose also returns a remover so an already retired
// ephemeral invocation does not consume transport-lifetime callback quota.
func RegisterConnectionClose(ctx context.Context, fn func()) (func(), bool) {
	if ctx == nil || fn == nil {
		return nil, false
	}
	state, _ := ctx.Value(closeKey{}).(*connectionClose)
	if state == nil {
		return nil, false
	}
	state.mu.Lock()
	if state.closed {
		state.mu.Unlock()
		fn()
		return func() {}, true
	}
	if len(state.callbacks) >= 8192 || state.next == ^uint64(0) {
		state.mu.Unlock()
		return nil, false
	}
	if state.callbacks == nil {
		state.callbacks = map[uint64]func(){}
	}
	state.next++
	id := state.next
	state.callbacks[id] = fn
	state.mu.Unlock()
	return func() { state.mu.Lock(); delete(state.callbacks, id); state.mu.Unlock() }, true
}
func (c *connectionClose) close() {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.closed = true
	callbacks := c.callbacks
	c.callbacks = nil
	c.mu.Unlock()
	for _, fn := range callbacks {
		fn()
	}
}
