package daemon

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
)

func TestConnectionCleanupRegistrationRetirementAndClosedRace(t *testing.T) {
	state := &connectionClose{}
	ctx := context.WithValue(context.Background(), closeKey{}, state)
	if OnConnectionClose(context.Background(), func() {}) {
		t.Fatal("foreign context owns lifetime")
	}
	for i := 0; i < 10000; i++ {
		remove, ok := RegisterConnectionClose(ctx, func() { t.Error("retired callback ran") })
		if !ok {
			t.Fatal("retired call consumed quota", i)
		}
		remove()
	}
	var called atomic.Int32
	var group sync.WaitGroup
	for i := 0; i < 128; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			if !OnConnectionClose(ctx, func() { called.Add(1) }) {
				t.Error("registration refused")
			}
		}()
	}
	group.Wait()
	state.close()
	state.close()
	if called.Load() != 128 {
		t.Fatal("missed/doubled lifetime callback", called.Load())
	}
	if !OnConnectionClose(ctx, func() { called.Add(1) }) || called.Load() != 129 {
		t.Fatal("late cleanup lost")
	}
	if len(state.callbacks) != 0 {
		t.Fatal("closed callback state retained")
	}
}
