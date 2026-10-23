package capture

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
)

type failingFrameReader struct {
	data []byte
	err  error
}

func (r *failingFrameReader) Read(p []byte) (int, error) {
	n := copy(p, r.data)
	r.data = r.data[n:]
	if len(r.data) == 0 {
		return n, r.err
	}
	return n, nil
}

type cancellingFrameReader struct {
	r      io.Reader
	cancel context.CancelFunc
	reads  int
}

func (r *cancellingFrameReader) Read(p []byte) (int, error) {
	r.reads++
	n, e := r.r.Read(p)
	if r.reads == 2 {
		r.cancel()
	}
	return n, e
}

type noProgressFrameReader struct{}

func (noProgressFrameReader) Read([]byte) (int, error) { return 0, nil }

func TestOwnedFrameBuffersClearedOnEveryExitAndGrowth(t *testing.T) {
	for _, which := range []string{"success", "growth_success", "partial_line", "growth_partial", "frame_limit", "unit_limit", "cancel_before", "cancel_after_yield", "cancel_partial", "read_error", "growth_read_error", "yield_error", "growth_yield_error", "no_progress"} {
		t.Run(which, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			data := "RAW_TRANSIENT_CANARY_947cb3\n"
			want := ""
			unit, frame := maxUnit, maxFrame
			var r io.Reader
			switch which {
			case "growth_success":
				data = strings.Repeat("RAW_TRANSIENT_CANARY_947cb3", 6000) + "\n"
			case "partial_line":
				data = strings.TrimSuffix(data, "\n")
				want = "partial_line"
			case "growth_partial":
				data = strings.Repeat("RAW_TRANSIENT_CANARY_947cb3", 6000)
				want = "partial_line"
			case "frame_limit":
				data = strings.Repeat("RAW_TRANSIENT_CANARY_947cb3", 6000)
				frame = 70000
				want = "frame_limit"
			case "unit_limit":
				unit = 4
				want = "unit_limit"
			case "cancel_before":
				cancel()
				want = "cancelled"
			case "cancel_after_yield":
				want = "cancelled"
			case "cancel_partial":
				data = strings.Repeat("RAW_TRANSIENT_CANARY_947cb3", 6000)
				r = &cancellingFrameReader{r: strings.NewReader(data), cancel: cancel}
				want = "cancelled"
			case "growth_read_error":
				r = &failingFrameReader{data: []byte(strings.Repeat("RAW_TRANSIENT_CANARY_947cb3", 6000)), err: errors.New("untrusted failure")}
				want = "read_failed"
			case "growth_yield_error":
				data = strings.Repeat("RAW_TRANSIENT_CANARY_947cb3", 6000) + "\n"
				want = "test_yield_refused"
			case "read_error":
				r = &failingFrameReader{data: []byte(strings.TrimSuffix(data, "\n")), err: errors.New("untrusted failure")}
				want = "read_failed"
			case "yield_error":
				want = "test_yield_refused"
			case "no_progress":
				r = noProgressFrameReader{}
				want = "read_failed"
			}
			if r == nil {
				r = strings.NewReader(data)
			}
			var allocated [][]byte
			m := &frameMemory{allocated: func(b []byte) { allocated = append(allocated, b) }}
			err := frameReader(ctx, r, func(_ int, b []byte) error {
				if !bytes.Contains(b, []byte("RAW_TRANSIENT_CANARY_947cb3")) {
					t.Fatal("fixture did not reach reader")
				}
				// Retired frame arrays have already been cleared before growth returns.
				for _, old := range allocated {
					if len(old) > 0 && &old[0] != &m.scratch[0] && &old[0] != &m.frame[:cap(m.frame)][0] && !allZero(old) {
						t.Fatal("retired growth buffer retained raw bytes")
					}
				}
				if which == "cancel_after_yield" {
					cancel()
				}
				if which == "yield_error" || which == "growth_yield_error" {
					return hold("test_yield_refused")
				}
				return nil
			}, unit, frame, m)
			if Code(err) != want {
				t.Fatal("wrong fixed exit", Code(err), want)
			}
			if (which == "growth_success" || which == "growth_partial") && len(allocated) < 3 {
				t.Fatal("growth not exercised")
			}
			for _, b := range allocated {
				if !allZero(b) {
					t.Fatal("owned backing allocation was not cleared", len(b))
				}
			}
			if m.scratch != nil || m.frame != nil {
				t.Fatal("owned buffers retained")
			}
		})
	}
}
func allZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}
