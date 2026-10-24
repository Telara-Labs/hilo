package capture

import (
	"bytes"
	"context"
	"io"
)

type frameMemory struct {
	scratch, frame []byte
	// Test-only observer retains backing storage to verify its lifecycle. Nil in
	// production. No raw storage is retained by the framer after return.
	allocated func([]byte)
}

func (m *frameMemory) allocate(n int) []byte {
	b := make([]byte, n)
	if m.allocated != nil {
		m.allocated(b)
	}
	return b
}
func (m *frameMemory) close() {
	clear(m.scratch)
	clear(m.frame[:cap(m.frame)])
	m.scratch = nil
	m.frame = nil
}
func (m *frameMemory) append(piece []byte, limit int) {
	need := len(m.frame) + len(piece)
	if need > cap(m.frame) {
		capacity := min(limit, max(4096, max(need, cap(m.frame)*2)))
		next := m.allocate(capacity)
		copy(next, m.frame)
		clear(m.frame[:cap(m.frame)])
		m.frame = next[:len(m.frame)]
	}
	m.frame = m.frame[:need]
	copy(m.frame[need-len(piece):], piece)
}

func frameUnit(ctx context.Context, h *openedUnitHandle, yield func(int, []byte) error) error {
	if !h.stable() {
		if h.bound() {
			return hold("source_unsettled")
		}
		return hold("source_changed")
	}
	err := frameReader(ctx, h.file, yield, maxUnit, maxFrame, &frameMemory{})
	if err != nil {
		if !h.bound() {
			return hold("source_changed")
		}
		if !h.stable() && h.bound() && (Code(err) == "invalid_json" || Code(err) == "native_shape" || Code(err) == "partial_line") {
			return hold("source_unsettled")
		}
		return err
	}
	if !h.stable() {
		if h.bound() {
			return hold("source_unsettled")
		}
		return hold("source_changed")
	}
	return nil
}

// All raw byte backing arrays are explicitly owned and cleared, including old
// storage retired during growth and partial frames on every refusal. This makes
// no guarantee about parser-created Go strings or allocator/runtime copies.
func frameReader(ctx context.Context, r io.Reader, yield func(int, []byte) error, unitLimit, frameLimit int, m *frameMemory) error {
	defer m.close()
	m.scratch = m.allocate(64 << 10)
	total, line, emptyReads := 0, 0, 0
	for {
		if ctx.Err() != nil {
			return hold("cancelled")
		}
		n, err := r.Read(m.scratch)
		if n < 0 || n > len(m.scratch) {
			return hold("read_failed")
		}
		if ctx.Err() != nil {
			return hold("cancelled")
		}
		total += n
		if total > unitLimit {
			return hold("unit_limit")
		}
		piece := m.scratch[:n]
		for len(piece) > 0 {
			end := bytes.IndexByte(piece, '\n')
			take := len(piece)
			if end >= 0 {
				take = end + 1
			}
			if len(m.frame)+take > frameLimit {
				return hold("frame_limit")
			}
			m.append(piece[:take], frameLimit)
			piece = piece[take:]
			if end >= 0 {
				line++
				if e := yield(line, m.frame); e != nil {
					return e
				}
				clear(m.frame[:cap(m.frame)])
				m.frame = m.frame[:0]
			}
			if ctx.Err() != nil {
				return hold("cancelled")
			}
		}
		clear(m.scratch)
		if err == io.EOF {
			if len(m.frame) > 0 {
				return hold("partial_line")
			}
			return nil
		}
		if err != nil {
			return hold("read_failed")
		}
		if n == 0 {
			emptyReads++
			if emptyReads >= 100 {
				return hold("read_failed")
			}
		} else {
			emptyReads = 0
		}
	}
}
