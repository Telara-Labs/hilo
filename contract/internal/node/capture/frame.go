package capture

import (
	"bufio"
	"context"
	"io"
)

func frameUnit(ctx context.Context, h *openedUnitHandle, yield func(int, []byte) error) error {
	if !h.stable() {
		return hold("source_changed")
	}
	r := bufio.NewReaderSize(io.LimitReader(h.file, maxUnit+1), 64<<10)
	total, line := 0, 0
	for {
		if ctx.Err() != nil {
			return hold("cancelled")
		}
		var frame []byte
		for {
			piece, err := r.ReadSlice('\n')
			total += len(piece)
			if total > maxUnit {
				return hold("unit_limit")
			}
			if len(frame)+len(piece) > maxFrame {
				return hold("frame_limit")
			}
			frame = append(frame, piece...)
			if err == bufio.ErrBufferFull {
				if ctx.Err() != nil {
					return hold("cancelled")
				}
				continue
			}
			if err == io.EOF {
				// An unterminated final line is an unsettled native write, not a
				// successful shorter snapshot. Discard all prepared observations.
				if len(frame) != 0 {
					return hold("partial_line")
				}
				if !h.stable() {
					return hold("source_changed")
				}
				return nil
			}
			if err != nil {
				return hold("read_failed")
			}
			break
		}
		line++
		if err := yield(line, frame); err != nil {
			return err
		}
	}
}
