//go:build darwin || linux

package shim

import (
	"context"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

// Inherited stdio is not necessarily registered with Go's runtime poller.
// Closing os.Stdin cannot interrupt its blocking read. Use an owned duplicate
// with nonblocking syscalls and bounded poll waits for both input and output.
// Duplicates share status flags, so restore them after all shim calls finish.
func cancelableFile(ctx context.Context, f *os.File) (io.ReadWriter, func(), error) {
	raw, e := f.SyscallConn()
	if e != nil {
		return nil, nil, e
	}
	fd, flags := -1, 0
	var setupErr error
	e = raw.Control(func(handle uintptr) {
		flags, setupErr = unix.FcntlInt(handle, unix.F_GETFL, 0)
		if setupErr != nil {
			return
		}
		fd, setupErr = unix.FcntlInt(handle, unix.F_DUPFD_CLOEXEC, 0)
		if setupErr == nil {
			setupErr = unix.SetNonblock(fd, true)
		}
	})
	if e != nil || setupErr != nil {
		if fd >= 0 {
			unix.Close(fd)
		}
		if e == nil {
			e = setupErr
		}
		return nil, nil, e
	}
	return &stdioFile{ctx: ctx, fd: fd}, func() {
		unix.FcntlInt(uintptr(fd), unix.F_SETFL, flags)
		unix.Close(fd)
	}, nil
}

type stdioFile struct {
	ctx context.Context
	fd  int
}

func (f *stdioFile) wait(events int16) error {
	for {
		if e := f.ctx.Err(); e != nil {
			return e
		}
		// No background goroutine retains a blocked syscall or caller buffer.
		// Cancellation is observed within 50ms even if no pipe event arrives.
		p := []unix.PollFd{{Fd: int32(f.fd), Events: events}}
		n, e := unix.Poll(p, 50)
		if e == unix.EINTR {
			continue
		}
		if e != nil {
			return e
		}
		if n > 0 {
			if p[0].Revents&unix.POLLNVAL != 0 {
				return os.ErrClosed
			}
			return nil
		}
	}
}

func (f *stdioFile) Read(b []byte) (int, error) {
	for {
		if e := f.ctx.Err(); e != nil {
			return 0, e
		}
		n, e := unix.Read(f.fd, b)
		if e == unix.EINTR {
			continue
		}
		if e == unix.EAGAIN {
			if e = f.wait(unix.POLLIN); e != nil {
				return 0, e
			}
			continue
		}
		if n == 0 && e == nil && len(b) > 0 {
			e = io.EOF
		}
		return max(n, 0), e
	}
}

func (f *stdioFile) Write(b []byte) (int, error) {
	for {
		if e := f.ctx.Err(); e != nil {
			return 0, e
		}
		n, e := unix.Write(f.fd, b)
		if e == unix.EINTR {
			continue
		}
		if e == unix.EAGAIN {
			if e = f.wait(unix.POLLOUT); e != nil {
				return 0, e
			}
			continue
		}
		return max(n, 0), e
	}
}
