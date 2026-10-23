package daemon

import (
	"context"
	"errors"

	"golang.org/x/sys/unix"
)

func watchProcess(pid int) (func(context.Context) error, func(), error) {
	fd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		return nil, nil, err
	}
	wait := func(ctx context.Context) error {
		for {
			if err := ctx.Err(); err != nil {
				return err
			}
			fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
			n, err := unix.Poll(fds, 20)
			if err == unix.EINTR {
				continue
			}
			if err != nil {
				return err
			}
			if n > 0 {
				if fds[0].Revents&unix.POLLIN != 0 {
					return nil
				}
				return ErrSettlement
			}
		}
	}
	return wait, func() { unix.Close(fd) }, nil
}

func processAbsent(err error) bool { return errors.Is(err, unix.ESRCH) }
