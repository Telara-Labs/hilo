package daemon

import (
	"context"
	"errors"

	"golang.org/x/sys/unix"
)

// A kernel process event pins the observed lifetime across PID reuse.
func watchProcess(pid int) (func(context.Context) error, func(), error) {
	fd, err := unix.Kqueue()
	if err != nil {
		return nil, nil, err
	}
	event := unix.Kevent_t{Ident: uint64(pid), Filter: unix.EVFILT_PROC, Flags: unix.EV_ADD | unix.EV_ONESHOT, Fflags: unix.NOTE_EXIT}
	if _, err = unix.Kevent(fd, []unix.Kevent_t{event}, nil, nil); err != nil {
		unix.Close(fd)
		return nil, nil, err
	}
	wait := func(ctx context.Context) error {
		for {
			if err := ctx.Err(); err != nil {
				return err
			}
			events := make([]unix.Kevent_t, 1)
			timeout := unix.Timespec{Nsec: 20_000_000}
			n, err := unix.Kevent(fd, nil, events, &timeout)
			if err == unix.EINTR {
				continue
			}
			if err != nil {
				return err
			}
			if n == 1 && events[0].Filter == unix.EVFILT_PROC && events[0].Fflags&unix.NOTE_EXIT != 0 {
				return nil
			}
		}
	}
	return wait, func() { unix.Close(fd) }, nil
}

func processAbsent(err error) bool { return errors.Is(err, unix.ESRCH) }
