package daemon

import (
	"context"
	"errors"

	"golang.org/x/sys/windows"
)

func watchProcess(pid int) (func(context.Context) error, func(), error) {
	h, err := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(pid))
	if err != nil {
		return nil, nil, err
	}
	wait := func(ctx context.Context) error {
		for {
			if err := ctx.Err(); err != nil {
				return err
			}
			result, err := windows.WaitForSingleObject(h, 20)
			if err != nil {
				return err
			}
			if result == windows.WAIT_OBJECT_0 {
				return nil
			}
			if result != uint32(windows.WAIT_TIMEOUT) {
				return ErrSettlement
			}
		}
	}
	return wait, func() { windows.CloseHandle(h) }, nil
}

func processAbsent(err error) bool { return errors.Is(err, windows.ERROR_INVALID_PARAMETER) }
