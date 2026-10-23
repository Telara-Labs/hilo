package install

import (
	"errors"
	"golang.org/x/sys/unix"
)

func checkACL(fd int, private bool) error {
	for _, name := range []string{"system.posix_acl_access", "system.posix_acl_default"} {
		_, e := unix.Fgetxattr(fd, name, nil)
		if !errors.Is(e, unix.ENODATA) && !errors.Is(e, unix.ENOTSUP) {
			return ErrUnsafe
		}
	}
	return nil
}
