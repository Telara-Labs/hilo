package install

import (
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
)

func checkACL(fd int, private bool) error {
	for _, name := range []string{"system.posix_acl_access", "system.posix_acl_default"} {
		_, e := unix.Fgetxattr(fd, name, nil)
		if !errors.Is(e, unix.ENODATA) && !errors.Is(e, unix.ENOTSUP) {
			return unsafePath("fgetxattr", fmt.Sprintf("fd=%d", fd), "ACL "+name+" must be absent or unsupported", e)
		}
	}
	return nil
}
