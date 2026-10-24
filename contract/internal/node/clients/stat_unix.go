//go:build darwin || linux

package clients

import (
	"fmt"
	"golang.org/x/sys/unix"
	"os"
)

func clientStat(st *unix.Stat_t, path string, directory, private bool) error {
	fail := func(rule string) error {
		return unsafePath("validate metadata", path, fmt.Sprintf("%s (uid=%d mode=%#o nlink=%d)", rule, st.Uid, st.Mode, st.Nlink), nil)
	}
	if st.Uid != uint32(os.Geteuid()) && (!directory || private || st.Uid != 0) {
		return fail("owner must be current user, or root for non-private directories")
	}
	if directory {
		if st.Mode&0022 != 0 && st.Mode&unix.S_ISVTX == 0 {
			return fail("mode forbids group/other writes without sticky protection")
		}
		if private && st.Mode&0777 != 0700 {
			return fail("private directory mode must be 0700")
		}
	} else {
		if st.Mode&unix.S_IFMT != unix.S_IFREG {
			return fail("type must be regular file")
		}
		if st.Nlink != 1 {
			return fail("link count must be one")
		}
		if st.Mode&0022 != 0 {
			return fail("mode forbids group/other writes")
		}
		if private && st.Mode&0777 != 0600 {
			return fail("private file mode must be 0600")
		}
	}
	return nil
}
