package store

import "golang.org/x/sys/windows"

// The caller has flushed and closed the private file and retains writer
// admission. Windows cannot fsync a read-only directory handle. Publish with
// native write-through rename instead, preserving explicit replacement policy.
func publishPrivateRecord(source, target string, replace bool) error {
	src, err := windows.UTF16PtrFromString(source)
	if err != nil {
		return err
	}
	dst, err := windows.UTF16PtrFromString(target)
	if err != nil {
		return err
	}
	flags := uint32(windows.MOVEFILE_WRITE_THROUGH)
	if replace {
		flags |= windows.MOVEFILE_REPLACE_EXISTING
	}
	return windows.MoveFileEx(src, dst, flags)
}
