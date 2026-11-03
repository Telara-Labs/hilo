package main

import "golang.org/x/sys/windows"

func renameReleaseTreeNoReplace(source, destination string) error {
	src, err := windows.UTF16PtrFromString(source)
	if err != nil {
		return err
	}
	dst, err := windows.UTF16PtrFromString(destination)
	if err != nil {
		return err
	}
	// No MOVEFILE_REPLACE_EXISTING or cross-volume copy fallback.
	return windows.MoveFileEx(src, dst, windows.MOVEFILE_WRITE_THROUGH)
}
