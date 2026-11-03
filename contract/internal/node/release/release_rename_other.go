//go:build !linux && !darwin && !windows

package main

func renameReleaseTreeNoReplace(source, destination string) error {
	return errReleasePublicationIncomplete
}
