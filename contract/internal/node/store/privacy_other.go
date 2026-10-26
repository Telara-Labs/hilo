//go:build !linux && !darwin && !windows

package store

func privateDir(string) error  { return failure("unsupported_privacy") }
func privateFile(string) error { return failure("unsupported_privacy") }
