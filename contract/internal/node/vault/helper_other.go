//go:build !darwin || !cgo

package vault

import "io"

func RunHelper([]string, io.Reader, io.Writer) bool { return false }
