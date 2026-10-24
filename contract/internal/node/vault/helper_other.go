//go:build !darwin || !cgo

package vault

import "io"

func RunHelper(args []string, in io.Reader, out io.Writer) bool {
	return runCapabilities(args, in, out, false)
}
