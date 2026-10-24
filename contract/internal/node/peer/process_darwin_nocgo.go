//go:build darwin && !cgo

package peer

import "os"

func openImage(int, string) (*os.File, error) { return nil, ErrAuthority }

func executable(int) (string, string, error) { return "", "", ErrAuthority }
