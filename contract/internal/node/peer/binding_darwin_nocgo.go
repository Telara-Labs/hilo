//go:build darwin && !cgo

package peer

import "net"

// Static builds retain diagnostic IPC, but install no proof-bearing binding.
func bindProcess(net.Conn) (processBinding, error) { return nil, nil }
