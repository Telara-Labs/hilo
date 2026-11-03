package fixture

import (
	"errors"

	"github.com/Telara-Labs/hilo/contract/internal/node/daemon"
	"github.com/Telara-Labs/hilo/contract/record"
)

// Transport numbers must never pass through binary floating point. Keep the
// record hash's five parts while normalizing equal decimal IDs exactly.
func fallbackOpID(scope, connection string, id []byte, tool, argsHash string) (string, error) {
	if scope == "" || connection == "" || tool == "" || !record.IsHex64(argsHash) {
		return "", errors.New("invalid operation identity")
	}
	canonical, e := exactRPCID(id)
	if e != nil {
		return "", e
	}
	return record.HE("op", scope, connection, canonical, tool, argsHash)
}
func exactRPCID(raw []byte) (string, error) { return daemon.RPCIDKey(raw) }
