package daemon

import (
	"encoding/json"

	"github.com/Telara-Labs/hilo/contract/internal/node/ipc"
)

// ForwardedRequest is private local IPC framing. Stdio Parse rejects its extra
// field, so client metadata cannot replace the correlation selected by the shim.
type ForwardedRequest struct {
	Request
	ClientRequestID json.RawMessage `json:"client_request_id,omitempty"`
}

func (r Request) CorrelationID() json.RawMessage {
	if len(r.OriginalID) != 0 {
		return r.OriginalID
	}
	return r.ID
}

func parseForwarded(b []byte) (Request, error) {
	var wire ForwardedRequest
	if !validateEnvelope(b) || ipc.DecodeStrict(b, &wire) != nil {
		return Request{}, ipc.ErrFrame
	}
	r := wire.Request
	if r.JSONRPC != "2.0" || r.Method == "" || (len(r.ID) > 0 && !ValidRPCID(r.ID)) {
		return Request{}, ipc.ErrFrame
	}
	if len(wire.ClientRequestID) > 0 {
		if len(r.ID) == 0 || !ValidRPCID(wire.ClientRequestID) {
			return Request{}, ipc.ErrFrame
		}
		r.OriginalID = wire.ClientRequestID
	}
	return r, nil
}
