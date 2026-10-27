// Package ipc implements the owner-authenticated local wire transport.
package ipc

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"time"
)

const MaxFrame = 4 << 20
const MaxInFlight = 16
const HandshakeTimeout = 10 * time.Second
const WireVersion = 1

var ErrFrame = errors.New("invalid_frame")
var ErrBusy = errors.New("busy")
var ErrUnsafe = errors.New("unsafe_path")
var ErrPeer = errors.New("peer_identity")

type Proc struct {
	PID     int   `json:"pid"`
	StartMS int64 `json:"start_ms"`
}
type Hello struct {
	RepositoryContext string `json:"repository_context,omitempty"`
	T                 string `json:"t"`
	V                 int    `json:"v"`
	Kind              string `json:"kind"`
	Shim              string `json:"shim"`
	PID               int    `json:"pid"`
	Ancestry          []Proc `json:"ancestry"`
	Cwd               string `json:"cwd"`
	Client            string `json:"client"`
	NodeVersion       string `json:"node_version"`
}

func (h Hello) Valid() bool {
	if h.RepositoryContext != "" {
		b, err := hex.DecodeString(h.RepositoryContext)
		if err != nil || len(b) != 16 || hex.EncodeToString(b) != h.RepositoryContext || h.Kind != "mcp" {
			return false
		}
	}
	if h.T != "hello" || h.V != WireVersion || (h.Kind != "mcp" && h.Kind != "control") || h.PID <= 0 || len(h.Ancestry) > 6 || h.Client == "" {
		return false
	}
	for _, p := range h.Ancestry {
		if p.PID <= 0 || p.StartMS <= 0 {
			return false
		}
	}
	return true
}

// ReadFrame bounds allocations even when the peer never sends a newline.
func ReadFrame(r *bufio.Reader) ([]byte, error) {
	var b []byte
	for {
		part, e := r.ReadSlice('\n')
		if len(b)+len(part) > MaxFrame {
			return nil, ErrFrame
		}
		b = append(b, part...)
		if e == bufio.ErrBufferFull {
			if len(b) >= MaxFrame {
				return nil, ErrFrame
			}
			continue
		}
		if e != nil {
			if e == io.EOF && len(b) > 0 {
				return nil, ErrFrame
			}
			return nil, e
		}
		b = bytes.TrimSuffix(b, []byte{'\n'})
		if len(b) == 0 || !json.Valid(b) {
			return nil, ErrFrame
		}
		return b, nil
	}
}
func EncodeFrame(v any) ([]byte, error) {
	b, e := json.Marshal(v)
	if e != nil || len(b)+1 > MaxFrame {
		return nil, ErrFrame
	}
	return append(b, '\n'), nil
}
func WriteFrame(w io.Writer, v any) error {
	b, e := EncodeFrame(v)
	if e != nil {
		return e
	}
	return WriteEncodedFrame(w, b)
}

// WriteEncodedFrame writes bytes already validated by EncodeFrame.
func WriteEncodedFrame(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, e := w.Write(b)
		if e != nil {
			return e
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		b = b[n:]
	}
	return nil
}
func DecodeStrict(b []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil {
		return ErrFrame
	}
	return nil
}
