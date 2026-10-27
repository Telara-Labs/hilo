//go:build darwin && cgo

package vault

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/binary"
	"io"
	"os"
	"os/exec"
	"time"
)

const helperArg = "native-vault-operation"

// RunHelper must be called before normal argument handling by executables using
// this backend. Secrets travel only on anonymous pipes, never argv or files.
func RunHelper(args []string, in io.Reader, out io.Writer) bool {
	if runCapabilities(args, in, out, true) {
		return true
	}
	if runHandoffHelper(args, in, out) {
		return true
	}
	if len(args) != 1 || args[0] != helperArg {
		return false
	}
	raw := make([]byte, 8193)
	defer clear(raw)
	count, e := io.ReadFull(in, raw)
	if (e != nil && e != io.EOF && e != io.ErrUnexpectedEOF) || count > 8192 {
		return true
	}
	raw = raw[:count]
	e = nil
	if len(raw) < 35 {
		return true
	}
	op := raw[0]
	if op < 1 || op > 10 {
		// Removed operations (including account-wide enumeration opcode11)
		// are refused before even selecting/opening a native Keychain.
		_, _ = out.Write([]byte{3})
		return true
	}
	h := string(raw[1:33])
	n := int(binary.BigEndian.Uint16(raw[33:35]))
	if n > 4096 || 35+n > len(raw) {
		return true
	}
	keychain := string(raw[35 : 35+n])
	secret := raw[35+n:]
	var result []byte
	v := New()
	if keychain != "" {
		v, e = openIsolated(keychain)
		if e == nil {
			defer v.closeIsolated()
		}
	}
	if e == nil {
		e = valid(context.Background(), h)
	}
	if e == nil {
		switch op {
		case 1:
			if len(secret) == 0 || len(secret) > maxSecret {
				e = ErrInvalid
			} else {
				e = v.nativePut(context.Background(), h, secret)
			}
		case 4:
			if len(secret) == 0 || len(secret) > maxSecret {
				e = ErrInvalid
				break
			}
			e = v.nativePut(context.Background(), h, secret)
			if e == nil || e == ErrExists {
				result, e = v.nativeGetOwn(h)
				if e == nil && subtle.ConstantTimeCompare(result, secret) != 1 {
					e = ErrUnavailable
				}
			}
		case 6:
			e = v.nativeDeleteSlot(h, false)
		case 7:
			e = v.nativeDeleteSlot(h, true)
		case 8:
			result, e = v.nativeLegacySlot(h)
		case 9:
			result, e = v.nativeGetOwn(h)
		case 10:
			result, e = nativeDefaultKeychain()
		case 5:
			var name string
			name, e = nativeService()
			result = []byte(name)
		case 2:
			result, e = v.nativeGet(context.Background(), h)
		case 3:
			e = v.nativeDelete(context.Background(), h)
		default:
			e = ErrInvalid
		}
	}
	defer clear(result)
	code := byte(0)
	if e != nil {
		code = 3
		if e == ErrExists {
			code = 1
		}
		if e == ErrNotFound {
			code = 2
		}
	}
	_, _ = out.Write([]byte{code})
	if e == nil {
		_, _ = out.Write(result)
	}
	return true
}
func (v *Vault) operation(ctx context.Context, op, h string, b []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	exe, e := os.Executable()
	if e != nil {
		return nil, ErrKeychainUnavailable
	}
	code := byte(0)
	switch op {
	case "put":
		code = 1
	case "get":
		code = 2
	case "delete":
		code = 3
	case "legacy-slot":
		code = 8
	case "get-own":
		code = 9
	case "default-keychain":
		code = 10
	}
	if len(v.keychainPath) > 4096 {
		return nil, ErrInvalid
	}
	raw := make([]byte, 35+len(v.keychainPath)+len(b))
	defer clear(raw)
	raw[0] = code
	copy(raw[1:33], h)
	binary.BigEndian.PutUint16(raw[33:35], uint16(len(v.keychainPath)))
	copy(raw[35:], v.keychainPath)
	copy(raw[35+len(v.keychainPath):], b)
	cmd := exec.CommandContext(ctx, exe, helperArg)
	cmd.WaitDelay = time.Second
	cmd.Stdin = bytes.NewReader(raw)
	output := &custodyOutput{}
	cmd.Stdout = output
	if cmd.Run() != nil {
		clear(output.b[:])
		return nil, ErrKeychainUnavailable
	}
	defer clear(output.b[:])
	reply := output.b[:output.n]
	if len(reply) == 0 || len(reply) > maxSecret+1 {
		return nil, ErrKeychainUnavailable
	}
	switch reply[0] {
	case 0:
		if (op == "get" || op == "get-own") && len(reply) == 1 {
			return nil, ErrKeychainUnavailable
		}
		return append([]byte(nil), reply[1:]...), nil
	case 1:
		return nil, ErrExists
	case 2:
		return nil, ErrNotFound
	default:
		return nil, ErrKeychainUnavailable
	}
}
func (v *Vault) put(ctx context.Context, h string, b []byte) error {
	_, e := v.operation(ctx, "put", h, b)
	return e
}
func (v *Vault) get(ctx context.Context, h string) ([]byte, error) {
	return v.operation(ctx, "get", h, nil)
}
func (v *Vault) delete(ctx context.Context, h string) error {
	_, e := v.operation(ctx, "delete", h, nil)
	return e
}
