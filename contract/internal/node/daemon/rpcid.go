package daemon

import (
	"bytes"
	"errors"
	"math/big"
	"strings"

	"github.com/Telara-Labs/telara-memory/contract/jcs"
)

// RPCIDKey preserves exact decimal identity without floating point.
func RPCIDKey(raw []byte) (string, error) {
	if !ValidRPCID(raw) {
		return "", errors.New("invalid RPC id")
	}
	raw = bytes.TrimSpace(raw)
	if raw[0] == '"' {
		b, e := jcs.Canonicalize(raw)
		return string(b), e
	}
	text := string(raw)
	sign := ""
	if strings.HasPrefix(text, "-") {
		sign = "-"
		text = text[1:]
	}
	exponent := new(big.Int)
	if i := strings.IndexAny(text, "eE"); i >= 0 {
		if len(text[i+1:]) > 1024 {
			return "", errors.New("RPC exponent exceeds operation bound")
		}
		if _, ok := exponent.SetString(text[i+1:], 10); !ok {
			return "", errors.New("invalid RPC id")
		}
		text = text[:i]
	}
	if i := strings.IndexByte(text, '.'); i >= 0 {
		exponent.Sub(exponent, big.NewInt(int64(len(text)-i-1)))
		text = text[:i] + text[i+1:]
	}
	text = strings.TrimLeft(text, "0")
	if text == "" {
		return "0", nil
	}
	exponent.Add(exponent, big.NewInt(int64(len(text)-1)))
	text = strings.TrimRight(text, "0")
	if exponent.IsInt64() && exponent.Int64() >= -6 && exponent.Int64() < 21 {
		point := int(exponent.Int64() + 1)
		switch {
		case point <= 0:
			return sign + "0." + strings.Repeat("0", -point) + text, nil
		case point >= len(text):
			return sign + text + strings.Repeat("0", point-len(text)), nil
		default:
			return sign + text[:point] + "." + text[point:], nil
		}
	}
	mantissa := text[:1]
	if len(text) > 1 {
		mantissa += "." + text[1:]
	}
	exp := exponent.String()
	if exponent.Sign() >= 0 {
		exp = "+" + exp
	}
	return sign + mantissa + "e" + exp, nil
}
