package fixture

import (
	"strings"
	"testing"
)

func TestExactFallbackIDs(t *testing.T) {
	pairs := [][2]string{
		{"9007199254740992", "9007199254740993"}, {"-9007199254740992", "-9007199254740993"},
		{"18446744073709551616", "18446744073709551617"}, {"1.00000000000000001", "1.00000000000000002"},
		{"1e400", "1e401"}, {`1`, `"1"`},
	}
	for _, pair := range pairs {
		a, e := fallbackOpID("scope", "connection", []byte(pair[0]), "tool", strings.Repeat("a", 64))
		if e != nil {
			t.Fatal(e)
		}
		b, e := fallbackOpID("scope", "connection", []byte(pair[1]), "tool", strings.Repeat("a", 64))
		if e != nil || a == b {
			t.Fatal("distinct exact ids aliased", pair, e)
		}
	}
	for _, pair := range [][2]string{{"1", "1.0"}, {"1", "1e0"}, {"-0", "0"}, {"0e400", "0"}, {"9007199254740993", "90071992547409930e-1"}, {"0.0000001", "1e-7"}, {`"a"`, `"\u0061"`}} {
		a, e := exactRPCID([]byte(pair[0]))
		if e != nil {
			t.Fatal(e)
		}
		b, e := exactRPCID([]byte(pair[1]))
		if e != nil || a != b {
			t.Fatal("equal ids differ", pair, a, b, e)
		}
	}
	for _, raw := range []string{"null", "true", "{}", "[]", "", "\"\\ud800\""} {
		if _, e := exactRPCID([]byte(raw)); e == nil {
			t.Fatal("invalid id accepted")
		}
	}
	if _, e := exactRPCID([]byte("1e" + strings.Repeat("9", 1025))); e == nil {
		t.Fatal("unbounded exponent work accepted")
	}
	if _, e := fallbackOpID("", "", []byte("1"), "", ""); e == nil {
		t.Fatal("missing fallback identity accepted")
	}
}
