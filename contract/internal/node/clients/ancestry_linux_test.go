package clients

import (
	"strings"
	"testing"
)

func TestProcStatParentAndEpochStart(t *testing.T) {
	fields := []string{"S", "7"}
	for len(fields) < 19 {
		fields = append(fields, "0")
	}
	fields = append(fields, "1234")
	p, name, ms, e := parseProcStat("42 (test with ) chars) "+strings.Join(fields, " "), 1000)
	if e != nil || p != 7 || name != "test with ) chars" || ms != 1012340 {
		t.Fatalf("%d %q %d %v", p, name, ms, e)
	}
	for _, s := range []string{"bad", "42 (test) S 1", "42 (test) " + strings.Repeat("x ", 20)} {
		if _, _, _, e = parseProcStat(s, 1000); e == nil {
			t.Fatal("malformed proc accepted")
		}
	}
}
