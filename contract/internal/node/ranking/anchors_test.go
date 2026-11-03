package ranking

import (
	"fmt"
	"strings"
	"testing"
)

func TestAnchorSHAReportsDistinctCollisions(t *testing.T) {
	a := "abcdef0" + strings.Repeat("1", 33)
	b := "abcdef0" + strings.Repeat("2", 33)
	r, err := MatchAnchor("sha", "ABCDEF0", []AnchorRecord{{"z", "sha", a}, {"a", "sha", b}, {"other", "sha", a}})
	if err != nil || !r.Ambiguous || r.Truncated || len(r.IDs) != 3 || r.IDs[0] != "a" {
		t.Fatalf("got %+v %v", r, err)
	}
	r, err = MatchAnchor("sha", a, []AnchorRecord{{"x", "sha", a}, {"y", "sha", a}})
	if err != nil || r.Ambiguous || len(r.IDs) != 2 {
		t.Fatalf("same hash %+v %v", r, err)
	}
}
func TestAnchorPathBoundariesAndValidation(t *testing.T) {
	r, err := MatchAnchor("path", "src/auth.go", []AnchorRecord{{"a", "path", "repo/src/auth.go"}, {"b", "path", "repo/not-src/auth.go"}})
	if err != nil || len(r.IDs) != 1 || r.IDs[0] != "a" {
		t.Fatalf("got %+v %v", r, err)
	}
	for _, query := range []string{"../secret", "/etc/passwd", "src//x", `src\x`} {
		if _, err := MatchAnchor("path", query, nil); err == nil {
			t.Fatalf("accepted %q", query)
		}
	}
	if _, err := MatchAnchor("sha", "a123", nil); err == nil {
		t.Fatal("accepted short hash")
	}
}
func TestAnchorTruncationAndExactMatching(t *testing.T) {
	records := make([]AnchorRecord, 51)
	for i := range records {
		records[i] = AnchorRecord{fmt.Sprintf("id-%02d", i), "issue", "ABC-42"}
	}
	r, err := MatchAnchor("issue", "abc-42", records)
	if err != nil || !r.Truncated || len(r.IDs) != 50 || r.IDs[0] != "id-00" {
		t.Fatalf("got %+v %v", r, err)
	}
	r, err = MatchAnchor("url", "https://example.com/a", []AnchorRecord{{"x", "url", "https://example.com/ab"}})
	if err != nil || len(r.IDs) != 0 {
		t.Fatalf("unexpected url match %+v %v", r, err)
	}
}
