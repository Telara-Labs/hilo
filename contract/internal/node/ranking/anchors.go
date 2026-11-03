package ranking

import (
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

// AnchorRecord contains one indexed anchor attached to an already authorized
// record. Callers must enforce repository, tenant, lifecycle and disclosure
// policy before passing records, including before exposing ambiguity counts.
type AnchorRecord struct{ ID, Kind, Value string }
type AnchorMatches struct {
	IDs                  []string
	Ambiguous, Truncated bool
}

var issuePattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]{0,15}-[1-9][0-9]{0,15}$`)

func validAnchor(kind, value string, query bool) bool {
	if value == "" || len(value) > 2048 || strings.ContainsAny(value, "\x00\r\n") {
		return false
	}
	switch kind {
	case "sha":
		if (query && (len(value) < 7 || len(value) > 64)) || (!query && len(value) != 40 && len(value) != 64) {
			return false
		}
		for _, c := range value {
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
				return false
			}
		}
		return true
	case "path":
		if strings.HasPrefix(value, "/") || strings.Contains(value, `\`) {
			return false
		}
		for _, part := range strings.Split(value, "/") {
			if part == "" || part == "." || part == ".." {
				return false
			}
		}
		return true
	case "issue":
		return issuePattern.MatchString(value)
	case "url":
		u, err := url.Parse(value)
		return err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != "" && u.User == nil
	default:
		return false
	}
}

// MatchAnchor searches bounded, already authorized candidates, returning at
// most 50 record IDs in stable order. SHA ambiguity counts distinct complete
// hashes across all matches before truncation; it never chooses a winner.
// Matching paths uses whole path segments, and URLs are exact byte matches.
func MatchAnchor(kind, query string, records []AnchorRecord) (AnchorMatches, error) {
	if !validAnchor(kind, query, true) || len(records) > 5000 {
		return AnchorMatches{}, fmt.Errorf("invalid anchor query or input bound")
	}
	ids, hashes := map[string]bool{}, map[string]bool{}
	for _, r := range records {
		if r.ID == "" || len(r.ID) > 256 || !validAnchor(r.Kind, r.Value, false) {
			return AnchorMatches{}, fmt.Errorf("invalid anchor record")
		}
		if r.Kind != kind {
			continue
		}
		matched := false
		switch kind {
		case "sha":
			matched = strings.HasPrefix(strings.ToLower(r.Value), strings.ToLower(query))
		case "issue":
			matched = strings.EqualFold(r.Value, query)
		case "path":
			matched = r.Value == query || strings.HasSuffix(r.Value, "/"+query)
		case "url":
			matched = r.Value == query
		}
		if matched {
			ids[r.ID] = true
			if kind == "sha" {
				hashes[strings.ToLower(r.Value)] = true
			}
		}
	}
	out := AnchorMatches{Ambiguous: len(hashes) > 1}
	for id := range ids {
		out.IDs = append(out.IDs, id)
	}
	sort.Strings(out.IDs)
	if len(out.IDs) > 50 {
		out.IDs = out.IDs[:50]
		out.Truncated = true
	}
	return out, nil
}
