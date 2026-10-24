package sync

import (
	"net/url"
	"regexp"
	"strings"

	"github.com/Telara-Labs/telara-memory/contract/record"
)

var metaTool = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.:-]{0,127}$`)
var metaIssue = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,31}-[1-9][0-9]{0,19}$`)
var metaRevision = regexp.MustCompile(`^[0-9a-f]{7,64}$`)
var metaSegment = regexp.MustCompile(`^[A-Za-z0-9_.@+~-]+$`)
var metaOS = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)
var metaHost = regexp.MustCompile(`^[A-Za-z0-9.\[\]:-]+$`)

// Admission validates the reduced wire shape; it never cleans, normalizes or
// rewrites signed bytes. Tenant redaction is an additional independent gate.
func metadataPath(s string, absolute bool) bool {
	if absolute {
		s = strings.TrimSuffix(strings.TrimPrefix(s, "/"), "/")
		if s == "" {
			return true
		}
	}
	if s == "" || len(s) > 1024 || strings.HasPrefix(s, "~") {
		return false
	}
	for _, part := range strings.Split(s, "/") {
		if part == "" || part == "." || part == ".." || !metaSegment.MatchString(part) {
			return false
		}
	}
	return true
}
func metadataURL(s string) bool {
	if len(s) > 2048 || strings.ContainsAny(s, "?#\\") {
		return false
	}
	u, err := url.Parse(s)
	return err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != "" && u.Hostname() != "" &&
		metaHost.MatchString(u.Host) && u.User == nil && u.Opaque == "" && !u.ForceQuery && u.RawQuery == "" &&
		u.Fragment == "" && metadataPath(u.Path, true)
}

// validSessionMetadata is an admission gate for sealed bytes, separate from the
// export sanitizer used when authoring a new record.
func validSessionMetadata(b *record.SessionMetaBody) bool {
	if b.MachineOS != "" && !metaOS.MatchString(b.MachineOS) {
		return false
	}
	if b.Counts != nil && (b.Counts.Requests < 0 || b.Counts.ToolCalls < 0 || b.Counts.ToolFailures < 0) {
		return false
	}
	if b.Repo != nil {
		r := b.Repo
		if (r.CommitStart != "" && !metaRevision.MatchString(r.CommitStart)) || (r.CommitEnd != "" && !metaRevision.MatchString(r.CommitEnd)) {
			return false
		}
		if r.Remote != "" {
			id, err := record.RepoID(r.Remote)
			if err != nil || id != r.ID || !metadataURL("https://"+r.Remote) {
				return false
			}
		}
	}
	for _, p := range b.Pointers {
		if !metaTool.MatchString(p.Tool) || !metadataOutcome(p.Outcome) || (p.Revision != "" && !metaRevision.MatchString(p.Revision)) {
			return false
		}
		switch p.Kind {
		case "file":
			if !metadataPath(p.Ref, false) {
				return false
			}
		case "issue":
			if !metaIssue.MatchString(p.Ref) {
				return false
			}
		case "url":
			if !metadataURL(p.Ref) {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func metadataOutcome(outcome string) bool {
	switch outcome {
	case "ok", "error", "unknown":
		return true
	}
	return false
}
