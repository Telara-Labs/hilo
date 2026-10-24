package record

import (
	"fmt"
	"net/url"
	"path"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

// Export constructs a NEW hosted metadata variant, never a full-body bundle or
// a rewritten signed source. The adapter must supply current verified live
// source/manifest/export heads under its authority, grant, policy and tomb fence,
// resolve durable export settlement before invocation, and sign/commit before
// disclosure. Regrant requires the originating device and a fresh signed variant.
func Export(source *Record, author Author, exportHeads []*Record, rs Ruleset, redactor Redactor, chunks []*Record) (*Record, error) {
	if source == nil || redactor == nil {
		return nil, fmt.Errorf("export source/redactor required")
	}
	src, err := Parse(source.HeaderJCS, source.BodyJCS, source.ID)
	if err != nil || src.Body == nil || src.Header.Red.Profile != ProfileLocal || src.Header.Author.MachineID == "" || author.MachineID != src.Header.Author.MachineID || !IsKeyID(author.KeyID) {
		return nil, fmt.Errorf("origin device local source required")
	}
	sanitize := func(s string, max int) string {
		s = redactor.RedactProfile(ProfilePushMetadata, redactor.Redact(s))
		if len(s) > max {
			s = s[:max]
			for !utf8.ValidString(s) {
				s = s[:len(s)-1]
			}
		}
		return s
	}
	h := src.Header
	h.Author = author
	h.Prov = ProvDerived
	h.Op = ""
	h.Links = Links{Origin: src.ID}
	h.Body = nil
	h.Red = Redact{Profile: ProfilePushMetadata, Epoch: rs.Epoch, Fingerprint: rs.Fingerprint()}
	held := []*Record{}
	for _, candidate := range exportHeads {
		if candidate == nil {
			return nil, fmt.Errorf("invalid export head")
		}
		r, err := Parse(candidate.HeaderJCS, candidate.BodyJCS, candidate.ID)
		if err != nil || r.Header.LID != h.LID || r.Header.Type != h.Type || r.Header.Red.Profile != ProfilePushMetadata || r.Header.Author.MachineID != author.MachineID {
			return nil, fmt.Errorf("foreign export head")
		}
		held = append(held, r)
	}
	sort.Slice(held, func(i, j int) bool {
		if held[i].Header.At != held[j].Header.At {
			return held[i].Header.At > held[j].Header.At
		}
		return held[i].ID > held[j].ID
	})
	seen := map[string]bool{}
	for _, r := range held {
		if !seen[r.ID] && len(h.Links.Supersedes) < 8 {
			h.Links.Supersedes = append(h.Links.Supersedes, r.ID)
			seen[r.ID] = true
		}
	}
	switch b := src.Body.(type) {
	case *TaskBody:
		return Build(h, &TaskMetaBody{Status: b.Status})
	case *SessionBody:
		byID := map[string]*ChunkBody{}
		for _, candidate := range chunks {
			if candidate == nil {
				return nil, fmt.Errorf("missing chunk")
			}
			r, err := Parse(candidate.HeaderJCS, candidate.BodyJCS, candidate.ID)
			if err != nil || r.Header.Subj.SessionKey != h.Subj.SessionKey || r.Header.Type != KindChunk {
				return nil, fmt.Errorf("invalid manifest chunk")
			}
			chunk, ok := r.Body.(*ChunkBody)
			if !ok {
				return nil, fmt.Errorf("full manifest chunk required")
			}
			byID[r.ID] = chunk
		}
		meta := &SessionMetaBody{NativeIDKind: b.NativeIDKind, MachineOS: sanitize(b.MachineOS, 128), StartedAt: b.StartedAt, LastEventAt: b.LastEventAt, EndedAt: b.EndedAt, End: b.End}
		remote := ""
		if b.Repo != nil {
			remote = sanitize(b.Repo.Remote, 2048)
			if clean, ok := metadataRef(remote); ok {
				remote = clean
			} else {
				remote = ""
			}
			meta.Repo = &MetaRepo{ID: b.Repo.ID, Remote: remote, CommitStart: sanitize(b.Repo.CommitStart, 128), CommitEnd: sanitize(b.Repo.CommitEnd, 128)}
			if *meta.Repo == (MetaRepo{}) {
				meta.Repo = nil
			}
		}
		if b.Counts != nil && (b.Counts.Requests != 0 || b.Counts.ToolCalls != 0 || b.Counts.ToolFailures != 0) {
			meta.Counts = &MetaCounts{Requests: b.Counts.Requests, ToolCalls: b.Counts.ToolCalls, ToolFailures: b.Counts.ToolFailures}
		}
		client := "client"
		if h.Subj.Client != nil {
			client = h.Subj.Client.ID
		}
		title := client + " session"
		if remote != "" {
			title += " · " + remote
		}
		title += " · " + time.UnixMilli(h.At).UTC().Format("2006-01-02")
		title = sanitize(title, 4096)
		runes := []rune(title)
		if len(runes) > MaxTitleRunes {
			title = string(runes[:MaxTitleRunes])
		}
		meta.Title = title
		pointers := []MetaPointer{}
		for _, id := range b.Chunks {
			chunk, ok := byID[id]
			if !ok {
				return nil, fmt.Errorf("source manifest incomplete")
			}
			tools := map[string]string{}
			for _, e := range chunk.Events {
				if e.Call != nil {
					tools[e.ID] = sanitize(e.Call.Tool, 128)
				}
			}
			for _, e := range chunk.Events {
				if e.Result == nil {
					continue
				}
				result := e.Result
				for _, ref := range result.OutPaths {
					if safe, ok := metadataRef(sanitize(ref, 2048)); ok {
						pointers = append(pointers, MetaPointer{Tool: tools[result.CallEventID], Outcome: result.Outcome, Kind: "file", Ref: safe})
					}
				}
			}
		}
		// Stable partition puts failure pointers first without using arrival time.
		sort.SliceStable(pointers, func(i, j int) bool { return pointers[i].Outcome == "error" && pointers[j].Outcome != "error" })
		if len(pointers) > MaxMetaPointers {
			pointers = pointers[:MaxMetaPointers]
		}
		meta.Pointers = pointers
		return Build(h, meta)
	default:
		return nil, fmt.Errorf("hosted export supports session/task metadata only")
	}
}
func metadataRef(ref string) (string, bool) {
	if ref == "" || strings.ContainsAny(ref, "\r\n\x00\\") {
		return "", false
	}
	if u, err := url.Parse(ref); err == nil && u.IsAbs() {
		if (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			return "", false
		}
		u.User = nil
		u.RawQuery = ""
		u.Fragment = ""
		u.RawFragment = ""
		return u.String(), true
	}
	if strings.HasPrefix(ref, "/") || path.Clean(ref) != ref || ref == ".." || strings.HasPrefix(ref, "../") {
		return "", false
	}
	return ref, true
}
