package record

import (
	"bytes"
	"reflect"
	"strings"
	"testing"

	"github.com/Telara-Labs/hilo/contract/jcs"
)

func exportIdentitySource(t *testing.T, headerRepo string, repo *RepoRef) *Record {
	t.Helper()
	h, body := fixtures()["session"]()
	h.Subj.RepoID = headerRepo
	b := body.(*SessionBody)
	b.Chunks = nil
	b.Repo = repo
	r, err := Build(h, b)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func exportIdentityRuleset() Ruleset {
	return Ruleset{Epoch: 7, Digest: hx("export-identity-rules"), Engine: "test", Behavior: hx("export-identity-behavior")}
}

func TestExportRepositoryIdentityComesOnlyFromSource(t *testing.T) {
	const remote = "github.com/acme/api"
	repoID, err := RepoID(remote)
	if err != nil {
		t.Fatal(err)
	}
	dirty := false
	for _, tc := range []struct {
		name       string
		headerRepo string
		repo       *RepoRef
		want       *MetaRepo
	}{
		{"header-only-id", repoID, &RepoRef{Remote: remote}, &MetaRepo{ID: repoID, Remote: remote}},
		{"header-only-no-repo-object", repoID, nil, &MetaRepo{ID: repoID}},
		{"body-only-id", "", &RepoRef{ID: repoID, Remote: remote}, &MetaRepo{ID: repoID, Remote: remote}},
		{"matching-ids", repoID, &RepoRef{ID: repoID, Remote: remote, CommitStart: "3f9c2e1", CommitEnd: "a1b2c3d", Branch: "private-branch"}, &MetaRepo{ID: repoID, Remote: remote, CommitStart: "3f9c2e1", CommitEnd: "a1b2c3d"}},
		{"unknown-identity-never-inferred", "", &RepoRef{Remote: remote}, nil},
		{"unknown-identity-keeps-ordinary-commits", "", &RepoRef{Remote: remote, CommitStart: "3f9c2e1"}, &MetaRepo{CommitStart: "3f9c2e1"}},
		{"no-repository-evidence", "", nil, nil},
		{"known-id-no-remote", repoID, &RepoRef{Dirty: &dirty}, &MetaRepo{ID: repoID}},
		{"different-remote-suppressed", repoID, &RepoRef{ID: repoID, Remote: "github.com/acme/other"}, &MetaRepo{ID: repoID}},
		{"noncanonical-remote-suppressed", repoID, &RepoRef{Remote: "https://github.com/acme/api"}, &MetaRepo{ID: repoID}},
		{"git-suffix-suppressed", repoID, &RepoRef{Remote: remote + ".git"}, &MetaRepo{ID: repoID}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := exportIdentitySource(t, tc.headerRepo, tc.repo)
			headerBytes, bodyBytes, id := bytes.Clone(source.HeaderJCS), bytes.Clone(source.BodyJCS), source.ID
			out, err := Export(source, source.Header.Author, nil, exportIdentityRuleset(), actualRedactor{}, nil)
			if err != nil {
				t.Fatal(err)
			}
			meta := out.Body.(*SessionMetaBody)
			if !reflect.DeepEqual(meta.Repo, tc.want) {
				t.Fatalf("source-backed repository mismatch: got %+v want %+v", meta.Repo, tc.want)
			}
			if !reflect.DeepEqual(out.Header.Subj, source.Header.Subj) || out.Header.LID != source.Header.LID || out.Header.Type != source.Header.Type || out.Header.Links.Origin != id || out.Header.Red.Profile != ProfilePushMetadata || out.ID == id {
				t.Fatal("export changed source subject or immutable variant lineage")
			}
			if meta.NativeIDKind != NativeGlobal || meta.MachineOS != "darwin" || meta.StartedAt != tAt-1000 || meta.LastEventAt != tAt || !strings.HasPrefix(meta.Title, "claude-code session") || strings.Contains(string(out.BodyJCS), "private-branch") {
				t.Fatal("ordinary allowed metadata or closed allowlist changed")
			}
			if tc.want == nil || tc.want.Remote == "" {
				if strings.Contains(meta.Title, "github.com/") {
					t.Fatal("suppressed remote leaked through derived title")
				}
			}
			if source.ID != id || !bytes.Equal(source.HeaderJCS, headerBytes) || !bytes.Equal(source.BodyJCS, bodyBytes) {
				t.Fatal("export rewrote original received source bytes or id")
			}
			if _, err := Parse(headerBytes, bodyBytes, id); err != nil {
				t.Fatal("original source no longer admits", err)
			}
		})
	}
}

func TestExportRepositoryRedactedRemoteCannotChangeIdentity(t *testing.T) {
	secret := "ghp_" + strings.Repeat("a", 36)
	remote := "github.com/acme/" + secret
	if (actualRedactor{}).Redact(remote) == remote {
		t.Fatal("actual redactor did not inspect synthetic credential")
	}
	repoID, err := RepoID(remote)
	if err != nil {
		t.Fatal(err)
	}
	source := exportIdentitySource(t, repoID, &RepoRef{Remote: remote, CommitStart: "3f9c2e1"})
	beforeHeader, beforeBody, id := bytes.Clone(source.HeaderJCS), bytes.Clone(source.BodyJCS), source.ID
	out, err := Export(source, source.Header.Author, nil, exportIdentityRuleset(), actualRedactor{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	meta := out.Body.(*SessionMetaBody)
	if meta.Repo == nil || meta.Repo.ID != repoID || meta.Repo.Remote != "" || meta.Repo.CommitStart != "3f9c2e1" || strings.Contains(meta.Title, "github.com/") || strings.Contains(string(out.BodyJCS), secret) {
		t.Fatal("redacted remote was retained or became repository authority")
	}
	if source.ID != id || !bytes.Equal(source.HeaderJCS, beforeHeader) || !bytes.Equal(source.BodyJCS, beforeBody) {
		t.Fatal("redacted export rewrote source")
	}
}

func TestExportRepositoryExplicitBodyHeaderMismatchRefused(t *testing.T) {
	repoA, _ := RepoID("github.com/acme/api")
	repoB, _ := RepoID("github.com/acme/other")
	source := exportIdentitySource(t, repoA, &RepoRef{ID: repoA, Remote: "github.com/acme/api"})
	h := source.Header
	h.Subj.RepoID = repoB
	headerBytes, err := jcs.MarshalRecord(&h)
	if err != nil {
		t.Fatal(err)
	}
	id := ContentID(headerBytes)
	if _, err := Parse(headerBytes, source.BodyJCS, id); CodeOf(err) != CodeInvalidBody {
		t.Fatal("explicit body/header identity mismatch did not fail admission", err)
	}
	// Construct the received envelope directly. Export must reparse and reject
	// its actual canonical bytes, even if decoded convenience fields look valid.
	received := &Record{ID: id, HeaderJCS: bytes.Clone(headerBytes), BodyJCS: bytes.Clone(source.BodyJCS), Header: source.Header, Body: source.Body}
	beforeHeader, beforeBody := bytes.Clone(received.HeaderJCS), bytes.Clone(received.BodyJCS)
	if out, err := Export(received, source.Header.Author, nil, exportIdentityRuleset(), actualRedactor{}, nil); err == nil || out != nil {
		t.Fatal("export repaired conflicting received source instead of refusing")
	}
	if received.ID != id || !bytes.Equal(received.HeaderJCS, beforeHeader) || !bytes.Equal(received.BodyJCS, beforeBody) {
		t.Fatal("refused source was rewritten")
	}
}

func TestExportRepositoryUsesCanonicalWireIdentity(t *testing.T) {
	repoA, _ := RepoID("github.com/acme/api")
	repoB, _ := RepoID("github.com/acme/other")
	source := exportIdentitySource(t, repoA, &RepoRef{Remote: "github.com/acme/api"})
	headerBytes, bodyBytes, id := bytes.Clone(source.HeaderJCS), bytes.Clone(source.BodyJCS), source.ID
	// Decoded caller fields are not independent repository authority.
	source.Header.Subj.RepoID = repoB
	source.Body.(*SessionBody).Repo = &RepoRef{ID: repoB, Remote: "github.com/acme/other"}
	out, err := Export(source, source.Header.Author, nil, exportIdentityRuleset(), actualRedactor{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if out.Header.Subj.RepoID != repoA || out.Body.(*SessionMetaBody).Repo.ID != repoA || out.Body.(*SessionMetaBody).Repo.Remote != "github.com/acme/api" || out.Header.Links.Origin != id {
		t.Fatal("export trusted mutable decoded identity instead of source wire bytes")
	}
	if source.ID != id || !bytes.Equal(source.HeaderJCS, headerBytes) || !bytes.Equal(source.BodyJCS, bodyBytes) {
		t.Fatal("export changed original source wire bytes")
	}
}
