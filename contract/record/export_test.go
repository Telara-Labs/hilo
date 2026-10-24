package record

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestV3ExportMetadataAndRegrant(t *testing.T) {
	source := mustBuild(t, "task")
	author := source.Header.Author
	rs := Ruleset{Epoch: 7, Digest: hx("rules"), Engine: "test", Behavior: hx("public")}
	first, err := Export(source, author, nil, rs, actualRedactor{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Export(source, author, []*Record{first}, rs, actualRedactor{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	json.Unmarshal(second.BodyJCS, &body)
	if len(body) != 2 || body["status"] != "active" || second.Header.Links.Origin != source.ID || len(second.Header.Links.Supersedes) != 1 || second.Header.Links.Supersedes[0] != first.ID || first.ID == second.ID || first.Header.Body.Digest == second.Header.Body.Digest {
		t.Fatal("regrant rewrote source or reused withdrawn id")
	}
	for _, name := range []string{"chunk", "conclusion-explicit", "rollup", "call"} {
		if _, err := Export(mustBuild(t, name), author, nil, rs, actualRedactor{}, nil); err == nil {
			t.Fatal("full hosted body allowed", name)
		}
	}
	foreign := author
	foreign.MachineID = tMachine2
	if _, err := Export(source, foreign, nil, rs, actualRedactor{}, nil); err == nil {
		t.Fatal("hosted/foreign device reissued source")
	}
	h, b := fixtures()["session"]()
	session := b.(*SessionBody)
	session.Chunks = nil
	session.Title = "private source prompt"
	session.Cwd = "/private/path"
	session.Counts = &Counts{Requests: 1, AssistantFinals: 2}
	session.Repo = &RepoRef{Remote: "github.com/acme/api", Branch: "private-branch"}
	s, err := Build(h, b)
	if err != nil {
		t.Fatal(err)
	}
	meta, err := Export(s, author, nil, rs, actualRedactor{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(meta.BodyJCS), "private") || strings.Contains(string(meta.BodyJCS), "assistant_finals") || !strings.Contains(string(meta.BodyJCS), "claude-code session") {
		t.Fatal("metadata copied prose/nonallowlist counters")
	}
	h, b = fixtures()["session"]()
	s, err = Build(h, b)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Export(s, author, nil, rs, actualRedactor{}, nil); err == nil {
		t.Fatal("missing manifest chunk accepted")
	}
	for _, ref := range []string{"/absolute/private", "../escape", "file:///private", "a\\b", "a\nb"} {
		if _, ok := metadataRef(ref); ok {
			t.Fatal("unsafe ref", ref)
		}
	}
	if safe, ok := metadataRef("https://u:p@example.com/ticket?id=secret#part"); !ok || safe != "https://example.com/ticket" {
		t.Fatal("URL metadata not stripped")
	}
}

func TestV3ExportSessionUsesOnlyManifestPointers(t *testing.T) {
	h, b := fixtures()["chunk"]()
	chunk := b.(*ChunkBody)
	chunk.Events[1].Result = &ToolResult{CallEventID: chunk.Events[0].ID, Outcome: "error", OutPaths: []string{"src/retry.go", "/private/path"}}
	c, err := Build(h, b)
	if err != nil {
		t.Fatal(err)
	}
	h, b = fixtures()["session"]()
	b.(*SessionBody).Chunks = []string{c.ID}
	source, err := Build(h, b)
	if err != nil {
		t.Fatal(err)
	}
	rs := Ruleset{Epoch: 7, Digest: hx("public"), Engine: "test", Behavior: hx("fixture")}
	meta, err := Export(source, source.Header.Author, nil, rs, actualRedactor{}, []*Record{c})
	if err != nil {
		t.Fatal(err)
	}
	pointers := meta.Body.(*SessionMetaBody).Pointers
	if len(pointers) != 1 || pointers[0].Ref != "src/retry.go" || pointers[0].Outcome != "error" || pointers[0].Tool != "shell" {
		t.Fatal("non-manifest or unsafe pointer", pointers)
	}
	bad := *c
	bad.BodyJCS = nil
	if _, err := Export(source, source.Header.Author, nil, rs, actualRedactor{}, []*Record{&bad}); err == nil {
		t.Fatal("bodyless manifest accepted")
	}
}
