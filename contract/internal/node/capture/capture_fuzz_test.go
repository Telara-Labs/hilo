//go:build linux || darwin

package capture

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Telara-Labs/hilo/contract/record"
	"golang.org/x/sys/unix"
)

// fuzzCanary is a credential-shaped value the local ruleset must redact.
var fuzzCanary = "ghp_" + strings.Repeat("Z", 36)

var clientFixtures = map[string][]string{
	"claude-code":  {"claude.jsonl"},
	"codex":        {"codex.jsonl", "codex-0.161.0.jsonl"},
	"cursor-agent": {"cursor-agent-2026.10.22.jsonl"},
	"pi":           {"pi-1.1.0.jsonl"},
}

// decodeUnitBytes runs the same frame, strict JSON, decoder, redaction and
// normalization steps as preparation, over an in-memory unit with the given
// bounds. It returns the prepared batch and its events.
func decodeUnitBytes(client string, r io.Reader, unitLimit, frameLimit int) (preparedBatch, []record.Event, error) {
	batch, err := prepareUnitBytes(client, r, unitLimit, frameLimit)
	if err != nil {
		return preparedBatch{}, nil, err
	}
	rs, err := checkedRuleset()
	if err != nil {
		return preparedBatch{}, nil, err
	}
	events, err := normalize(batch, rs)
	return batch, events, err
}

// prepareUnitBytes is the in-memory counterpart of prepareHeld after open.
func prepareUnitBytes(client string, r io.Reader, unitLimit, frameLimit int) (preparedBatch, error) {
	policy, err := selectLocalPolicy("local", false)
	if err != nil {
		return preparedBatch{}, err
	}
	session, err := record.SessionKey(client, "local", record.NativeGlobal, syntheticSession, "")
	if err != nil {
		return preparedBatch{}, err
	}
	batch := preparedBatch{occurrence: sourceOccurrence{session: session}, client: client, homeRelativeUnit: "synthetic/unit.jsonl", nativeSession: syntheticSession}
	tree := piTree{}
	err = frameReader(context.Background(), r, func(line int, b []byte) error {
		if err := strictJSON(b); err != nil {
			return err
		}
		var observations []preparedObservation
		var err error
		switch client {
		case "claude-code":
			observations, err = decodeClaude(b, line, syntheticSession)
		case "codex":
			observations, err = decodeCodex(b, line, syntheticSession)
		case "cursor-agent":
			observations, err = decodeCursor(b, line)
		case "pi":
			if err = tree.add(b, line); err == nil {
				observations, err = decodePi(b, line, syntheticSession)
			}
		}
		if err != nil {
			return err
		}
		for _, o := range observations {
			if len(batch.observations) >= maxObservations {
				return hold("observation_limit")
			}
			clean, err := redactObservation(o, policy)
			if err != nil {
				return err
			}
			batch.observations = append(batch.observations, clean)
		}
		return nil
	}, unitLimit, frameLimit, &frameMemory{})
	if err == nil && client == "pi" {
		err = tree.finish(&batch)
	}
	if err != nil {
		return preparedBatch{}, err
	}
	return batch, nil
}

func addTranscriptSeeds(f *testing.F, client string) {
	f.Helper()
	for _, name := range clientFixtures[client] {
		b, err := os.ReadFile(filepath.Join("testdata", name))
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
		lines := bytes.SplitAfter(b, []byte("\n"))
		for _, l := range lines {
			if len(l) > 0 {
				f.Add(l)
			}
		}
		// Duplicate and reordered lines, a missing final newline.
		f.Add(append(append([]byte(nil), b...), b...))
		f.Add(bytes.TrimRight(b, "\n"))
		if len(lines) > 1 {
			f.Add(bytes.Join([][]byte{lines[len(lines)-1], lines[0]}, nil))
		}
		// A secret in the middle of a large text field.
		big := bytes.Replace(b, []byte(`"text":"`), []byte(`"text":"`+strings.Repeat("x", maxText)+" token "+fuzzCanary+" "), 1)
		f.Add(big)
	}
	f.Add([]byte("{}\n"))
	f.Add([]byte("\n\n\n"))
	f.Add([]byte(`{"type":"x","a":"\ud800"}` + "\n"))
	f.Add([]byte(`{"a":1,"a":2}` + "\n"))
	f.Add([]byte(strings.Repeat("[", 4096) + strings.Repeat("]", 4096) + "\n"))
	f.Add(append(bytes.Repeat([]byte{' '}, maxFrame), '\n'))
	f.Add(bytes.Repeat([]byte("{}\n"), maxObservations+1))
}

func checkAccepted(t *testing.T, input []byte, batch preparedBatch, events []record.Event) {
	t.Helper()
	if len(batch.observations) > maxObservations || len(events) != len(batch.observations) {
		t.Fatal("observation bound or count broken")
	}
	ids := map[string]bool{}
	for i, e := range events {
		if ids[e.ID] || e.Seq != int64(i) || !record.IsEventID(e.ID) {
			t.Fatal("event identities are not unique and ordered")
		}
		ids[e.ID] = true
	}
	for _, o := range batch.observations {
		if len(o.fields) > maxArgs {
			t.Fatal("field bound broken")
		}
		for _, fd := range o.fields {
			if len(fd.text) > maxText || (fd.truncated && fd.fullRedactedBytes <= maxText) {
				t.Fatal("field text bound broken")
			}
			if strings.Contains(fd.text, fuzzCanary) || strings.Contains(fd.name, fuzzCanary) {
				t.Fatal("credential-shaped value retained")
			}
		}
	}
}

func fuzzDecoder(f *testing.F, client string) {
	addTranscriptSeeds(f, client)
	f.Fuzz(func(t *testing.T, data []byte) {
		start := time.Now()
		batch, events, err := decodeUnitBytes(client, bytes.NewReader(data), maxUnit, maxFrame)
		if d := time.Since(start); len(data) <= maxFrame && d > 10*time.Second {
			t.Fatalf("decode of %d bytes took %v", len(data), d)
		}
		if err != nil {
			if Code(err) == "" {
				t.Fatalf("refusal is not a fixed hold code: %v", err)
			}
			return
		}
		checkAccepted(t, data, batch, events)
		again, events2, err := decodeUnitBytes(client, bytes.NewReader(data), maxUnit, maxFrame)
		if err != nil || !reflect.DeepEqual(batch, again) || !reflect.DeepEqual(events, events2) {
			t.Fatal("decoding is not deterministic")
		}
	})
}

// FuzzDecodeClaudeCode, FuzzDecodeCodex, FuzzDecodeCursor and FuzzDecodePi
// decode arbitrary transcripts. No input may panic, exceed the observation
// and field bounds, retain a credential-shaped value, produce colliding
// event ids, or decode differently twice.
func FuzzDecodeClaudeCode(f *testing.F) { fuzzDecoder(f, "claude-code") }
func FuzzDecodeCodex(f *testing.F)      { fuzzDecoder(f, "codex") }
func FuzzDecodeCursor(f *testing.F)     { fuzzDecoder(f, "cursor-agent") }
func FuzzDecodePi(f *testing.F)         { fuzzDecoder(f, "pi") }

// repeatReader yields data n times without materializing the expansion,
// modelling a small source that expands far beyond its size.
type repeatReader struct {
	data      []byte
	left, pos int
	read      int
}

func (r *repeatReader) Read(p []byte) (int, error) {
	if r.left == 0 || len(r.data) == 0 {
		return 0, io.EOF
	}
	n := 0
	for n < len(p) && r.left > 0 {
		c := copy(p[n:], r.data[r.pos:])
		n += c
		r.pos += c
		if r.pos == len(r.data) {
			r.pos = 0
			r.left--
		}
	}
	r.read += n
	return n, nil
}

// FuzzDecodeAmplified streams a repeated input, like a decompression bomb,
// through smaller unit and frame bounds. Reading stops at the unit bound,
// and allocation stays proportional to the bounded bytes read.
func FuzzDecodeAmplified(f *testing.F) {
	const unitLimit, frameLimit = 1 << 20, 256 << 10
	for client, names := range clientFixtures {
		b, err := os.ReadFile(filepath.Join("testdata", names[0]))
		if err != nil {
			f.Fatal(err)
		}
		which := map[string]uint8{"claude-code": 0, "codex": 1, "cursor-agent": 2, "pi": 3}[client]
		f.Add(which, b, uint16(4))
		f.Add(which, b, uint16(65535))
		f.Add(which, []byte(" "), uint16(65535))
		f.Add(which, []byte(`{"type":"user","message":{"content":"`+strings.Repeat("a", 1024)), uint16(65535))
	}
	f.Fuzz(func(t *testing.T, which uint8, data []byte, repeat uint16) {
		client := []string{"claude-code", "codex", "cursor-agent", "pi"}[which%4]
		r := &repeatReader{data: data, left: int(repeat)}
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		start := time.Now()
		_, _, err := decodeUnitBytes(client, r, unitLimit, frameLimit)
		elapsed := time.Since(start)
		runtime.ReadMemStats(&after)
		if r.read > unitLimit+(64<<10) {
			t.Fatalf("read %d bytes past the %d unit bound", r.read, unitLimit)
		}
		if len(data)*int(repeat) > unitLimit+(64<<10) && Code(err) != "unit_limit" && err != nil && Code(err) == "" {
			t.Fatalf("expanded input not refused with a hold code: %v", err)
		}
		// The race detector's shadow allocations make this budget meaningless;
		// every decode check above still runs under -race.
		if alloc := after.TotalAlloc - before.TotalAlloc; !raceDetector && alloc > uint64(64*unitLimit+(256<<20)) {
			t.Fatalf("allocated %d bytes for %d bytes read", alloc, r.read)
		}
		if elapsed > 20*time.Second {
			t.Fatalf("bounded decode took %v", elapsed)
		}
	})
}

// FuzzPrepareUnitShape writes the input as a real transcript unit, then
// replaces it with a symlink, hard link, FIFO, directory or permissive
// file. Only a private regular file is read, and its result matches the
// in-memory decoder exactly.
func FuzzPrepareUnitShape(f *testing.F) {
	claude, err := os.ReadFile(filepath.Join("testdata", "claude.jsonl"))
	if err != nil {
		f.Fatal(err)
	}
	for shape := uint8(0); shape < 8; shape++ {
		f.Add(shape, claude)
		f.Add(shape, []byte("{}\n"))
	}
	f.Fuzz(func(t *testing.T, shape uint8, data []byte) {
		if len(data) > 1<<20 {
			return
		}
		c, u := fixture(t, "claude-code", data)
		path := filepath.Join(c.root, u.relative)
		name := []string{"regular", "final_symlink", "child_symlink", "hardlink", "fifo", "directory", "public_file", "missing"}[shape%8]
		switch name {
		case "final_symlink":
			if err := os.Rename(path, path+".target"); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(path+".target", path); err != nil {
				t.Fatal(err)
			}
		case "child_symlink":
			if err := os.Symlink(c.root, filepath.Join(c.root, "child")); err != nil {
				t.Fatal(err)
			}
			u.relative = filepath.Join("child", u.relative)
		case "hardlink":
			if err := os.Link(path, path+".alias"); err != nil {
				t.Fatal(err)
			}
		case "fifo":
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := unix.Mkfifo(path, 0600); err != nil {
				t.Fatal(err)
			}
		case "directory":
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(path, 0700); err != nil {
				t.Fatal(err)
			}
		case "public_file":
			if err := os.Chmod(path, 0644); err != nil {
				t.Fatal(err)
			}
		case "missing":
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
		}
		bindIdentity(t, c, &u, syntheticSession)
		b, err := prepare(context.Background(), c, u, allow)
		if err != nil {
			if len(b.observations) != 0 || !strings.HasPrefix(err.Error(), "capture held: ") || strings.Contains(err.Error(), c.root) {
				t.Fatalf("%s: refusal exposed content or path: %v", name, err)
			}
		}
		switch name {
		case "regular", "hardlink":
			want, werr := prepareUnitBytes("claude-code", bytes.NewReader(data), maxUnit, maxFrame)
			if name == "hardlink" && err != nil {
				return
			}
			if Code(err) != Code(werr) {
				t.Fatalf("%s: file and memory decoders disagree: %v vs %v", name, err, werr)
			}
			if err == nil && werr == nil && !reflect.DeepEqual(b.observations, want.observations) {
				t.Fatalf("%s: file and memory observations differ", name)
			}
		default:
			if err == nil {
				t.Fatalf("%s: unsafe unit was read", name)
			}
		}
	})
}
