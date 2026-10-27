package heads

import (
	"crypto/sha256"
	"encoding/hex"
	"math/rand"
	"testing"

	"github.com/Telara-Labs/hilo/contract/record"
)

func hx(s string) string { sum := sha256.Sum256([]byte(s)); return hex.EncodeToString(sum[:]) }

var L = hx("lid")

func v(name string, at int64, sup ...string) Version {
	var s []string
	for _, n := range sup {
		s = append(s, hx(n))
	}
	return Version{ID: hx(name), LID: L, Type: record.KindTask, Owner: "g", At: at, Profile: record.ProfileLocal, Supersedes: s, Live: true}
}

func ids(vs []Version) []string {
	var out []string
	for _, x := range vs {
		out = append(out, x.ID)
	}
	return out
}

func permute(r *rand.Rand, in []Version) []Version {
	out := append([]Version(nil), in...)
	r.Shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
	return out
}

func TestFiveVersionsEveryOrder(t *testing.T) {
	// v1 <- v2 <- v3, v4 concurrent with v3 (both supersede v2), v5 supersedes v3 and v4
	set := []Version{v("v1", 10), v("v2", 20, "v1"), v("v3", 30, "v2"), v("v4", 25, "v2"), v("v5", 40, "v3", "v4")}
	perms := [][]Version{}
	var gen func(prefix, rest []Version)
	gen = func(prefix, rest []Version) {
		if len(rest) == 0 {
			perms = append(perms, append([]Version(nil), prefix...))
			return
		}
		for i := range rest {
			r := append(append([]Version(nil), rest[:i]...), rest[i+1:]...)
			gen(append(prefix, rest[i]), r)
		}
	}
	gen(nil, set)
	if len(perms) != 120 {
		t.Fatalf("%d permutations", len(perms))
	}
	for _, p := range perms {
		// every prefix of an arrival order is a state some replica can be in;
		// the full set must always give v5
		h, ok := Head(p, nil, L, record.KindTask)
		if !ok || h.ID != hx("v5") {
			t.Fatalf("head %v", h)
		}
	}
}

func TestPrefixStatesAgree(t *testing.T) {
	set := []Version{v("v1", 10), v("v2", 20, "v1"), v("v3", 30, "v2"), v("v4", 25, "v2"), v("v5", 40, "v3", "v4")}
	r := rand.New(rand.NewSource(3))
	// the head of a subset depends only on the subset, not on its order
	for i := 0; i < 500; i++ {
		n := 1 + r.Intn(len(set))
		sub := permute(r, set)[:n]
		a := ids(Heads(sub, nil, L, record.KindTask))
		b := ids(Heads(permute(r, sub), nil, L, record.KindTask))
		if len(a) != len(b) {
			t.Fatal("order dependence")
		}
		for j := range a {
			if a[j] != b[j] {
				t.Fatal("order dependence")
			}
		}
	}
}

func TestFutureDatedSupersededByNextWrite(t *testing.T) {
	future := v("future", 9999999999999)
	next := v("next", 100, "future")
	h, _ := Head([]Version{future, next}, nil, L, record.KindTask)
	if h.ID != next.ID {
		t.Fatal("a future-dated version must not pin the head once superseded")
	}
	h, _ = Head([]Version{future, v("other", 100)}, nil, L, record.KindTask)
	if h.ID != future.ID {
		t.Fatal("without supersession the larger key wins")
	}
}

func TestInvalidatedSuperseder(t *testing.T) {
	a, b, c := v("A", 10), v("B", 20, "A"), v("C", 30, "B")
	b.Live = false // B retracted
	h, ok := Head([]Version{a, b, c}, nil, L, record.KindTask)
	if !ok || h.ID != c.ID {
		t.Fatalf("head %v", h)
	}
	// C retracted too: A stays superseded by the invalidated B
	c.Live = false
	if hs := Heads([]Version{a, b, c}, nil, L, record.KindTask); len(hs) != 0 {
		t.Fatalf("A revived: %v", ids(hs))
	}
	// B's header purged: the index pair keeps A superseded
	if hs := Heads([]Version{a, c}, []Pair{{From: b.ID, To: a.ID, Owner: a.Owner, LID: a.LID, Type: a.Type}}, L, record.KindTask); len(hs) != 0 {
		t.Fatalf("A revived after header purge: %v", ids(hs))
	}
}

func TestHeadMultiConflict(t *testing.T) {
	a, b := v("A", 10), v("B", 10)
	hs := Heads([]Version{a, b}, nil, L, record.KindTask)
	if len(hs) != 2 || !Conflict([]Version{b, a}, nil, L, record.KindTask) {
		t.Fatal("concurrent versions are both heads")
	}
	// equal At: ordered by id, descending
	if !(hs[0].ID > hs[1].ID) {
		t.Fatal("tie-break by id")
	}
	m := v("M", 5, "A", "B")
	if Conflict([]Version{a, b, m}, nil, L, record.KindTask) {
		t.Fatal("a merge supersedes both")
	}
}

func TestIgnoredSupersedes(t *testing.T) {
	a := v("A", 10)
	other := v("X", 20, "A")
	other.LID = hx("other")
	foreign := v("F", 30, "A")
	foreign.Owner = "tenant:acme"
	wrongType := v("W", 40, "A")
	wrongType.Type = record.KindRollup
	all := []Version{a, other, foreign, wrongType}
	hs := Heads(all, nil, L, record.KindTask)
	// A is not superseded by a record of another LID, type or owner;
	// the foreign-owner version is itself a version of L (same LID) and a head
	if len(hs) != 2 || hs[0].ID != foreign.ID || hs[1].ID != a.ID {
		t.Fatalf("%v", ids(hs))
	}
}

func TestShadowing(t *testing.T) {
	local := v("local", 10)
	exp := v("export", 20)
	exp.Profile = record.ProfilePushMetadata
	h, _ := Head([]Version{exp, local}, nil, L, record.KindTask)
	if h.ID != local.ID {
		t.Fatal("local versions shadow export variants")
	}
	h, _ = Head([]Version{exp}, nil, L, record.KindTask)
	if h.ID != exp.ID {
		t.Fatal("without a local version the variant is the head")
	}
}
