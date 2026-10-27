package jcs

import (
	"errors"
	"math"
	"strings"
	"testing"
)

// u returns the six-character JSON escape for the UTF-16 code unit hex. The
// escapes are built at run time so no tool can rewrite them in the source.
func u(hex string) string { return "\x5cu" + hex }

func TestCanonicalizeRFC8785Example(t *testing.T) {
	in := `{
  "numbers": [333333333.33333329, 1E30, 4.50, 2e-3, 0.000000000000000000000000001],
  "string": "` + u("20ac") + `$` + u("000F") + u("000a") + `A'` + u("0042") + u("0022") + u("005c") + `\\\"\/",
  "literals": [null, true, false]
}`
	want := `{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"` + "\xe2\x82\xac" + `$` + u("000f") + `\nA'B\"\\\\\"/"}`
	got, err := Canonicalize([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}

func TestFormatNumberRFC8785AppendixB(t *testing.T) {
	cases := []struct {
		bits uint64
		want string
	}{
		{0x0000000000000000, "0"},
		{0x8000000000000000, "0"},
		{0x0000000000000001, "5e-324"},
		{0x8000000000000001, "-5e-324"},
		{0x7fefffffffffffff, "1.7976931348623157e+308"},
		{0xffefffffffffffff, "-1.7976931348623157e+308"},
		{0x4340000000000000, "9007199254740992"},
		{0xc340000000000000, "-9007199254740992"},
		{0x4430000000000000, "295147905179352830000"},
		{0x44b52d02c7e14af5, "9.999999999999997e+22"},
		{0x44b52d02c7e14af6, "1e+23"},
		{0x44b52d02c7e14af7, "1.0000000000000001e+23"},
		{0x444b1ae4d6e2ef4e, "999999999999999700000"},
		{0x444b1ae4d6e2ef4f, "999999999999999900000"},
		{0x444b1ae4d6e2ef50, "1e+21"},
		{0x3eb0c6f7a0b5ed8c, "9.999999999999997e-7"},
		{0x3eb0c6f7a0b5ed8d, "0.000001"},
		{0x41b3de4355555553, "333333333.3333332"},
		{0x41b3de4355555554, "333333333.33333325"},
		{0x41b3de4355555555, "333333333.3333333"},
		{0x41b3de4355555556, "333333333.3333334"},
		{0x41b3de4355555557, "333333333.33333343"},
		{0xbecbf647612f3696, "-0.0000033333333333333333"},
		{0x43143ff3c1cb0959, "1424953923781206.2"},
	}
	for _, c := range cases {
		if got := FormatNumber(math.Float64frombits(c.bits)); got != c.want {
			t.Errorf("%016x: got %s want %s", c.bits, got, c.want)
		}
	}
}

func TestCanonicalizeAccepts(t *testing.T) {
	cases := []struct{ in, want string }{
		{`{}`, `{}`},
		{` {} `, `{}`},
		{"\n[1,2]\r\n\t", `[1,2]`},
		{`"a"`, `"a"`},
		{`true`, `true`},
		{`null`, `null`},
		{`{"b":1,"a":2}`, `{"a":2,"b":1}`},
		{`{"` + u("00e9") + `":1,"e":2}`, `{"e":2,"` + "\xc3\xa9" + `":1}`},
		// UTF-16 ordering: U+1F600 (D83D DE00) sorts before U+FB33 though its code point is larger.
		{`{"` + u("fb33") + `":1,"` + u("d83d") + u("de00") + `":2}`, `{"` + "\xf0\x9f\x98\x80" + `":2,"` + "\xef\xac\xb3" + `":1}`},
		{`"` + u("2028") + u("007f") + `"`, "\"\xe2\x80\xa8\x7f\""},
		{`"<>&"`, `"<>&"`},
		{`"` + u("003c") + `"`, `"<"`},
		{`"` + u("001f") + `"`, `"` + u("001f") + `"`},
		{`-0`, `0`},
		{`1E2`, `100`},
		{`[[[]]]`, `[[[]]]`},
	}
	for _, c := range cases {
		got, err := Canonicalize([]byte(c.in))
		if err != nil {
			t.Errorf("%q: %v", c.in, err)
			continue
		}
		if string(got) != c.want {
			t.Errorf("%q: got %s want %s", c.in, got, c.want)
		}
	}
}

func TestCanonicalizeRejects(t *testing.T) {
	cases := []struct {
		name, in, code string
	}{
		{"empty", ``, CodeSyntax},
		{"only whitespace", `   `, CodeSyntax},
		{"trailing token", `{}x`, CodeTrailingData},
		{"trailing value", `{} {}`, CodeTrailingData},
		{"trailing comma", `[1,]`, CodeSyntax},
		{"bom", "\xef\xbb\xbf{}", CodeSyntax},
		{"invalid utf8 raw", "\"a\xffb\"", CodeInvalidUTF8},
		{"invalid utf8 outside string", "{}\xff", CodeInvalidUTF8},
		{"encoded surrogate", "\"\xed\xa0\x80\"", CodeInvalidUTF8},
		{"lone high", `"` + u("d800") + `"`, CodeLoneSurrogate},
		{"lone high then text", `"` + u("d800") + `x"`, CodeLoneSurrogate},
		{"lone low", `"` + u("dc00") + `"`, CodeLoneSurrogate},
		{"high high", `"` + u("d800") + u("d800") + `"`, CodeLoneSurrogate},
		{"lone in key", `{"` + u("dfff") + `":1}`, CodeLoneSurrogate},
		{"duplicate key", `{"a":1,"a":2}`, CodeDuplicateKey},
		{"duplicate after unescape", `{"a":1,"` + u("0061") + `":2}`, CodeDuplicateKey},
		{"nested duplicate", `{"x":{"k":1,"k":1}}`, CodeDuplicateKey},
		{"noncharacter escaped", `"` + u("ffff") + `"`, CodeNoncharacter},
		{"noncharacter raw", "\"\xef\xb7\x90\"", CodeNoncharacter},
		{"noncharacter astral", `"` + u("d83f") + u("dffe") + `"`, CodeNoncharacter},
		{"overflow", `1e400`, CodeNumberRange},
		{"underflow", `1e-400`, CodeNumberRange},
		{"leading zero", `01`, CodeTrailingData},
		{"plus sign", `+1`, CodeSyntax},
		{"bare fraction", `1.`, CodeSyntax},
		{"control char", "\"a\x01\"", CodeSyntax},
		{"bad escape", `"\x"`, CodeSyntax},
		{"single quotes", `'a'`, CodeSyntax},
		{"NaN", `NaN`, CodeSyntax},
		{"unterminated", `{"a":1`, CodeSyntax},
		{"too deep", strings.Repeat("[", MaxDepth+1) + strings.Repeat("]", MaxDepth+1), CodeDepth},
	}
	for _, c := range cases {
		_, err := Canonicalize([]byte(c.in))
		var je *Error
		if !errors.As(err, &je) {
			t.Errorf("%s: want error %s, got %v", c.name, c.code, err)
			continue
		}
		if je.Code != c.code {
			t.Errorf("%s: want code %s, got %s (%v)", c.name, c.code, je.Code, err)
		}
	}
}

func TestCanonicalizeRecordProfile(t *testing.T) {
	ok := []string{`{"a":9007199254740991}`, `{"a":-9007199254740991}`, `{"a":0}`, `[1,2,3]`}
	for _, in := range ok {
		if _, err := CanonicalizeRecord([]byte(in)); err != nil {
			t.Errorf("%s: %v", in, err)
		}
	}
	bad := []struct{ in, code string }{
		{`{"a":null}`, CodeNullNotAllowed},
		{`{"a":1.5}`, CodeNotInteger},
		{`{"a":1.0}`, CodeNotInteger},
		{`{"a":1e2}`, CodeNotInteger},
		{`{"a":-0}`, CodeNotInteger},
		{`{"a":9007199254740992}`, CodeNumberRange},
		{`{"a":-9007199254740993}`, CodeNumberRange},
	}
	for _, c := range bad {
		_, err := CanonicalizeRecord([]byte(c.in))
		var je *Error
		if !errors.As(err, &je) || je.Code != c.code {
			t.Errorf("%s: want %s, got %v", c.in, c.code, err)
		}
	}
}

func TestIsCanonicalRecord(t *testing.T) {
	if !IsCanonicalRecord([]byte(`{"a":1,"b":[true]}`)) {
		t.Fatal("canonical input reported non-canonical")
	}
	for _, in := range []string{`{"b":1,"a":1}`, `{"a": 1}`, `{"a":"` + u("0041") + `"}`, ` {}`} {
		if IsCanonicalRecord([]byte(in)) {
			t.Errorf("%q reported canonical", in)
		}
	}
}

func TestMarshalRecordGoValues(t *testing.T) {
	type inner struct {
		Z string `json:"z"`
		A int64  `json:"a"`
	}
	got, err := MarshalRecord(map[string]any{"k": inner{Z: "<&>", A: 7}})
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `{"k":{"a":7,"z":"<&>"}}` {
		t.Fatalf("got %s", got)
	}
	// Reject before encoding/json can silently replace invalid UTF-8.
	if _, err := Marshal("a\xffb"); err == nil {
		t.Fatal("typed invalid UTF-8 repaired")
	}
}

func TestStringArray(t *testing.T) {
	got, err := StringArray("mnc1", "tag", "a\"b", "\xc3\xa9")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `["mnc1","tag","a\"b","`+"\xc3\xa9"+`"]` {
		t.Fatalf("got %s", got)
	}
	if _, err := StringArray("ok", "bad\xff"); err == nil {
		t.Fatal("invalid UTF-8 accepted")
	}
	if _, err := StringArray("\xef\xbf\xbe"); err == nil {
		t.Fatal("noncharacter accepted")
	}
	empty, _ := StringArray()
	if string(empty) != `[]` {
		t.Fatalf("got %s", empty)
	}
}

// Canonicalization is idempotent on everything it accepts.
func TestIdempotent(t *testing.T) {
	inputs := []string{`{"z":[1,2.5,{"y":"` + u("00ff") + `"}],"a":-1e-7}`, `[1e21,1e-6,1e-7,123456789012345680000]`}
	for _, in := range inputs {
		a, err := Canonicalize([]byte(in))
		if err != nil {
			t.Fatal(err)
		}
		b, err := Canonicalize(a)
		if err != nil {
			t.Fatal(err)
		}
		if string(a) != string(b) {
			t.Errorf("not idempotent: %s vs %s", a, b)
		}
	}
}
