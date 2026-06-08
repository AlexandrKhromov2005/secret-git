package manifest

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// These tests validate the canonical JSON encoder byte-for-byte against EXTERNAL
// authorities — the RFC 8785 reference test vectors (testdata/jcs, from the
// json-canonicalization project) and the normative escape table in RFC 8785
// §3.2.2.2 — rather than against expectations fitted to our own encoder.
//
// IMPORTANT: a mismatch here means the implementation does NOT conform to the
// frozen JCS format. The correct response is to STOP and report, not to change the
// encoder (changing canonicalization changes every signature and hash).

func readVector(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "jcs", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestJCS_ReferenceObjects runs the within-domain (string-only) RFC 8785 reference
// objects and checks the encoder reproduces the reference output exactly. Coverage:
//   - weird.json:   UTF-16 code-unit key sorting incl. a surrogate-pair (astral)
//     key (U+1F602) that sorts BEFORE a BMP key (U+FB33); newline and carriage
//     return short escapes; C1 control U+0080 and DEL U+007F emitted literally
//     (>= U+0020); non-ASCII literal UTF-8.
//   - french.json:  locale-independent code-unit ordering (accented letters literal).
//   - unicode.json: an un-normalized combining sequence emitted literally (no NFC).
func TestJCS_ReferenceObjects(t *testing.T) {
	for _, name := range []string{"weird", "french", "unicode"} {
		in := readVector(t, name+".in.json")
		want := readVector(t, name+".out.json")

		var v map[string]any // all reference values here are strings
		if err := json.Unmarshal(in, &v); err != nil {
			t.Fatalf("%s: unmarshal: %v", name, err)
		}
		got, err := canonicalJSON(v)
		if err != nil {
			t.Fatalf("%s: encoder error: %v", name, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("%s: encoder does NOT match RFC 8785 reference (STOP & report, do not change format):\n got: %q\nwant: %q", name, got, want)
		}
	}
}

// TestJCS_ReferenceStringEscapes pins string escaping against the reference
// values.json output. That string carries U+000F (a control with no short escape,
// so it must use a lowercase hex escape), a newline (short escape), a quote and
// backslashes (escaped), and a forward slash (left unescaped), plus a literal
// non-ASCII character. The expected bytes are sliced out of the reference output
// file itself, so there is no hand-authored expectation.
func TestJCS_ReferenceStringEscapes(t *testing.T) {
	in := readVector(t, "values.in.json")
	out := readVector(t, "values.out.json")

	var doc map[string]any
	if err := json.Unmarshal(in, &doc); err != nil {
		t.Fatal(err)
	}
	strVal, ok := doc["string"].(string)
	if !ok {
		t.Fatal("values.in.json: 'string' field is not a string")
	}

	// Slice the reference output's canonical "string" field and wrap it as a
	// one-field object: {"string":<canonical>} — byte-exact, sourced externally.
	idx := bytes.Index(out, []byte(`"string":`))
	if idx < 0 {
		t.Fatal("values.out.json: missing 'string' field")
	}
	want := append([]byte("{"), out[idx:]...) // out ends with the closing brace

	got, err := canonicalJSON(map[string]any{"string": strVal})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("string escaping does NOT match RFC 8785 reference (STOP & report):\n got: %q\nwant: %q", got, want)
	}
}

// TestJCS_ShortEscapesPerRFC8785 covers the five short escapes (backspace, tab,
// newline, form feed, carriage return) and the lowercase hex form for other control
// characters, per the normative table in RFC 8785 §3.2.2.2. Expected bytes are
// built from a literal backslash so no escape text appears in the test source.
func TestJCS_ShortEscapesPerRFC8785(t *testing.T) {
	bs := "\\"
	in := "\b\t\n\f\r" + string(rune(0x01)) + string(rune(0x1f))
	// RFC 8785 §3.2.2.2: U+0008->\b U+0009->\t U+000A->\n U+000C->\f U+000D->\r;
	// other U+0000..U+001F -> lowercase \u00xx.
	want := `"` + bs + "b" + bs + "t" + bs + "n" + bs + "f" + bs + "r" + bs + "u0001" + bs + "u001f" + `"`

	got, err := canonicalJSON(in)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatalf("short-escape serialization does NOT match RFC 8785 §3.2.2.2 (STOP & report):\n got: %s\nwant: %s", got, want)
	}
}

// TestJCS_RejectsOutOfDomain confirms the encoder fails EXPLICITLY (returns an
// error) on values outside the manifest domain — floats, booleans, signed ints,
// json.Number, and heterogeneous arrays — rather than emitting incorrect bytes.
// This includes feeding the float/array-bearing reference inputs.
func TestJCS_RejectsOutOfDomain(t *testing.T) {
	bad := []any{
		float64(1.5),
		float64(0),
		true,
		false,
		int(5),
		int64(7),
		json.Number("1.5"),
		[]int{1, 2},
		[]any{"ok", float64(1)}, // an array element out of domain
		map[string]any{"x": float64(2)},
		map[string]any{"y": true},
		map[string]int{"z": 1},
	}
	for i, v := range bad {
		if _, err := canonicalJSON(v); err == nil {
			t.Errorf("case %d (%T): expected an error, got none", i, v)
		}
	}

	// In-domain []any (arrays of strings / objects, used by the roster) is accepted.
	if _, err := canonicalJSON([]any{"a", "b"}); err != nil {
		t.Errorf("[]any of strings: unexpected error: %v", err)
	}
	if _, err := canonicalJSON([]any{map[string]string{"k": "v"}}); err != nil {
		t.Errorf("[]any of objects: unexpected error: %v", err)
	}

	// Reference documents containing floats / heterogeneous arrays must also error.
	var vdoc map[string]any
	if err := json.Unmarshal(readVector(t, "values.in.json"), &vdoc); err != nil {
		t.Fatal(err)
	}
	if _, err := canonicalJSON(vdoc); err == nil {
		t.Error("values.in.json (has floats/heterogeneous arrays): expected error, got none")
	}

	var adoc []any
	if err := json.Unmarshal(readVector(t, "arrays.in.json"), &adoc); err != nil {
		t.Fatal(err)
	}
	if _, err := canonicalJSON(adoc); err == nil {
		t.Error("arrays.in.json (top-level heterogeneous array): expected error, got none")
	}
}
