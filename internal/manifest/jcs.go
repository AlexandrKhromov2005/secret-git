package manifest

import (
	"bytes"
	"fmt"
	"sort"
	"strconv"
	"unicode/utf16"
)

// canonicalJSON implements the subset of RFC 8785 (JSON Canonicalization Scheme)
// needed for the manifest. The manifest value space is restricted to strings,
// uint64, null, string->string maps, and string arrays — there are no floats — so
// the difficult part of JCS (ECMAScript number serialization) never arises.
//
// SECURITY-REVIEW (§7.4): determinism of this encoder. Object members are sorted
// by UTF-16 code-unit order; integers are plain decimal; strings are escaped per
// RFC 8785 §3.2.2.2; arrays keep their order. The bytes produced here are exactly
// what gets signed and what gets encrypted.
func canonicalJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	if err := encodeValue(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func encodeValue(buf *bytes.Buffer, v any) error {
	switch x := v.(type) {
	case nil:
		buf.WriteString("null")
	case string:
		encodeString(buf, x)
	case uint64:
		buf.WriteString(strconv.FormatUint(x, 10))
	case []string:
		buf.WriteByte('[')
		for i, s := range x {
			if i > 0 {
				buf.WriteByte(',')
			}
			encodeString(buf, s)
		}
		buf.WriteByte(']')
	case map[string]string:
		m := make(map[string]any, len(x))
		for k, val := range x {
			m[k] = val
		}
		return encodeObject(buf, m)
	case map[string]any:
		return encodeObject(buf, x)
	default:
		return fmt.Errorf("manifest: canonical encode: unsupported type %T", v)
	}
	return nil
}

func encodeObject(buf *bytes.Buffer, m map[string]any) error {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return jcsLess(keys[i], keys[j]) })

	buf.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			buf.WriteByte(',')
		}
		encodeString(buf, k)
		buf.WriteByte(':')
		if err := encodeValue(buf, m[k]); err != nil {
			return err
		}
	}
	buf.WriteByte('}')
	return nil
}

// jcsLess orders strings by their UTF-16 code-unit sequence, as RFC 8785 requires
// for object member names.
func jcsLess(a, b string) bool {
	ua := utf16.Encode([]rune(a))
	ub := utf16.Encode([]rune(b))
	for i := 0; i < len(ua) && i < len(ub); i++ {
		if ua[i] != ub[i] {
			return ua[i] < ub[i]
		}
	}
	return len(ua) < len(ub)
}

const hexDigits = "0123456789abcdef"

// encodeString writes a JSON string escaped per RFC 8785 §3.2.2.2.
func encodeString(buf *bytes.Buffer, s string) {
	buf.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			buf.WriteString(`\"`)
		case '\\':
			buf.WriteString(`\\`)
		case '\b':
			buf.WriteString(`\b`)
		case '\t':
			buf.WriteString(`\t`)
		case '\n':
			buf.WriteString(`\n`)
		case '\f':
			buf.WriteString(`\f`)
		case '\r':
			buf.WriteString(`\r`)
		default:
			if r < 0x20 {
				buf.WriteString(`\u00`)
				buf.WriteByte(hexDigits[(r>>4)&0xf])
				buf.WriteByte(hexDigits[r&0xf])
			} else {
				buf.WriteRune(r)
			}
		}
	}
	buf.WriteByte('"')
}
