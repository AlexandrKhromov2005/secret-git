// Package bech32 is a minimal BIP-173 (bech32) encoder.
//
// It exists only to turn a raw 32-byte X25519 scalar into the exact string that
// filippo.io/age's (*X25519Identity).String() would produce, so that the result
// round-trips through age.ParseX25519Identity. age exposes no constructor from raw
// key bytes, hence this small helper. Only Encode is needed (no decode).
//
// The encoding mirrors age's own internal bech32 exactly: the checksum is computed
// over the LOWER-cased HRP, and if the supplied HRP is upper-case the whole output
// string is upper-cased (this is how age formats "AGE-SECRET-KEY-1..." secret
// keys). Producing byte-identical output to age guarantees age parses it back.
package bech32

import (
	"fmt"
	"strings"
)

const charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

var generator = []uint32{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}

func polymod(values []byte) uint32 {
	chk := uint32(1)
	for _, v := range values {
		top := chk >> 25
		chk = (chk&0x1ffffff)<<5 ^ uint32(v)
		for i := 0; i < 5; i++ {
			if (top>>uint(i))&1 == 1 {
				chk ^= generator[i]
			}
		}
	}
	return chk
}

// hrpExpand expands the HRP for the checksum, lower-casing it first (as age does),
// so the checksum is case-independent of how the HRP is presented.
func hrpExpand(hrp string) []byte {
	h := []byte(strings.ToLower(hrp))
	ret := make([]byte, 0, len(h)*2+1)
	for _, c := range h {
		ret = append(ret, c>>5)
	}
	ret = append(ret, 0)
	for _, c := range h {
		ret = append(ret, c&31)
	}
	return ret
}

func createChecksum(hrp string, data []byte) []byte {
	values := append(hrpExpand(hrp), data...)
	values = append(values, 0, 0, 0, 0, 0, 0)
	mod := polymod(values) ^ 1
	ret := make([]byte, 6)
	for p := 0; p < 6; p++ {
		ret[p] = byte(mod>>uint(5*(5-p))) & 31
	}
	return ret
}

func convertBits(data []byte, frombits, tobits byte, pad bool) ([]byte, error) {
	var ret []byte
	acc := uint32(0)
	bits := byte(0)
	maxv := byte(1<<tobits - 1)
	for idx, value := range data {
		if value>>frombits != 0 {
			return nil, fmt.Errorf("bech32: invalid data range: data[%d]=%d", idx, value)
		}
		acc = acc<<frombits | uint32(value)
		bits += frombits
		for bits >= tobits {
			bits -= tobits
			ret = append(ret, byte(acc>>bits)&maxv)
		}
	}
	if pad {
		if bits > 0 {
			ret = append(ret, byte(acc<<(tobits-bits))&maxv)
		}
	} else if bits >= frombits {
		return nil, fmt.Errorf("bech32: illegal zero padding")
	} else if byte(acc<<(tobits-bits))&maxv != 0 {
		return nil, fmt.Errorf("bech32: non-zero padding")
	}
	return ret, nil
}

// Encode encodes the HRP and data to bech32. If the HRP is upper-case, the whole
// output is upper-cased (matching age). Mixed-case HRPs are rejected.
func Encode(hrp string, data []byte) (string, error) {
	values, err := convertBits(data, 8, 5, true)
	if err != nil {
		return "", err
	}
	if len(hrp) < 1 {
		return "", fmt.Errorf("bech32: invalid HRP: %q", hrp)
	}
	for p, c := range hrp {
		if c < 33 || c > 126 {
			return "", fmt.Errorf("bech32: invalid HRP character: hrp[%d]=%d", p, c)
		}
	}
	if strings.ToUpper(hrp) != hrp && strings.ToLower(hrp) != hrp {
		return "", fmt.Errorf("bech32: mixed case HRP: %q", hrp)
	}
	wasLower := strings.ToLower(hrp) == hrp
	lhrp := strings.ToLower(hrp)

	var b strings.Builder
	b.WriteString(lhrp)
	b.WriteByte('1')
	for _, p := range values {
		b.WriteByte(charset[p])
	}
	for _, p := range createChecksum(lhrp, values) {
		b.WriteByte(charset[p])
	}
	if wasLower {
		return b.String(), nil
	}
	return strings.ToUpper(b.String()), nil
}
