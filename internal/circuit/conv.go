package circuit

// Bit convention of the Bristol SHA-256 compression circuit (test/sha256.txt).
//
// Each segment (the 512-bit message block, the 256-bit state, the 256-bit
// output) is carried on the wires as the *bit-reversal of its standard
// big-endian byte string*. Concretely, for a byte slice b read MSB-first as a
// bit stream of length 8*len(b), wire bit i holds stream bit (8*len(b)-1-i).
//
// This was verified against crypto/sha256 (see TestSHA256Conformance):
// compress(state, block) with the Davies-Meyer feed-forward, inputs ordered
// block-then-state, output in the same convention as the state input — so
// chaining one compression's 256-bit output directly into the next block's
// state input is identity wiring.

// BytesToWires converts a big-endian byte string to its wire-bit vector under
// the SHA-256 Bristol convention (full bit-reversal of the MSB-first stream).
func BytesToWires(b []byte) []uint8 {
	n := len(b) * 8
	out := make([]uint8, n)
	for p := 0; p < n; p++ {
		bit := (b[p/8] >> (7 - uint(p%8))) & 1
		out[n-1-p] = bit
	}
	return out
}

// WiresToBytes is the inverse of BytesToWires. len(bits) must be a multiple of 8.
func WiresToBytes(bits []uint8) []byte {
	n := len(bits)
	out := make([]byte, n/8)
	for p := 0; p < n; p++ {
		if bits[n-1-p]&1 == 1 {
			out[p/8] |= 1 << (7 - uint(p%8))
		}
	}
	return out
}
