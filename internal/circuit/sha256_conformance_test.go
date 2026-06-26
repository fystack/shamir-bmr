package circuit

import (
	"crypto/sha256"
	"encoding/binary"
	"testing"
)

// sha256IV is the SHA-256 initial hash value, as 32 big-endian bytes.
func sha256IVBytes() []byte {
	iv := []uint32{0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
		0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19}
	b := make([]byte, 32)
	for i, w := range iv {
		binary.BigEndian.PutUint32(b[i*4:], w)
	}
	return b
}

// shaPad applies standard SHA-256 padding to msg.
func shaPad(msg []byte) []byte {
	out := append([]byte{}, msg...)
	out = append(out, 0x80)
	for len(out)%64 != 56 {
		out = append(out, 0)
	}
	var l [8]byte
	binary.BigEndian.PutUint64(l[:], uint64(len(msg))*8)
	return append(out, l[:]...)
}

// sha256ViaCircuit computes a full SHA-256 by driving the compression circuit
// block-by-block, using the pinned BytesToWires/WiresToBytes convention. This
// exercises exactly the byte<->wire mapping and chaining that HMAC reuses.
func sha256ViaCircuit(t *testing.T, comp *Circuit, msg []byte) [32]byte {
	t.Helper()
	state := sha256IVBytes()
	padded := shaPad(msg)
	for off := 0; off < len(padded); off += 64 {
		block := padded[off : off+64]
		in := append(BytesToWires(block), BytesToWires(state)...)
		out, err := comp.Eval(in)
		if err != nil {
			t.Fatal(err)
		}
		state = WiresToBytes(out)
	}
	var d [32]byte
	copy(d[:], state)
	return d
}

// TestSHA256Conformance verifies test/sha256.txt really is SHA-256 (the prior
// suite only checked BMR-vs-circuit.Eval self-consistency). It pins the bit
// convention and Davies-Meyer feed-forward that HMAC-SHA256 depends on.
func TestSHA256Conformance(t *testing.T) {
	p := sha256Path()
	if p == "" {
		t.Skip("test/sha256.txt not present")
	}
	comp, err := ParseFile(p)
	if err != nil {
		t.Fatal(err)
	}
	cases := [][]byte{
		[]byte(""),
		[]byte("abc"),
		[]byte("The quick brown fox jumps over the lazy dog"),
		make([]byte, 55),  // largest single-block message
		make([]byte, 56),  // forces a second block
		make([]byte, 200), // multi-block
	}
	for i := range cases[3] {
		cases[3][i] = byte(i)
	}
	for i := range cases[5] {
		cases[5][i] = byte(i * 7)
	}
	for _, m := range cases {
		got := sha256ViaCircuit(t, comp, m)
		want := sha256.Sum256(m)
		if got != want {
			t.Fatalf("len=%d: circuit SHA-256=%x want %x", len(m), got, want)
		}
	}
}
