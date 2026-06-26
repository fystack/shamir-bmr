package hmacsha

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/nan/shamir-bmr/internal/circuit"
)

func compCircuit(t *testing.T) *circuit.Circuit {
	t.Helper()
	p := filepath.Join("..", "..", "test", "sha256.txt")
	if _, err := os.Stat(p); err != nil {
		t.Skip("test/sha256.txt not present")
	}
	c, err := circuit.ParseFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// evalPlain builds and plaintext-evaluates the HMAC circuit (fast), returning
// the tag — exercising the full byte<->wire wiring without the BMR engine.
func evalPlain(t *testing.T, comp *circuit.Circuit, key, msg []byte) []byte {
	t.Helper()
	h, err := Build(comp, len(key), len(msg))
	if err != nil {
		t.Fatal(err)
	}
	kb, err := h.KeyBits(key)
	if err != nil {
		t.Fatal(err)
	}
	mb, err := h.MsgBits(msg)
	if err != nil {
		t.Fatal(err)
	}
	in := append(append([]uint8{}, kb...), mb...)
	out, err := h.C.Eval(in)
	if err != nil {
		t.Fatal(err)
	}
	return h.DecodeTag(out)
}

func wantHMAC(key, msg []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	return m.Sum(nil)
}

func TestHMACPlaintext(t *testing.T) {
	comp := compCircuit(t)
	type tc struct{ key, msg string }
	cases := []tc{
		{"", ""},
		{"key", "The quick brown fox jumps over the lazy dog"},
		{"0123456789abcdef0123456789abcdef0123", // 36-byte key, bybit-like
			`GET/v5/order/realtime`},
		{"k", ""},                         // empty message
		{"key", string(make([]byte, 55))}, // inner stays 2 blocks
		{"key", string(make([]byte, 56))}, // inner spills to 3 blocks
		{string(make([]byte, 64)), "x"},   // full 64-byte key block
		{"secret", string(make([]byte, 200))},
	}
	for _, c := range cases {
		got := evalPlain(t, comp, []byte(c.key), []byte(c.msg))
		want := wantHMAC([]byte(c.key), []byte(c.msg))
		if hex.EncodeToString(got) != hex.EncodeToString(want) {
			t.Fatalf("HMAC(key=%dB,msg=%dB) = %x, want %x", len(c.key), len(c.msg), got, want)
		}
	}
}

func TestBuildStats(t *testing.T) {
	comp := compCircuit(t)
	h, err := Build(comp, 36, 64)
	if err != nil {
		t.Fatal(err)
	}
	ands := 0
	for _, g := range h.C.Gates {
		if g.Type == circuit.AND {
			ands++
		}
	}
	t.Logf("HMAC(key=36B,msg=64B): wires=%d gates=%d AND=%d inputs=%d (key=%d msg=%d) outputs=%d",
		h.C.NumWires, len(h.C.Gates), ands, h.C.NumInputWires(), len(h.KeyWires), len(h.MsgWires), h.C.NumOutputWires())
}
