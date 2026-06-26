package eval

import (
	"crypto/hmac"
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"

	"github.com/nan/shamir-bmr/internal/circuit"
	"github.com/nan/shamir-bmr/internal/garble"
	"github.com/nan/shamir-bmr/internal/hmacsha"
	"github.com/nan/shamir-bmr/internal/mpc"
)

// TestE2EThresholdHMAC garbles and evaluates HMAC-SHA256 with a secret-shared
// key via the malicious Shamir-BMR protocol and checks the tag against
// crypto/hmac. The key is never reconstructed: its wires use the threshold
// encoding (masked external only). Slow (~minutes); skipped under -short.
func TestE2EThresholdHMAC(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping threshold-HMAC garbling under -short")
	}
	path := filepath.Join("..", "..", "test", "sha256.txt")
	if _, err := os.Stat(path); err != nil {
		t.Skip("test/sha256.txt not present")
	}
	comp, err := circuit.ParseFile(path)
	if err != nil {
		t.Fatal(err)
	}

	// bybit-like: 36-byte api_secret, a short public sign-string.
	key := []byte("0123456789abcdef0123456789abcdef0123")
	msg := []byte("1700000000api_key5000")

	h, err := hmacsha.Build(comp, len(key), len(msg))
	if err != nil {
		t.Fatal(err)
	}

	eng, err := mpc.NewEngine(mpc.Config{N: 3, T: 1})
	if err != nil {
		t.Fatal(err)
	}
	g := garble.NewGarbler(eng, h.C)

	// The key is secret-shared: mark its wires secret and supply the (simulated)
	// shared bits. The message wires stay public.
	keyBits, err := h.KeyBits(key)
	if err != nil {
		t.Fatal(err)
	}
	for i, w := range h.KeyWires {
		g.MarkSecret(w, keyBits[i])
	}

	if err := g.Garble(); err != nil {
		t.Fatalf("garble: %v", err)
	}

	// Public input: only the message bits matter; key slots are ignored.
	realBits := make([]uint8, h.C.NumInputWires())
	msgBits, err := h.MsgBits(msg)
	if err != nil {
		t.Fatal(err)
	}
	for i, w := range h.MsgWires {
		realBits[w] = msgBits[i]
	}

	ext, super := g.EncodeInput(realBits)
	outExt, err := Evaluate(g.Public(), ext, super)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	got := h.DecodeTag(g.DecodeOutput(outExt))

	m := hmac.New(sha256.New, key)
	m.Write(msg)
	want := m.Sum(nil)
	if string(got) != string(want) {
		t.Fatalf("threshold-HMAC tag = %x, want %x", got, want)
	}
	t.Logf("threshold HMAC-SHA256 tag = %x (matches crypto/hmac)", got)
}
