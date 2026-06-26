package eval

import (
	"math/rand"
	"os"
	"path/filepath"
	"testing"

	"github.com/nan/shamir-bmr/internal/circuit"
	"github.com/nan/shamir-bmr/internal/garble"
	"github.com/nan/shamir-bmr/internal/mpc"
)

// TestE2ESHA256 garbles and evaluates the full SHA-256 compression circuit via
// the malicious Shamir-BMR protocol and checks the result against a plaintext
// evaluation of the same circuit. It is slow (~1 min) and skipped under -short.
func TestE2ESHA256(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping full SHA-256 garbling under -short")
	}
	path := filepath.Join("..", "..", "test", "sha256.txt")
	if _, err := os.Stat(path); err != nil {
		t.Skip("test/sha256.txt not present")
	}
	c, err := circuit.ParseFile(path)
	if err != nil {
		t.Fatal(err)
	}

	rng := rand.New(rand.NewSource(42))
	inputs := make([]uint8, c.NumInputWires())
	for i := range inputs {
		inputs[i] = uint8(rng.Intn(2))
	}

	eng, err := mpc.NewEngine(mpc.Config{N: 3, T: 1})
	if err != nil {
		t.Fatal(err)
	}
	g := garble.NewGarbler(eng, c)
	if err := g.Garble(); err != nil {
		t.Fatalf("garble: %v", err)
	}
	ext, super := g.EncodeInput(inputs)
	outExt, err := Evaluate(g.Public(), ext, super)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	got := g.DecodeOutput(outExt)

	want, err := c.Eval(inputs)
	if err != nil {
		t.Fatal(err)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("output bit %d mismatch: bmr=%d plaintext=%d", i, got[i], want[i])
		}
	}
}
