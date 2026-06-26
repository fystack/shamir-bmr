package prf

import (
	"testing"

	"github.com/nan/shamir-bmr/internal/gf128"
)

func TestDeterministic(t *testing.T) {
	k := gf128.Random()
	if !Hash(k, 5, 2).Equal(Hash(k, 5, 2)) {
		t.Fatal("Hash not deterministic")
	}
}

func TestDistinctInputsDistinctOutputs(t *testing.T) {
	k := gf128.Random()
	seen := map[[16]byte]bool{}
	add := func(e gf128.Elem) {
		b := e.Bytes()
		if seen[b] {
			t.Fatal("collision across distinct (gate,slot)")
		}
		seen[b] = true
	}
	for g := uint64(0); g < 50; g++ {
		for s := uint32(0); s < 4; s++ {
			add(Hash(k, g, s))
		}
	}
}

func TestKeySensitivity(t *testing.T) {
	// Keys differing by the free-XOR offset must give unrelated-looking outputs.
	k0 := gf128.Random()
	R := gf128.Random()
	k1 := k0.Add(R)
	h0 := Hash(k0, 7, 1)
	h1 := Hash(k1, 7, 1)
	if h0.Equal(h1) {
		t.Fatal("Hash insensitive to key offset")
	}
	// The difference must not simply equal R (which would break free-XOR).
	if h0.Add(h1).Equal(R) {
		t.Fatal("H(k)^H(k+R) == R: not correlation robust")
	}
}
