package mpc

import (
	"sync"
	"testing"

	"github.com/nan/shamir-bmr/internal/gf128"
)

func newEngine(t *testing.T) *Engine {
	t.Helper()
	e, err := NewEngine(Config{N: 3, T: 1})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestInputOpenRoundTrip(t *testing.T) {
	e := newEngine(t)
	secret := gf128.FromUint64(0xABCD)
	a, err := e.Input(secret)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Verify(); err != nil {
		t.Fatal(err)
	}
	got, err := e.Open(a)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(secret) {
		t.Fatalf("open mismatch: got %x", got.Bytes())
	}
}

func TestAddAndMul(t *testing.T) {
	e := newEngine(t)
	x, _ := e.Input(gf128.FromUint64(7))
	y, _ := e.Input(gf128.FromUint64(11))

	sum := e.Add(x, y)
	prod, err := e.Mul(x, y)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Verify(); err != nil {
		t.Fatal(err)
	}

	gotSum, _ := e.Open(sum)
	gotProd, _ := e.Open(prod)
	if !gotSum.Equal(gf128.FromUint64(7).Add(gf128.FromUint64(11))) {
		t.Fatal("sum wrong")
	}
	if !gotProd.Equal(gf128.FromUint64(7).Mul(gf128.FromUint64(11))) {
		t.Fatal("product wrong")
	}
}

func TestBitMultiplicationIsAnd(t *testing.T) {
	// For bits, field multiply == AND and field add == XOR.
	for _, tc := range [][2]uint64{{0, 0}, {0, 1}, {1, 0}, {1, 1}} {
		e := newEngine(t)
		a, _ := e.Input(gf128.FromUint64(tc[0]))
		b, _ := e.Input(gf128.FromUint64(tc[1]))
		and, _ := e.Mul(a, b)
		xor := e.Add(a, b)
		if err := e.Verify(); err != nil {
			t.Fatal(err)
		}
		gotAnd, _ := e.Open(and)
		gotXor, _ := e.Open(xor)
		wantAnd := gf128.FromUint64((tc[0] & tc[1]))
		wantXor := gf128.FromUint64(tc[0] ^ tc[1])
		if !gotAnd.Equal(wantAnd) || !gotXor.Equal(wantXor) {
			t.Fatalf("bit ops wrong for %v", tc)
		}
	}
}

func TestRandomBitIsBit(t *testing.T) {
	e := newEngine(t)
	bits := make([]Auth, 50)
	for i := range bits {
		b, err := e.RandomBit()
		if err != nil {
			t.Fatal(err)
		}
		bits[i] = b
	}
	if err := e.Verify(); err != nil {
		t.Fatal(err)
	}
	ones := 0
	for _, b := range bits {
		v, _ := e.Open(b)
		if !v.Equal(gf128.Zero) && !v.Equal(gf128.One) {
			t.Fatalf("RandomBit produced non-bit %x", v.Bytes())
		}
		if v.Equal(gf128.One) {
			ones++
		}
	}
	if ones == 0 || ones == len(bits) {
		t.Fatalf("RandomBit looks biased: %d/%d ones", ones, len(bits))
	}
}

// TestMaliciousOpenIsCaught simulates a corrupt party injecting an additive
// error into a single DN opening. The MAC verification must abort.
func TestMaliciousOpenIsCaught(t *testing.T) {
	e := newEngine(t)

	// Inject an error into exactly one DN product opening, leaving the
	// corresponding MAC multiplication's product open untouched. This models a
	// corrupt party lying about its share during reconstruction.
	var once sync.Once
	injected := false
	e.SetOpenHook(func(purpose string, v gf128.Elem) gf128.Elem {
		if purpose == "product" {
			once.Do(func() { injected = true; v = v.Add(gf128.One) })
		}
		return v
	})

	a, err := e.Input(gf128.FromUint64(1))
	if err != nil {
		t.Fatal(err)
	}
	b, err := e.Input(gf128.FromUint64(1))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.Mul(a, b); err != nil {
		t.Fatal(err)
	}
	if !injected {
		t.Fatal("test did not inject an error")
	}
	if err := e.Verify(); err == nil {
		t.Fatal("expected Verify to abort on injected error, but it passed")
	}
}

func TestRejectsBadConfig(t *testing.T) {
	if _, err := NewEngine(Config{N: 2, T: 1}); err == nil {
		t.Fatal("n=2,t=1 violates n>=2t+1 but was accepted")
	}
}
