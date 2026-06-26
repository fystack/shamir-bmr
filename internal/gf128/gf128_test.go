package gf128

import "testing"

func TestAddIsInvolutionAndIdentity(t *testing.T) {
	for i := 0; i < 1000; i++ {
		a := Random()
		if !a.Add(Zero).Equal(a) {
			t.Fatal("a + 0 != a")
		}
		if !a.Add(a).IsZero() {
			t.Fatal("a + a != 0 (char 2)")
		}
	}
}

func TestMulIdentityAndZero(t *testing.T) {
	for i := 0; i < 1000; i++ {
		a := Random()
		if !a.Mul(One).Equal(a) {
			t.Fatal("a * 1 != a")
		}
		if !a.Mul(Zero).IsZero() {
			t.Fatal("a * 0 != 0")
		}
	}
}

func TestMulCommutative(t *testing.T) {
	for i := 0; i < 1000; i++ {
		a, b := Random(), Random()
		if !a.Mul(b).Equal(b.Mul(a)) {
			t.Fatal("multiplication not commutative")
		}
	}
}

func TestMulAssociative(t *testing.T) {
	for i := 0; i < 500; i++ {
		a, b, c := Random(), Random(), Random()
		if !a.Mul(b).Mul(c).Equal(a.Mul(b.Mul(c))) {
			t.Fatal("multiplication not associative")
		}
	}
}

func TestDistributive(t *testing.T) {
	for i := 0; i < 500; i++ {
		a, b, c := Random(), Random(), Random()
		left := a.Mul(b.Add(c))
		right := a.Mul(b).Add(a.Mul(c))
		if !left.Equal(right) {
			t.Fatal("distributive law failed")
		}
	}
}

func TestInverse(t *testing.T) {
	for i := 0; i < 1000; i++ {
		a := Random()
		if a.IsZero() {
			continue
		}
		if !a.Mul(a.Inv()).Equal(One) {
			t.Fatalf("a * a^-1 != 1 for %x", a.Bytes())
		}
	}
}

func TestBytesRoundTrip(t *testing.T) {
	for i := 0; i < 1000; i++ {
		a := Random()
		b := a.Bytes()
		if !FromBytes(b[:]).Equal(a) {
			t.Fatal("Bytes/FromBytes round-trip failed")
		}
	}
}

func TestBitOnePolynomialMultiply(t *testing.T) {
	// Multiplying by x repeatedly should match a manual shift+reduce, and
	// x^128 must reduce to x^7 + x^2 + x + 1 (0x87).
	x := Elem{lo: 2} // polynomial x
	acc := One
	for i := 0; i < 127; i++ {
		acc = acc.Mul(x)
	}
	// acc = x^127, top bit set.
	if acc.hi != (uint64(1) << 63) {
		t.Fatalf("x^127 wrong: %x", acc.Bytes())
	}
	acc = acc.Mul(x) // x^128 -> reduction
	if acc.hi != 0 || acc.lo != reduction {
		t.Fatalf("x^128 did not reduce to 0x87, got %x", acc.Bytes())
	}
}

func TestLsb(t *testing.T) {
	if One.Lsb() != 1 {
		t.Fatal("Lsb(1) != 1")
	}
	if Zero.Lsb() != 0 {
		t.Fatal("Lsb(0) != 0")
	}
}
