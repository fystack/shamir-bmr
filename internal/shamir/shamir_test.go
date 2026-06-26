package shamir

import (
	"testing"

	"github.com/nan/shamir-bmr/internal/gf128"
)

func TestShareReconstructRoundTrip(t *testing.T) {
	for trial := 0; trial < 500; trial++ {
		secret := gf128.Random()
		shares := Split(secret, 1, 3)
		if !Reconstruct(shares).Equal(secret) {
			t.Fatal("reconstruct from all shares failed")
		}
		// Any t+1 = 2 shares suffice.
		if !Reconstruct(shares[:2]).Equal(secret) {
			t.Fatal("reconstruct from 2 shares failed")
		}
		if !Reconstruct([]Share{shares[0], shares[2]}).Equal(secret) {
			t.Fatal("reconstruct from shares {0,2} failed")
		}
	}
}

func TestThresholdHidesSecret(t *testing.T) {
	// With t=1, a single share must be independent of the secret: for any
	// candidate secret there exists a consistent polynomial. We check that a
	// single share takes many different values across random sharings of the
	// SAME secret (i.e. it is masked).
	secret := gf128.FromUint64(0x1234)
	seen := map[[16]byte]bool{}
	for i := 0; i < 100; i++ {
		s := Split(secret, 1, 3)
		b := s[0].Y.Bytes()
		seen[b] = true
	}
	if len(seen) < 90 {
		t.Fatalf("party-1 share looks non-random across sharings: %d distinct", len(seen))
	}
}

func TestLinearity(t *testing.T) {
	// Shares add component-wise to share the sum (same polynomial degree).
	for trial := 0; trial < 200; trial++ {
		a, b := gf128.Random(), gf128.Random()
		sa := Split(a, 1, 3)
		sb := Split(b, 1, 3)
		sum := make([]Share, 3)
		for i := range sum {
			sum[i] = Share{X: sa[i].X, Y: sa[i].Y.Add(sb[i].Y)}
		}
		if !Reconstruct(sum).Equal(a.Add(b)) {
			t.Fatal("share linearity (addition) failed")
		}
	}
}

func TestScalarMul(t *testing.T) {
	for trial := 0; trial < 200; trial++ {
		a := gf128.Random()
		c := gf128.Random()
		sa := Split(a, 1, 3)
		scaled := make([]Share, 3)
		for i := range scaled {
			scaled[i] = Share{X: sa[i].X, Y: sa[i].Y.Mul(c)}
		}
		if !Reconstruct(scaled).Equal(a.Mul(c)) {
			t.Fatal("scalar multiplication of shares failed")
		}
	}
}

func TestReconstructCheckDetectsTampering(t *testing.T) {
	for trial := 0; trial < 200; trial++ {
		secret := gf128.Random()
		shares := Split(secret, 1, 5) // degree 1, 5 shares -> 3 redundant

		got, ok := ReconstructCheck(shares, 1)
		if !ok || !got.Equal(secret) {
			t.Fatal("ReconstructCheck rejected honest shares")
		}

		// Tamper with one share; with t=1 and 5 shares this must be detected.
		bad := make([]Share, len(shares))
		copy(bad, shares)
		bad[3].Y = bad[3].Y.Add(gf128.One)
		if _, ok := ReconstructCheck(bad, 1); ok {
			t.Fatal("ReconstructCheck failed to detect a tampered share")
		}
	}
}

func TestInterpolateCoeffsMatchesEval(t *testing.T) {
	// A degree-2 polynomial recovered from 3 points must reproduce its values.
	coeffs := []gf128.Elem{gf128.Random(), gf128.Random(), gf128.Random()}
	pts := Points(3)
	shares := make([]Share, 3)
	for i, x := range pts {
		shares[i] = Share{X: x, Y: evalPoly(coeffs, x)}
	}
	got := interpolateCoeffs(shares)
	for i := range coeffs {
		if !got[i].Equal(coeffs[i]) {
			t.Fatalf("coefficient %d mismatch", i)
		}
	}
}
