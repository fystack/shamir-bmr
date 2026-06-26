// Package shamir implements Shamir secret sharing over GF(2^128).
//
// A secret s is hidden as the constant term of a random polynomial of degree t;
// each party i holds the evaluation of that polynomial at a fixed, distinct,
// non-zero point alpha_i. Any t+1 shares reconstruct s (Lagrange interpolation
// at x=0); any t or fewer reveal nothing.
//
// Party points are alpha_i = i (as a field element) for i = 1..n, so the point
// 0 is reserved for the secret and never assigned to a party.
package shamir

import "github.com/nan/shamir-bmr/internal/gf128"

// Share is one party's piece of a secret: the polynomial value Y at point X.
type Share struct {
	X gf128.Elem // evaluation point (party id as a field element)
	Y gf128.Elem // polynomial value at X
}

// Points returns the n party evaluation points alpha_1..alpha_n = 1..n.
func Points(n int) []gf128.Elem {
	pts := make([]gf128.Elem, n)
	for i := 0; i < n; i++ {
		pts[i] = gf128.FromUint64(uint64(i + 1))
	}
	return pts
}

// evalPoly evaluates the polynomial with the given coefficients (coeffs[k] is
// the coefficient of x^k) at x using Horner's method.
func evalPoly(coeffs []gf128.Elem, x gf128.Elem) gf128.Elem {
	acc := gf128.Zero
	for i := len(coeffs) - 1; i >= 0; i-- {
		acc = acc.Mul(x).Add(coeffs[i])
	}
	return acc
}

// Split shares secret into n shares with reconstruction threshold t (a degree-t
// polynomial, so t+1 shares are needed to recover the secret). It panics if the
// parameters are out of range. The randomness source is gf128.Random.
func Split(secret gf128.Elem, t, n int) []Share {
	if t < 0 || n <= 0 || t >= n {
		panic("shamir: require 0 <= t < n and n > 0")
	}
	coeffs := make([]gf128.Elem, t+1)
	coeffs[0] = secret
	for i := 1; i <= t; i++ {
		coeffs[i] = gf128.Random()
	}
	pts := Points(n)
	shares := make([]Share, n)
	for i, x := range pts {
		shares[i] = Share{X: x, Y: evalPoly(coeffs, x)}
	}
	return shares
}

// SplitWithCoeffs is like Split but uses caller-supplied higher-order
// coefficients (coeffs[0] is ignored and replaced by secret). This exists so
// the MPC layer can derive correlated/deterministic sharings; for normal use
// prefer Split.
func SplitWithCoeffs(secret gf128.Elem, higher []gf128.Elem, n int) []Share {
	t := len(higher)
	if n <= 0 || t >= n {
		panic("shamir: require t < n and n > 0")
	}
	coeffs := make([]gf128.Elem, t+1)
	coeffs[0] = secret
	copy(coeffs[1:], higher)
	pts := Points(n)
	shares := make([]Share, n)
	for i, x := range pts {
		shares[i] = Share{X: x, Y: evalPoly(coeffs, x)}
	}
	return shares
}

// lagrangeAtZero returns the Lagrange basis coefficients L_j(0) for the points
// xs, such that the interpolated polynomial's value at 0 is sum_j L_j * y_j.
// In characteristic 2, subtraction equals addition, so
//
//	L_j(0) = prod_{m != j} x_m / (x_j + x_m).
func lagrangeAtZero(xs []gf128.Elem) []gf128.Elem {
	coeffs := make([]gf128.Elem, len(xs))
	for j := range xs {
		num := gf128.One
		den := gf128.One
		for m := range xs {
			if m == j {
				continue
			}
			num = num.Mul(xs[m])
			den = den.Mul(xs[j].Add(xs[m]))
		}
		coeffs[j] = num.Mul(den.Inv())
	}
	return coeffs
}

// LagrangeWeights returns weights w_j such that, for the unique polynomial f of
// degree < len(xs) through the points (xs[j], y_j), the value f(at) equals
// sum_j w_j * y_j. The weights depend only on xs and at, so callers with a fixed
// point set can precompute them once and avoid per-reconstruction inversions.
//
//	w_j = L_j(at) = prod_{m != j} (at + x_m) / (x_j + x_m)   (char 2: - == +).
func LagrangeWeights(xs []gf128.Elem, at gf128.Elem) []gf128.Elem {
	w := make([]gf128.Elem, len(xs))
	for j := range xs {
		num := gf128.One
		den := gf128.One
		for m := range xs {
			if m == j {
				continue
			}
			num = num.Mul(at.Add(xs[m]))
			den = den.Mul(xs[j].Add(xs[m]))
		}
		w[j] = num.Mul(den.Inv())
	}
	return w
}

// Reconstruct recovers the secret (the polynomial value at x=0) from any subset
// of shares whose size exceeds the polynomial degree. It assumes the shares are
// consistent; use ReconstructCheck when shares may be corrupted.
func Reconstruct(shares []Share) gf128.Elem {
	xs := make([]gf128.Elem, len(shares))
	for i, s := range shares {
		xs[i] = s.X
	}
	coeffs := lagrangeAtZero(xs)
	acc := gf128.Zero
	for i, s := range shares {
		acc = acc.Add(coeffs[i].Mul(s.Y))
	}
	return acc
}

// ReconstructCheck recovers the secret while verifying that all supplied shares
// lie on a single polynomial of degree at most t. With more than t+1 shares
// this detects inconsistent (maliciously altered) shares: it interpolates the
// polynomial through the first t+1 shares and checks every remaining share
// against it. Returns (secret, true) if consistent, (zero, false) otherwise.
//
// This is the error-detecting reconstruction the malicious-secure protocol
// relies on (security with abort): with an honest majority and n >= 2t+1, an
// adversary controlling t parties cannot forge a consistent alternative.
func ReconstructCheck(shares []Share, t int) (gf128.Elem, bool) {
	if len(shares) < t+1 {
		return gf128.Zero, false
	}
	// Interpolate the degree-t polynomial through the first t+1 shares, then
	// evaluate it at every share's point and compare.
	base := shares[:t+1]
	xs := make([]gf128.Elem, len(base))
	for i, s := range base {
		xs[i] = s.X
	}
	// Recover full coefficient vector via Lagrange interpolation in coeff form.
	coeffs := interpolateCoeffs(base)
	for _, s := range shares[t+1:] {
		if !evalPoly(coeffs, s.X).Equal(s.Y) {
			return gf128.Zero, false
		}
	}
	return coeffs[0], true
}

// interpolateCoeffs returns the coefficient vector of the unique polynomial of
// degree < len(shares) passing through the given points.
func interpolateCoeffs(shares []Share) []gf128.Elem {
	n := len(shares)
	result := make([]gf128.Elem, n) // accumulates the full polynomial
	for j := 0; j < n; j++ {
		// Build the Lagrange basis polynomial L_j(x) = prod_{m!=j} (x - x_m)/(x_j - x_m),
		// scaled by y_j, and add it into result.
		basis := []gf128.Elem{gf128.One} // start with constant 1
		denom := gf128.One
		for m := 0; m < n; m++ {
			if m == j {
				continue
			}
			// Multiply basis by (x - x_m) = (x + x_m) in char 2.
			basis = mulLinear(basis, shares[m].X)
			denom = denom.Mul(shares[j].X.Add(shares[m].X))
		}
		scale := shares[j].Y.Mul(denom.Inv())
		for k, c := range basis {
			result[k] = result[k].Add(c.Mul(scale))
		}
	}
	return result
}

// mulLinear multiplies polynomial p by the linear factor (x + c).
func mulLinear(p []gf128.Elem, c gf128.Elem) []gf128.Elem {
	out := make([]gf128.Elem, len(p)+1)
	for i, coef := range p {
		out[i] = out[i].Add(coef.Mul(c)) // c * p
		out[i+1] = out[i+1].Add(coef)    // x * p
	}
	return out
}
