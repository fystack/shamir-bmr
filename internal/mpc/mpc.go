// Package mpc is a single-process simulation of a maliciously-secure,
// honest-majority MPC engine over GF(2^128), built on Shamir secret sharing.
//
// All n parties live in one process: a Sharing holds the share vector that, in
// a real deployment, would be split one-per-party. "Opening" a value simulates
// the broadcast-and-reconstruct step.
//
// # Security design
//
// Multiplication uses the Damgård–Nielsen (DN) protocol: a local degree-2t
// product is re-randomised by a random double-sharing ([r]_t, [r]_{2t}) and the
// masked product is opened, then unmasked into a fresh degree-t sharing.
//
// Malicious security follows Chida et al. (CRYPTO 2018). Every value carries an
// information-theoretic MAC under a global secret key alpha: an authenticated
// value is the pair [x], [alpha·x]. The MAC of a product is computed by a second
// DN multiplication [alpha·x]·[y] = [alpha·z]. A corrupt party can inject an
// additive error during any DN opening, but to pass verification it would need
// the MAC error to equal alpha times the value error — and alpha is secret until
// the final check. A single batched check over a random linear combination of
// all authenticated values therefore catches any deviation except with
// probability 2^-128.
//
// Honest majority is required: n >= 2t+1 so that degree-2t sharings can be
// opened. Defaults are n=3, t=1.
//
// Out of scope (documented, not defended against here): a corrupt dealer
// supplying an over-degree share when contributing to a random/double sharing.
// Such degree attacks surface downstream as error-detecting-reconstruction
// failures and trigger the same abort, but we do not run a dedicated VSS.
package mpc

import (
	"errors"
	"fmt"

	"github.com/nan/shamir-bmr/internal/gf128"
	"github.com/nan/shamir-bmr/internal/shamir"
)

// ErrAbort is returned by Verify (and Open helpers) when malicious behaviour is
// detected and the protocol must abort.
var ErrAbort = errors.New("mpc: verification failed, aborting")

// Config holds the party count and threshold.
type Config struct {
	N int // number of parties
	T int // privacy/reconstruction threshold (degree of sharing polynomials)
}

// Valid reports whether the configuration satisfies the honest-majority bound.
func (c Config) Valid() bool { return c.N >= 2*c.T+1 && c.T >= 1 }

// Sharing is a vector of n Shamir shares (one per simulated party).
type Sharing struct {
	shares []shamir.Share
}

// Auth is an authenticated value: X = [x] and AX = [alpha·x].
type Auth struct {
	X  Sharing
	AX Sharing
}

// Engine drives the simulated MPC.
type Engine struct {
	cfg    Config
	points []gf128.Elem

	// Precomputed Lagrange weights for the fixed party points (no per-open
	// inversions). wFull recovers f(0) from all n shares (degree-2t opens);
	// wRec recovers f(0) from the first t+1 shares; checkPts/checkW verify the
	// remaining shares lie on that degree-t polynomial.
	wFull    []gf128.Elem
	wRec     []gf128.Elem
	checkPts []int
	checkW   [][]gf128.Elem

	alpha Sharing // [alpha], the secret MAC key (degree t), revealed only in Verify

	// values accumulates every authenticated value whose integrity must hold;
	// Verify batch-checks all of them.
	values []Auth

	aborted bool

	// openHook, if non-nil, is applied to every opened value and can perturb it
	// to simulate a malicious party injecting an additive error. The purpose
	// string identifies the opening site ("product", "dscheck", "alpha",
	// "maccheck", "output"). Test-only.
	openHook func(purpose string, v gf128.Elem) gf128.Elem
}

// NewEngine constructs an engine and samples the secret MAC key alpha.
func NewEngine(cfg Config) (*Engine, error) {
	if !cfg.Valid() {
		return nil, fmt.Errorf("mpc: invalid config n=%d t=%d (need n>=2t+1, t>=1)", cfg.N, cfg.T)
	}
	e := &Engine{cfg: cfg, points: shamir.Points(cfg.N)}
	// Precompute reconstruction weights for the fixed point set.
	e.wFull = shamir.LagrangeWeights(e.points, gf128.Zero)
	e.wRec = shamir.LagrangeWeights(e.points[:cfg.T+1], gf128.Zero)
	for j := cfg.T + 1; j < cfg.N; j++ {
		e.checkPts = append(e.checkPts, j)
		e.checkW = append(e.checkW, shamir.LagrangeWeights(e.points[:cfg.T+1], e.points[j]))
	}
	e.alpha = e.randomSharing(cfg.T)
	return e, nil
}

// Config returns the engine configuration.
func (e *Engine) Config() Config { return e.cfg }

// SetOpenHook installs a test-only perturbation applied to opened values.
func (e *Engine) SetOpenHook(h func(purpose string, v gf128.Elem) gf128.Elem) { e.openHook = h }

// --- low-level sharing helpers (all "local" operations) ---

func (e *Engine) zeroSharing() Sharing {
	s := Sharing{shares: make([]shamir.Share, e.cfg.N)}
	for i := range s.shares {
		s.shares[i] = shamir.Share{X: e.points[i], Y: gf128.Zero}
	}
	return s
}

// constSharing returns the degree-0 sharing of a public constant (every share
// equals c). It reconstructs to c and has degree <= t.
func (e *Engine) constSharing(c gf128.Elem) Sharing {
	s := Sharing{shares: make([]shamir.Share, e.cfg.N)}
	for i := range s.shares {
		s.shares[i] = shamir.Share{X: e.points[i], Y: c}
	}
	return s
}

// addSharings returns the component-wise sum a+b.
func addSharings(a, b Sharing) Sharing {
	out := Sharing{shares: make([]shamir.Share, len(a.shares))}
	for i := range a.shares {
		out.shares[i] = shamir.Share{X: a.shares[i].X, Y: a.shares[i].Y.Add(b.shares[i].Y)}
	}
	return out
}

// addConst adds a public constant to the shared secret.
func (e *Engine) addConst(a Sharing, c gf128.Elem) Sharing {
	out := Sharing{shares: make([]shamir.Share, len(a.shares))}
	for i := range a.shares {
		out.shares[i] = shamir.Share{X: a.shares[i].X, Y: a.shares[i].Y.Add(c)}
	}
	return out
}

// scalarMul multiplies the shared secret by a public constant.
func scalarMul(a Sharing, c gf128.Elem) Sharing {
	out := Sharing{shares: make([]shamir.Share, len(a.shares))}
	for i := range a.shares {
		out.shares[i] = shamir.Share{X: a.shares[i].X, Y: a.shares[i].Y.Mul(c)}
	}
	return out
}

// randomSharing produces a jointly-random degree-`degree` sharing: each party
// deals a random secret at that degree and the deals are summed, so the result
// is uniform as long as one party is honest.
func (e *Engine) randomSharing(degree int) Sharing {
	acc := e.zeroSharing()
	for j := 0; j < e.cfg.N; j++ {
		deal := shamir.Split(gf128.Random(), degree, e.cfg.N)
		acc = addSharings(acc, Sharing{shares: deal})
	}
	return acc
}

// randomDoubleSharing returns ([r]_t, [r]_{2t}) for a common random r, summing
// each party's contribution, and checks the two encode the same secret.
func (e *Engine) randomDoubleSharing() (rt Sharing, r2t Sharing, err error) {
	rt = e.zeroSharing()
	r2t = e.zeroSharing()
	for j := 0; j < e.cfg.N; j++ {
		r := gf128.Random()
		rt = addSharings(rt, Sharing{shares: shamir.Split(r, e.cfg.T, e.cfg.N)})
		r2t = addSharings(r2t, Sharing{shares: shamir.Split(r, 2*e.cfg.T, e.cfg.N)})
	}
	// Consistency: rt - r2t must encode 0 (its value at x=0 is 0). This catches
	// a party whose two sharings have mismatched constant terms.
	diff := subSharings(rt, r2t)
	if !e.openRaw(diff, "dscheck").IsZero() {
		return Sharing{}, Sharing{}, ErrAbort
	}
	return rt, r2t, nil
}

func subSharings(a, b Sharing) Sharing { return addSharings(a, b) } // char 2: a-b == a+b

// openRaw reconstructs f(0) from all n shares using precomputed weights, with no
// error detection (used for degree-2t openings, where n=2t+1 leaves no
// redundancy). Applies the test openHook if set.
func (e *Engine) openRaw(s Sharing, purpose string) gf128.Elem {
	v := gf128.Zero
	for i := range s.shares {
		v = v.Add(e.wFull[i].Mul(s.shares[i].Y))
	}
	if e.openHook != nil {
		v = e.openHook(purpose, v)
	}
	return v
}

// openChecked reconstructs a degree-t sharing with error detection, aborting on
// inconsistency. It recovers f(0) from the first t+1 shares and verifies every
// remaining share lies on the same degree-t polynomial. Applies the test
// openHook (after the check) if set.
func (e *Engine) openChecked(s Sharing, purpose string) (gf128.Elem, error) {
	// Predict and verify the redundant shares.
	for ci, j := range e.checkPts {
		pred := gf128.Zero
		w := e.checkW[ci]
		for k := 0; k <= e.cfg.T; k++ {
			pred = pred.Add(w[k].Mul(s.shares[k].Y))
		}
		if !pred.Equal(s.shares[j].Y) {
			return gf128.Zero, ErrAbort
		}
	}
	// Recover the secret from the first t+1 shares.
	v := gf128.Zero
	for k := 0; k <= e.cfg.T; k++ {
		v = v.Add(e.wRec[k].Mul(s.shares[k].Y))
	}
	if e.openHook != nil {
		v = e.openHook(purpose, v)
	}
	return v, nil
}

// --- DN multiplication of bare (unauthenticated) sharings ---

func (e *Engine) mulSharing(a, b Sharing) (Sharing, error) {
	rt, r2t, err := e.randomDoubleSharing()
	if err != nil {
		return Sharing{}, err
	}
	// Local degree-2t product.
	prod := Sharing{shares: make([]shamir.Share, e.cfg.N)}
	for i := range prod.shares {
		prod.shares[i] = shamir.Share{X: a.shares[i].X, Y: a.shares[i].Y.Mul(b.shares[i].Y)}
	}
	// Mask, open, unmask: z = (ab - r) + r, as a fresh degree-t sharing.
	masked := subSharings(prod, r2t)
	d := e.openRaw(masked, "product") // public value ab - r
	return e.addConst(rt, d), nil
}

// --- public authenticated API ---

// Input authenticates a secret known to the (simulated) dealer: it shares the
// secret and derives its MAC via the multiplication protocol. In a real system
// the dealer would not know alpha; the MAC is produced obliviously.
func (e *Engine) Input(secret gf128.Elem) (Auth, error) {
	x := Sharing{shares: shamir.Split(secret, e.cfg.T, e.cfg.N)}
	ax, err := e.mulSharing(e.alpha, x)
	if err != nil {
		return Auth{}, err
	}
	v := Auth{X: x, AX: ax}
	e.values = append(e.values, v)
	return v, nil
}

// Constant returns an authenticated public constant (MAC = c·[alpha], no open).
func (e *Engine) Constant(c gf128.Elem) Auth {
	v := Auth{X: e.constSharing(c), AX: scalarMul(e.alpha, c)}
	e.values = append(e.values, v)
	return v
}

// RandomBit returns an authenticated uniformly-random bit in {0,1}. Each party
// contributes a random bit; their field sum is the XOR (uniform if one honest).
func (e *Engine) RandomBit() (Auth, error) {
	x := e.zeroSharing()
	for j := 0; j < e.cfg.N; j++ {
		bit := gf128.FromUint64(uint64(randBit()))
		x = addSharings(x, Sharing{shares: shamir.Split(bit, e.cfg.T, e.cfg.N)})
	}
	ax, err := e.mulSharing(e.alpha, x)
	if err != nil {
		return Auth{}, err
	}
	v := Auth{X: x, AX: ax}
	e.values = append(e.values, v)
	return v, nil
}

// Add returns a+b (free, local on both share and MAC).
func (e *Engine) Add(a, b Auth) Auth {
	return Auth{X: addSharings(a.X, b.X), AX: addSharings(a.AX, b.AX)}
}

// AddConst returns a+c for public c.
func (e *Engine) AddConst(a Auth, c gf128.Elem) Auth {
	return Auth{X: e.addConst(a.X, c), AX: addSharings(a.AX, scalarMul(e.alpha, c))}
}

// MulConst returns c·a for public c.
func (e *Engine) MulConst(a Auth, c gf128.Elem) Auth {
	return Auth{X: scalarMul(a.X, c), AX: scalarMul(a.AX, c)}
}

// Mul returns a·b, computing both the product and its MAC via DN, and registers
// the result for verification.
func (e *Engine) Mul(a, b Auth) (Auth, error) {
	z, err := e.mulSharing(a.X, b.X)
	if err != nil {
		return Auth{}, err
	}
	az, err := e.mulSharing(a.AX, b.X) // (alpha·x)·y = alpha·z
	if err != nil {
		return Auth{}, err
	}
	v := Auth{X: z, AX: az}
	e.values = append(e.values, v)
	return v, nil
}

// Open reveals a value. It must only be trusted after a successful Verify; it
// performs error-detecting reconstruction and aborts on inconsistency.
func (e *Engine) Open(a Auth) (gf128.Elem, error) {
	return e.openChecked(a.X, "output")
}

// Verify runs the batched MAC check over every registered authenticated value.
// It must be called (and succeed) before outputs are trusted. After a failure
// the engine is marked aborted and all further high-level calls should stop.
func (e *Engine) Verify() error {
	if e.aborted {
		return ErrAbort
	}
	if len(e.values) == 0 {
		return nil
	}
	// Random public combination coefficients, fixed before alpha is revealed.
	U := e.zeroSharing() // sum r_i [x_i]
	W := e.zeroSharing() // sum r_i [alpha x_i]
	for _, v := range e.values {
		r := gf128.Random()
		U = addSharings(U, scalarMul(v.X, r))
		W = addSharings(W, scalarMul(v.AX, r))
	}
	// Reveal alpha (commit-then-open in a real protocol).
	alphaVal, err := e.openChecked(e.alpha, "alpha")
	if err != nil {
		e.aborted = true
		return err
	}
	// Check W - alpha·U opens to zero.
	tShare := subSharings(W, scalarMul(U, alphaVal))
	tv, err := e.openChecked(tShare, "maccheck")
	if err != nil || !tv.IsZero() {
		e.aborted = true
		return ErrAbort
	}
	return nil
}

// Aborted reports whether the engine has aborted.
func (e *Engine) Aborted() bool { return e.aborted }
