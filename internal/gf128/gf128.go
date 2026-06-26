// Package gf128 implements arithmetic in the finite field GF(2^128).
//
// Field elements are polynomials over GF(2) of degree < 128, reduced modulo
// the irreducible polynomial
//
//	f(x) = x^128 + x^7 + x^2 + x + 1
//
// (the same low-weight pentanomial used by AES-GCM). Addition is XOR;
// multiplication is carry-less polynomial multiplication followed by reduction.
//
// Bit convention: an Elem is two uint64 words {hi, lo}. The coefficient of x^k
// is bit k, where bit 0 is the least-significant bit of lo and bit 127 is the
// most-significant bit of hi. This "natural" ordering is internally consistent;
// it is NOT the bit-reversed ordering GHASH uses, so these values are not meant
// to interoperate byte-for-byte with GHASH.
package gf128

import (
	crand "crypto/rand"
	"encoding/binary"
	"math/rand/v2"
	"sync"
)

// Elem is an element of GF(2^128).
type Elem struct {
	hi, lo uint64
}

// reduction is the low 64 bits of f(x) without the x^128 term:
// x^7 + x^2 + x + 1 = 0b1000_0111 = 0x87.
const reduction = 0x87

// Zero is the additive identity.
var Zero = Elem{}

// One is the multiplicative identity (the polynomial 1).
var One = Elem{hi: 0, lo: 1}

// FromUint64 returns the element whose low word is v (and high word 0).
func FromUint64(v uint64) Elem { return Elem{lo: v} }

// FromBytes interprets a 16-byte big-endian buffer as a field element.
// b[0] is the most-significant byte (top of hi). Inputs shorter than 16 bytes
// are right-aligned (treated as a small integer); longer inputs panic.
func FromBytes(b []byte) Elem {
	if len(b) > 16 {
		panic("gf128: FromBytes input longer than 16 bytes")
	}
	var buf [16]byte
	copy(buf[16-len(b):], b)
	return Elem{
		hi: binary.BigEndian.Uint64(buf[0:8]),
		lo: binary.BigEndian.Uint64(buf[8:16]),
	}
}

// Bytes returns the 16-byte big-endian encoding of e.
func (e Elem) Bytes() [16]byte {
	var buf [16]byte
	binary.BigEndian.PutUint64(buf[0:8], e.hi)
	binary.BigEndian.PutUint64(buf[8:16], e.lo)
	return buf
}

// Equal reports whether e == other.
func (e Elem) Equal(other Elem) bool { return e.hi == other.hi && e.lo == other.lo }

// IsZero reports whether e is the additive identity.
func (e Elem) IsZero() bool { return e.hi == 0 && e.lo == 0 }

// Lsb returns the least-significant bit (coefficient of x^0), used as the
// free-XOR pointer/select bit.
func (e Elem) Lsb() uint8 { return uint8(e.lo & 1) }

// Add returns e + other (field addition == bitwise XOR).
func (e Elem) Add(other Elem) Elem {
	return Elem{hi: e.hi ^ other.hi, lo: e.lo ^ other.lo}
}

// Mul returns e * other in GF(2^128).
func (e Elem) Mul(other Elem) Elem {
	// Shift-and-add: iterate over the bits of `other`, accumulating shifted
	// copies of `e`, reducing modulo f(x) after each shift.
	a := e
	var res Elem
	for i := 0; i < 128; i++ {
		// If bit i of `other` is set, add the current a = e * x^i.
		var word uint64
		if i < 64 {
			word = other.lo
		} else {
			word = other.hi
		}
		if (word>>(uint(i)%64))&1 == 1 {
			res.hi ^= a.hi
			res.lo ^= a.lo
		}
		// a *= x  (shift left by one bit, reduce on overflow past x^127).
		carry := a.hi >> 63
		a.hi = (a.hi << 1) | (a.lo >> 63)
		a.lo = a.lo << 1
		if carry == 1 {
			a.lo ^= reduction
		}
	}
	return res
}

// Square returns e * e.
func (e Elem) Square() Elem { return e.Mul(e) }

// Inv returns the multiplicative inverse of e via Fermat's little theorem:
// e^(2^128 - 2). Panics if e is zero (zero has no inverse).
func (e Elem) Inv() Elem {
	if e.IsZero() {
		panic("gf128: inverse of zero")
	}
	// 2^128 - 2 = 2^1 + 2^2 + ... + 2^127. Accumulate e^(2^i) for i = 1..127.
	x := e.Square() // e^(2^1)
	res := x
	for i := 2; i <= 127; i++ {
		x = x.Square() // e^(2^i)
		res = res.Mul(x)
	}
	return res
}

// fastRNG is a ChaCha8 CSPRNG seeded once from crypto/rand. The protocol draws
// large amounts of randomness; a buffered userspace CSPRNG avoids a syscall per
// 16 bytes. This is appropriate for the single-process simulation. The mutex
// keeps it safe under the concurrent use the test suite exercises.
var (
	fastMu  sync.Mutex
	fastRNG *rand.ChaCha8
)

func init() {
	var seed [32]byte
	if _, err := crand.Read(seed[:]); err != nil {
		panic("gf128: seeding CSPRNG failed: " + err.Error())
	}
	fastRNG = rand.NewChaCha8(seed)
}

// Random returns a uniformly random field element.
func Random() Elem {
	fastMu.Lock()
	hi := fastRNG.Uint64()
	lo := fastRNG.Uint64()
	fastMu.Unlock()
	return Elem{hi: hi, lo: lo}
}

// RandomByte returns a single uniformly random byte from the same CSPRNG.
func RandomByte() byte {
	fastMu.Lock()
	b := byte(fastRNG.Uint64())
	fastMu.Unlock()
	return b
}
