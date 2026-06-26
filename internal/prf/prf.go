// Package prf provides the correlation-robust hash used to expand wire keys
// during BMR garbling.
//
// Each party expands its own wire keys locally (the FKOS optimisation keeps AES
// out of the MPC). With free-XOR the 1-key of a wire is the 0-key XORed with a
// global offset R, so the expansion function must be *correlation robust*. We
// use a fixed-key-AES Matyas–Meyer–Oseas construction
//
//	H(k, tweak) = pi(k ^ tweak) ^ (k ^ tweak),  pi = AES_{fixedKey},
//
// which is correlation-robust in the ideal-cipher model. The tweak binds each
// evaluation to a (gate, output-slot) pair so the same wire key produces
// independent-looking outputs across the gates and parties that consume it.
package prf

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"

	"github.com/nan/shamir-bmr/internal/gf128"
)

// fixedKey is an arbitrary public constant; security comes from the
// construction, not from this value being secret.
var fixedKey = [16]byte{
	0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
	0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
}

var blockCipher cipher.Block

func init() {
	c, err := aes.NewCipher(fixedKey[:])
	if err != nil {
		panic("prf: cannot init fixed-key AES: " + err.Error())
	}
	blockCipher = c
}

// tweak packs a gate id and output slot into a field element.
func tweak(gateID uint64, slot uint32) gf128.Elem {
	var b [16]byte
	binary.BigEndian.PutUint64(b[0:8], gateID)
	binary.BigEndian.PutUint32(b[8:12], slot)
	return gf128.FromBytes(b[:])
}

// Hash returns H(key, gateID, slot): a 128-bit pseudorandom value derived from
// a wire key, bound to the given gate and output slot.
func Hash(key gf128.Elem, gateID uint64, slot uint32) gf128.Elem {
	x := key.Add(tweak(gateID, slot)) // k ^ tweak
	xb := x.Bytes()
	var pb [16]byte
	blockCipher.Encrypt(pb[:], xb[:]) // pi(x)
	return gf128.FromBytes(pb[:]).Add(x)
}
