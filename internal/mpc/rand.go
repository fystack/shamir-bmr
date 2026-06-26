package mpc

import "github.com/nan/shamir-bmr/internal/gf128"

// randBit returns a uniformly random bit, drawn from gf128's fast CSPRNG.
func randBit() uint8 {
	return gf128.RandomByte() & 1
}
