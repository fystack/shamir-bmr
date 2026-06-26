// Package eval implements Phase 2 of Shamir-BMR: local, single-round evaluation
// of a garbled circuit. The evaluator holds, per wire, a public external value
// and the active superkey (one key per party); it never learns the wire masks
// or the inactive keys.
//
// XOR/INV/EQW gates are free (key and external-value algebra). For an AND gate
// the evaluator recomputes the per-slot PRF masks from the active input
// superkeys, decrypts the row selected by the input external values, and reads
// the output external value from the lsb of party 0's recovered key (the
// point-and-permute pointer set up during garbling).
package eval

import (
	"fmt"

	"github.com/nan/shamir-bmr/internal/circuit"
	"github.com/nan/shamir-bmr/internal/garble"
	"github.com/nan/shamir-bmr/internal/gf128"
	"github.com/nan/shamir-bmr/internal/prf"
)

// Evaluate runs the garbled circuit. ext and super give the external value and
// active superkey for each input wire (length NumInputWires). It returns the
// external values of the output wires.
func Evaluate(gc *garble.GarbledCircuit, ext []uint8, super [][]gf128.Elem) ([]uint8, error) {
	c := gc.Circuit
	if len(ext) != c.NumInputWires() || len(super) != c.NumInputWires() {
		return nil, fmt.Errorf("eval: expected %d input wires", c.NumInputWires())
	}

	wireExt := make([]uint8, c.NumWires)
	wireKey := make([][]gf128.Elem, c.NumWires)

	for w := 0; w < c.NumInputWires(); w++ {
		wireExt[w] = ext[w]
		wireKey[w] = super[w]
	}
	// Seed constant (EQ) wires.
	for wire, cw := range gc.ConstWires {
		wireExt[wire] = cw.Ext
		wireKey[wire] = cw.Super
	}

	for _, g := range c.Gates {
		out := g.Out
		switch g.Type {
		case circuit.XOR:
			a, b := g.In[0], g.In[1]
			wireExt[out] = wireExt[a] ^ wireExt[b]
			key := make([]gf128.Elem, gc.N)
			for i := 0; i < gc.N; i++ {
				key[i] = wireKey[a][i].Add(wireKey[b][i])
			}
			wireKey[out] = key
		case circuit.INV, circuit.EQW:
			a := g.In[0]
			wireExt[out] = wireExt[a]
			wireKey[out] = wireKey[a]
		case circuit.EQ:
			// already seeded
		case circuit.AND:
			a, b := g.In[0], g.In[1]
			table, ok := gc.AndTables[out]
			if !ok {
				return nil, fmt.Errorf("eval: missing AND table for wire %d", out)
			}
			row := table[wireExt[a]][wireExt[b]]
			gateID := uint64(out)
			key := make([]gf128.Elem, gc.N)
			for i := 0; i < gc.N; i++ {
				// mask_i = XOR_j H(K_a[j], g, i) XOR H(K_b[j], g, i)
				mask := gf128.Zero
				for j := 0; j < gc.N; j++ {
					mask = mask.Add(prf.Hash(wireKey[a][j], gateID, uint32(i)))
					mask = mask.Add(prf.Hash(wireKey[b][j], gateID, uint32(i)))
				}
				key[i] = row[i].Add(mask)
			}
			wireKey[out] = key
			// external value = lsb of party 0's recovered key (the pointer bit).
			wireExt[out] = key[0].Lsb()
		}
	}

	outExt := make([]uint8, c.NumOutputWires())
	copy(outExt, wireExt[c.FirstOutputWire():])
	return outExt, nil
}
