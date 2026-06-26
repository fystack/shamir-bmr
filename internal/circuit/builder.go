package circuit

import "fmt"

// Builder constructs a Circuit by emitting gates and embedding sub-circuits. It
// is used to compose multiple SHA-256 compression instances into one larger
// circuit (e.g. HMAC-SHA256) that the BMR engine garbles in a single pass.
//
// Wire ids 0..numIn-1 are reserved for input wires. Every other wire is the
// output of exactly one gate; fresh ids are handed out in increasing order, so
// a gate's output id always exceeds its input ids (the circuit is therefore
// topologically ordered by wire id, as garble/eval require). Finish enforces
// that the chosen output wires are the highest ids, matching the Bristol
// convention that outputs occupy the top wires.
type Builder struct {
	numIn int
	next  int
	gates []Gate
}

// NewBuilder starts a circuit with numIn input wires (ids 0..numIn-1).
func NewBuilder(numIn int) *Builder {
	return &Builder{numIn: numIn, next: numIn}
}

func (b *Builder) fresh() int {
	w := b.next
	b.next++
	return w
}

// Input returns the id of input wire i.
func (b *Builder) Input(i int) int { return i }

// Const emits an EQ gate producing a constant wire.
func (b *Builder) Const(v uint8) int {
	w := b.fresh()
	b.gates = append(b.gates, Gate{Type: EQ, Out: w, Const: v & 1})
	return w
}

// Copy emits an EQW gate (out = in).
func (b *Builder) Copy(a int) int {
	w := b.fresh()
	b.gates = append(b.gates, Gate{Type: EQW, In: []int{a}, Out: w})
	return w
}

// Inv emits an INV gate (out = NOT in).
func (b *Builder) Inv(a int) int {
	w := b.fresh()
	b.gates = append(b.gates, Gate{Type: INV, In: []int{a}, Out: w})
	return w
}

// Embed copies sub into the builder, wiring sub's input wires (0..NumInputWires)
// to the provided wire ids and allocating fresh ids for all internal/output
// wires. It returns the wire ids of sub's outputs (its top NumOutputWires).
func (b *Builder) Embed(sub *Circuit, in []int) ([]int, error) {
	nIn := sub.NumInputWires()
	if len(in) != nIn {
		return nil, fmt.Errorf("circuit: Embed got %d input wires, sub needs %d", len(in), nIn)
	}
	remap := make([]int, sub.NumWires)
	copy(remap, in)
	for w := nIn; w < sub.NumWires; w++ {
		remap[w] = b.fresh()
	}
	for _, g := range sub.Gates {
		ng := Gate{Type: g.Type, Out: remap[g.Out], Const: g.Const}
		if len(g.In) > 0 {
			ng.In = make([]int, len(g.In))
			for k, x := range g.In {
				ng.In[k] = remap[x]
			}
		}
		b.gates = append(b.gates, ng)
	}
	outs := make([]int, sub.NumOutputWires())
	first := sub.FirstOutputWire()
	for i := range outs {
		outs[i] = remap[first+i]
	}
	return outs, nil
}

// Finish assembles the Circuit. outputs must be the highest len(outputs) wire
// ids, contiguous and in order (the natural result of embedding the final
// sub-circuit last). inputBits gives the bit-widths of the input segments.
func (b *Builder) Finish(inputBits []int, outputs []int) (*Circuit, error) {
	sum := 0
	for _, x := range inputBits {
		sum += x
	}
	if sum != b.numIn {
		return nil, fmt.Errorf("circuit: inputBits sum %d != numIn %d", sum, b.numIn)
	}
	numOut := len(outputs)
	for i, w := range outputs {
		if w != b.next-numOut+i {
			return nil, fmt.Errorf("circuit: output wire %d (=%d) is not at the top; expected %d", i, w, b.next-numOut+i)
		}
	}
	return &Circuit{
		NumWires:   b.next,
		InputBits:  inputBits,
		OutputBits: []int{numOut},
		Gates:      b.gates,
	}, nil
}
