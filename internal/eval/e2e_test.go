package eval

import (
	"strings"
	"testing"

	"github.com/nan/shamir-bmr/internal/circuit"
	"github.com/nan/shamir-bmr/internal/garble"
	"github.com/nan/shamir-bmr/internal/mpc"
)

// out = (a XOR b) AND (NOT a)  -- exercises XOR, INV, and AND.
const tinyBristol = `3 5
2 1 1
1 1

2 1 0 1 2 XOR
1 1 0 3 INV
2 1 2 3 4 AND
`

// multiGate exercises a deeper circuit: two ANDs chained with XOR/INV.
//
//	t0 = a AND b
//	t1 = NOT c
//	t2 = t0 XOR t1
//	out = t2 AND a
const multiBristol = `4 8
3 1 1 1
1 1

2 1 0 1 4 AND
1 1 2 5 INV
2 1 4 5 6 XOR
2 1 6 0 7 AND
`

func runE2E(t *testing.T, src string, inputs []uint8) []uint8 {
	t.Helper()
	c, err := circuit.Parse(strings.NewReader(src))
	if err != nil {
		t.Fatal(err)
	}
	eng, err := mpc.NewEngine(mpc.Config{N: 3, T: 1})
	if err != nil {
		t.Fatal(err)
	}
	g := garble.NewGarbler(eng, c)
	if err := g.Garble(); err != nil {
		t.Fatalf("garble: %v", err)
	}
	ext, super := g.EncodeInput(inputs)
	outExt, err := Evaluate(g.Public(), ext, super)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	return g.DecodeOutput(outExt)
}

func TestE2ETinyAllInputs(t *testing.T) {
	c, _ := circuit.Parse(strings.NewReader(tinyBristol))
	for a := uint8(0); a <= 1; a++ {
		for b := uint8(0); b <= 1; b++ {
			want, _ := c.Eval([]uint8{a, b})
			got := runE2E(t, tinyBristol, []uint8{a, b})
			if got[0] != want[0] {
				t.Fatalf("a=%d b=%d: bmr=%d plaintext=%d", a, b, got[0], want[0])
			}
		}
	}
}

func TestE2EMultiGateAllInputs(t *testing.T) {
	c, _ := circuit.Parse(strings.NewReader(multiBristol))
	for x := 0; x < 8; x++ {
		in := []uint8{uint8(x & 1), uint8((x >> 1) & 1), uint8((x >> 2) & 1)}
		want, _ := c.Eval(in)
		got := runE2E(t, multiBristol, in)
		if got[0] != want[0] {
			t.Fatalf("inputs=%v: bmr=%d plaintext=%d", in, got[0], want[0])
		}
	}
}
