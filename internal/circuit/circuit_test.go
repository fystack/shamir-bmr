package circuit

import (
	"strings"
	"testing"
)

// out = (a XOR b) AND (NOT a)
const tinyBristol = `3 5
2 1 1
1 1

2 1 0 1 2 XOR
1 1 0 3 INV
2 1 2 3 4 AND
`

func TestParseTiny(t *testing.T) {
	c, err := Parse(strings.NewReader(tinyBristol))
	if err != nil {
		t.Fatal(err)
	}
	if c.NumWires != 5 || len(c.Gates) != 3 {
		t.Fatalf("bad parse: wires=%d gates=%d", c.NumWires, len(c.Gates))
	}
	if c.NumInputWires() != 2 || c.NumOutputWires() != 1 {
		t.Fatalf("bad io: in=%d out=%d", c.NumInputWires(), c.NumOutputWires())
	}
	if c.FirstOutputWire() != 4 {
		t.Fatalf("first output wire = %d, want 4", c.FirstOutputWire())
	}
	if c.Gates[0].Type != XOR || c.Gates[1].Type != INV || c.Gates[2].Type != AND {
		t.Fatal("gate types parsed wrong")
	}
}

func TestEvalTinyTruthTable(t *testing.T) {
	c, err := Parse(strings.NewReader(tinyBristol))
	if err != nil {
		t.Fatal(err)
	}
	for a := uint8(0); a <= 1; a++ {
		for b := uint8(0); b <= 1; b++ {
			got, err := c.Eval([]uint8{a, b})
			if err != nil {
				t.Fatal(err)
			}
			want := (a ^ b) & (1 ^ a)
			if got[0] != want {
				t.Fatalf("a=%d b=%d: got %d want %d", a, b, got[0], want)
			}
		}
	}
}

func TestEvalRejectsWrongInputLen(t *testing.T) {
	c, _ := Parse(strings.NewReader(tinyBristol))
	if _, err := c.Eval([]uint8{1}); err == nil {
		t.Fatal("expected error on wrong input length")
	}
}
