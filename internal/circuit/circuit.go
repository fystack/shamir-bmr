// Package circuit parses and represents boolean circuits in "Bristol Fashion"
// (the format used by https://nigelsmart.github.io/MPC-Circuits/, including the
// SHA-256 circuit). It also provides a plaintext evaluator used as ground truth
// in tests.
//
// Bristol Fashion layout:
//
//	line 1: <#gates> <#wires>
//	line 2: <#inputs> <bits of input 1> <bits of input 2> ...
//	line 3: <#outputs> <bits of output 1> ...
//	(blank line)
//	one line per gate: <#in> <#out> <in wires...> <out wires...> <TYPE>
//
// Input values occupy the lowest-numbered wires; output values occupy the
// highest-numbered wires. Supported gate types: XOR, AND, INV, EQW (copy),
// EQ (assign a constant).
package circuit

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

// GateType enumerates the supported gate kinds.
type GateType uint8

const (
	XOR GateType = iota
	AND
	INV
	EQW // copy: out = in
	EQ  // constant: out = const
)

func (g GateType) String() string {
	switch g {
	case XOR:
		return "XOR"
	case AND:
		return "AND"
	case INV:
		return "INV"
	case EQW:
		return "EQW"
	case EQ:
		return "EQ"
	default:
		return "?"
	}
}

// Gate is a single boolean gate. In holds input wire ids; Out is the output
// wire. For EQ, Const holds the assigned constant and In is empty.
type Gate struct {
	Type  GateType
	In    []int
	Out   int
	Const uint8
}

// Circuit is a parsed Bristol-Fashion boolean circuit.
type Circuit struct {
	NumWires   int
	InputBits  []int // bit-width of each input value, in wire order
	OutputBits []int // bit-width of each output value
	Gates      []Gate
}

// NumInputWires returns the total number of input wires.
func (c *Circuit) NumInputWires() int { return sum(c.InputBits) }

// NumOutputWires returns the total number of output wires.
func (c *Circuit) NumOutputWires() int { return sum(c.OutputBits) }

// FirstOutputWire returns the id of the lowest-numbered output wire (outputs are
// the highest NumOutputWires wires).
func (c *Circuit) FirstOutputWire() int { return c.NumWires - c.NumOutputWires() }

func sum(xs []int) int {
	s := 0
	for _, x := range xs {
		s += x
	}
	return s
}

// ParseFile reads and parses a Bristol-Fashion circuit from a file.
func ParseFile(path string) (*Circuit, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return Parse(f)
}

// Parse reads a Bristol-Fashion circuit from r.
func Parse(r io.Reader) (*Circuit, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1024*1024), 64*1024*1024)

	// Gather non-empty lines; the header is the first three.
	var header []string
	var gateLines []string
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		if len(header) < 3 {
			header = append(header, line)
		} else {
			gateLines = append(gateLines, line)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(header) < 3 {
		return nil, fmt.Errorf("circuit: truncated header")
	}

	numGates, numWires, err := parseTwoInts(header[0])
	if err != nil {
		return nil, fmt.Errorf("circuit: header line 1: %w", err)
	}
	inputBits, err := parseCountedList(header[1])
	if err != nil {
		return nil, fmt.Errorf("circuit: header line 2 (inputs): %w", err)
	}
	outputBits, err := parseCountedList(header[2])
	if err != nil {
		return nil, fmt.Errorf("circuit: header line 3 (outputs): %w", err)
	}

	c := &Circuit{NumWires: numWires, InputBits: inputBits, OutputBits: outputBits}
	for i, line := range gateLines {
		g, err := parseGate(line)
		if err != nil {
			return nil, fmt.Errorf("circuit: gate %d: %w", i, err)
		}
		c.Gates = append(c.Gates, g)
	}
	if len(c.Gates) != numGates {
		return nil, fmt.Errorf("circuit: header declares %d gates, found %d", numGates, len(c.Gates))
	}
	return c, nil
}

func parseTwoInts(line string) (int, int, error) {
	f := strings.Fields(line)
	if len(f) < 2 {
		return 0, 0, fmt.Errorf("expected 2 integers, got %q", line)
	}
	a, err := strconv.Atoi(f[0])
	if err != nil {
		return 0, 0, err
	}
	b, err := strconv.Atoi(f[1])
	if err != nil {
		return 0, 0, err
	}
	return a, b, nil
}

// parseCountedList parses "<n> v1 v2 ... vn".
func parseCountedList(line string) ([]int, error) {
	f := strings.Fields(line)
	if len(f) == 0 {
		return nil, fmt.Errorf("empty list")
	}
	n, err := strconv.Atoi(f[0])
	if err != nil {
		return nil, err
	}
	if len(f) < 1+n {
		return nil, fmt.Errorf("declared %d values but only %d present", n, len(f)-1)
	}
	vals := make([]int, n)
	for i := 0; i < n; i++ {
		v, err := strconv.Atoi(f[1+i])
		if err != nil {
			return nil, err
		}
		vals[i] = v
	}
	return vals, nil
}

func parseGate(line string) (Gate, error) {
	f := strings.Fields(line)
	if len(f) < 3 {
		return Gate{}, fmt.Errorf("too few fields: %q", line)
	}
	nin, err := strconv.Atoi(f[0])
	if err != nil {
		return Gate{}, err
	}
	nout, err := strconv.Atoi(f[1])
	if err != nil {
		return Gate{}, err
	}
	if nout != 1 {
		return Gate{}, fmt.Errorf("only single-output gates supported, got %d", nout)
	}
	typ := f[len(f)-1]
	wires := f[2 : len(f)-1]
	if len(wires) != nin+nout {
		return Gate{}, fmt.Errorf("expected %d wire ids, got %d", nin+nout, len(wires))
	}
	ints := make([]int, len(wires))
	for i, w := range wires {
		v, err := strconv.Atoi(w)
		if err != nil {
			return Gate{}, err
		}
		ints[i] = v
	}
	out := ints[len(ints)-1]
	in := ints[:len(ints)-1]

	switch typ {
	case "XOR":
		if nin != 2 {
			return Gate{}, fmt.Errorf("XOR needs 2 inputs")
		}
		return Gate{Type: XOR, In: in, Out: out}, nil
	case "AND":
		if nin != 2 {
			return Gate{}, fmt.Errorf("AND needs 2 inputs")
		}
		return Gate{Type: AND, In: in, Out: out}, nil
	case "INV", "NOT":
		if nin != 1 {
			return Gate{}, fmt.Errorf("INV needs 1 input")
		}
		return Gate{Type: INV, In: in, Out: out}, nil
	case "EQW":
		if nin != 1 {
			return Gate{}, fmt.Errorf("EQW needs 1 input")
		}
		return Gate{Type: EQW, In: in, Out: out}, nil
	case "EQ":
		// In Bristol Fashion the single "input" of EQ is the literal constant.
		if nin != 1 {
			return Gate{}, fmt.Errorf("EQ needs 1 constant input")
		}
		return Gate{Type: EQ, Out: out, Const: uint8(in[0] & 1)}, nil
	default:
		return Gate{}, fmt.Errorf("unsupported gate type %q", typ)
	}
}

// Eval evaluates the circuit in the clear. inputs is the concatenation of all
// input-value bits in wire order (length must equal NumInputWires). It returns
// the output bits (length NumOutputWires).
func (c *Circuit) Eval(inputs []uint8) ([]uint8, error) {
	if len(inputs) != c.NumInputWires() {
		return nil, fmt.Errorf("circuit: expected %d input bits, got %d", c.NumInputWires(), len(inputs))
	}
	wires := make([]uint8, c.NumWires)
	copy(wires, inputs)
	for _, g := range c.Gates {
		switch g.Type {
		case XOR:
			wires[g.Out] = wires[g.In[0]] ^ wires[g.In[1]]
		case AND:
			wires[g.Out] = wires[g.In[0]] & wires[g.In[1]]
		case INV:
			wires[g.Out] = 1 ^ wires[g.In[0]]
		case EQW:
			wires[g.Out] = wires[g.In[0]]
		case EQ:
			wires[g.Out] = g.Const
		}
	}
	out := make([]uint8, c.NumOutputWires())
	copy(out, wires[c.FirstOutputWire():])
	return out, nil
}
