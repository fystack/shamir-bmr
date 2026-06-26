package circuit

import (
	"os"
	"path/filepath"
	"testing"
)

// sha256Path locates the downloaded Bristol-Fashion SHA-256 circuit, if present.
func sha256Path() string {
	// internal/circuit -> ../../test/sha256.txt
	p := filepath.Join("..", "..", "test", "sha256.txt")
	if _, err := os.Stat(p); err == nil {
		return p
	}
	return ""
}

func TestParseSHA256(t *testing.T) {
	p := sha256Path()
	if p == "" {
		t.Skip("test/sha256.txt not present; skipping SHA-256 parse test")
	}
	c, err := ParseFile(p)
	if err != nil {
		t.Fatal(err)
	}
	// Single-block SHA-256 compression: 512-bit message + 256-bit state in,
	// 256-bit state out.
	if c.NumInputWires() != 768 {
		t.Fatalf("input wires = %d, want 768", c.NumInputWires())
	}
	if c.NumOutputWires() != 256 {
		t.Fatalf("output wires = %d, want 256", c.NumOutputWires())
	}
	counts := map[GateType]int{}
	for _, g := range c.Gates {
		counts[g.Type]++
	}
	t.Logf("SHA-256 gate composition: XOR=%d AND=%d INV=%d EQW=%d EQ=%d (total %d)",
		counts[XOR], counts[AND], counts[INV], counts[EQW], counts[EQ], len(c.Gates))
	if counts[AND] == 0 {
		t.Fatal("expected nonzero AND gates")
	}
}
