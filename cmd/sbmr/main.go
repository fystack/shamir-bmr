// Command sbmr is a single-process driver for the Shamir-BMR protocol: it
// garbles a Bristol-Fashion circuit with the maliciously-secure Shamir MPC
// (Phase 1) and evaluates it (Phase 2), then checks the result against a
// plaintext evaluation of the same circuit.
//
// Usage:
//
//	sbmr -circuit path/to/circuit.txt [-n 3] [-t 1] [-seed 12345]
//
// With no -circuit, a built-in tiny demo circuit is used.
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"strings"
	"time"

	"github.com/nan/shamir-bmr/internal/circuit"
	"github.com/nan/shamir-bmr/internal/eval"
	"github.com/nan/shamir-bmr/internal/garble"
	"github.com/nan/shamir-bmr/internal/hmacsha"
	"github.com/nan/shamir-bmr/internal/mpc"
)

const tinyDemo = `3 5
2 1 1
1 1

2 1 0 1 2 XOR
1 1 0 3 INV
2 1 2 3 4 AND
`

func main() {
	circuitPath := flag.String("circuit", "", "path to a Bristol-Fashion circuit (default: built-in tiny demo)")
	n := flag.Int("n", 3, "number of parties")
	t := flag.Int("t", 1, "privacy/reconstruction threshold (need n >= 2t+1)")
	seed := flag.Int64("seed", 1, "PRNG seed for random circuit inputs")
	doHMAC := flag.Bool("hmac", false, "compute threshold HMAC-SHA256 instead of a raw circuit")
	hmacKey := flag.String("key", "secretkey", "HMAC secret key (the secret-shared api_secret; <=64 bytes; prefix 'hex:' for hex)")
	hmacMsg := flag.String("msg", "hello", "HMAC public message (prefix 'hex:' for hex)")
	compPath := flag.String("comp", "test/sha256.txt", "SHA-256 compression circuit for -hmac")
	flag.Parse()

	if *doHMAC {
		runHMAC(*compPath, *hmacKey, *hmacMsg, *n, *t)
		return
	}

	var c *circuit.Circuit
	var err error
	if *circuitPath == "" {
		c, err = circuit.Parse(strings.NewReader(tinyDemo))
		fmt.Println("circuit: built-in tiny demo  out = (a XOR b) AND (NOT a)")
	} else {
		c, err = circuit.ParseFile(*circuitPath)
		fmt.Printf("circuit: %s\n", *circuitPath)
	}
	if err != nil {
		fail("parse circuit: %v", err)
	}

	ands := 0
	for _, g := range c.Gates {
		if g.Type == circuit.AND {
			ands++
		}
	}
	fmt.Printf("  wires=%d gates=%d (AND=%d, others free)  inputs=%d bits  outputs=%d bits\n",
		c.NumWires, len(c.Gates), ands, c.NumInputWires(), c.NumOutputWires())
	fmt.Printf("  parties n=%d threshold t=%d (malicious, honest majority)\n", *n, *t)

	// Random inputs.
	rng := rand.New(rand.NewSource(*seed))
	inputs := make([]uint8, c.NumInputWires())
	for i := range inputs {
		inputs[i] = uint8(rng.Intn(2))
	}

	eng, err := mpc.NewEngine(mpc.Config{N: *n, T: *t})
	if err != nil {
		fail("engine: %v", err)
	}

	fmt.Println("\n[Phase 1] garbling via Shamir MPC ...")
	start := time.Now()
	g := garble.NewGarbler(eng, c)
	if err := g.Garble(); err != nil {
		fail("garble aborted: %v", err)
	}
	garbleTime := time.Since(start)
	fmt.Printf("  done in %s\n", garbleTime.Round(time.Millisecond))

	fmt.Println("[Phase 2] evaluating garbled circuit ...")
	start = time.Now()
	extIn, super := g.EncodeInput(inputs)
	outExt, err := eval.Evaluate(g.Public(), extIn, super)
	if err != nil {
		fail("evaluate: %v", err)
	}
	got := g.DecodeOutput(outExt)
	evalTime := time.Since(start)
	fmt.Printf("  done in %s\n", evalTime.Round(time.Millisecond))

	want, err := c.Eval(inputs)
	if err != nil {
		fail("plaintext eval: %v", err)
	}

	match := equal(got, want)
	fmt.Printf("\nBMR output    : %s\n", bits(got))
	fmt.Printf("plaintext eval: %s\n", bits(want))
	if match {
		fmt.Println("RESULT: MATCH ✓")
	} else {
		fmt.Println("RESULT: MISMATCH ✗")
		os.Exit(1)
	}
}

// runHMAC computes HMAC-SHA256 with a secret-shared key via the Shamir-BMR
// protocol: the key bits are threshold-shared input wires (never reconstructed),
// the message is public, and the 32-byte tag is the revealed output. It checks
// the tag against crypto/hmac.
func runHMAC(compPath, keyArg, msgArg string, n, t int) {
	key, err := decodeArg(keyArg)
	if err != nil {
		fail("key: %v", err)
	}
	msg, err := decodeArg(msgArg)
	if err != nil {
		fail("msg: %v", err)
	}
	if len(key) > 64 {
		fail("key is %d bytes; this build supports <=64-byte keys (every bybit api_secret qualifies)", len(key))
	}

	comp, err := circuit.ParseFile(compPath)
	if err != nil {
		fail("parse compression circuit %s: %v", compPath, err)
	}
	h, err := hmacsha.Build(comp, len(key), len(msg))
	if err != nil {
		fail("build HMAC circuit: %v", err)
	}

	ands := 0
	for _, g := range h.C.Gates {
		if g.Type == circuit.AND {
			ands++
		}
	}
	fmt.Printf("threshold HMAC-SHA256  key=%d bytes (secret-shared)  msg=%d bytes (public)\n", len(key), len(msg))
	fmt.Printf("  circuit: wires=%d gates=%d (AND=%d)  parties n=%d threshold t=%d\n", h.C.NumWires, len(h.C.Gates), ands, n, t)

	eng, err := mpc.NewEngine(mpc.Config{N: n, T: t})
	if err != nil {
		fail("engine: %v", err)
	}
	g := garble.NewGarbler(eng, h.C)
	keyBits, err := h.KeyBits(key)
	if err != nil {
		fail("key bits: %v", err)
	}
	for i, w := range h.KeyWires {
		g.MarkSecret(w, keyBits[i])
	}

	fmt.Println("\n[Phase 1] garbling HMAC circuit via Shamir MPC ...")
	start := time.Now()
	if err := g.Garble(); err != nil {
		fail("garble aborted: %v", err)
	}
	fmt.Printf("  done in %s\n", time.Since(start).Round(time.Millisecond))

	fmt.Println("[Phase 2] evaluating garbled circuit ...")
	start = time.Now()
	realBits := make([]uint8, h.C.NumInputWires())
	msgBits, err := h.MsgBits(msg)
	if err != nil {
		fail("msg bits: %v", err)
	}
	for i, w := range h.MsgWires {
		realBits[w] = msgBits[i]
	}
	ext, super := g.EncodeInput(realBits)
	outExt, err := eval.Evaluate(g.Public(), ext, super)
	if err != nil {
		fail("evaluate: %v", err)
	}
	got := h.DecodeTag(g.DecodeOutput(outExt))
	fmt.Printf("  done in %s\n", time.Since(start).Round(time.Millisecond))

	m := hmac.New(sha256.New, key)
	m.Write(msg)
	want := m.Sum(nil)

	fmt.Printf("\nBMR HMAC tag  : %s\n", hex.EncodeToString(got))
	fmt.Printf("crypto/hmac   : %s\n", hex.EncodeToString(want))
	if hmac.Equal(got, want) {
		fmt.Println("RESULT: MATCH ✓")
	} else {
		fmt.Println("RESULT: MISMATCH ✗")
		os.Exit(1)
	}
}

// decodeArg returns the bytes of a CLI string argument, honoring a "hex:" prefix.
func decodeArg(s string) ([]byte, error) {
	if strings.HasPrefix(s, "hex:") {
		return hex.DecodeString(strings.TrimPrefix(s, "hex:"))
	}
	return []byte(s), nil
}

func bits(b []uint8) string {
	var sb strings.Builder
	for _, x := range b {
		sb.WriteByte('0' + x)
	}
	return sb.String()
}

func equal(a, b []uint8) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", args...)
	os.Exit(1)
}
