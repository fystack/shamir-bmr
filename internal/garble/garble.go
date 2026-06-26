// Package garble implements Phase 1 of the Shamir-BMR protocol: the parties
// jointly garble a boolean circuit using the maliciously-secure Shamir MPC, so
// that no party learns the wire masks or the others' wire keys.
//
// # Scheme (free-XOR BMR with point-and-permute)
//
// Each wire w has a secret masking bit lambda_w (a shared bit) and, per party i,
// a "0-key" k0[w][i]; the "1-key" is k0[w][i] XOR R[i], where R[i] is party i's
// global free-XOR offset. The external (public) value carried on a wire during
// evaluation is e = rho XOR lambda, where rho is the real bit.
//
// Point-and-permute: party 1 (index 0) samples every fresh 0-key with lsb 0 and
// its offset R[0] with lsb 1. Then the lsb of party 1's component of a wire's
// active superkey equals that wire's external value, so the evaluator reads the
// external bit directly from the recovered key — without it leaking lambda.
//
// XOR/INV/EQW gates are free: output keys and masks are linear functions of the
// inputs, computed locally. Only AND gates produce a garbled table. For an AND
// gate g: a -> b -> c, and each external-input combination (alpha, beta), the
// per-slot garbled entry is
//
//	G[alpha][beta][i] = (XOR_j H(k_{a,alpha}^j, g, i) XOR H(k_{b,beta}^j, g, i))
//	                    XOR k0[c][i] XOR (gamma * R[i])
//
// where gamma = ((alpha XOR lambda_a)(beta XOR lambda_b)) XOR lambda_c is the
// output external value for that row. The only nonlinearity, lambda_a*lambda_b,
// is one secure multiplication per gate; the gamma*R[i] terms are secure
// multiplications of the shared bit gamma by party i's shared offset. The PRF
// values H(...) are computed locally by each party (AES never enters the MPC),
// fed in as authenticated inputs, combined, and the rows opened — all under the
// MPC's MAC verification, which aborts on any active deviation.
//
// # Scope note on malicious security
//
// The MPC layer is maliciously secure (Chida et al. verification), so the
// garbled tables are guaranteed to be a correct function of the values each
// party fed in. Cryptographically binding each party's locally-computed PRF
// outputs to its committed keys (the FKOS PRF-consistency / cut-and-choose
// layer) is the one piece modeled but not fully enforced here; in this
// single-process simulation all parties compute the PRF honestly. The hook
// where that proof attaches is the per-party Input of H(...) below.
package garble

import (
	"github.com/nan/shamir-bmr/internal/circuit"
	"github.com/nan/shamir-bmr/internal/gf128"
	"github.com/nan/shamir-bmr/internal/mpc"
	"github.com/nan/shamir-bmr/internal/prf"
)

// GarbledCircuit is the public output of garbling, consumed by the evaluator.
type GarbledCircuit struct {
	Circuit *circuit.Circuit
	N       int
	// AndTables maps an AND gate's output wire id to its 2x2 table; each entry
	// is the per-slot superkey ciphertext (length N). Indexed [alpha][beta][i].
	AndTables map[int][2][2][]gf128.Elem
	// ConstWires holds seeded superkeys for EQ (constant) wires.
	ConstWires map[int]ConstWire
}

// ConstWire is a constant wire's public external value and active superkey.
type ConstWire struct {
	Ext   uint8
	Super []gf128.Elem
}

// Garbler holds all (simulated) secret state and drives garbling.
type Garbler struct {
	eng *mpc.Engine
	c   *circuit.Circuit
	n   int

	R     []gf128.Elem // R[i] plaintext (sim); R[0] has lsb 1
	rAuth []mpc.Auth   // authenticated offsets

	key0   [][]gf128.Elem // key0[wire][party]: the 0-key, plaintext (sim)
	lambda []mpc.Auth     // lambda[wire]: authenticated masking bit

	gc *GarbledCircuit

	// accumulated during garbling, opened only after Verify:
	pendingTables []pendingTable
	pendingConst  []constSeed

	// revealed after Verify:
	lambdaPlain []uint8 // lambda[wire] opened (for input/output/const wires)
	hasLambda   []bool

	// Threshold (secret-shared) input wires. For these, the real bit is a shared
	// secret rho[w] (e.g. an HMAC key bit); the garbler never reveals lambda[w],
	// only opens the masked external e = lambda[w] XOR rho[w] and stores the
	// resulting (external, superkey) so the evaluator can run without anyone
	// learning the secret.
	isSecret    []bool
	secretBit   []uint8        // plaintext bit (simulation only; the sharing is real)
	rho         []mpc.Auth     // shared secret bit
	secretExt   []uint8        // opened external value e
	secretSuper [][]gf128.Elem // active superkey per party for e
}

// MarkSecret designates an input wire as carrying a secret-shared real bit
// (e.g. an HMAC key bit). Call before Garble. In this single-process simulation
// the plaintext bit is supplied; the engine shares it at degree t exactly as a
// pre-shared key would be, and the bit is never reconstructed — only the masked
// external lambda XOR bit is opened.
func (g *Garbler) MarkSecret(wire int, bit uint8) {
	g.isSecret[wire] = true
	g.secretBit[wire] = bit & 1
}

// NewGarbler creates a garbler for circuit c over an engine with N parties.
func NewGarbler(eng *mpc.Engine, c *circuit.Circuit) *Garbler {
	n := eng.Config().N
	return &Garbler{
		eng:         eng,
		c:           c,
		n:           n,
		key0:        make([][]gf128.Elem, c.NumWires),
		lambda:      make([]mpc.Auth, c.NumWires),
		lambdaPlain: make([]uint8, c.NumWires),
		hasLambda:   make([]bool, c.NumWires),
		isSecret:    make([]bool, c.NumWires),
		secretBit:   make([]uint8, c.NumWires),
		rho:         make([]mpc.Auth, c.NumWires),
		secretExt:   make([]uint8, c.NumWires),
		secretSuper: make([][]gf128.Elem, c.NumWires),
		gc: &GarbledCircuit{
			Circuit:    c,
			N:          n,
			AndTables:  make(map[int][2][2][]gf128.Elem),
			ConstWires: make(map[int]ConstWire),
		},
	}
}

// activeKey returns k_{w,e}^j = k0[w][j] XOR (e ? R[j] : 0).
func (g *Garbler) activeKey(wire int, e uint8, party int) gf128.Elem {
	k := g.key0[wire][party]
	if e == 1 {
		k = k.Add(g.R[party])
	}
	return k
}

// newKeyRow allocates fresh 0-keys for a wire; party 0's key gets lsb 0.
func (g *Garbler) newKeyRow(wire int) {
	row := make([]gf128.Elem, g.n)
	for i := 0; i < g.n; i++ {
		k := gf128.Random()
		if i == 0 {
			k = clearLsb(k)
		}
		row[i] = k
	}
	g.key0[wire] = row
}

// Garble runs the full garbling protocol, returning an error on MPC abort.
func (g *Garbler) Garble() error {
	// Setup: free-XOR offsets. Party 0's offset has lsb 1 (the pointer bit).
	g.R = make([]gf128.Elem, g.n)
	g.rAuth = make([]mpc.Auth, g.n)
	for i := 0; i < g.n; i++ {
		r := gf128.Random()
		if i == 0 {
			r = setLsb(r)
		}
		g.R[i] = r
		a, err := g.eng.Input(r)
		if err != nil {
			return err
		}
		g.rAuth[i] = a
	}

	// Input wires: fresh keys and random masks. Secret wires also get their
	// shared real bit registered (authenticated) for the masked-external open.
	for w := 0; w < g.c.NumInputWires(); w++ {
		g.newKeyRow(w)
		lam, err := g.eng.RandomBit()
		if err != nil {
			return err
		}
		g.lambda[w] = lam
		if g.isSecret[w] {
			rho, err := g.eng.Input(bit(g.secretBit[w]))
			if err != nil {
				return err
			}
			g.rho[w] = rho
		}
	}

	// Process gates in topological (file) order.
	for _, gate := range g.c.Gates {
		if err := g.garbleGate(gate); err != nil {
			return err
		}
	}

	// Single batched malicious-security check before revealing anything.
	if err := g.eng.Verify(); err != nil {
		return err
	}

	// Reveal the masks needed for input encoding and output decoding, plus the
	// const-wire seeds. (AND-table opens happen in garbleGate after Verify is
	// conceptually required; we open them here to keep all opens post-Verify.)
	if err := g.openTablesAndMasks(); err != nil {
		return err
	}
	return nil
}

func (g *Garbler) garbleGate(gate circuit.Gate) error {
	c := gate.Out
	switch gate.Type {
	case circuit.XOR:
		a, b := gate.In[0], gate.In[1]
		row := make([]gf128.Elem, g.n)
		for i := 0; i < g.n; i++ {
			row[i] = g.key0[a][i].Add(g.key0[b][i])
		}
		g.key0[c] = row
		g.lambda[c] = g.eng.Add(g.lambda[a], g.lambda[b])
	case circuit.INV:
		a := gate.In[0]
		g.key0[c] = g.key0[a] // same keys
		g.lambda[c] = g.eng.AddConst(g.lambda[a], gf128.One)
	case circuit.EQW:
		a := gate.In[0]
		g.key0[c] = g.key0[a]
		g.lambda[c] = g.lambda[a]
	case circuit.EQ:
		// Constant wire: lambda = 0, external value = Const, fresh keys.
		g.newKeyRow(c)
		g.lambda[c] = g.eng.Constant(gf128.Zero)
		// Seed recorded after Verify in openTablesAndMasks.
		g.markConst(c, gate.Const)
	case circuit.AND:
		return g.garbleAnd(gate)
	}
	return nil
}

// constSeeds tracks EQ wires to seed after Verify.
type constSeed struct {
	wire  int
	value uint8
}

func (g *Garbler) markConst(wire int, value uint8) {
	g.pendingConst = append(g.pendingConst, constSeed{wire, value})
}

func (g *Garbler) garbleAnd(gate circuit.Gate) error {
	a, b, c := gate.In[0], gate.In[1], gate.Out
	g.newKeyRow(c)
	lamC, err := g.eng.RandomBit()
	if err != nil {
		return err
	}
	g.lambda[c] = lamC

	// One secure multiplication per gate: P = lambda_a * lambda_b.
	P, err := g.eng.Mul(g.lambda[a], g.lambda[b])
	if err != nil {
		return err
	}

	gateID := uint64(c) // unique per gate (each wire is assigned once)

	// Precompute authenticated inputs reused across the 4 rows:
	//   kc0[i]      = party i's 0-key for c (same in every row)
	//   fa[e][i][j] = H(k_{a,e}^j, g, i)  (independent of beta)
	//   fb[e][i][j] = H(k_{b,e}^j, g, i)  (independent of alpha)
	kc0 := make([]mpc.Auth, g.n)
	for i := 0; i < g.n; i++ {
		v, err := g.eng.Input(g.key0[c][i])
		if err != nil {
			return err
		}
		kc0[i] = v
	}
	fa, err := g.prfInputs(a, gateID)
	if err != nil {
		return err
	}
	fb, err := g.prfInputs(b, gateID)
	if err != nil {
		return err
	}

	var table [2][2][]mpc.Auth
	for alpha := uint8(0); alpha <= 1; alpha++ {
		for beta := uint8(0); beta <= 1; beta++ {
			// gamma = alpha*beta XOR alpha*lambda_b XOR beta*lambda_a XOR P XOR lambda_c
			gamma := g.eng.Constant(bit(alpha & beta))
			if alpha == 1 {
				gamma = g.eng.Add(gamma, g.lambda[b])
			}
			if beta == 1 {
				gamma = g.eng.Add(gamma, g.lambda[a])
			}
			gamma = g.eng.Add(gamma, P)
			gamma = g.eng.Add(gamma, lamC)

			slot := make([]mpc.Auth, g.n)
			for i := 0; i < g.n; i++ {
				// S = XOR_j H(k_{a,alpha}^j, g, i) XOR H(k_{b,beta}^j, g, i)
				S := g.eng.Constant(gf128.Zero)
				for j := 0; j < g.n; j++ {
					S = g.eng.Add(S, fa[alpha][i][j])
					S = g.eng.Add(S, fb[beta][i][j])
				}
				// gamma * R[i].
				gR, err := g.eng.Mul(gamma, g.rAuth[i])
				if err != nil {
					return err
				}
				slot[i] = g.eng.Add(g.eng.Add(S, kc0[i]), gR)
			}
			table[alpha][beta] = slot
		}
	}
	g.pendingTables = append(g.pendingTables, pendingTable{gateID: gateID, table: table})
	return nil
}

type pendingTable struct {
	gateID uint64
	table  [2][2][]mpc.Auth
}

// prfInputs computes and authenticates H(k_{wire,e}^j, gateID, i) for both key
// values e in {0,1}, all output slots i, and all parties j. The result is
// indexed [e][i][j].
func (g *Garbler) prfInputs(wire int, gateID uint64) ([2][][]mpc.Auth, error) {
	var out [2][][]mpc.Auth
	for e := uint8(0); e <= 1; e++ {
		perSlot := make([][]mpc.Auth, g.n)
		for i := 0; i < g.n; i++ {
			perParty := make([]mpc.Auth, g.n)
			for j := 0; j < g.n; j++ {
				h := prf.Hash(g.activeKey(wire, e, j), gateID, uint32(i))
				v, err := g.eng.Input(h)
				if err != nil {
					return out, err
				}
				perParty[j] = v
			}
			perSlot[i] = perParty
		}
		out[e] = perSlot
	}
	return out, nil
}

// open the accumulated authenticated tables and masks after Verify.
func (g *Garbler) openTablesAndMasks() error {
	// AND tables.
	for _, pt := range g.pendingTables {
		var out [2][2][]gf128.Elem
		for alpha := 0; alpha < 2; alpha++ {
			for beta := 0; beta < 2; beta++ {
				row := make([]gf128.Elem, g.n)
				for i := 0; i < g.n; i++ {
					v, err := g.eng.Open(pt.table[alpha][beta][i])
					if err != nil {
						return err
					}
					row[i] = v
				}
				out[alpha][beta] = row
			}
		}
		g.gc.AndTables[int(pt.gateID)] = out
	}

	// Input-wire encoding. Public wires reveal lambda (the driver knows the real
	// bit); secret wires instead open the masked external e = lambda XOR rho and
	// store (e, superkey), so the secret real bit is never revealed.
	for w := 0; w < g.c.NumInputWires(); w++ {
		if g.isSecret[w] {
			if err := g.encodeSecret(w); err != nil {
				return err
			}
		} else if err := g.revealLambda(w); err != nil {
			return err
		}
	}
	// Output-wire masks (for decoding outputs).
	for w := g.c.FirstOutputWire(); w < g.c.NumWires; w++ {
		if err := g.revealLambda(w); err != nil {
			return err
		}
	}
	// Const wires: reveal masks (should be 0) and seed superkeys.
	for _, cs := range g.pendingConst {
		if err := g.revealLambda(cs.wire); err != nil {
			return err
		}
		super := make([]gf128.Elem, g.n)
		for i := 0; i < g.n; i++ {
			super[i] = g.activeKey(cs.wire, cs.value, i)
		}
		g.gc.ConstWires[cs.wire] = ConstWire{Ext: cs.value, Super: super}
	}
	return nil
}

// encodeSecret opens the masked external e = lambda[w] XOR rho[w] for a secret
// input wire and records (e, active superkey) for the evaluator. Neither lambda
// nor the secret bit rho is revealed; e is a uniform masked bit, safe to publish.
func (g *Garbler) encodeSecret(w int) error {
	eAuth := g.eng.Add(g.lambda[w], g.rho[w])
	ev, err := g.eng.Open(eAuth)
	if err != nil {
		return err
	}
	e := ev.Lsb()
	g.secretExt[w] = e
	super := make([]gf128.Elem, g.n)
	for i := 0; i < g.n; i++ {
		super[i] = g.activeKey(w, e, i)
	}
	g.secretSuper[w] = super
	return nil
}

func (g *Garbler) revealLambda(w int) error {
	if g.hasLambda[w] {
		return nil
	}
	v, err := g.eng.Open(g.lambda[w])
	if err != nil {
		return err
	}
	g.lambdaPlain[w] = v.Lsb()
	g.hasLambda[w] = true
	return nil
}

// Public returns the public garbled circuit for the evaluator.
func (g *Garbler) Public() *GarbledCircuit { return g.gc }

// EncodeInput maps real input bits to external values and active superkeys.
// realBits must have length NumInputWires. Entries for wires marked secret (via
// MarkSecret) are ignored: those wires use the threshold encoding computed
// during Garble (the masked external and superkey), so the caller need not — and
// in a real deployment cannot — supply their real bits.
func (g *Garbler) EncodeInput(realBits []uint8) (ext []uint8, super [][]gf128.Elem) {
	niw := g.c.NumInputWires()
	ext = make([]uint8, niw)
	super = make([][]gf128.Elem, niw)
	for w := 0; w < niw; w++ {
		if g.isSecret[w] {
			ext[w] = g.secretExt[w]
			super[w] = g.secretSuper[w]
			continue
		}
		e := realBits[w] ^ g.lambdaPlain[w]
		ext[w] = e
		ks := make([]gf128.Elem, g.n)
		for i := 0; i < g.n; i++ {
			ks[i] = g.activeKey(w, e, i)
		}
		super[w] = ks
	}
	return ext, super
}

// DecodeOutput maps external output values back to real bits.
func (g *Garbler) DecodeOutput(ext []uint8) []uint8 {
	out := make([]uint8, len(ext))
	first := g.c.FirstOutputWire()
	for k := range ext {
		out[k] = ext[k] ^ g.lambdaPlain[first+k]
	}
	return out
}

// --- small helpers ---

func bit(b uint8) gf128.Elem { return gf128.FromUint64(uint64(b & 1)) }

func clearLsb(e gf128.Elem) gf128.Elem {
	b := e.Bytes()
	b[15] &^= 1
	return gf128.FromBytes(b[:])
}

func setLsb(e gf128.Elem) gf128.Elem {
	b := e.Bytes()
	b[15] |= 1
	return gf128.FromBytes(b[:])
}
