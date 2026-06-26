# Shamir-BMR

A Shamir-secret-sharing–based **BMR** (Beaver–Micali–Rogaway) constant-round
multiparty garbled-circuit protocol, in Go. It garbles arbitrary boolean
circuits (Bristol Fashion) and can evaluate **SHA-256** end to end.

- **Security:** malicious, honest majority, security-with-abort
- **Field / keys:** GF(2¹²⁸) wire keys and secret-shared masks, with **free-XOR**
- **Execution:** single-process simulation of all `n` parties
- **Defaults:** `n = 3` parties, threshold `t = 1`

See [`plan.md`](plan.md) for the design rationale and the decisions behind it.

## Quick start

```bash
# Built-in tiny demo: out = (a XOR b) AND (NOT a)
go run ./cmd/sbmr

# Any Bristol-Fashion circuit, with chosen party count / threshold
go run ./cmd/sbmr -circuit path/to/circuit.txt -n 3 -t 1

# Full SHA-256 compression (≈1 min to garble, instant to evaluate)
go run ./cmd/sbmr -circuit test/sha256.txt
```

The driver garbles the circuit with the Shamir MPC (Phase 1), evaluates the
garbled circuit (Phase 2), and checks the result against a plaintext evaluation
of the same circuit.

```bash
go test ./...            # full suite (includes ~1 min SHA-256 e2e)
go test -short ./...     # fast suite (skips SHA-256)
```

## How it works

The protocol has two phases.

### Phase 1 — Garbling (offline, in the MPC)

Each wire `w` gets a secret-shared masking bit `λ_w`. Each party `i` holds a
per-wire 0-key `k0[w][i]`; the 1-key is `k0[w][i] ⊕ R[i]`, where `R[i]` is party
`i`'s global free-XOR offset. The public *external value* carried on a wire at
evaluation time is `e = ρ ⊕ λ` (`ρ` = real bit).

- **XOR / INV / EQW gates are free** — output keys and masks are linear and are
  derived locally, with no garbled table.
- **AND gates** produce a 2×2 garbled table. For input externals `(α, β)` the
  per-party-slot entry is

  ```
  G[α][β][i] = (⊕_j H(k_{a,α}^j, g, i) ⊕ H(k_{b,β}^j, g, i)) ⊕ k0[c][i] ⊕ (γ·R[i])
  γ = ((α ⊕ λ_a)(β ⊕ λ_b)) ⊕ λ_c
  ```

  The only nonlinearity, `λ_a·λ_b`, is **one secure multiplication per gate**;
  `γ·R[i]` are multiplications of the shared bit `γ` by party `i`'s shared
  offset. The PRF values `H(·)` are computed **locally** by each party (AES never
  enters the MPC — the FKOS optimisation), fed in as authenticated inputs,
  combined, and the rows opened, all under the MPC's MAC verification.

**Point-and-permute:** party 0 samples every fresh 0-key with `lsb = 0` and its
offset `R[0]` with `lsb = 1`. The lsb of party 0's component of a wire's active
superkey then equals that wire's external value, so the evaluator reads the
external bit directly from the recovered key without it leaking `λ`.

### Phase 2 — Evaluation (online, one round, local)

The evaluator holds an external value and active superkey per wire. XOR/INV are
free; for an AND gate it recomputes the PRF masks from the active input
superkeys, decrypts the row selected by the input externals, and reads the
output external from the pointer bit. Output masks are revealed to decode.

## The MPC layer (malicious, honest-majority Shamir)

- **Sharing:** Shamir over GF(2¹²⁸); a value is its share vector (one per party).
  Field add = XOR, and for bits in `{0,1}` field multiply = AND.
- **Multiplication:** Damgård–Nielsen — a local degree-`2t` product is
  re-randomised by a random double-sharing `([r]_t, [r]_{2t})` and the masked
  product opened into a fresh degree-`t` sharing.
- **Malicious security (Chida et al., CRYPTO 2018):** every value carries an
  information-theoretic MAC `[α·x]` under a global secret key `α`. A single
  batched check over a random linear combination of all authenticated values
  catches any additive deviation introduced during an opening, except with
  probability `2⁻¹²⁸`. `internal/mpc` includes a fault-injection test that
  perturbs one opening and confirms `Verify` aborts.
- **Reconstruction** is error-detecting at degree `t`; Lagrange weights for the
  fixed party points are precomputed once (no per-open field inversions).

## Layout

```
cmd/sbmr/            CLI driver
internal/gf128/      GF(2^128) arithmetic
internal/shamir/     Shamir secret sharing + Lagrange weights
internal/mpc/        simulated parties, DN multiply, Chida verification
internal/prf/        fixed-key-AES correlation-robust hash
internal/circuit/    Bristol-Fashion parser + plaintext evaluator
internal/garble/     BMR garbling (Phase 1) + threshold secret-input support
internal/eval/       garbled-circuit evaluation (Phase 2) + e2e tests
internal/hmacsha/    HMAC-SHA256 circuit builder (composes the compression circuit)
test/sha256.txt      SHA-256 compression circuit (Bristol Fashion)
```

## Threshold HMAC-SHA256 (bybit)

The protocol also computes `HMAC-SHA256(K, m)` with the key `K` **secret-shared
across the parties** and the message `m` public — the bybit request-signing use
case (`signature = HMAC_SHA256(api_secret, timestamp+api_key+recv_window+body)`).
Splitting `api_secret` across `n` custody nodes means `≥ t+1` must cooperate to
sign, and no minority can forge a signature or recover the secret.

```bash
# Threshold HMAC: key is secret-shared, message public, tag revealed.
go run ./cmd/sbmr -hmac -key 0123456789abcdef0123456789abcdef0123 -msg "1700000000api_key5000"
go run ./cmd/sbmr -hmac -key hex:00112233 -msg hex:deadbeef   # hex: prefix for raw bytes
```

```
HMAC(K,m) = SHA256( (K0 ⊕ opad) || SHA256( (K0 ⊕ ipad) || m ) )
ipad = 0x36×64,  opad = 0x5c×64,  K0 = K zero-padded to 64 bytes (block size)
```

**How it is built.** `internal/hmacsha` composes the SHA-256 compression circuit
into a *single* boolean circuit for the whole HMAC (typically 4–6 compression
instances), which the unchanged BMR engine garbles in one pass. Building one
circuit — rather than garbling each block and feeding states between them — keeps
every keyed intermediate chaining state garbled, as HMAC security requires. The
`K0⊕ipad` / `K0⊕opad` blocks are free `INV`/`EQW` gates on the secret key wires;
IV, message padding, and lengths are constant wires; the message is public input
wires. The compression circuit's exact bit convention (block-then-state input,
Davies–Meyer feed-forward, each segment carried as the bit-reversal of its
big-endian bytes, output in the same convention as the state input) is pinned by
`circuit.TestSHA256Conformance` against `crypto/sha256`.

**Threshold key input.** Key bits are a genuine degree-`t` Shamir sharing; the
garbler never opens their mask `λ`. For each key wire it instead opens the masked
external `e = λ ⊕ ρ` (a uniform bit, safe to publish) and derives the superkey
publicly — the standard BMR "input on a secret-shared value" step
(`garble.MarkSecret`). `mpc` and `eval` are unchanged. `eval.TestE2EThresholdHMAC`
garbles+evaluates the whole thing and checks the tag equals `crypto/hmac`.

**Scope.** Keys `≤ 64 bytes` (every bybit api_secret qualifies; `K0` = key
zero-padded). Garbling the full HMAC takes minutes; a per-key precomputation
(reusing the garbled `ipad`/`opad` key blocks across many signatures) is the
natural optimisation and is future work.

## Scope and limitations

- The MPC is maliciously secure, so the garbled tables are guaranteed to be a
  correct function of the values each party fed in. Cryptographically **binding
  each party's locally-computed PRF outputs to its committed keys** (the FKOS
  PRF-consistency / cut-and-choose layer) is modeled but not fully enforced;
  in this single-process simulation all parties compute the PRF honestly. The
  attachment point is the per-party `Input` of `H(·)` in `internal/garble`.
- This is a research/teaching prototype: no networking, and the internal
  protocol randomness uses a fast userspace CSPRNG (seeded from `crypto/rand`)
  suitable for simulation, not production key material.
- Honest majority is required (`n ≥ 2t+1`).
