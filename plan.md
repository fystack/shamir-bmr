# Shamir-BMR Protocol — Implementation Plan

A Shamir-secret-sharing–based **BMR** (Beaver–Micali–Rogaway) constant-round
multiparty garbled-circuit protocol, capable *in theory* of evaluating SHA-256.

## Locked decisions (confirmed with user)

| Decision        | Choice                                               |
|-----------------|------------------------------------------------------|
| Language        | **Go** (go1.26)                                      |
| Security model  | **Malicious**, honest majority, security-with-abort  |
| Execution       | **Single-process simulation** of all `n` parties     |
| Field / keys    | **GF(2^128)** wire keys & shared masks, **free-XOR**  |

## Defaults I chose (configurable — tell me to change any)

- **Parties / threshold:** default `n = 3`, `t = 1` (honest majority, `2t < n`,
  abort on cheating). Both configurable.
- **MPC multiplication:** Damgård–Nielsen (DN) style degree reduction, with
  **Chida et al. (CRYPTO'18) randomized verification** for malicious security
  (multiply all values & products by a shared random key, open a random linear
  combination, check it is zero). This is the "Shamir with abort" route MP-SPDZ
  takes, avoiding per-value SPDZ MACs.
- **PRG/PRF for garbling:** fixed-key **AES-128** as a correlation-robust hash
  `H(k, gateId, rowIdx, targetParty)`; chosen because free-XOR needs a
  circular-correlation-robust function and AES-NI is available.
- **Circuit format:** **Bristol Fashion** parser (gate types `XOR`, `AND`,
  `INV`/`NOT`, `EQ`/`EQW` passthroughs). SHA-256 circuit is a standard Bristol
  circuit, so the same evaluator runs it.

## Protocol structure

Two phases, exactly as in BMR / LPSY / FKOS:

### Phase 1 — Garbling (offline, uses the Shamir MPC)
The expensive secure computation. Parties jointly produce a garbled circuit
without anyone learning wire masks or other parties' keys.

1. **Setup.** Each party `i` samples a global free-XOR offset `Rᵢ ∈ GF(2^128)`
   with `lsb(Rᵢ)=1`, and commits to it. The superkey offset is `R = (R₁..Rₙ)`.
2. **Wire masks.** Every wire `w` gets a secret-shared permutation bit
   `[λ_w] ∈ {0,1} ⊂ GF(2^128)`. Bits are shared via Shamir; AND of bits = field
   multiply, XOR of bits = field add (both 0/1-closed in GF(2^128)).
3. **Wire keys.** Each party `i` picks a 0-key `k_w^i`; the 1-key is
   `k_w^i ⊕ Rᵢ` (free-XOR). For an XOR gate `c=a⊕b`, output keys/masks are the
   XORs of inputs (free). Only **AND** gates produce garbled tables.
4. **Garbled AND tables.** For each AND gate and each of the 4 input-pointer
   combinations `(α,β)`, the output superkey is `K_{c,0} ⊕ χ·R` where the
   selector bit `χ = ((λ_a⊕α)(λ_b⊕β)) ⊕ λ_c`. The product `(λ_a⊕α)(λ_b⊕β)`
   is the **secure multiplication** done in the Shamir MPC. The PRF/PRG outputs
   `H(k_{a,α}^i, …) ⊕ H(k_{b,β}^i, …)` are computed **locally** by each party
   (FKOS trick — AES is *not* evaluated inside MPC), then combined by the MPC.
5. **Malicious checks.** Parties commit to / input their PRF outputs as shares;
   verified triples + randomized MAC check guarantee a corrupt garbler cannot
   slip in an inconsistent row (defends the BMR "additive" attack).

### Phase 2 — Online evaluation (local, one round)
1. Reveal external values `Λ_w = ρ_w ⊕ λ_w` for input wires and the active
   input superkeys.
2. Evaluate gate-by-gate: XOR/INV are free (XOR keys / flip external bit); for
   AND, use row `(Λ_a, Λ_b)` to decrypt `K_c` and recover `Λ_c`.
3. For output wires, reconstruct `λ_w` and output real bit `Λ_w ⊕ λ_w`.

## Package layout (Go)

```
shamir-bmr/
  go.mod
  plan.md
  cmd/sbmr/            # CLI demo runner
  internal/
    gf128/            # GF(2^128) arithmetic (add=XOR, carryless mul, inverse)
    shamir/           # Shamir SS over GF(2^128): share/reconstruct/Lagrange
    mpc/              # simulated parties, DN multiply, triples, malicious checks
    circuit/          # Bristol-Fashion parser + in-memory circuit model
    garble/           # BMR garbling over the MPC (Phase 1)
    eval/             # online garbled-circuit evaluator (Phase 2)
    prf/              # fixed-key AES correlation-robust hash
  test/               # small circuits + (optionally) sha256 bristol fixture
```

## Build & verification order (each step lands with tests)

1. `gf128` — field arithmetic + property tests (assoc/dist/inverse).
2. `shamir` — share/reconstruct round-trip; linearity; threshold privacy.
3. `mpc` — simulated parties, beaver triples, DN multiply, malicious verify;
   inject a fault and confirm the check aborts.
4. `prf` — fixed-key AES hash.
5. `circuit` — Bristol parser on a tiny hand circuit; then ingest SHA-256.
6. `garble` + `eval` — garble & evaluate small circuits (AND/XOR/INV), check
   against plaintext truth tables.
7. End-to-end: a small circuit fully, then SHA-256 wired up (slow but correct);
   default demo uses a small circuit, SHA-256 behind a flag.

## Status

Implemented and tested end-to-end (see README). The defaults above (`n=3, t=1`,
Chida-style verification) are in use and validated: all unit tests pass, the
malicious fault-injection test aborts as expected, and the full SHA-256
compression circuit garbles + evaluates with output matching a plaintext run.

Still your call if you want different defaults:
- A specific party count / threshold (the engine is configurable via `-n`/`-t`).
- A SPDZ-MAC-style check instead of the Chida randomized verification.
- Prioritising the FKOS PRF-consistency layer (the one modeled-not-enforced
  piece; see README "Scope and limitations").

---

# Next phase — Threshold-HMAC-SHA256 (bybit)

## Goal

Compute `HMAC-SHA256(K, m)` where the HMAC key `K` is **secret-shared across the
parties** (no single party ever holds it) and the message `m` is **public**. The
32-byte tag is the revealed output. This is the bybit API-signing use case:
`signature = HMAC_SHA256(api_secret, timestamp + api_key + recv_window + body)`.
Splitting `api_secret` across `n` custody nodes means `≥ t+1` of them must
cooperate to produce a valid signature, and no minority (and no single node) can
forge one or recover the secret.

```
HMAC(K,m) = SHA256( (K0 ⊕ opad) || SHA256( (K0 ⊕ ipad) || m ) )
ipad = 0x36×64,  opad = 0x5c×64,  K0 = K zero-padded to 64 bytes (block size)
```

## Pinned fact: the compression circuit's bit convention

`test/sha256.txt` is the SHA-256 **compression** function
`compress(state₂₅₆, block₅₁₂) → state₂₅₆`, **including** the Davies–Meyer
feed-forward. Verified this phase against `crypto/sha256` (the prior suite only
checked BMR-vs-`circuit.Eval` self-consistency, never *real* SHA-256):

- **Input wire order:** message block (512) **then** state (256).
- **Bit convention:** each segment is the **bit-reversal of its standard
  big-endian byte string** (equivalently: 4-byte words reversed in order, stored
  little-endian, bits LSB-first). The 256-bit **output uses the same convention
  as the 256-bit state input**, so chaining one compression into the next is
  *direct identity wiring* — no byte round-trip between blocks.

A permanent `TestSHA256Conformance` (empty / "abc" / multi-block vs `crypto/sha256`)
will lock this down before anything builds on it.

## Approach: compose ONE big circuit, garble it once

HMAC is a fixed chain of compressions. We **build a single Bristol-style
`*circuit.Circuit` in memory** that wires all compression instances together,
then garble+evaluate it with the *existing, unchanged* BMR engine. The
alternative — garble each block separately and feed states between them — is
rejected: it would have to reveal the keyed intermediate chaining states (they
are secret), defeating HMAC. Composing one circuit keeps every intermediate wire
garbled.

Compression calls for a message of `L` bytes:
`inner = 1 (key block) + ceil((64+L+9)/64 − 1) message blocks`, `outer = 2`
(key block + the 1-block inner-digest). Typical bybit sign-string (~100–200 B):
**4–6 compressions** ≈ 4–6 min to garble (behind `-short` skip / a CLI flag).

### Circuit builder (`internal/hmacsha`)

A `circuit.Builder` (new tiny helper) allocates fresh wire ids and appends
remapped copies of the compression gates per instance. Wiring per instance:

- **IV** (first inner & first outer block's state input): 256 `EQ` constant wires
  in the pinned convention.
- **`K0 ⊕ ipad` / `K0 ⊕ opad` blocks:** the key occupies the first `|K|·8`
  **secret input wires**; the block bit is `key_bit ⊕ pad_bit`, realised by an
  `INV` gate where the public pad bit is 1, `EQW` where it is 0 — *free* in BMR.
  Zero-padded key bytes (`|K|..63`) XOR pad = `EQ` constant.
- **Message + SHA padding blocks (inner):** all **public** — public input wires
  for `m`, `EQ` constants for the `0x80`, zero pad, and the 64-bit length
  (length = `64+L`, public).
- **Inner→outer:** the inner hash's 256 output wires feed the first 256 bits of
  the outer second block directly (identity wiring); the remaining 256 bits are
  `EQ` constants (`0x80`, zeros, length `= 96`).
- **Output:** the final outer compression's 256 output wires are the circuit
  outputs; `DecodeTag` converts them back to the 32-byte tag via the pinned
  convention.

The builder returns the `*circuit.Circuit` plus a **layout**: which input wires
are the secret key and which are the public message.

### Threshold key input (the one engine-facing addition)

The key bits are a genuine Shamir sharing — `mpc.Engine.Input` already produces a
degree-`t` sharing of a secret, which *is* a threshold sharing (any `t` parties
learn nothing); in a real deployment the parties pre-share `K` and input their
shares, with identical distribution. The security-relevant requirement is that we
**never open the key wires' masks `λ`**. Instead, for each secret key wire `w`:

```
e_w = Open( λ_w ⊕ ρ_w )     // ρ_w = shared key bit; e_w = public external value
super_w[i] = k0[w][i] ⊕ e_w·R[i]
```

`e_w` is a masked bit (uniform given `λ_w` secret) — safe to publish, and it is
all the evaluator needs. This is the standard BMR "input on a secret-shared
value" step. Garbler changes (small, additive):

- `MarkSecretInput(wire)` + supply the shared key bits; the garbler calls
  `eng.Input` on them during garbling (registered for `Verify`).
- In the post-`Verify` reveal: for secret wires, open `λ⊕ρ` and store
  `(ext, super)` instead of revealing `λ`. Public input wires and output wires
  are unchanged (their `λ` reveal is fine — message and tag are public).
- `EncodeInputs(publicBits)` fills only the public message wires; the key wires'
  `(ext, super)` come from the stored threshold encoding. The evaluator path is
  unchanged.

### Deliverables

1. `internal/circuit`: `TestSHA256Conformance` (real SHA-256) + exported
   byte↔wire convention helpers.
2. `internal/hmacsha`: circuit builder + layout, `pad`/`DecodeTag`, and a
   plaintext `HMAC` oracle test vs `crypto/hmac` for many key/message lengths.
3. `internal/garble`: `MarkSecretInput` + threshold key-wire encoding
   (open `λ⊕ρ`), `EncodeInputs` for the public-wire split. No `mpc`/`eval`
   changes.
4. e2e test: garble+evaluate threshold-HMAC, assert the tag equals
   `crypto/hmac` over the same `K,m` (skipped under `-short`).
5. CLI: `sbmr -hmac -key <hex|str> -msg <str> [-n -t]`, prints the tag and
   checks it against `crypto/hmac`.
6. README/plan note on scope, the ~minutes cost, and the per-key precomputation
   optimisation (reuse the garbled `ipad`/`opad` key blocks across signatures) as
   future work.

## Locked decisions (confirmed with user)

| Decision            | Choice                                                         |
|---------------------|----------------------------------------------------------------|
| Key length          | **`|K| ≤ 64 B` only** — `K0` = key zero-padded (covers bybit)   |
| Threshold key model | **Pre-shared** — engine generates the degree-`t` Shamir sharing |
| Secrecy             | **Key secret-shared, message public, tag revealed**            |

`|K| > 64 B` (key pre-hash) and message privacy are explicitly out of scope.
