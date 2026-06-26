// Package hmacsha builds a single boolean circuit computing HMAC-SHA256 with a
// secret-shared key, by composing the SHA-256 compression circuit
// (test/sha256.txt) multiple times. The resulting circuit is garbled and
// evaluated once by the BMR engine, which keeps every keyed intermediate
// chaining state hidden (the reason HMAC is built as one circuit rather than
// per-block).
//
//	HMAC(K,m) = SHA256( (K0 ⊕ opad) || SHA256( (K0 ⊕ ipad) || m ) )
//	ipad = 0x36×64,  opad = 0x5c×64,  K0 = K zero-padded to 64 bytes
//
// Scope: |K| ≤ 64 bytes (covers every bybit api_secret; K0 is the key
// zero-padded). The key bits are secret (threshold-shared) input wires; the
// message bits are public input wires; the 32-byte tag is the revealed output.
package hmacsha

import (
	"encoding/binary"
	"fmt"

	"github.com/nan/shamir-bmr/internal/circuit"
)

const (
	blockBytes = 64
	ipad       = 0x36
	opad       = 0x5c
)

// Circuit is a built HMAC-SHA256 circuit plus its input-wire layout.
type Circuit struct {
	C        *circuit.Circuit
	KeyWires []int // secret (threshold) key input wire ids, len = KeyLen*8
	MsgWires []int // public message input wire ids, len = MsgLen*8
	KeyLen   int
	MsgLen   int
}

// srcKind tags how a single block bit is produced.
type srcKind uint8

const (
	sConst srcKind = iota
	sWire
	sWireInv
)

type bitSrc struct {
	kind srcKind
	val  uint8
	wire int
}

// byteSrc tags a block byte as either a public message byte (index into the
// message) or a constant (padding / fixed bytes).
type byteSrc struct {
	isMsg  bool
	msgIdx int
	val    byte
}

// Build constructs the HMAC-SHA256 circuit for a keyLen-byte key (≤64) and a
// msgLen-byte public message, using comp as the SHA-256 compression circuit.
func Build(comp *circuit.Circuit, keyLen, msgLen int) (*Circuit, error) {
	if keyLen < 0 || keyLen > blockBytes {
		return nil, fmt.Errorf("hmacsha: key length %d unsupported (need 0..64)", keyLen)
	}
	if msgLen < 0 {
		return nil, fmt.Errorf("hmacsha: negative message length")
	}
	if comp.NumInputWires() != 768 || comp.NumOutputWires() != 256 {
		return nil, fmt.Errorf("hmacsha: comp is not a 512+256 -> 256 SHA-256 compression circuit")
	}

	keyBits, msgBits := keyLen*8, msgLen*8
	b := circuit.NewBuilder(keyBits + msgBits)

	keyWires := make([]int, keyBits)
	for i := range keyWires {
		keyWires[i] = b.Input(i)
	}
	msgWires := make([]int, msgBits)
	for i := range msgWires {
		msgWires[i] = b.Input(keyBits + i)
	}

	iv := circuit.BytesToWires(sha256IV())

	// --- inner hash: SHA256( (K0 ⊕ ipad) || m ) ---
	state, err := embedBlock(b, comp, keyBlock(keyWires, keyLen, ipad), ivState(b, iv))
	if err != nil {
		return nil, err
	}
	for _, blk := range innerTailBlocks(msgLen) {
		state, err = embedBlock(b, comp, msgBlock(msgWires, blk), state)
		if err != nil {
			return nil, err
		}
	}
	inner := state // 256 inner-digest wires (wire convention)

	// --- outer hash: SHA256( (K0 ⊕ opad) || inner ) ---
	state, err = embedBlock(b, comp, keyBlock(keyWires, keyLen, opad), ivState(b, iv))
	if err != nil {
		return nil, err
	}
	tag, err := embedBlock(b, comp, outerTailBlock(inner), state)
	if err != nil {
		return nil, err
	}

	c, err := b.Finish([]int{keyBits, msgBits}, tag)
	if err != nil {
		return nil, err
	}
	return &Circuit{C: c, KeyWires: keyWires, MsgWires: msgWires, KeyLen: keyLen, MsgLen: msgLen}, nil
}

// embedBlock materializes the 512 block-source wires (wire-convention input
// order) and embeds one compression instance over (block, state).
func embedBlock(b *circuit.Builder, comp *circuit.Circuit, block [512]bitSrc, state []int) ([]int, error) {
	in := make([]int, 0, 768)
	for i := 0; i < 512; i++ {
		s := block[511-i] // input wire i carries MSB-stream position 511-i
		switch s.kind {
		case sConst:
			in = append(in, b.Const(s.val))
		case sWire:
			in = append(in, s.wire)
		case sWireInv:
			in = append(in, b.Inv(s.wire))
		}
	}
	in = append(in, state...)
	return b.Embed(comp, in)
}

// ivState emits the 256 IV state input wires (constants) in wire convention.
func ivState(b *circuit.Builder, ivWires []uint8) []int {
	s := make([]int, 256)
	for i := range s {
		s[i] = b.Const(ivWires[i])
	}
	return s
}

// keyBlock builds K0 ⊕ pad: key bytes are (inverted) key wires, the zero-padded
// tail is the constant pad. Indexed by MSB-stream position p (0..511).
func keyBlock(keyWires []int, keyLen int, pad byte) [512]bitSrc {
	var src [512]bitSrc
	for p := 0; p < 512; p++ {
		byteIdx, bitInByte := p/8, p%8
		padBit := (pad >> (7 - uint(bitInByte))) & 1
		if byteIdx < keyLen {
			w := keyWires[byteIdx*8+bitInByte]
			if padBit == 1 {
				src[p] = bitSrc{kind: sWireInv, wire: w}
			} else {
				src[p] = bitSrc{kind: sWire, wire: w}
			}
		} else {
			src[p] = bitSrc{kind: sConst, val: padBit}
		}
	}
	return src
}

// msgBlock builds a 512-bit block from a 64-byte spec: message bytes map to the
// corresponding 8 public message wires; constant bytes become const bits.
func msgBlock(msgWires []int, content [blockBytes]byteSrc) [512]bitSrc {
	var src [512]bitSrc
	for p := 0; p < 512; p++ {
		byteIdx, bitInByte := p/8, p%8
		bs := content[byteIdx]
		if bs.isMsg {
			src[p] = bitSrc{kind: sWire, wire: msgWires[bs.msgIdx*8+bitInByte]}
		} else {
			src[p] = bitSrc{kind: sConst, val: (bs.val >> (7 - uint(bitInByte))) & 1}
		}
	}
	return src
}

// outerTailBlock builds the outer second block: bytes 0..31 are the inner digest
// (from inner output wires, identity-mapped), bytes 32..63 are SHA padding for
// the 96-byte outer message (0x80, zeros, 64-bit length = 768).
func outerTailBlock(inner []int) [512]bitSrc {
	pad := outerPadBytes() // 32 padding bytes for byte positions 32..63
	var src [512]bitSrc
	for p := 0; p < 512; p++ {
		byteIdx := p / 8
		if byteIdx < 32 {
			// MSB-stream position p of the inner digest is held by inner output
			// wire (255-p): innerOut[k] carries wire-convention bit k = position 255-k.
			src[p] = bitSrc{kind: sWire, wire: inner[255-p]}
		} else {
			bitInByte := p % 8
			src[p] = bitSrc{kind: sConst, val: (pad[byteIdx-32] >> (7 - uint(bitInByte))) & 1}
		}
	}
	return src
}

// innerTailBlocks returns the inner message blocks after the key block: the
// message bytes followed by SHA padding for total length (64 + msgLen).
func innerTailBlocks(msgLen int) [][blockBytes]byteSrc {
	// Padded tail length: msgLen + 1(0x80) + zeros + 8(length), to a 64-multiple.
	tailLen := msgLen + 1 + 8
	if r := tailLen % blockBytes; r != 0 {
		tailLen += blockBytes - r
	}
	tail := make([]byteSrc, tailLen)
	for q := 0; q < tailLen; q++ {
		switch {
		case q < msgLen:
			tail[q] = byteSrc{isMsg: true, msgIdx: q}
		case q == msgLen:
			tail[q] = byteSrc{val: 0x80}
		case q >= tailLen-8:
			tail[q] = byteSrc{val: 0} // overwritten below
		default:
			tail[q] = byteSrc{val: 0}
		}
	}
	// 64-bit big-endian total bit length in the last 8 bytes.
	var l [8]byte
	binary.BigEndian.PutUint64(l[:], uint64(blockBytes+msgLen)*8)
	for i := 0; i < 8; i++ {
		tail[tailLen-8+i] = byteSrc{val: l[i]}
	}

	var blocks [][blockBytes]byteSrc
	for off := 0; off < tailLen; off += blockBytes {
		var blk [blockBytes]byteSrc
		copy(blk[:], tail[off:off+blockBytes])
		blocks = append(blocks, blk)
	}
	return blocks
}

// outerPadBytes returns the 32 bytes following the inner digest in the outer
// second block: 0x80, zeros, and the 64-bit length (96 bytes = 768 bits).
func outerPadBytes() [32]byte {
	var p [32]byte
	p[0] = 0x80
	binary.BigEndian.PutUint64(p[24:], uint64(96)*8)
	return p
}

// sha256IV returns the SHA-256 initial hash value as 32 big-endian bytes.
func sha256IV() []byte {
	iv := []uint32{0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
		0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19}
	out := make([]byte, 32)
	for i, w := range iv {
		binary.BigEndian.PutUint32(out[i*4:], w)
	}
	return out
}

// KeyBits expands a key into MSB-first bits matching KeyWires order.
func (h *Circuit) KeyBits(key []byte) ([]uint8, error) {
	if len(key) != h.KeyLen {
		return nil, fmt.Errorf("hmacsha: key length %d != circuit key length %d", len(key), h.KeyLen)
	}
	return bytesMSB(key), nil
}

// MsgBits expands a message into MSB-first bits matching MsgWires order.
func (h *Circuit) MsgBits(msg []byte) ([]uint8, error) {
	if len(msg) != h.MsgLen {
		return nil, fmt.Errorf("hmacsha: message length %d != circuit message length %d", len(msg), h.MsgLen)
	}
	return bytesMSB(msg), nil
}

// DecodeTag converts the 256 circuit output bits to the 32-byte HMAC tag.
func (h *Circuit) DecodeTag(outBits []uint8) []byte {
	return circuit.WiresToBytes(outBits)
}

// bytesMSB expands bytes to bits, MSB-first within each byte.
func bytesMSB(b []byte) []uint8 {
	out := make([]uint8, len(b)*8)
	for i, by := range b {
		for j := 0; j < 8; j++ {
			out[i*8+j] = (by >> (7 - uint(j))) & 1
		}
	}
	return out
}
