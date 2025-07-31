package hash

import (
	"encoding/binary"
	"fmt"
	"github.com/DavidHospinal/CryptoToolkit-Go/pkg/crypto/common"
)

// SHA256 represents our SHA-256 implementation
type SHA256 struct {
	h           [8]uint32
	totalBytes  uint64
	buffer      []byte
	ExplainMode bool
}

// NewSHA256 creates a new SHA-256 hasher
func NewSHA256(explainMode bool) *SHA256 {
	sha := &SHA256{
		ExplainMode: explainMode,
	}
	sha.Reset()
	return sha
}

// Reset resets the hasher to initial state
func (s *SHA256) Reset() {
	s.h = common.SHA256InitialHashValues
	s.totalBytes = 0
	s.buffer = nil

	if s.ExplainMode {
		fmt.Printf("SHA-256 Reset\n")
		fmt.Printf("Initial hash values (H0-H7):\n")
		for i, h := range s.h {
			fmt.Printf("H%d: 0x%08x\n", i, h)
		}
	}
}

// Write implements io.Writer interface
func (s *SHA256) Write(data []byte) (int, error) {
	s.totalBytes += uint64(len(data))
	s.buffer = append(s.buffer, data...)

	// Process complete 64-byte blocks
	for len(s.buffer) >= 64 {
		s.processBlock(s.buffer[:64])
		s.buffer = s.buffer[64:]
	}

	return len(data), nil
}

// Sum returns the SHA-256 checksum
func (s *SHA256) Sum() []byte {
	// Create a copy to avoid modifying the original state
	clone := *s

	// Padding
	msgLen := clone.totalBytes
	clone.buffer = append(clone.buffer, 0x80) // Append '1' bit followed by zeros

	// Pad to 56 bytes (leaving 8 bytes for length)
	for len(clone.buffer)%64 != 56 {
		clone.buffer = append(clone.buffer, 0x00)
	}

	// Append length in bits as 64-bit big-endian
	lengthBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(lengthBytes, msgLen*8)
	clone.buffer = append(clone.buffer, lengthBytes...)

	if clone.ExplainMode {
		fmt.Printf("Padding applied:\n")
		fmt.Printf("Original length: %d bytes\n", msgLen)
		fmt.Printf("After padding: %d bytes (%d blocks)\n", len(clone.buffer), len(clone.buffer)/64)
	}

	// Process remaining blocks
	for len(clone.buffer) >= 64 {
		clone.processBlock(clone.buffer[:64])
		clone.buffer = clone.buffer[64:]
	}

	// Convert hash to bytes
	result := make([]byte, 32)
	for i, h := range clone.h {
		binary.BigEndian.PutUint32(result[i*4:], h)
	}

	if clone.ExplainMode {
		fmt.Printf("Final hash: %x\n", result)
	}

	return result
}

// processBlock processes a single 512-bit (64-byte) block
func (s *SHA256) processBlock(block []byte) {
	// Message schedule (W)
	w := make([]uint32, 64)

	// First 16 words are the input block
	for i := 0; i < 16; i++ {
		w[i] = binary.BigEndian.Uint32(block[i*4:])
	}

	// Extend to 64 words
	for i := 16; i < 64; i++ {
		s1 := common.RightRotate(w[i-2], 17) ^ common.RightRotate(w[i-2], 19) ^ (w[i-2] >> 10)
		s0 := common.RightRotate(w[i-15], 7) ^ common.RightRotate(w[i-15], 18) ^ (w[i-15] >> 3)
		w[i] = w[i-16] + s0 + w[i-7] + s1
	}

	if s.ExplainMode {
		fmt.Printf("Processing block:\n")
		fmt.Printf("First 4 words: %08x %08x %08x %08x\n", w[0], w[1], w[2], w[3])
	}

	// Initialize working variables
	a, b, c, d, e, f, g, h := s.h[0], s.h[1], s.h[2], s.h[3], s.h[4], s.h[5], s.h[6], s.h[7]

	// Main loop (64 rounds)
	for i := 0; i < 64; i++ {
		s1 := common.RightRotate(e, 6) ^ common.RightRotate(e, 11) ^ common.RightRotate(e, 25)
		ch := (e & f) ^ (^e & g)
		temp1 := h + s1 + ch + common.SHA256RoundConstants[i] + w[i]
		s0 := common.RightRotate(a, 2) ^ common.RightRotate(a, 13) ^ common.RightRotate(a, 22)
		maj := (a & b) ^ (a & c) ^ (b & c)
		temp2 := s0 + maj

		h = g
		g = f
		f = e
		e = d + temp1
		d = c
		c = b
		b = a
		a = temp1 + temp2

		if s.ExplainMode && i < 3 {
			fmt.Printf("Round %d: a=%08x e=%08x\n", i, a, e)
		}
	}

	// Add to hash values
	s.h[0] += a
	s.h[1] += b
	s.h[2] += c
	s.h[3] += d
	s.h[4] += e
	s.h[5] += f
	s.h[6] += g
	s.h[7] += h
}

// SimpleHash computes SHA-256 of input with optional explanation
func SimpleHash(input string, explain bool) []byte {
	hasher := NewSHA256(explain)
	hasher.Write([]byte(input))
	return hasher.Sum()
}
