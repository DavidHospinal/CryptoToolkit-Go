package common

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

// GenerateRandomBytes generates cryptographically secure random bytes
func GenerateRandomBytes(length int) ([]byte, error) {
	if length <= 0 {
		return nil, ErrInvalidKeySize
	}

	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random bytes: %w", err)
	}

	return bytes, nil
}

// RightRotate performs a right rotation on a 32-bit integer
func RightRotate(n uint32, d uint) uint32 {
	return (n >> d) | (n << (32 - d))
}

// LeftRotate performs a left rotation on a 32-bit integer
func LeftRotate(n uint32, d uint) uint32 {
	return (n << d) | (n >> (32 - d))
}

// XORBytes performs XOR operation on two byte slices
func XORBytes(a, b []byte) ([]byte, error) {
	if len(a) != len(b) {
		return nil, ErrInvalidInput
	}

	result := make([]byte, len(a))
	for i := range a {
		result[i] = a[i] ^ b[i]
	}

	return result, nil
}

// IsPrime checks if a number is prime (basic implementation for educational purposes)
func IsPrime(n *big.Int) bool {
	if n.Cmp(big.NewInt(2)) < 0 {
		return false
	}
	if n.Cmp(big.NewInt(2)) == 0 {
		return true
	}
	if new(big.Int).Mod(n, big.NewInt(2)).Cmp(big.NewInt(0)) == 0 {
		return false
	}

	// Simple trial division for educational purposes
	// In production, use probabilistic tests like Miller-Rabin
	sqrt := new(big.Int).Sqrt(n)
	for i := big.NewInt(3); i.Cmp(sqrt) <= 0; i.Add(i, big.NewInt(2)) {
		if new(big.Int).Mod(n, i).Cmp(big.NewInt(0)) == 0 {
			return false
		}
	}

	return true
}

// Min returns the minimum of two integers
func Min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Max returns the maximum of two integers
func Max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
