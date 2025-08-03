package common

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
)

// GenerateRandomBytes genera bytes aleatorios criptográficamente seguros
func GenerateRandomBytes(length int) ([]byte, error) {
	if length <= 0 {
		return nil, ErrInvalidInput
	}

	bytes := make([]byte, length)
	if _, err := io.ReadFull(rand.Reader, bytes); err != nil {
		return nil, fmt.Errorf("failed to generate random bytes: %w", err)
	}

	return bytes, nil
}

// GenerateRandomHex genera una cadena hexadecimal aleatoria
func GenerateRandomHex(length int) (string, error) {
	bytes, err := GenerateRandomBytes(length)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// RightRotate realiza rotación a la derecha de bits
func RightRotate(value uint32, amount uint) uint32 {
	return (value >> amount) | (value << (32 - amount))
}

// LeftRotate realiza rotación a la izquierda de bits
func LeftRotate(value uint32, amount uint) uint32 {
	return (value << amount) | (value >> (32 - amount))
}

// XORBytes realiza XOR entre dos slices de bytes
func XORBytes(a, b []byte) ([]byte, error) {
	if len(a) != len(b) {
		return nil, fmt.Errorf("byte slices must have the same length")
	}

	result := make([]byte, len(a))
	for i := range a {
		result[i] = a[i] ^ b[i]
	}
	return result, nil
}

// PadToBlockSize aplica padding a los datos para ajustarlos al tamaño de bloque
func PadToBlockSize(data []byte, blockSize int) []byte {
	if blockSize <= 0 {
		return data
	}

	padding := blockSize - (len(data) % blockSize)
	if padding == 0 {
		padding = blockSize
	}

	padded := make([]byte, len(data)+padding)
	copy(padded, data)

	// PKCS7 padding
	for i := len(data); i < len(padded); i++ {
		padded[i] = byte(padding)
	}

	return padded
}

// RemovePadding remueve el padding PKCS7
func RemovePadding(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, ErrInsufficientData
	}

	padding := int(data[len(data)-1])
	if padding > len(data) || padding == 0 {
		return nil, ErrAESInvalidPadding
	}

	// Verificar que todos los bytes de padding sean correctos
	for i := len(data) - padding; i < len(data); i++ {
		if data[i] != byte(padding) {
			return nil, ErrAESInvalidPadding
		}
	}

	return data[:len(data)-padding], nil
}

// BytesToHex convierte bytes a string hexadecimal
func BytesToHex(data []byte) string {
	return hex.EncodeToString(data)
}

// HexToBytes convierte string hexadecimal a bytes
func HexToBytes(hexStr string) ([]byte, error) {
	return hex.DecodeString(hexStr)
}

// ValidateKeySize verifica que el tamaño de clave sea válido para AES
func ValidateAESKeySize(keySize int) error {
	switch keySize {
	case AESKeySize128, AESKeySize192, AESKeySize256:
		return nil
	default:
		return ErrAESInvalidKeySize
	}
}

// ValidateRSAKeySize verifica que el tamaño de clave RSA sea válido
func ValidateRSAKeySize(keySize int) error {
	if keySize < RSAMinKeySize {
		return ErrRSAKeySizeTooSmall
	}
	if keySize > RSAMaxKeySize {
		return ErrRSAKeySizeTooLarge
	}
	return nil
}

// ValidatePOWDifficulty verifica que la dificultad de PoW sea válida
func ValidatePOWDifficulty(difficulty int) error {
	if difficulty < POWMinDifficulty {
		return ErrPOWDifficultyTooLow
	}
	if difficulty > POWMaxDifficulty {
		return ErrPOWDifficultyTooHigh
	}
	return nil
}

// SecureCompare compara dos slices de bytes de forma segura contra timing attacks
func SecureCompare(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}

	var result byte
	for i := 0; i < len(a); i++ {
		result |= a[i] ^ b[i]
	}

	return result == 0
}

// Min retorna el menor de dos enteros
func Min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Max retorna el mayor de dos enteros
func Max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// IsPowerOfTwo verifica si un número es potencia de 2
func IsPowerOfTwo(n int) bool {
	return n > 0 && (n&(n-1)) == 0
}

// NextPowerOfTwo retorna la siguiente potencia de 2
func NextPowerOfTwo(n int) int {
	if n <= 0 {
		return 1
	}

	// Si ya es potencia de 2, retornar el mismo número
	if IsPowerOfTwo(n) {
		return n
	}

	// Encontrar la siguiente potencia de 2
	power := 1
	for power < n {
		power <<= 1
	}
	return power
}

// ZeroBytes limpia un slice de bytes de forma segura
func ZeroBytes(data []byte) {
	for i := range data {
		data[i] = 0
	}
}
