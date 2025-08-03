package common

import (
	"fmt"
)

// CryptoError representa un error criptográfico con contexto adicional
type CryptoError struct {
	Op      string // Operación que causó el error
	Module  string // Módulo criptográfico (AES, RSA, etc.)
	Err     error  // Error subyacente
	Context string // Contexto adicional
}

func (e *CryptoError) Error() string {
	if e.Context != "" {
		return fmt.Sprintf("%s.%s: %v (%s)", e.Module, e.Op, e.Err, e.Context)
	}
	return fmt.Sprintf("%s.%s: %v", e.Module, e.Op, e.Err)
}

func (e *CryptoError) Unwrap() error {
	return e.Err
}

// NewCryptoError crea un nuevo error criptográfico
func NewCryptoError(module, op string, err error, context string) *CryptoError {
	return &CryptoError{
		Module:  module,
		Op:      op,
		Err:     err,
		Context: context,
	}
}

// Funciones helper para crear errores específicos

// NewOTPError crea un error relacionado con One-Time Pad
func NewOTPError(op string, err error, context string) *CryptoError {
	return NewCryptoError("OTP", op, err, context)
}

// NewAESError crea un error relacionado con AES
func NewAESError(op string, err error, context string) *CryptoError {
	return NewCryptoError("AES", op, err, context)
}

// NewRSAError crea un error relacionado con RSA
func NewRSAError(op string, err error, context string) *CryptoError {
	return NewCryptoError("RSA", op, err, context)
}

// NewHashError crea un error relacionado con funciones hash
func NewHashError(op string, err error, context string) *CryptoError {
	return NewCryptoError("HASH", op, err, context)
}

// NewPOWError crea un error relacionado con Proof of Work
func NewPOWError(op string, err error, context string) *CryptoError {
	return NewCryptoError("POW", op, err, context)
}

// Validadores con errores contextuales

// ValidateNotEmpty valida que los datos no estén vacíos
func ValidateNotEmpty(data []byte, fieldName string) error {
	if len(data) == 0 {
		return fmt.Errorf("%s cannot be empty", fieldName)
	}
	return nil
}

// ValidateStringNotEmpty valida que una string no esté vacía
func ValidateStringNotEmpty(str, fieldName string) error {
	if str == "" {
		return fmt.Errorf("%s cannot be empty", fieldName)
	}
	return nil
}

// ValidateKeyLength valida la longitud de una clave
func ValidateKeyLength(key []byte, expectedLengths []int, keyType string) error {
	keyLen := len(key)
	for _, expected := range expectedLengths {
		if keyLen == expected {
			return nil
		}
	}

	return fmt.Errorf("invalid %s key length: got %d bytes, expected one of %v",
		keyType, keyLen, expectedLengths)
}

// ValidateRange valida que un valor esté dentro de un rango
func ValidateRange(value, min, max int, fieldName string) error {
	if value < min || value > max {
		return fmt.Errorf("%s must be between %d and %d, got %d",
			fieldName, min, max, value)
	}
	return nil
}

// ValidatePositive valida que un valor sea positivo
func ValidatePositive(value int, fieldName string) error {
	if value <= 0 {
		return fmt.Errorf("%s must be positive, got %d", fieldName, value)
	}
	return nil
}

// ValidateBufferSize valida que un buffer tenga el tamaño correcto
func ValidateBufferSize(buffer []byte, expectedSize int, bufferName string) error {
	if len(buffer) != expectedSize {
		return fmt.Errorf("%s must be exactly %d bytes, got %d",
			bufferName, expectedSize, len(buffer))
	}
	return nil
}

// IsValidHex verifica si una string es hexadecimal válida
func IsValidHex(s string) bool {
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return false
		}
	}
	return len(s)%2 == 0 // Debe tener longitud par
}

// ValidateHex valida que una string sea hexadecimal válida
func ValidateHex(hexStr, fieldName string) error {
	if !IsValidHex(hexStr) {
		return fmt.Errorf("%s must be a valid hexadecimal string", fieldName)
	}
	return nil
}
