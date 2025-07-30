package common

import "errors"

// General crypto errors
var (
	ErrInvalidKeySize   = errors.New("invalid key size")
	ErrInvalidInput     = errors.New("invalid input")
	ErrKeyNotSet        = errors.New("key not set")
	ErrInvalidOperation = errors.New("invalid operation")
)

// OTP specific errors
var (
	ErrOTPKeyReused    = errors.New("OTP key reused - security violation")
	ErrOTPInputTooLong = errors.New("input longer than key")
	ErrOTPKeyTooShort  = errors.New("key too short for input")
)

// RSA specific errors
var (
	ErrRSAKeyGeneration    = errors.New("RSA key generation failed")
	ErrRSAInvalidPadding   = errors.New("invalid RSA padding")
	ErrRSAInvalidKeySize   = errors.New("invalid RSA key size")
	ErrRSAEncryptionFailed = errors.New("RSA encryption failed")
	ErrRSADecryptionFailed = errors.New("RSA decryption failed")
)

// Hash specific errors
var (
	ErrInvalidHashInput = errors.New("invalid hash input")
	ErrMerkleTreeEmpty  = errors.New("merkle tree is empty")
	ErrInvalidProof     = errors.New("invalid merkle proof")
	ErrHashMismatch     = errors.New("hash mismatch")
)

// Proof of Work errors
var (
	ErrInvalidDifficulty = errors.New("invalid difficulty")
	ErrInvalidNonce      = errors.New("invalid nonce")
	ErrMiningFailed      = errors.New("mining failed")
)
