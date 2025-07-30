package symmetric

import (
	"fmt"

	"github.com/DavidHospinal/CryptoToolkit-Go/pkg/crypto/common"
)

type OTP struct {
	Key         []byte
	ExplainMode bool
}

type ExplanationStep struct {
	Step        int
	Description string
	Input       []byte
	Output      []byte
	Operation   string
}

func NewOTP(explainMode bool) *OTP {
	return &OTP{
		ExplainMode: explainMode,
	}
}

func (otp *OTP) GenerateRandomKey(length int) ([]byte, error) {
	if length <= 0 {
		return nil, common.ErrInvalidKeySize
	}

	key, err := common.GenerateRandomBytes(length)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random key: %w", err)
	}

	otp.Key = key

	if otp.ExplainMode {
		fmt.Printf("Generated %d-byte random key\n", length)
		fmt.Printf("Key (hex): %x\n", key[:min(16, len(key))])
		if len(key) > 16 {
			fmt.Printf("... (showing first 16 bytes)\n")
		}
	}

	return key, nil
}

func (otp *OTP) Encrypt(plaintext []byte) ([]byte, []ExplanationStep, error) {
	if len(otp.Key) == 0 {
		return nil, nil, common.ErrKeyNotSet
	}

	if len(plaintext) > len(otp.Key) {
		return nil, nil, common.ErrOTPInputTooLong
	}

	ciphertext := make([]byte, len(plaintext))
	var steps []ExplanationStep

	for i := 0; i < len(plaintext); i++ {
		ciphertext[i] = plaintext[i] ^ otp.Key[i]

		if otp.ExplainMode {
			step := ExplanationStep{
				Step:        i + 1,
				Description: fmt.Sprintf("XOR byte %d", i),
				Input:       []byte{plaintext[i]},
				Output:      []byte{ciphertext[i]},
				Operation:   fmt.Sprintf("0x%02x XOR 0x%02x = 0x%02x", plaintext[i], otp.Key[i], ciphertext[i]),
			}
			steps = append(steps, step)
		}
	}

	if otp.ExplainMode {
		fmt.Printf("OTP Encryption Complete\n")
		fmt.Printf("Plaintext:  %s\n", string(plaintext))
		fmt.Printf("Key (hex):  %x\n", otp.Key[:len(plaintext)])
		fmt.Printf("Ciphertext: %x\n", ciphertext)
		fmt.Printf("Perfect secrecy achieved (if key never reused)\n")
	}

	return ciphertext, steps, nil
}

func (otp *OTP) Decrypt(ciphertext []byte) ([]byte, []ExplanationStep, error) {
	return otp.Encrypt(ciphertext)
}

func (otp *OTP) DemonstrateKeyReuse(msg1, msg2 string) {
	fmt.Printf("SECURITY DEMONSTRATION: Why Key Reuse Breaks OTP\n")
	fmt.Printf("Message 1: '%s'\n", msg1)
	fmt.Printf("Message 2: '%s'\n", msg2)

	cipher1, _, _ := otp.Encrypt([]byte(msg1))
	cipher2, _, _ := otp.Encrypt([]byte(msg2))

	fmt.Printf("Cipher 1:  %x\n", cipher1)
	fmt.Printf("Cipher 2:  %x\n", cipher2)

	xored := make([]byte, min(len(cipher1), len(cipher2)))
	for i := range xored {
		xored[i] = cipher1[i] ^ cipher2[i]
	}

	fmt.Printf("C1 XOR C2: %x\n", xored)
	fmt.Printf("Which equals: '%s'\n", string(xored))
	fmt.Printf("This reveals the XOR of the original messages!\n")
	fmt.Printf("WARNING: NEVER reuse OTP keys!\n")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
