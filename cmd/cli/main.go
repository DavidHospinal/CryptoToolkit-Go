package main

import (
	"fmt"
	"os"

	"github.com/DavidHospinal/CryptoToolkit-Go/pkg/crypto/symmetric"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "cryptotoolkit",
	Short: "Educational Blockchain Cryptography Toolkit",
	Long: `CryptoToolkit-Go is an interactive educational platform for learning
the cryptographic fundamentals behind blockchain technology.

Learn and experiment with:
- One-Time Pad (OTP) encryption
- SHA-256 hash functions  
- RSA asymmetric cryptography
- Merkle Trees
- Proof of Work mining`,
}

var otpCmd = &cobra.Command{
	Use:   "otp",
	Short: "One-Time Pad operations",
	Long:  "Explore perfect secrecy with One-Time Pad encryption",
}

var otpEncryptCmd = &cobra.Command{
	Use:   "encrypt [message]",
	Short: "Encrypt a message using OTP",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		explain, _ := cmd.Flags().GetBool("explain")
		keySize, _ := cmd.Flags().GetInt("key-size")

		otp := symmetric.NewOTP(explain)

		message := args[0]
		if keySize == 0 {
			keySize = len(message)
		}

		fmt.Printf("OTP Encryption Demo\n")
		fmt.Printf("Message: '%s'\n", message)

		_, err := otp.GenerateRandomKey(keySize)
		if err != nil {
			fmt.Printf("Error generating key: %v\n", err)
			return
		}

		ciphertext, steps, err := otp.Encrypt([]byte(message))
		if err != nil {
			fmt.Printf("Error encrypting: %v\n", err)
			return
		}

		fmt.Printf("Ciphertext (hex): %x\n", ciphertext)

		if explain && len(steps) > 0 {
			fmt.Printf("\nStep-by-step explanation:\n")
			for _, step := range steps {
				fmt.Printf("Step %d: %s\n", step.Step, step.Operation)
			}
		}

		fmt.Printf("\nDecryption:\n")
		plaintext, _, err := otp.Decrypt(ciphertext)
		if err != nil {
			fmt.Printf("Error decrypting: %v\n", err)
			return
		}

		fmt.Printf("Decrypted: '%s'\n", string(plaintext))
		fmt.Printf("Encryption/Decryption successful!\n")
	},
}

var otpDemoBreakCmd = &cobra.Command{
	Use:   "demo-break [msg1] [msg2]",
	Short: "Demonstrate why key reuse breaks OTP",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		otp := symmetric.NewOTP(true)

		maxLen := len(args[0])
		if len(args[1]) > maxLen {
			maxLen = len(args[1])
		}

		otp.GenerateRandomKey(maxLen)
		otp.DemonstrateKeyReuse(args[0], args[1])
	},
}

func init() {
	otpEncryptCmd.Flags().Bool("explain", false, "Show step-by-step explanation")
	otpEncryptCmd.Flags().Int("key-size", 0, "Key size in bytes (default: message length)")

	otpCmd.AddCommand(otpEncryptCmd)
	otpCmd.AddCommand(otpDemoBreakCmd)
	rootCmd.AddCommand(otpCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
