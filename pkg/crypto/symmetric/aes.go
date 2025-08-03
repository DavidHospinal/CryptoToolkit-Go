package symmetric

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"

	"github.com/DavidHospinal/CryptoToolkit-Go/pkg/crypto/common"
)

type AES struct {
	ExplainMode bool
}

type AESExplanationStep struct {
	Step        int
	Description string
	Operation   string
	Details     string
}

func NewAES(explainMode bool) *AES {
	return &AES{
		ExplainMode: explainMode,
	}
}

// EncryptAES cifra un mensaje usando AES con el modo especificado
func (a *AES) Encrypt(plaintext []byte, key []byte, mode string) ([]byte, []byte, []AESExplanationStep, error) {
	var steps []AESExplanationStep

	// Validar longitud de clave
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return nil, nil, nil, common.ErrInvalidKeySize
	}

	if a.ExplainMode {
		steps = append(steps, AESExplanationStep{
			Step:        1,
			Description: "Validación de clave",
			Operation:   fmt.Sprintf("Clave de %d bytes validada para AES-%d", len(key), len(key)*8),
			Details:     "AES soporta claves de 128, 192 o 256 bits",
		})
	}

	// Crear cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("error creating AES cipher: %w", err)
	}

	if a.ExplainMode {
		steps = append(steps, AESExplanationStep{
			Step:        2,
			Description: "Creación del cipher",
			Operation:   "Inicialización del algoritmo AES con la clave proporcionada",
			Details:     "Se crean las tablas S-Box y se programan las claves de ronda",
		})
	}

	switch mode {
	case "CBC":
		return a.encryptCBC(block, plaintext, steps)
	case "ECB":
		return a.encryptECB(block, plaintext, steps)
	case "CTR":
		return a.encryptCTR(block, plaintext, steps)
	default:
		return a.encryptCBC(block, plaintext, steps) // Default to CBC
	}
}

func (a *AES) encryptCBC(block cipher.Block, plaintext []byte, steps []AESExplanationStep) ([]byte, []byte, []AESExplanationStep, error) {
	// Generar IV aleatorio
	iv := make([]byte, block.BlockSize())
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, nil, nil, fmt.Errorf("error generating IV: %w", err)
	}

	if a.ExplainMode {
		steps = append(steps, AESExplanationStep{
			Step:        3,
			Description: "Generación de IV",
			Operation:   fmt.Sprintf("Vector de inicialización de %d bytes generado", len(iv)),
			Details:     "El IV debe ser único para cada cifrado y no predecible",
		})
	}

	// Aplicar padding PKCS7
	paddedPlaintext := a.pkcs7Pad(plaintext, block.BlockSize())

	if a.ExplainMode {
		steps = append(steps, AESExplanationStep{
			Step:        4,
			Description: "Aplicación de padding",
			Operation:   fmt.Sprintf("PKCS7 padding aplicado: %d → %d bytes", len(plaintext), len(paddedPlaintext)),
			Details:     "El padding asegura que el texto sea múltiplo del tamaño de bloque",
		})
	}

	// Cifrar usando CBC
	ciphertext := make([]byte, len(paddedPlaintext))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, paddedPlaintext)

	if a.ExplainMode {
		steps = append(steps, AESExplanationStep{
			Step:        5,
			Description: "Cifrado CBC",
			Operation:   "Cada bloque se XOR con el bloque cifrado anterior (o IV)",
			Details:     "CBC proporciona seguridad mediante la dependencia entre bloques",
		})

		steps = append(steps, AESExplanationStep{
			Step:        6,
			Description: "Resultado final",
			Operation:   fmt.Sprintf("Texto cifrado de %d bytes generado", len(ciphertext)),
			Details:     "IV + texto cifrado listo para transmitir o almacenar",
		})
	}

	return ciphertext, iv, steps, nil
}

func (a *AES) encryptECB(block cipher.Block, plaintext []byte, steps []AESExplanationStep) ([]byte, []byte, []AESExplanationStep, error) {
	if a.ExplainMode {
		steps = append(steps, AESExplanationStep{
			Step:        3,
			Description: "Modo ECB seleccionado",
			Operation:   "Electronic Codebook - cada bloque se cifra independientemente",
			Details:     "⚠️ ADVERTENCIA: ECB no es seguro para la mayoría de aplicaciones",
		})
	}

	// Aplicar padding PKCS7
	paddedPlaintext := a.pkcs7Pad(plaintext, block.BlockSize())

	if a.ExplainMode {
		steps = append(steps, AESExplanationStep{
			Step:        4,
			Description: "Aplicación de padding",
			Operation:   fmt.Sprintf("PKCS7 padding aplicado: %d → %d bytes", len(plaintext), len(paddedPlaintext)),
			Details:     "Necesario para completar bloques de 128 bits",
		})
	}

	// Cifrar bloque por bloque
	ciphertext := make([]byte, len(paddedPlaintext))
	for i := 0; i < len(paddedPlaintext); i += block.BlockSize() {
		block.Encrypt(ciphertext[i:i+block.BlockSize()], paddedPlaintext[i:i+block.BlockSize()])
	}

	if a.ExplainMode {
		steps = append(steps, AESExplanationStep{
			Step:        5,
			Description: "Cifrado ECB completado",
			Operation:   fmt.Sprintf("%d bloques cifrados independientemente", len(paddedPlaintext)/block.BlockSize()),
			Details:     "Cada bloque de 128 bits se cifra con la misma clave",
		})
	}

	return ciphertext, nil, steps, nil // ECB no usa IV
}

func (a *AES) encryptCTR(block cipher.Block, plaintext []byte, steps []AESExplanationStep) ([]byte, []byte, []AESExplanationStep, error) {
	// Generar IV aleatorio para CTR
	iv := make([]byte, block.BlockSize())
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, nil, nil, fmt.Errorf("error generating IV: %w", err)
	}

	if a.ExplainMode {
		steps = append(steps, AESExplanationStep{
			Step:        3,
			Description: "Modo CTR inicializado",
			Operation:   "Counter Mode - convierte cifrado de bloque en cifrado de flujo",
			Details:     "Permite paralelización y acceso aleatorio a los datos",
		})
	}

	// Cifrar usando CTR
	stream := cipher.NewCTR(block, iv)
	ciphertext := make([]byte, len(plaintext))
	stream.XORKeyStream(ciphertext, plaintext)

	if a.ExplainMode {
		steps = append(steps, AESExplanationStep{
			Step:        4,
			Description: "Cifrado CTR completado",
			Operation:   "Texto plano XOR con keystream generado",
			Details:     "No requiere padding - funciona con cualquier longitud de datos",
		})
	}

	return ciphertext, iv, steps, nil
}

// DecryptAES descifra un mensaje cifrado con AES
func (a *AES) Decrypt(ciphertext []byte, key []byte, iv []byte, mode string) ([]byte, []AESExplanationStep, error) {
	var steps []AESExplanationStep

	// Crear cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating AES cipher: %w", err)
	}

	switch mode {
	case "CBC":
		return a.decryptCBC(block, ciphertext, iv, steps)
	case "ECB":
		return a.decryptECB(block, ciphertext, steps)
	case "CTR":
		return a.decryptCTR(block, ciphertext, iv, steps)
	default:
		return a.decryptCBC(block, ciphertext, iv, steps)
	}
}

func (a *AES) decryptCBC(block cipher.Block, ciphertext []byte, iv []byte, steps []AESExplanationStep) ([]byte, []AESExplanationStep, error) {
	if len(ciphertext)%block.BlockSize() != 0 {
		return nil, nil, fmt.Errorf("ciphertext is not a multiple of block size")
	}

	plaintext := make([]byte, len(ciphertext))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plaintext, ciphertext)

	// Remover padding
	unpadded, err := a.pkcs7Unpad(plaintext)
	if err != nil {
		return nil, nil, fmt.Errorf("error removing padding: %w", err)
	}

	if a.ExplainMode {
		steps = append(steps, AESExplanationStep{
			Step:        1,
			Description: "Descifrado CBC completado",
			Operation:   "Texto descifrado y padding removido",
			Details:     fmt.Sprintf("Recuperados %d bytes del texto original", len(unpadded)),
		})
	}

	return unpadded, steps, nil
}

func (a *AES) decryptECB(block cipher.Block, ciphertext []byte, steps []AESExplanationStep) ([]byte, []AESExplanationStep, error) {
	if len(ciphertext)%block.BlockSize() != 0 {
		return nil, nil, fmt.Errorf("ciphertext is not a multiple of block size")
	}

	plaintext := make([]byte, len(ciphertext))
	for i := 0; i < len(ciphertext); i += block.BlockSize() {
		block.Decrypt(plaintext[i:i+block.BlockSize()], ciphertext[i:i+block.BlockSize()])
	}

	// Remover padding
	unpadded, err := a.pkcs7Unpad(plaintext)
	if err != nil {
		return nil, nil, fmt.Errorf("error removing padding: %w", err)
	}

	return unpadded, steps, nil
}

func (a *AES) decryptCTR(block cipher.Block, ciphertext []byte, iv []byte, steps []AESExplanationStep) ([]byte, []AESExplanationStep, error) {
	stream := cipher.NewCTR(block, iv)
	plaintext := make([]byte, len(ciphertext))
	stream.XORKeyStream(plaintext, ciphertext)

	return plaintext, steps, nil
}

// PKCS7 Padding functions
func (a *AES) pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padText := make([]byte, padding)
	for i := range padText {
		padText[i] = byte(padding)
	}
	return append(data, padText...)
}

func (a *AES) pkcs7Unpad(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("data is empty")
	}

	padding := int(data[len(data)-1])
	if padding > len(data) || padding == 0 {
		return nil, fmt.Errorf("invalid padding")
	}

	// Verificar que todos los bytes de padding sean correctos
	for i := len(data) - padding; i < len(data); i++ {
		if data[i] != byte(padding) {
			return nil, fmt.Errorf("invalid padding")
		}
	}

	return data[:len(data)-padding], nil
}

// ValidateKey verifica que la clave tenga un tamaño válido para AES
func ValidateKey(key []byte) error {
	switch len(key) {
	case 16, 24, 32:
		return nil
	default:
		return fmt.Errorf("invalid key size: %d bytes. AES requires 16, 24, or 32 bytes", len(key))
	}
}
