package asymmetric

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
)

type RSA struct {
	ExplainMode bool
}

type RSAKeyPair struct {
	PublicKey  *RSAPublicKey
	PrivateKey *RSAPrivateKey
	N          *big.Int // Modulus
	BitSize    int
}

type RSAPublicKey struct {
	E *big.Int // Public exponent
	N *big.Int // Modulus
}

type RSAPrivateKey struct {
	D *big.Int // Private exponent
	N *big.Int // Modulus
	P *big.Int // Prime p (for optimization)
	Q *big.Int // Prime q (for optimization)
}

type RSAExplanationStep struct {
	Step        int
	Description string
	Operation   string
	Details     string
}

func NewRSA(explainMode bool) *RSA {
	return &RSA{
		ExplainMode: explainMode,
	}
}

// GenerateKeyPair genera un par de claves RSA
func (r *RSA) GenerateKeyPair(bitSize int) (*RSAKeyPair, []RSAExplanationStep, error) {
	var steps []RSAExplanationStep

	if bitSize < 512 {
		return nil, nil, fmt.Errorf("key size too small: minimum 512 bits")
	}

	if r.ExplainMode {
		steps = append(steps, RSAExplanationStep{
			Step:        1,
			Description: "Inicialización",
			Operation:   fmt.Sprintf("Generando claves RSA de %d bits", bitSize),
			Details:     "Tamaño mínimo recomendado: 2048 bits para uso real",
		})
	}

	// Paso 1: Generar dos primos grandes p y q
	primeBits := bitSize / 2
	p, err := r.generatePrime(primeBits)
	if err != nil {
		return nil, nil, fmt.Errorf("error generating prime p: %w", err)
	}

	q, err := r.generatePrime(primeBits)
	if err != nil {
		return nil, nil, fmt.Errorf("error generating prime q: %w", err)
	}

	// Asegurar que p != q
	for p.Cmp(q) == 0 {
		q, err = r.generatePrime(primeBits)
		if err != nil {
			return nil, nil, fmt.Errorf("error regenerating prime q: %w", err)
		}
	}

	if r.ExplainMode {
		steps = append(steps, RSAExplanationStep{
			Step:        2,
			Description: "Generación de primos",
			Operation:   fmt.Sprintf("Primos p y q de %d bits cada uno generados", primeBits),
			Details:     "Los primos deben ser grandes y diferentes para seguridad",
		})
	}

	// Paso 2: Calcular n = p * q
	n := new(big.Int).Mul(p, q)

	if r.ExplainMode {
		steps = append(steps, RSAExplanationStep{
			Step:        3,
			Description: "Cálculo del módulo",
			Operation:   "n = p × q",
			Details:     fmt.Sprintf("Módulo n de %d bits calculado", n.BitLen()),
		})
	}

	// Paso 3: Calcular φ(n) = (p-1)(q-1)
	p1 := new(big.Int).Sub(p, big.NewInt(1))
	q1 := new(big.Int).Sub(q, big.NewInt(1))
	phi := new(big.Int).Mul(p1, q1)

	if r.ExplainMode {
		steps = append(steps, RSAExplanationStep{
			Step:        4,
			Description: "Función totiente de Euler",
			Operation:   "φ(n) = (p-1) × (q-1)",
			Details:     "Cuenta los números menores que n que son coprimos con n",
		})
	}

	// Paso 4: Elegir e (exponente público)
	// Comúnmente se usa 65537 = 2^16 + 1
	e := big.NewInt(65537)

	// Verificar que gcd(e, φ(n)) = 1
	gcd := new(big.Int).GCD(nil, nil, e, phi)
	if gcd.Cmp(big.NewInt(1)) != 0 {
		// Si 65537 no funciona, buscar otro e
		e = big.NewInt(3)
		for {
			gcd = new(big.Int).GCD(nil, nil, e, phi)
			if gcd.Cmp(big.NewInt(1)) == 0 {
				break
			}
			e.Add(e, big.NewInt(2)) // Probar siguiente número impar
		}
	}

	if r.ExplainMode {
		steps = append(steps, RSAExplanationStep{
			Step:        5,
			Description: "Selección del exponente público",
			Operation:   fmt.Sprintf("e = %s (gcd(e, φ(n)) = 1)", e.String()),
			Details:     "65537 es comúnmente usado por ser primo y permitir exponenciación rápida",
		})
	}

	// Paso 5: Calcular d (exponente privado)
	// d = e^-1 mod φ(n)
	d := new(big.Int).ModInverse(e, phi)
	if d == nil {
		return nil, nil, fmt.Errorf("unable to compute private exponent")
	}

	if r.ExplainMode {
		steps = append(steps, RSAExplanationStep{
			Step:        6,
			Description: "Cálculo del exponente privado",
			Operation:   "d = e⁻¹ mod φ(n)",
			Details:     "d es el inverso modular de e, usado para descifrar",
		})
	}

	// Crear las claves
	publicKey := &RSAPublicKey{E: e, N: n}
	privateKey := &RSAPrivateKey{D: d, N: n, P: p, Q: q}

	keyPair := &RSAKeyPair{
		PublicKey:  publicKey,
		PrivateKey: privateKey,
		N:          n,
		BitSize:    bitSize,
	}

	if r.ExplainMode {
		steps = append(steps, RSAExplanationStep{
			Step:        7,
			Description: "Claves generadas",
			Operation:   "Clave pública: (e, n), Clave privada: (d, n)",
			Details:     "La clave pública puede compartirse, la privada debe mantenerse secreta",
		})
	}

	return keyPair, steps, nil
}

// Encrypt cifra un mensaje usando la clave pública
func (r *RSA) Encrypt(message []byte, publicKey *RSAPublicKey) ([]byte, []RSAExplanationStep, error) {
	var steps []RSAExplanationStep

	// Convertir mensaje a big.Int
	m := new(big.Int).SetBytes(message)

	// Verificar que el mensaje sea menor que n
	if m.Cmp(publicKey.N) >= 0 {
		return nil, nil, fmt.Errorf("message too large for key size")
	}

	if r.ExplainMode {
		steps = append(steps, RSAExplanationStep{
			Step:        1,
			Description: "Preparación del mensaje",
			Operation:   "Convertir mensaje a número entero",
			Details:     "El mensaje debe ser menor que el módulo n",
		})
	}

	// Cifrar: c = m^e mod n
	c := new(big.Int).Exp(m, publicKey.E, publicKey.N)

	if r.ExplainMode {
		steps = append(steps, RSAExplanationStep{
			Step:        2,
			Description: "Cifrado RSA",
			Operation:   "c = m^e mod n",
			Details:     "Exponenciación modular usando la clave pública",
		})
	}

	return c.Bytes(), steps, nil
}

// Decrypt descifra un mensaje usando la clave privada
func (r *RSA) Decrypt(ciphertext []byte, privateKey *RSAPrivateKey) ([]byte, []RSAExplanationStep, error) {
	var steps []RSAExplanationStep

	// Convertir ciphertext a big.Int
	c := new(big.Int).SetBytes(ciphertext)

	if r.ExplainMode {
		steps = append(steps, RSAExplanationStep{
			Step:        1,
			Description: "Preparación del texto cifrado",
			Operation:   "Convertir texto cifrado a número entero",
			Details:     "El texto cifrado se representa como un número grande",
		})
	}

	// Descifrar: m = c^d mod n
	m := new(big.Int).Exp(c, privateKey.D, privateKey.N)

	if r.ExplainMode {
		steps = append(steps, RSAExplanationStep{
			Step:        2,
			Description: "Descifrado RSA",
			Operation:   "m = c^d mod n",
			Details:     "Exponenciación modular usando la clave privada",
		})
	}

	return m.Bytes(), steps, nil
}

// Sign firma un mensaje usando la clave privada
func (r *RSA) Sign(message []byte, privateKey *RSAPrivateKey) ([]byte, string, []RSAExplanationStep, error) {
	var steps []RSAExplanationStep

	// Calcular hash del mensaje
	hash := sha256.Sum256(message)
	hashHex := fmt.Sprintf("%x", hash)

	if r.ExplainMode {
		steps = append(steps, RSAExplanationStep{
			Step:        1,
			Description: "Hash del mensaje",
			Operation:   "SHA-256(mensaje)",
			Details:     "Se firma el hash, no el mensaje completo por eficiencia",
		})
	}

	// Convertir hash a big.Int
	hashInt := new(big.Int).SetBytes(hash[:])

	// Verificar que el hash sea menor que n
	if hashInt.Cmp(privateKey.N) >= 0 {
		return nil, "", nil, fmt.Errorf("hash too large for key size")
	}

	// Firmar: s = hash^d mod n
	signature := new(big.Int).Exp(hashInt, privateKey.D, privateKey.N)

	if r.ExplainMode {
		steps = append(steps, RSAExplanationStep{
			Step:        2,
			Description: "Generación de firma",
			Operation:   "s = hash^d mod n",
			Details:     "Se usa la clave privada para crear la firma",
		})
	}

	return signature.Bytes(), hashHex, steps, nil
}

// Verify verifica una firma usando la clave pública
func (r *RSA) Verify(message []byte, signature []byte, publicKey *RSAPublicKey) (bool, []RSAExplanationStep, error) {
	var steps []RSAExplanationStep

	// Calcular hash del mensaje
	hash := sha256.Sum256(message)
	hashInt := new(big.Int).SetBytes(hash[:])

	if r.ExplainMode {
		steps = append(steps, RSAExplanationStep{
			Step:        1,
			Description: "Hash del mensaje recibido",
			Operation:   "SHA-256(mensaje)",
			Details:     "Se calcula el hash del mensaje para comparar",
		})
	}

	// Convertir firma a big.Int
	s := new(big.Int).SetBytes(signature)

	// Verificar: hash_verificado = s^e mod n
	verifiedHash := new(big.Int).Exp(s, publicKey.E, publicKey.N)

	if r.ExplainMode {
		steps = append(steps, RSAExplanationStep{
			Step:        2,
			Description: "Verificación de firma",
			Operation:   "hash_verificado = s^e mod n",
			Details:     "Se usa la clave pública para recuperar el hash firmado",
		})
	}

	// Comparar hashes
	isValid := hashInt.Cmp(verifiedHash) == 0

	if r.ExplainMode {
		steps = append(steps, RSAExplanationStep{
			Step:        3,
			Description: "Comparación de hashes",
			Operation:   "hash_calculado == hash_verificado",
			Details:     fmt.Sprintf("Firma %s", map[bool]string{true: "VÁLIDA", false: "INVÁLIDA"}[isValid]),
		})
	}

	return isValid, steps, nil
}

// generatePrime genera un número primo de la longitud especificada
func (r *RSA) generatePrime(bits int) (*big.Int, error) {
	for {
		// Generar número aleatorio de la longitud especificada
		candidate, err := rand.Prime(rand.Reader, bits)
		if err != nil {
			return nil, err
		}

		// Verificar que tenga la longitud correcta
		if candidate.BitLen() == bits {
			return candidate, nil
		}
	}
}

// FormatKeyPair formatea las claves para mostrar
func (keyPair *RSAKeyPair) FormatPublicKey() string {
	return fmt.Sprintf("e=%s, n=%s", keyPair.PublicKey.E.String(), keyPair.PublicKey.N.String())
}

func (keyPair *RSAKeyPair) FormatPrivateKey() string {
	return "****PRIVATE KEY - DO NOT SHARE****"
}

func (keyPair *RSAKeyPair) FormatModulus() string {
	return keyPair.N.String()
}

// GetKeySize retorna el tamaño de la clave en bits
func (keyPair *RSAKeyPair) GetKeySize() int {
	return keyPair.BitSize
}
