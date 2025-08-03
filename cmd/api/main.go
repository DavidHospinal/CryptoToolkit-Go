package main

import (
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"strings"
	"time"

	"github.com/DavidHospinal/CryptoToolkit-Go/internal/config"
	"github.com/DavidHospinal/CryptoToolkit-Go/pkg/crypto/hash"
	"github.com/DavidHospinal/CryptoToolkit-Go/pkg/crypto/symmetric"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

type OTPRequest struct {
	Message string `json:"message"`
	KeySize int    `json:"keySize,omitempty"`
	Explain bool   `json:"explain,omitempty"`
}

type OTPResponse struct {
	Success    bool   `json:"success"`
	Message    string `json:"message"`
	Key        string `json:"key"`
	Ciphertext string `json:"ciphertext"`
	Plaintext  string `json:"plaintext"`
	Steps      []Step `json:"steps,omitempty"`
}

type Step struct {
	StepNumber  int    `json:"step"`
	Description string `json:"description"`
	Operation   string `json:"operation"`
}

type HashRequest struct {
	Input   string `json:"input"`
	Explain bool   `json:"explain,omitempty"`
}

type HashResponse struct {
	Success bool   `json:"success"`
	Input   string `json:"input"`
	Hash    string `json:"hash"`
	Steps   []Step `json:"steps,omitempty"`
}

type KeyReuseRequest struct {
	Message1 string `json:"message1"`
	Message2 string `json:"message2"`
}

type KeyReuseResponse struct {
	Success   bool   `json:"success"`
	Message1  string `json:"message1"`
	Message2  string `json:"message2"`
	Cipher1   string `json:"cipher1"`
	Cipher2   string `json:"cipher2"`
	XORResult string `json:"xorResult"`
	Revealed  string `json:"revealed"`
}

type AESRequest struct {
	Message string `json:"message"`
	Key     string `json:"key"`
	Mode    string `json:"mode"`
	Explain bool   `json:"explain,omitempty"`
}

type AESResponse struct {
	Success    bool   `json:"success"`
	Message    string `json:"message"`
	Key        string `json:"key"`
	Mode       string `json:"mode"`
	Ciphertext string `json:"ciphertext"`
	IV         string `json:"iv,omitempty"`
	Steps      []Step `json:"steps,omitempty"`
}

// Tipos RSA
type RSAKeyGenRequest struct {
	KeySize int  `json:"keySize"`
	Explain bool `json:"explain,omitempty"`
}

type RSAKeyGenResponse struct {
	Success    bool   `json:"success"`
	KeySize    int    `json:"keySize"`
	PublicKey  string `json:"publicKey"`
	PrivateKey string `json:"privateKey"`
	Modulus    string `json:"modulus"`
	Steps      []Step `json:"steps,omitempty"`
}

type RSASignRequest struct {
	Message string `json:"message"`
	Explain bool   `json:"explain,omitempty"`
}

type RSASignResponse struct {
	Success     bool   `json:"success"`
	Message     string `json:"message"`
	MessageHash string `json:"messageHash"`
	Signature   string `json:"signature"`
	Steps       []Step `json:"steps,omitempty"`
}

type RSAVerifyRequest struct {
	Message   string `json:"message"`
	Signature string `json:"signature"`
	Explain   bool   `json:"explain,omitempty"`
}

type RSAVerifyResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	Valid   bool   `json:"valid"`
	Steps   []Step `json:"steps,omitempty"`
}

// Tipo Merkle
type MerkleRequest struct {
	Data    []string `json:"data"`
	Explain bool     `json:"explain,omitempty"`
}

type MerkleResponse struct {
	Success           bool     `json:"success"`
	OriginalData      []string `json:"originalData"`
	MerkleRoot        string   `json:"merkleRoot"`
	LeavesCount       int      `json:"leavesCount"`
	TreeHeight        int      `json:"treeHeight"`
	TreeVisualization string   `json:"treeVisualization"`
	SampleProof       string   `json:"sampleProof,omitempty"`
	Steps             []Step   `json:"steps,omitempty"`
}

type MerkleVerifyRequest struct {
	Data  string   `json:"data"`
	Proof []string `json:"proof"`
}

type MerkleVerifyResponse struct {
	Success bool   `json:"success"`
	Data    string `json:"data"`
	Valid   bool   `json:"valid"`
}

// Tipo Pow
type PowMineRequest struct {
	BlockData    string `json:"blockData"`
	PreviousHash string `json:"previousHash"`
	Difficulty   int    `json:"difficulty"`
	Explain      bool   `json:"explain,omitempty"`
}

type PowMineResponse struct {
	Success          bool   `json:"success"`
	BlockData        string `json:"blockData"`
	PreviousHash     string `json:"previousHash"`
	Nonce            int    `json:"nonce"`
	BlockHash        string `json:"blockHash"`
	Difficulty       int    `json:"difficulty"`
	ExpectedAttempts int    `json:"expectedAttempts"`
	Steps            []Step `json:"steps,omitempty"`
}

type PowDifficultyRequest struct {
	TargetTime        int `json:"targetTime"`
	ActualTime        int `json:"actualTime"`
	CurrentDifficulty int `json:"currentDifficulty"`
}

type PowDifficultyResponse struct {
	Success           bool    `json:"success"`
	CurrentDifficulty int     `json:"currentDifficulty"`
	NewDifficulty     int     `json:"newDifficulty"`
	AdjustmentFactor  float64 `json:"adjustmentFactor"`
}

// EndPoints
func setupRoutes(r *gin.Engine) {
	api := r.Group("/api/v1")

	api.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":  "healthy",
			"message": "CryptoToolkit-Go API is running",
		})
	})
	//ENDPOINT OTP
	otp := api.Group("/otp")
	{
		otp.POST("/encrypt", handleOTPEncrypt)
		otp.POST("/demo-break", handleOTPDemoBreak)
	}

	//ENDPOINT AES
	aes := api.Group("/aes")
	{
		aes.POST("/encrypt", handleAESEncrypt)
	}

	//ENDPOINT RSA
	rsa := api.Group("/rsa")
	{
		rsa.POST("/keygen", handleRSAKeyGen)
		rsa.POST("/sign", handleRSASign)
		rsa.POST("/verify", handleRSAVerify)
	}
	//Endpoint Hash Functions
	hashGroup := api.Group("/hash")
	{
		hashGroup.POST("/sha256", handleSHA256)
		hashGroup.POST("/merkle", handleMerkleTree)
		hashGroup.POST("/merkle-verify", handleMerkleVerify)
	}

	//Endpoint Pow
	pow := api.Group("/pow")
	{
		pow.POST("/mine", handlePowMine)
		pow.POST("/difficulty", handlePowDifficulty)
	}

}

func handleOTPEncrypt(c *gin.Context) {
	var req OTPRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	otp := symmetric.NewOTP(req.Explain)

	keySize := req.KeySize
	if keySize == 0 {
		keySize = len(req.Message)
	}

	key, err := otp.GenerateRandomKey(keySize)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	ciphertext, steps, err := otp.Encrypt([]byte(req.Message))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	var apiSteps []Step
	for _, step := range steps {
		apiSteps = append(apiSteps, Step{
			StepNumber:  step.Step,
			Description: step.Description,
			Operation:   step.Operation,
		})
	}

	response := OTPResponse{
		Success:    true,
		Message:    req.Message,
		Key:        fmt.Sprintf("%x", key),
		Ciphertext: fmt.Sprintf("%x", ciphertext),
		Steps:      apiSteps,
	}

	c.JSON(http.StatusOK, response)
}

func handleOTPDemoBreak(c *gin.Context) {
	var req KeyReuseRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	otp := symmetric.NewOTP(false)

	maxLen := len(req.Message1)
	if len(req.Message2) > maxLen {
		maxLen = len(req.Message2)
	}

	_, err := otp.GenerateRandomKey(maxLen)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	cipher1, _, _ := otp.Encrypt([]byte(req.Message1))
	cipher2, _, _ := otp.Encrypt([]byte(req.Message2))

	xored := make([]byte, min(len(cipher1), len(cipher2)))
	for i := range xored {
		xored[i] = cipher1[i] ^ cipher2[i]
	}

	response := KeyReuseResponse{
		Success:   true,
		Message1:  req.Message1,
		Message2:  req.Message2,
		Cipher1:   fmt.Sprintf("%x", cipher1),
		Cipher2:   fmt.Sprintf("%x", cipher2),
		XORResult: fmt.Sprintf("%x", xored),
		Revealed:  string(xored),
	}

	c.JSON(http.StatusOK, response)
}

func handleSHA256(c *gin.Context) {
	var req HashRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	result := hash.SimpleHash(req.Input, req.Explain)

	var steps []Step
	if req.Explain {
		steps = []Step{
			{StepNumber: 1, Description: "Preprocesamiento", Operation: "Agregar bit '1' seguido de ceros hasta completar 448 bits mod 512."},
			{StepNumber: 2, Description: "Longitud del mensaje", Operation: "Agregar longitud original como entero de 64 bits."},
			{StepNumber: 3, Description: "Inicialización", Operation: "Establecer 8 valores hash iniciales (constantes fraccionarias)."},
			{StepNumber: 4, Description: "Procesamiento por bloques", Operation: "Procesar mensaje en bloques de 512 bits."},
			{StepNumber: 5, Description: "Expansión del mensaje", Operation: "Expandir cada bloque de 16 a 64 palabras de 32 bits."},
			{StepNumber: 6, Description: "Compresión principal", Operation: "80 rondas de operaciones lógicas con constantes K."},
			{StepNumber: 7, Description: "Resultado final", Operation: "Concatenar 8 valores hash finales en 256 bits."},
		}
	}

	response := HashResponse{
		Success: true,
		Input:   req.Input,
		Hash:    fmt.Sprintf("%x", result),
		Steps:   steps,
	}

	c.JSON(http.StatusOK, response)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func handleAESEncrypt(c *gin.Context) {
	var req AESRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Simulación de pasos de AES para demostración educativa
	var steps []Step
	if req.Explain {
		steps = []Step{
			{StepNumber: 1, Description: "Validación de clave", Operation: "Verificar longitud de clave de 256 bits"},
			{StepNumber: 2, Description: "Generación de IV", Operation: "Crear vector de inicialización aleatorio"},
			{StepNumber: 3, Description: "Expansión de clave", Operation: "Generar claves de ronda desde clave maestra"},
			{StepNumber: 4, Description: "Ronda inicial", Operation: "AddRoundKey - XOR con primera clave de ronda"},
			{StepNumber: 5, Description: "Rondas principales", Operation: "13 rondas de SubBytes, ShiftRows, MixColumns, AddRoundKey"},
			{StepNumber: 6, Description: "Ronda final", Operation: "SubBytes, ShiftRows, AddRoundKey (sin MixColumns)"},
			{StepNumber: 7, Description: "Resultado", Operation: "Texto cifrado en hexadecimal"},
		}
	}

	// Simulación básica de cifrado
	ciphertext := "f8e2a1b4c7d3e9f6a2b5c8d1e4f7a0b3c6d9e2f5a8b1c4d7e0f3a6b9c2d5e8f1"
	if req.Mode == "ECB" {
		ciphertext = "a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456"
	} else if req.Mode == "CTR" {
		ciphertext = "1a2b3c4d5e6f789a012b345c678d901e234f567a890b123c456d789e012f345a"
	}

	response := AESResponse{
		Success:    true,
		Message:    req.Message,
		Key:        "****masked****",
		Mode:       req.Mode,
		Ciphertext: ciphertext,
		IV:         "1234567890abcdef",
		Steps:      steps,
	}

	c.JSON(http.StatusOK, response)
}

// Simulación RSA
func handleRSAKeyGen(c *gin.Context) {
	var req RSAKeyGenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var steps []Step
	if req.Explain {
		steps = []Step{
			{StepNumber: 1, Description: "Selección de primos", Operation: "Generar dos números primos grandes p y q"},
			{StepNumber: 2, Description: "Cálculo del módulo", Operation: "n = p × q"},
			{StepNumber: 3, Description: "Función totiente", Operation: "φ(n) = (p-1) × (q-1)"},
			{StepNumber: 4, Description: "Selección de exponente público", Operation: "Elegir e tal que gcd(e, φ(n)) = 1"},
			{StepNumber: 5, Description: "Cálculo de exponente privado", Operation: "d = e⁻¹ mod φ(n)"},
			{StepNumber: 6, Description: "Generación de claves", Operation: "Clave pública: (e, n), Clave privada: (d, n)"},
		}
	}

	response := RSAKeyGenResponse{
		Success:    true,
		KeySize:    req.KeySize,
		PublicKey:  "65537, " + generateMockModulus(req.KeySize),
		PrivateKey: "****PRIVADA****",
		Modulus:    generateMockModulus(req.KeySize),
		Steps:      steps,
	}

	c.JSON(http.StatusOK, response)
}

func handleRSASign(c *gin.Context) {
	var req RSASignRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var steps []Step
	if req.Explain {
		steps = []Step{
			{StepNumber: 1, Description: "Hash del mensaje", Operation: "Calcular SHA-256 del mensaje"},
			{StepNumber: 2, Description: "Padding", Operation: "Aplicar esquema de padding PKCS#1"},
			{StepNumber: 3, Description: "Firma", Operation: "s = (hash^d) mod n usando clave privada"},
			{StepNumber: 4, Description: "Codificación", Operation: "Convertir firma a hexadecimal"},
		}
	}

	response := RSASignResponse{
		Success:     true,
		Message:     req.Message,
		MessageHash: "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3",
		Signature:   "2d2d2d2d2d424547494e205253412050524956415445204b45592d2d2d2d2d",
		Steps:       steps,
	}

	c.JSON(http.StatusOK, response)
}

func handleRSAVerify(c *gin.Context) {
	var req RSAVerifyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var steps []Step
	if req.Explain {
		steps = []Step{
			{StepNumber: 1, Description: "Hash del mensaje", Operation: "Calcular SHA-256 del mensaje recibido"},
			{StepNumber: 2, Description: "Descifrado de firma", Operation: "m = (s^e) mod n usando clave pública"},
			{StepNumber: 3, Description: "Comparación", Operation: "Comparar hash calculado con hash descifrado"},
			{StepNumber: 4, Description: "Resultado", Operation: "Determinar validez de la firma"},
		}
	}

	// Simulación: firma válida si no está vacía
	isValid := len(req.Signature) > 10

	response := RSAVerifyResponse{
		Success: true,
		Message: req.Message,
		Valid:   isValid,
		Steps:   steps,
	}

	c.JSON(http.StatusOK, response)
}

func generateMockModulus(keySize int) string {
	// Generar módulo simulado basado en el tamaño de clave
	switch keySize {
	case 1024:
		return "c7b5a2e4f8d3c9b1a6e2f5d8c4b7a3e6f9d2c5b8a1e4f7d0c3b6a9e2f5d8c1b4a7"
	case 2048:
		return "a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456789012345678901234567890abcdef1234567890abcdef12345678901234567890abcdef1234567890abcdef123456"
	case 4096:
		return "f1e2d3c4b5a69788f1e2d3c4b5a69788f1e2d3c4b5a69788f1e2d3c4b5a69788f1e2d3c4b5a69788f1e2d3c4b5a69788f1e2d3c4b5a69788f1e2d3c4b5a69788f1e2d3c4b5a69788f1e2d3c4b5a69788f1e2d3c4b5a69788f1e2d3c4b5a69788"
	default:
		return "a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456"
	}
}

// Simulación Hash
func handleMerkleTree(c *gin.Context) {
	var req MerkleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if len(req.Data) < 2 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Se necesitan al menos 2 elementos"})
		return
	}

	// Simular construcción de árbol de Merkle
	var steps []Step
	if req.Explain {
		steps = []Step{
			{StepNumber: 1, Description: "Hash de hojas", Operation: "Calcular SHA-256 de cada elemento de datos."},
			{StepNumber: 2, Description: "Emparejamiento", Operation: "Agrupar hashes en pares para el siguiente nivel."},
			{StepNumber: 3, Description: "Hash de nodos", Operation: "Calcular hash de cada par concatenado."},
			{StepNumber: 4, Description: "Repetir proceso", Operation: "Continuar hasta obtener un solo hash raíz."},
			{StepNumber: 5, Description: "Raíz de Merkle", Operation: "El hash final es la raíz del árbol."},
		}
	}

	// Calcular altura del árbol
	treeHeight := calculateTreeHeight(len(req.Data))

	// Generar visualización simple
	visualization := generateTreeVisualization(req.Data)

	response := MerkleResponse{
		Success:           true,
		OriginalData:      req.Data,
		MerkleRoot:        "a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456",
		LeavesCount:       len(req.Data),
		TreeHeight:        treeHeight,
		TreeVisualization: visualization,
		SampleProof:       "b2c3d4e5f6789012,c3d4e5f6789012ab",
		Steps:             steps,
	}

	c.JSON(http.StatusOK, response)
}

func handleMerkleVerify(c *gin.Context) {
	var req MerkleVerifyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Simulación simple: válido si proof no está vacío
	isValid := len(req.Proof) > 0 && req.Data != ""

	response := MerkleVerifyResponse{
		Success: true,
		Data:    req.Data,
		Valid:   isValid,
	}

	c.JSON(http.StatusOK, response)
}

func calculateTreeHeight(leaves int) int {
	if leaves <= 1 {
		return 0
	}
	height := 0
	for leaves > 1 {
		leaves = (leaves + 1) / 2
		height++
	}
	return height
}

func generateTreeVisualization(data []string) string {
	if len(data) == 0 {
		return "Árbol vacío"
	}

	visualization := "ÁRBOL DE MERKLE:\n\n"
	visualization += "                    [RAÍZ]\n"
	visualization += "                   /       \\\n"
	visualization += "              [NODO1]     [NODO2]\n"
	visualization += "             /      \\    /      \\\n"

	for i, item := range data {
		if i < 4 {
			visualization += fmt.Sprintf("        [%s]", item[:min(8, len(item))])
			if i < 3 {
				visualization += " "
			}
		}
	}

	visualization += "\n\nNota: Visualización simplificada para fines educativos."
	return visualization
}

// Simulación Pow
func handlePowMine(c *gin.Context) {
	var req PowMineRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var steps []Step
	if req.Explain {
		steps = []Step{
			{StepNumber: 1, Description: "Preparación", Operation: "Combinar datos del bloque, hash anterior y timestamp."},
			{StepNumber: 2, Description: "Inicialización", Operation: "Comenzar con nonce = 0."},
			{StepNumber: 3, Description: "Cálculo de hash", Operation: "Calcular SHA-256 de (datos + hash_anterior + nonce)."},
			{StepNumber: 4, Description: "Verificación", Operation: "Comprobar si el hash tiene suficientes ceros iniciales."},
			{StepNumber: 5, Description: "Iteración", Operation: "Si no es válido, incrementar nonce y repetir."},
			{StepNumber: 6, Description: "Éxito", Operation: "Nonce encontrado, bloque válido creado."},
		}
	}

	// Calcular intentos esperados basado en dificultad
	expectedAttempts := calculateExpectedAttempts(req.Difficulty)

	// Simular nonce encontrado
	nonce := expectedAttempts + (rand.Intn(1000) - 500)

	// Generar hash simulado con ceros requeridos
	blockHash := generateHashWithDifficulty(req.Difficulty)

	response := PowMineResponse{
		Success:          true,
		BlockData:        req.BlockData,
		PreviousHash:     req.PreviousHash,
		Nonce:            nonce,
		BlockHash:        blockHash,
		Difficulty:       req.Difficulty,
		ExpectedAttempts: expectedAttempts,
		Steps:            steps,
	}

	c.JSON(http.StatusOK, response)
}

func handlePowDifficulty(c *gin.Context) {
	var req PowDifficultyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Calcular factor de ajuste
	adjustmentFactor := float64(req.TargetTime) / float64(req.ActualTime)

	// Limitar ajustes extremos (Bitcoin usa factor máximo de 4)
	if adjustmentFactor > 4.0 {
		adjustmentFactor = 4.0
	} else if adjustmentFactor < 0.25 {
		adjustmentFactor = 0.25
	}

	// Calcular nueva dificultad
	newDifficulty := req.CurrentDifficulty
	if adjustmentFactor > 1.1 {
		newDifficulty = min(req.CurrentDifficulty+1, 10) // Máximo 10 ceros
	} else if adjustmentFactor < 0.9 {
		newDifficulty = max(req.CurrentDifficulty-1, 1) // Mínimo 1 cero
	}

	response := PowDifficultyResponse{
		Success:           true,
		CurrentDifficulty: req.CurrentDifficulty,
		NewDifficulty:     newDifficulty,
		AdjustmentFactor:  adjustmentFactor,
	}

	c.JSON(http.StatusOK, response)
}

func calculateExpectedAttempts(difficulty int) int {
	// 2^(4*difficulty) intentos aproximados
	attempts := 1
	for i := 0; i < difficulty*4; i++ {
		attempts *= 2
	}
	return attempts / 2 // Promedio
}

func generateHashWithDifficulty(difficulty int) string {
	hash := ""

	// Agregar ceros requeridos
	for i := 0; i < difficulty; i++ {
		hash += "0"
	}

	// Completar con caracteres hexadecimales aleatorios
	hexChars := "0123456789abcdef"
	for len(hash) < 64 {
		hash += string(hexChars[rand.Intn(len(hexChars))])
	}

	return hash
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func main() {

	// Inicializar generador de números aleatorios
	rand.Seed(time.Now().UnixNano())

	cfg, err := config.Load()
	if err != nil {
		log.Fatal("Failed to load config:", err)
	}

	r := gin.Default()

	// MIDDLEWARE
	r.Use(func(c *gin.Context) {
		if strings.HasPrefix(c.Request.URL.Path, "/static/") {
			c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
			c.Header("Pragma", "no-cache")
			c.Header("Expires", "0")
		}
		c.Next()
	})

	// Middleware CORS

	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"*"},
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"*"},
		AllowCredentials: true,
	}))

	r.Static("/static", "./pkg/web/static")
	r.LoadHTMLGlob("pkg/web/templates/*")

	r.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "index.html", gin.H{
			"title": "CryptoToolkit-Go",
		})
	})

	setupRoutes(r)

	addr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)
	fmt.Printf("Starting API server on %s\n", addr)
	fmt.Printf("Web interface: http://%s\n", addr)

	if err := r.Run(addr); err != nil {
		log.Fatal("Failed to start server:", err)
	}
}
