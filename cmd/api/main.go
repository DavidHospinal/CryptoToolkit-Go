package main

import (
	"fmt"
	"log"
	"net/http"
	"strings"

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

	hashGroup := api.Group("/hash")
	{
		hashGroup.POST("/sha256", handleSHA256)
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

	response := HashResponse{
		Success: true,
		Input:   req.Input,
		Hash:    fmt.Sprintf("%x", result),
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

func main() {
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
