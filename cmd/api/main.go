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

func setupRoutes(r *gin.Engine) {
	api := r.Group("/api/v1")

	api.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":  "healthy",
			"message": "CryptoToolkit-Go API is running",
		})
	})

	otp := api.Group("/otp")
	{
		otp.POST("/encrypt", handleOTPEncrypt)
		otp.POST("/demo-break", handleOTPDemoBreak)
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
