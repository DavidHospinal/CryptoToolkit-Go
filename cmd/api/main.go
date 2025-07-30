package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/DavidHospinal/CryptoToolkit-Go/internal/config"
	"github.com/gin-gonic/gin"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatal("Failed to load config:", err)
	}

	r := gin.Default()

	r.GET("/", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message": "CryptoToolkit-Go API",
			"version": "1.0.0",
		})
	})

	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status": "healthy",
		})
	})

	addr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)
	fmt.Printf("Starting API server on %s\n", addr)

	if err := r.Run(addr); err != nil {
		log.Fatal("Failed to start server:", err)
	}
}
