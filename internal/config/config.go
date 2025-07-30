package config

import (
	"fmt"
	"os"
	"strconv"
)

// Config holds all configuration for the application
type Config struct {
	Server   ServerConfig
	Database DatabaseConfig
	Crypto   CryptoConfig
	Logging  LoggingConfig
}

// ServerConfig holds server-specific configuration
type ServerConfig struct {
	Host string
	Port int
}

// DatabaseConfig holds database-specific configuration
type DatabaseConfig struct {
	Type string
	URL  string
}

// CryptoConfig holds cryptography-specific configuration
type CryptoConfig struct {
	DefaultKeySize int
	ExplainMode    bool
}

// LoggingConfig holds logging-specific configuration
type LoggingConfig struct {
	Level  string
	Format string
}

// Load loads configuration from environment variables with defaults
func Load() (*Config, error) {
	config := &Config{
		Server: ServerConfig{
			Host: getEnvString("SERVER_HOST", "localhost"),
			Port: getEnvInt("SERVER_PORT", 8080),
		},
		Database: DatabaseConfig{
			Type: getEnvString("DATABASE_TYPE", "memory"),
			URL:  getEnvString("DATABASE_URL", ""),
		},
		Crypto: CryptoConfig{
			DefaultKeySize: getEnvInt("CRYPTO_DEFAULT_KEY_SIZE", 2048),
			ExplainMode:    getEnvBool("CRYPTO_EXPLAIN_MODE", false),
		},
		Logging: LoggingConfig{
			Level:  getEnvString("LOG_LEVEL", "info"),
			Format: getEnvString("LOG_FORMAT", "json"),
		},
	}

	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return config, nil
}

// Validate validates the configuration
func (c *Config) Validate() error {
	if c.Server.Port < 1 || c.Server.Port > 65535 {
		return fmt.Errorf("invalid server port: %d", c.Server.Port)
	}

	if c.Crypto.DefaultKeySize < 1024 {
		return fmt.Errorf("crypto key size too small: %d", c.Crypto.DefaultKeySize)
	}

	return nil
}

// Helper functions for environment variables
func getEnvString(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}

func getEnvBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if boolValue, err := strconv.ParseBool(value); err == nil {
			return boolValue
		}
	}
	return defaultValue
}
