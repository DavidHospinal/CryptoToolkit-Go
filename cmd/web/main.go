package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/DavidHospinal/CryptoToolkit-Go/internal/config"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatal("Failed to load config:", err)
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<html><head><title>CryptoToolkit-Go</title></head>")
		fmt.Fprint(w, "<body style='font-family: Arial; margin: 40px;'>")
		fmt.Fprint(w, "<h1>CryptoToolkit-Go Web Interface</h1>")
		fmt.Fprint(w, "<p>Educational Blockchain Cryptography Platform</p>")
		fmt.Fprint(w, "<p>Coming soon: Interactive cryptography demos</p>")
		fmt.Fprint(w, "<ul>")
		fmt.Fprint(w, "<li>One-Time Pad encryption</li>")
		fmt.Fprint(w, "<li>SHA-256 hash functions</li>")
		fmt.Fprint(w, "<li>RSA cryptography</li>")
		fmt.Fprint(w, "<li>Merkle Trees</li>")
		fmt.Fprint(w, "<li>Proof of Work mining</li>")
		fmt.Fprint(w, "</ul></body></html>")
	})

	addr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port+1)
	fmt.Printf("Starting Web server on %s\n", addr)

	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatal("Failed to start web server:", err)
	}
}
