# 🔐 CryptoToolkit-Go

> **Educational Blockchain Cryptography Platform**
> 
![Animation-AL002](https://github.com/user-attachments/assets/5c196649-bb59-4fac-9daf-1b320e47b817)


An interactive learning platform that implements blockchain cryptography fundamentals from scratch in Go. Perfect for understanding the mathematical and cryptographic foundations behind Bitcoin, Ethereum, and other blockchain technologies.

## 🎯 What You'll Learn

- **One-Time Pad (OTP)**: Perfect secrecy and why key reuse breaks security
- **AES Encryption**: Modern symmetric cryptography
- **RSA Cryptography**: Public key cryptography from mathematical foundations
- **SHA-256**: Cryptographic hash functions step-by-step
- **Merkle Trees**: Efficient verification structures
- **Proof of Work**: Mining algorithms and difficulty adjustment

## 🚀 Quick Start

```bash
# Clone and setup
git clone https://github.com/your-username/cryptotoolkit-go
cd cryptotoolkit-go
make setup

# Build the project
make build

# Try some demos
make demo-otp
make demo-hash
make demo-break
```

## 📚 Educational Features

### Interactive CLI
```bash
# Encrypt with OTP and see every step
./bin/cryptotoolkit otp encrypt "secret message" --explain

# Hash with detailed algorithm visualization  
./bin/cryptotoolkit hash sha256 "input" --explain

# Demonstrate security vulnerabilities
./bin/cryptotoolkit otp demo-break "message1" "message2"
```

## 🏗️ Architecture

```
cryptotoolkit-go/
├── pkg/crypto/
│   ├── symmetric/      # OTP, AES implementations
│   ├── asymmetric/     # RSA from scratch
│   ├── hash/          # SHA-256, Merkle trees
│   └── pow/           # Proof of Work
├── cmd/
│   ├── cli/           # Interactive CLI
│   ├── api/           # REST API server
│   └── web/           # Web interface
└── docs/              # Tutorials & examples
```

## 🧪 Testing

```bash
# Run all tests with coverage
make test-coverage

# Run benchmarks
make benchmark

# Run linter
make lint
```

## 🐳 Docker

```bash
# Build and run
make docker-build
make docker-run
```

## 📖 Learning Path

1. **Start Here**: One-Time Pad basics
2. **Hash Functions**: SHA-256 step-by-step
3. **Public Key Crypto**: RSA mathematics
4. **Merkle Trees**: Blockchain verification
5. **Proof of Work**: Mining simulation
6. **Build Your Own**: Simple blockchain

## 🤝 Contributing

We welcome contributions! Please read our contributing guidelines and code of conduct.

## 📄 License

MIT License - see [LICENSE](LICENSE) for details.

## 🌟 Getting Started

1. Install Go 1.21+
2. Clone this repository
3. Run `make setup` to install dependencies
4. Run `make quickstart` for a full demo
5. Explore the code and learn!

---

**Built with ❤️ for blockchain education**
<img width="699" height="416" alt="hospinal-systems-logo" src="https://github.com/user-attachments/assets/017a1517-94a2-40ab-a196-6ac36007e5e2" />

