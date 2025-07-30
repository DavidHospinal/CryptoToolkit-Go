# Contributing to CryptoToolkit-Go

Thank you for your interest in contributing to CryptoToolkit-Go! This document provides guidelines for contributing to the project.

## 🎯 Project Goals

CryptoToolkit-Go aims to be the best educational platform for learning blockchain cryptography fundamentals. All contributions should support this mission by:

- Making cryptographic concepts more accessible
- Providing clear, well-commented code
- Including comprehensive tests
- Maintaining educational value

## 🚀 Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/your-username/cryptotoolkit-go`
3. Install dependencies: `make setup`
4. Create a feature branch: `git checkout -b feature/your-feature-name`

## 📝 Development Guidelines

### Code Style
- Follow Go conventions and use `gofmt`
- Write clear, self-documenting code
- Include educational comments explaining cryptographic concepts
- Use meaningful variable names

### Testing
- Write tests for all new functionality
- Maintain test coverage above 80%
- Include benchmarks for performance-critical code
- Test edge cases and error conditions

### Educational Focus
- Prioritize code clarity over performance optimizations
- Include step-by-step explanations in educational modes
- Add visual demonstrations where possible
- Document the "why" behind cryptographic choices

## 🧪 Running Tests

```bash
# Run all tests
make test

# Run with coverage
make test-coverage

# Run benchmarks
make benchmark

# Run linter
make lint
```

## 📖 Documentation

- Update README.md for new features
- Add code comments explaining cryptographic concepts
- Include examples in the `examples/` directory
- Update API documentation for new endpoints

## 🎯 Types of Contributions

### High Priority
- Bug fixes
- Performance improvements
- Educational content improvements
- Test coverage improvements

### Medium Priority
- New cryptographic algorithm implementations
- CLI improvements
- API enhancements
- Documentation improvements

### Future Features
- Web interface enhancements
- Interactive visualizations
- Mobile app support
- Advanced cryptographic protocols

## 📋 Pull Request Process

1. Ensure your code passes all tests: `make test`
2. Update documentation as needed
3. Add educational examples if applicable
4. Write a clear PR description explaining the changes
5. Link to any relevant issues

## 🐛 Reporting Issues

When reporting issues, please include:
- Go version (`go version`)
- Operating system
- Steps to reproduce
- Expected vs actual behavior
- Relevant code snippets or logs

## 📞 Getting Help

- Open an issue for questions
- Check existing issues and PRs
- Review the documentation in `docs/`

## 🙏 Recognition

Contributors will be:
- Listed in the project README
- Mentioned in release notes
- Invited to join the core team for significant contributions

Thank you for helping make cryptography education more accessible! 🔐
