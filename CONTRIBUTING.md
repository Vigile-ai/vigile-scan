# Contributing to vigile-scan

Thanks for your interest in contributing to Vigile's open source security scanner.

## Getting Started

```bash
git clone https://github.com/Vigile-ai/vigile-scan.git
cd vigile-scan
npm install
npm run build
npm test
```

## Development

- **Language:** TypeScript
- **Build:** tsup
- **Tests:** Vitest (`npm test`)
- **Lint:** Run `npm run build` to catch type errors before submitting

## Submitting Changes

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/your-feature`)
3. Make your changes with tests
4. Ensure `npm test` passes
5. Submit a pull request against `main`

## Reporting Bugs

Use [GitHub Issues](https://github.com/Vigile-ai/vigile-scan/issues) for bug reports. Include:

- vigile-scan version (`vigile-scan --version`)
- Node.js version
- OS and shell
- Steps to reproduce
- Expected vs actual behavior

## Security Vulnerabilities

**Do not open public issues for security vulnerabilities.** See [SECURITY.md](SECURITY.md) for responsible disclosure instructions.

## Code of Conduct

Be respectful. We're building security tools to protect people — act accordingly.

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.
