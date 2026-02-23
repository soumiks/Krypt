# Contributing to Krypt

Thank you for your interest in contributing to Krypt! This guide will help you get set up.

## Prerequisites

- **Rust** (stable, 1.75+): [rustup.rs](https://rustup.rs)
- **wasm-pack**: `cargo install wasm-pack`
- **Foundry** (for Solidity): [getfoundry.sh](https://getfoundry.sh)
- **Node.js** (18+) and **npm**

## Repository Structure

```
packages/
├── crypto/       # Rust/WASM cryptographic core
├── contracts/    # Solidity smart contracts (Foundry)
├── sdk/          # TypeScript vendor SDK
└── mobile/       # React Native app
```

## Getting Started

### Crypto Package (Rust)

```bash
cd packages/crypto
cargo test          # Run all tests
cargo check         # Type-check without building
cargo doc --open    # View documentation
```

### Smart Contracts (Solidity)

```bash
cd packages/contracts
forge build         # Compile contracts
forge test          # Run tests
forge test -vvv     # Verbose test output
```

### SDK (TypeScript)

```bash
cd packages/sdk
npm install
npm run build
npm test
```

## Development Workflow

1. Fork the repository
2. Create a feature branch: `git checkout -b feat/my-feature`
3. Make your changes with tests
4. Run the full test suite
5. Submit a pull request

## Code Style

- **Rust**: Follow `rustfmt` defaults. Run `cargo fmt` before committing.
- **Solidity**: Follow Solidity style guide. Use `forge fmt`.
- **TypeScript**: Use the project's ESLint/Prettier config.

## Commit Messages

We use [Conventional Commits](https://www.conventionalcommits.org/):

- `feat:` new feature
- `fix:` bug fix
- `docs:` documentation
- `test:` adding/updating tests
- `refactor:` code refactoring

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.
