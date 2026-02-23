#!/bin/bash
set -e

# Update PATH for cargo
if [ -d "$HOME/.cargo/bin" ]; then
    export PATH="$HOME/.cargo/bin:$PATH"
fi

# Ensure we are in the root of the repo (or adjust paths)
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
REPO_ROOT="$SCRIPT_DIR/.."

# Check for wasm-pack
if ! command -v wasm-pack &> /dev/null; then
    echo "wasm-pack not found. Attempting to install binary..."
    
    # Download binary
    curl -L https://github.com/rustwasm/wasm-pack/releases/download/v0.12.1/wasm-pack-v0.12.1-x86_64-unknown-linux-musl.tar.gz -o wasm-pack.tar.gz
    
    # Extract
    tar -xzf wasm-pack.tar.gz
    
    # Move to /usr/local/bin
    if [ -w /usr/local/bin ]; then
        mv wasm-pack-v0.12.1-x86_64-unknown-linux-musl/wasm-pack /usr/local/bin/
        chmod +x /usr/local/bin/wasm-pack
    else
        echo "Cannot write to /usr/local/bin. Installing locally to ~/.cargo/bin..."
        mkdir -p ~/.cargo/bin
        mv wasm-pack-v0.12.1-x86_64-unknown-linux-musl/wasm-pack ~/.cargo/bin/
        chmod +x ~/.cargo/bin/wasm-pack
        export PATH="$HOME/.cargo/bin:$PATH"
    fi
    
    # Cleanup
    rm -rf wasm-pack.tar.gz wasm-pack-v0.12.1-x86_64-unknown-linux-musl
    
    echo "wasm-pack installed successfully!"
fi

echo "Building WASM bindings for crypto core..."
cd "$REPO_ROOT/packages/crypto"

# Run wasm-pack
wasm-pack build --target web --out-dir ../sdk/src/wasm

echo "Done! WASM bindings built to packages/sdk/src/wasm"
