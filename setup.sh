#!/bin/bash

echo "🚀 Setting up Kaspa on ICP project..."

# Check if dfx is installed
if ! command -v dfx &> /dev/null; then
    echo "❌ DFX SDK not found. Please install it first:"
    echo "   https://internetcomputer.org/docs/current/developer-docs/setup/install"
    exit 1
fi

# Check if mops is installed
if ! command -v mops &> /dev/null; then
    echo "❌ mops not found. Please install it first:"
    echo "   npm install -g ic-mops"
    exit 1
fi

echo "✅ Prerequisites check passed"

# Install dependencies
echo "📦 Installing dependencies..."
mops install

# Start local replica
echo "🌐 Starting local ICP replica..."
dfx start --background

# Wait for replica to start
echo "⏳ Waiting for replica to start..."
sleep 10

# Deploy canisters
echo "🚀 Deploying canisters..."
dfx deploy

echo ""
echo "🎉 Setup complete! Your Kaspa on ICP project is ready."
echo ""
echo "🧪 Test the system:"
echo "   dfx canister call kaspa-on-icp-backend getAvailableICPKeys"
echo "   dfx canister call kaspa-on-icp-backend generateKaspaAddressFormatted '(\"test_key_1\")'"
echo "   dfx canister call kaspa-on-icp-backend demonstrateKaspaSigning"
echo ""
echo "📖 See README.md for more details and examples."
