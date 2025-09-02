#!/bin/bash

echo "🧪 Testing Kaspa on ICP system..."

# Test 1: Check available keys
echo "1️⃣ Testing ICP key availability..."
dfx canister call kaspa-on-icp-backend getAvailableICPKeys

echo ""
echo "2️⃣ Testing Kaspa address generation..."
dfx canister call kaspa-on-icp-backend generateKaspaAddressFormatted '("test_key_1")'

echo ""
echo "3️⃣ Testing transaction hashing..."
dfx canister call kaspa-on-icp-backend demonstrateKaspaSigning

echo ""
echo "✅ All tests completed! Check the output above for results."
echo ""
echo "💡 If you see errors, make sure:"
echo "   - dfx start --background is running"
echo "   - dfx deploy has been run"
echo "   - All dependencies are installed (mops install)"
