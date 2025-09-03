#!/bin/bash

# Debug commands to identify signature issues
CANISTER_ID="kaspa-on-icp-backend"

echo "🔍 Debugging Kaspa Transaction Signature Issues"
echo "=============================================="

# Deploy the updated code first
echo "📦 Deploying updated canister..."
dfx deploy
echo ""

# Test 1: Try the main demo again
echo "🧪 Test 1: Main Demo with Updated Code"
dfx canister call $CANISTER_ID demonstrateKaspaSigning '("dfx_test_key")'
echo ""

# Test 2: Test signature hash calculation separately
echo "🧪 Test 2: Test Signature Hash Calculation"
echo "First, let's get our address to create proper scripts..."

# Get the address payload for proper script creation
ADDRESS_RESULT=$(dfx canister call $CANISTER_ID generateKaspaAddressFromICP '("dfx_test_key")')
echo "Address result: $ADDRESS_RESULT"
echo ""

# Test 3: Try with a different key name
echo "🧪 Test 3: Try Different Key Name"
dfx canister call $CANISTER_ID demonstrateKaspaSigning '("test_key_1")'
echo ""

# Test 4: Test individual components
echo "🧪 Test 4: Test calculateSignatureHash directly"
# Create a simple transaction to test signature hash
dfx canister call $CANISTER_ID calculateSignatureHash '(
  record {
    version = 1:nat16;
    inputs = vec {
      record {
        previousOutpoint = record {
          transactionId = vec { 0:nat8; 1:nat8; 2:nat8; 3:nat8; 4:nat8; 5:nat8; 6:nat8; 7:nat8; 8:nat8; 9:nat8; 10:nat8; 11:nat8; 12:nat8; 13:nat8; 14:nat8; 15:nat8; 16:nat8; 17:nat8; 18:nat8; 19:nat8; 20:nat8; 21:nat8; 22:nat8; 23:nat8; 24:nat8; 25:nat8; 26:nat8; 27:nat8; 28:nat8; 29:nat8; 30:nat8; 31:nat8 };
          index = 0:nat32;
        };
        signatureScript = vec {};
        sequence = 18446744073709551615:nat64;
        sigOpCount = 1:nat8;
      }
    };
    outputs = vec {
      record {
        value = 100000000:nat64;
        scriptPublicKey = record {
          version = 0:nat16;
          script = vec { 118:nat8; 169:nat8; 20:nat8; 156:nat8; 189:nat8; 80:nat8; 8:nat8; 41:nat8; 178:nat8; 143:nat8; 148:nat8; 94:nat8; 143:nat8; 172:nat8; 202:nat8; 144:nat8; 15:nat8; 178:nat8; 32:nat8; 195:nat8; 237:nat8; 43:nat8; 149:nat8; 136:nat8; 172:nat8 };
        };
      }
    };
    lockTime = 0:nat64;
    subnetworkId = vec { 0:nat8; 0:nat8; 0:nat8; 0:nat8; 0:nat8; 0:nat8; 0:nat8; 0:nat8; 0:nat8; 0:nat8; 0:nat8; 0:nat8; 0:nat8; 0:nat8; 0:nat8; 0:nat8; 0:nat8; 0:nat8; 0:nat8; 0:nat8 };
    gas = 0:nat64;
    payload = vec {};
  },
  0:nat,
  vec { 118:nat8; 169:nat8; 20:nat8; 156:nat8; 189:nat8; 80:nat8; 8:nat8; 41:nat8; 178:nat8; 143:nat8; 148:nat8; 94:nat8; 143:nat8; 172:nat8; 202:nat8; 144:nat8; 15:nat8; 178:nat8; 32:nat8; 195:nat8; 237:nat8; 43:nat8; 149:nat8; 136:nat8; 172:nat8 },
  variant { SIGHASH_ALL }
)'
echo ""

# Test 5: Check if it's an ECDSA key issue
echo "🧪 Test 5: Check ECDSA Key Access"
echo "Testing if we can get public key directly..."
dfx canister call $CANISTER_ID debugGenerateKaspaAddress '("signature_test_key")'
echo ""

# Test 6: Simple signature test (if the issue is in ICP ECDSA API)
echo "🧪 Test 6: Minimal Signature Test"
echo "This will help identify if the issue is with ICP ECDSA or our implementation..."

# Try to call signTransactionWithICP directly with minimal data
echo "Testing signTransactionWithICP with minimal transaction..."
dfx canister call $CANISTER_ID signTransactionWithICP '(
  record {
    version = 1:nat16;
    inputs = vec {
      record {
        previousOutpoint = record {
          transactionId = vec { 1:nat8; 1:nat8; 1:nat8; 1:nat8; 1:nat8; 1:nat8; 1:nat8; 1:nat8; 1:nat8; 1:nat8; 1:nat8; 1:nat8; 1:nat8; 1:nat8; 1:nat8; 1:nat8; 1:nat8; 1:nat8; 1:nat8; 1:nat8; 1:nat8; 1:nat8; 1:nat8; 1:nat8; 1:nat8; 1:nat8; 1:nat8; 1:nat8; 1:nat8; 1:nat8; 1:nat8; 1:nat8 };
          index = 0:nat32;
        };
        signatureScript = vec {};
        sequence = 18446744073709551615:nat64;
        sigOpCount = 1:nat8;
      }
    };
    outputs = vec {
      record {
        value = 50000000:nat64;
        scriptPublicKey = record {
          version = 0:nat16;
          script = vec { 118:nat8; 169:nat8; 20:nat8; 1:nat8; 2:nat8; 3:nat8; 4:nat8; 5:nat8; 6:nat8; 7:nat8; 8:nat8; 9:nat8; 10:nat8; 11:nat8; 12:nat8; 13:nat8; 14:nat8; 15:nat8; 16:nat8; 17:nat8; 18:nat8; 19:nat8; 20:nat8; 136:nat8; 172:nat8 };
        };
      }
    };
    lockTime = 0:nat64;
    subnetworkId = vec { 0:nat8; 0:nat8; 0:nat8; 0:nat8; 0:nat8; 0:nat8; 0:nat8; 0:nat8; 0:nat8; 0:nat8; 0:nat8; 0:nat8; 0:nat8; 0:nat8; 0:nat8; 0:nat8; 0:nat8; 0:nat8; 0:nat8; 0:nat8 };
    gas = 0:nat64;
    payload = vec {};
  },
  0:nat,
  "minimal_test",
  vec { 118:nat8; 169:nat8; 20:nat8; 1:nat8; 2:nat8; 3:nat8; 4:nat8; 5:nat8; 6:nat8; 7:nat8; 8:nat8; 9:nat8; 10:nat8; 11:nat8; 12:nat8; 13:nat8; 14:nat8; 15:nat8; 16:nat8; 17:nat8; 18:nat8; 19:nat8; 20:nat8; 136:nat8; 172:nat8 },
  variant { SIGHASH_ALL }
)'
echo ""

echo "✅ Debug tests completed!"
echo ""
echo "💡 What to look for:"
echo "   - If calculateSignatureHash works → Issue is in ECDSA signing"
echo "   - If signTransactionWithICP fails → Issue is in ICP ECDSA integration"
echo "   - If demonstrateKaspaSigning works → Problem was in the previous script logic"