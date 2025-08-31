import Array "mo:base/Array";
import Blob "mo:base/Blob";
import Nat8 "mo:base/Nat8";
import KaspaTransactionSigner "canister:kaspa-on-icp-backend";
import Test "mo:test";

actor {
  Test.describe("Kaspa Transaction Signer Tests", [
    Test.it("Test hashPublicKey", func() {
      let publicKey = {
        bytes = [
          2, 18, 52, 86, 120, 154, 188, 222, 240, 17, 34, 51, 68, 85, 102, 119,
          136, 153, 170, 187, 204, 221, 238, 255, 0, 17, 34, 51, 68, 85, 102, 119, 136
        ]
      };
      let expectedHash = [
        121, 15, 20, 9, 170, 240, 155, 6, 162, 77, 117, 65, 97, 113, 201, 141, 84, 140, 234, 133
      ];
      switch (KaspaTransactionSigner.hashPublicKey(publicKey)) {
        case (#ok(hash)) {
          Test.assertTrue(
            Array.equal(hash, expectedHash, Nat8.equal),
            "Public key hash does not match expected"
          )
        };
        case (#err(_)) {
          Test.assertTrue(false, "hashPublicKey failed")
        };
      }
    }),

    Test.it("Test createP2PKHAddress", func() {
      let pubKeyHash = [
        121, 15, 20, 9, 170, 240, 155, 6, 162, 77, 117, 65, 97, 113, 201, 141, 84, 140, 234, 133
      ];
      let networkPrefix = 97 : Nat8; // 0x61, testnet
      switch (KaspaTransactionSigner.createP2PKHAddress(pubKeyHash, networkPrefix)) {
        case (#ok(address)) {
          Test.assertTrue(
            address.version == networkPrefix,
            "Address version does not match"
          );
          Test.assertTrue(
            Array.equal(address.payload, pubKeyHash, Nat8.equal),
            "Address payload does not match"
          )
        };
        case (#err(_)) {
          Test.assertTrue(false, "createP2PKHAddress failed")
        };
      }
    }),

    Test.it("Test calculateSignatureHash", func() {
      let transaction = {
        gas = 0 : Nat64;
        version = 1 : Nat16;
        lockTime = 0 : Nat64;
        inputs = [{
          sigOpCount = 1 : Nat8;
          previousOutpoint = {
            index = 0 : Nat32;
            transactionId = [
              0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
              16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31
            ]
          };
          signatureScript = [];
          sequence = 18446744073709551615 : Nat64
        }];
        subnetworkId = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        outputs = [{
          value = 100000000 : Nat64;
          scriptPublicKey = {
            version = 0 : Nat16;
            script = [
              118, 169, 20, 121, 15, 20, 9, 170, 240, 155, 6, 162, 77,
              117, 65, 97, 113, 201, 141, 84, 140, 234, 133, 136, 172
            ]
          }
        }];
        payload = []
      };
      let inputIndex = 0 : Nat;
      let previousScript = [
        118, 169, 20, 121, 15, 20, 9, 170, 240, 155, 6, 162, 77,
        117, 65, 97, 113, 201, 141, 84, 140, 234, 133, 136, 172
      ];
      let sigHashType = #SIGHASH_ALL;
      // Expected hash from your successful dfx call (converted to vec)
      let expectedHash = [
        88, 83, 66, 249, 123, 91, 71, 180, 49, 34, 86, 206, 233, 99, 107, 217,
        158, 6, 119, 123, 29, 98, 17, 207, 148, 190, 95, 132, 116, 187, 151, 146
      ];
      switch (KaspaTransactionSigner.calculateSignatureHash(transaction, inputIndex, previousScript, sigHashType)) {
        case (#ok(hash)) {
          Test.assertTrue(
            Array.equal(hash, expectedHash, Nat8.equal),
            "Signature hash does not match expected"
          )
        };
        case (#err(_)) {
          Test.assertTrue(false, "calculateSignatureHash failed")
        };
      }
    })
  ])
}