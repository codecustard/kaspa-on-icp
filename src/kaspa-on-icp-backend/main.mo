// Kaspa Transaction Signing Example on ICP
// This project demonstrates basic Kaspa transaction signing functionality
// using BLAKE2b and RIPEMD160 packages from mops.one

import Blake2b "mo:blake2b";
import Ripemd160 "mo:ripemd160";
import Principal "mo:base/Principal";
import Result "mo:base/Result";
import Buffer "mo:base/Buffer";
import Array "mo:base/Array";
import Nat "mo:base/Nat";
import Nat8 "mo:base/Nat8";
import Nat16 "mo:base/Nat16";
import Nat32 "mo:base/Nat32";
import Nat64 "mo:base/Nat64";
import Text "mo:base/Text";
import Blob "mo:base/Blob";
import Debug "mo:base/Debug";
import Option "mo:base/Option";

persistent actor KaspaTransactionSigner {

    // Transaction Input structure
    public type TransactionInput = {
        previousOutpoint: Outpoint;
        signatureScript: [Nat8];
        sequence: Nat64;
        sigOpCount: Nat8;
    };

    // Transaction Output structure  
    public type TransactionOutput = {
        value: Nat64;
        scriptPublicKey: ScriptPublicKey;
    };

    // Outpoint structure (references previous transaction output)
    public type Outpoint = {
        transactionId: [Nat8]; // 32 bytes
        index: Nat32;
    };

    // Script Public Key structure
    public type ScriptPublicKey = {
        version: Nat16;
        script: [Nat8];
    };

    // Transaction structure (simplified Kaspa transaction)
    public type KaspaTransaction = {
        version: Nat16;
        inputs: [TransactionInput];
        outputs: [TransactionOutput];
        lockTime: Nat64;
        subnetworkId: [Nat8]; // 20 bytes
        gas: Nat64;
        payload: [Nat8];
    };

    // Signature Hash Type
    public type SigHashType = {
        #SIGHASH_ALL;
        #SIGHASH_NONE;
        #SIGHASH_SINGLE;
        #SIGHASH_ANYONECANPAY;
    };

    // Private key structure (simplified)
    public type PrivateKey = {
        bytes: [Nat8]; // 32 bytes
    };

    // Public key structure
    public type PublicKey = {
        bytes: [Nat8]; // 33 bytes (compressed) or 65 bytes (uncompressed)
    };

    // Address structure
    public type KaspaAddress = {
        version: Nat8;
        payload: [Nat8]; // 20 bytes for P2PKH
    };

    // Error types
    public type SigningError = {
        #InvalidPrivateKey;
        #InvalidTransaction;
        #HashingError;
        #SignatureError;
        #InvalidAddress;
    };

    // Create a Kaspa address from public key hash
    public query func createP2PKHAddress(publicKeyHash: [Nat8], networkPrefix: Nat8) : async Result.Result<KaspaAddress, SigningError> {
        if (publicKeyHash.size() != 20) {
            return #err(#InvalidAddress);
        };

        #ok({
            version = networkPrefix;
            payload = publicKeyHash;
        })
    };

    // Hash public key to create address payload
    public query func hashPublicKey(publicKey: PublicKey) : async Result.Result<[Nat8], SigningError> {
        try {
            // Convert [Nat8] to Blob for Blake2b
            let publicKeyBlob = Blob.fromArray(publicKey.bytes);
            
            // First, hash with BLAKE2b (256-bit output)
            // Blake2b.hash expects (data: Blob, config: ?Blake2bConfig)
            let blake2bHash = Blake2b.hash(publicKeyBlob, null);
            
            // Convert Blob to [Nat8] for RIPEMD160
            let blake2bArray = Blob.toArray(blake2bHash);
            
            // Then hash with RIPEMD160 (expects [Nat8], returns [Nat8])
            let ripemdHash = Ripemd160.RIPEMD160().hash(blake2bArray);
            
            #ok(ripemdHash)
        } catch (e) {
            #err(#HashingError)
        }
    };

    // Serialize transaction for signing (simplified)
    private func serializeTransactionForSigning(
        tx: KaspaTransaction, 
        inputIndex: Nat, 
        previousScript: [Nat8],
        sigHashType: SigHashType
    ) : Result.Result<[Nat8], SigningError> {
        
        let buffer = Buffer.Buffer<Nat8>(1024);
        
        // Add version (2 bytes, little endian)
        buffer.append(Buffer.fromArray(nat16ToBytes(tx.version)));
        
        // Add input count (varint, simplified to 1 byte for this example)
        buffer.add(Nat8.fromNat(tx.inputs.size()));
        
        // Serialize inputs
        for (i in tx.inputs.keys()) {
            let input = tx.inputs[i];
            
            // Previous outpoint (32 bytes + 4 bytes)
            buffer.append(Buffer.fromArray(input.previousOutpoint.transactionId));
            buffer.append(Buffer.fromArray(nat32ToBytes(input.previousOutpoint.index)));
            
            // Script handling for signing
            if (i == inputIndex) {
                // For the input being signed, use the previous output's script
                buffer.add(Nat8.fromNat(previousScript.size()));
                buffer.append(Buffer.fromArray(previousScript));
            } else {
                // For other inputs, use empty script
                buffer.add(0);
            };
            
            // Sequence (8 bytes)
            buffer.append(Buffer.fromArray(nat64ToBytes(input.sequence)));
        };
        
        // Add output count
        buffer.add(Nat8.fromNat(tx.outputs.size()));
        
        // Serialize outputs
        for (output in tx.outputs.vals()) {
            // Value (8 bytes)
            buffer.append(Buffer.fromArray(nat64ToBytes(output.value)));
            
            // Script public key
            buffer.append(Buffer.fromArray(nat16ToBytes(output.scriptPublicKey.version)));
            buffer.add(Nat8.fromNat(output.scriptPublicKey.script.size()));
            buffer.append(Buffer.fromArray(output.scriptPublicKey.script));
        };
        
        // Lock time (8 bytes)
        buffer.append(Buffer.fromArray(nat64ToBytes(tx.lockTime)));
        
        // Subnetwork ID (20 bytes)
        buffer.append(Buffer.fromArray(tx.subnetworkId));
        
        // Gas (8 bytes)  
        buffer.append(Buffer.fromArray(nat64ToBytes(tx.gas)));
        
        // Payload length and data
        buffer.append(Buffer.fromArray(nat64ToBytes(Nat64.fromNat(tx.payload.size()))));
        buffer.append(Buffer.fromArray(tx.payload));
        
        // SigHash type (4 bytes)
        let sigHashBytes : [Nat8] = switch (sigHashType) {
            case (#SIGHASH_ALL) { [1, 0, 0, 0] };
            case (#SIGHASH_NONE) { [2, 0, 0, 0] };
            case (#SIGHASH_SINGLE) { [3, 0, 0, 0] };
            case (#SIGHASH_ANYONECANPAY) { [0x80, 0, 0, 0] };
        };
        buffer.append(Buffer.fromArray(sigHashBytes));
        
        #ok(Buffer.toArray(buffer))
    };

    // Calculate signature hash for transaction input
    public func calculateSignatureHash(
        tx: KaspaTransaction,
        inputIndex: Nat,
        previousScript: [Nat8],
        sigHashType: SigHashType
    ) : async Result.Result<[Nat8], SigningError> {
        
        switch (serializeTransactionForSigning(tx, inputIndex, previousScript, sigHashType)) {
            case (#ok(serialized)) {
                try {
                    // Convert [Nat8] to Blob for Blake2b
                    let serializedBlob = Blob.fromArray(serialized);
                    
                    // Double BLAKE2b hash (similar to Bitcoin's double SHA256)
                    let firstHash = Blake2b.hash(serializedBlob, null);
                    let finalHash = Blake2b.hash(firstHash, null);
                    
                    // Convert back to [Nat8]
                    #ok(Blob.toArray(finalHash))
                } catch (e) {
                    #err(#HashingError)
                }
            };
            case (#err(e)) #err(e);
        }
    };

    // Sign a transaction input (simplified ECDSA simulation)
    // Note: In a real implementation, you'd use proper ECDSA signing
    public func signTransactionInput(
        tx: KaspaTransaction,
        inputIndex: Nat,
        privateKey: PrivateKey,
        previousScript: [Nat8],
        sigHashType: SigHashType
    ) : async Result.Result<[Nat8], SigningError> {
        
        // Calculate signature hash
        switch (await calculateSignatureHash(tx, inputIndex, previousScript, sigHashType)) {
            case (#ok(hash)) {
                // Simplified signature creation (in reality, use ECDSA)
                // This is just a placeholder that combines the hash with private key
                try {
                    let combinedData = Array.append(hash, privateKey.bytes);
                    let combinedBlob = Blob.fromArray(combinedData);
                    let signature = Blake2b.hash(combinedBlob, null);
                    
                    // Append sig hash type byte
                    let sigHashTypeByte = switch (sigHashType) {
                        case (#SIGHASH_ALL) 1;
                        case (#SIGHASH_NONE) 2;
                        case (#SIGHASH_SINGLE) 3;
                        case (#SIGHASH_ANYONECANPAY) 0x80;
                    };
                    
                    let signatureArray = Blob.toArray(signature);
                    let sigHashTypeByteArray : [Nat8] = [Nat8.fromNat(sigHashTypeByte)];
                    let finalSig : [Nat8] = Array.append(signatureArray, sigHashTypeByteArray);
                    #ok(finalSig)
                } catch (e) {
                    #err(#SignatureError)
                }
            };
            case (#err(e)) #err(e);
        }
    };

    // Create a simple P2PKH transaction
    public query func createP2PKHTransaction(
        inputs: [TransactionInput],
        outputs: [TransactionOutput],
        lockTime: Nat64
    ) : async Result.Result<KaspaTransaction, SigningError> {
        
        // Create default subnetwork ID (20 zero bytes)
        let defaultSubnetworkId = Array.tabulate<Nat8>(20, func(i) = 0);
        
        #ok({
            version = 1;
            inputs = inputs;
            outputs = outputs;
            lockTime = lockTime;
            subnetworkId = defaultSubnetworkId;
            gas = 0;
            payload = [];
        })
    };

    // Example function to demonstrate the workflow
    public func demonstrateKaspaSigning() : async Text {
        // Create a sample private key (32 bytes)
        let samplePrivateKey: PrivateKey = {
            bytes = [
                0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
                0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
                0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99
            ];
        };

        // Create sample public key (33 bytes compressed)
        let samplePublicKey: PublicKey = {
            bytes = [
                0x02, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
                0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
                0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22,
                0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa
            ];
        };

        // Hash the public key to create address
        let pubKeyHashResult = await hashPublicKey(samplePublicKey);
        switch (pubKeyHashResult) {
            case (#ok(pubKeyHash)) {
                // Create sample transaction input
                let sampleInput: TransactionInput = {
                    previousOutpoint = {
                        transactionId = Array.tabulate<Nat8>(32, func(i) = Nat8.fromNat(i));
                        index = 0;
                    };
                    signatureScript = [];
                    sequence = 0xFFFFFFFFFFFFFFFF;
                    sigOpCount = 1;
                };

                // Create sample transaction output
                let p2pkhPrefix : [Nat8] = [0x76, 0xa9, 0x14]; // OP_DUP OP_HASH160 PUSH(20)
                let p2pkhSuffix : [Nat8] = [0x88, 0xac]; // OP_EQUALVERIFY OP_CHECKSIG
                let p2pkhScript = Array.append(p2pkhPrefix, Array.append(pubKeyHash, p2pkhSuffix));
                
                let sampleOutput: TransactionOutput = {
                    value = 100000000; // 1 KAS in sompi
                    scriptPublicKey = {
                        version = 0;
                        script = p2pkhScript;
                    };
                };

                // Create transaction
                let txResult = await createP2PKHTransaction([sampleInput], [sampleOutput], 0);
                switch (txResult) {
                    case (#ok(tx)) {
                        // Sign the transaction
                        let previousScript = sampleOutput.scriptPublicKey.script;
                        let signatureResult = await signTransactionInput(tx, 0, samplePrivateKey, previousScript, #SIGHASH_ALL);
                        switch (signatureResult) {
                            case (#ok(signature)) {
                                "Successfully created and signed Kaspa transaction! Signature length: " # 
                                Nat.toText(signature.size()) # " bytes";
                            };
                            case (#err(e)) {
                                "Error signing transaction: " # debug_show(e);
                            };
                        };
                    };
                    case (#err(e)) {
                        "Error creating transaction: " # debug_show(e);
                    };
                };
            };
            case (#err(e)) {
                "Error hashing public key: " # debug_show(e);
            };
        };
    };

    // Utility functions for byte conversion
    private func nat16ToBytes(n: Nat16) : [Nat8] {
        [
            Nat8.fromNat(Nat16.toNat(n) % 256),
            Nat8.fromNat(Nat16.toNat(n) / 256)
        ]
    };

    private func nat32ToBytes(n: Nat32) : [Nat8] {
        let val = Nat32.toNat(n);
        [
            Nat8.fromNat(val % 256),
            Nat8.fromNat((val / 256) % 256),
            Nat8.fromNat((val / 65536) % 256),
            Nat8.fromNat((val / 16777216) % 256)
        ]
    };

    private func nat64ToBytes(n: Nat64) : [Nat8] {
        let val = Nat64.toNat(n);
        [
            Nat8.fromNat(val % 256),
            Nat8.fromNat((val / 256) % 256),
            Nat8.fromNat((val / 65536) % 256),
            Nat8.fromNat((val / 16777216) % 256),
            Nat8.fromNat((val / 4294967296) % 256),
            Nat8.fromNat((val / 1099511627776) % 256),
            Nat8.fromNat((val / 281474976710656) % 256),
            Nat8.fromNat((val / 72057594037927936) % 256)
        ]
    };

    // Get canister principal (useful for identifying the signer)
    public query func getCanisterPrincipal() : async Text {
        Principal.toText(Principal.fromActor(KaspaTransactionSigner))
    };
};