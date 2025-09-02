// Kaspa Transaction Signing Example on ICP
// This project demonstrates basic Kaspa transaction signing functionality
// using BLAKE2b and RIPEMD160 packages from mops.one
// and ICP ECDSA API for secure key management

import Blake2b "mo:blake2b";
import Ripemd160 "mo:ripemd160";
import BaseX "mo:base-x-encoder";
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
import Error "mo:base/Error";

// ICP ECDSA API types based on official documentation
// The ECDSA canister is available at: fg7gi-vyaaa-aaaal-qadca-cai (mainnet) or q3fc5-haaaa-aaaaa-qaaha-cai (testnet)

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

    // ICP ECDSA API types based on official documentation
    public type EcdsaCurve = {
        #secp256k1;
    };

    public type EcdsaKeyId = {
        curve: EcdsaCurve;
        name: Text;
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

    // ICP ECDSA Integration Functions
    
    // Generate a new ECDSA key using ICP chain
    public shared func generateICPKey(keyName: Text) : async Result.Result<Text, SigningError> {
        try {
            // This would typically call the ECDSA canister to generate a new key
            // For now, we'll return a success message indicating the key generation process
            // In a real implementation, you'd call the ECDSA canister's key generation methods
            
            #ok("ECDSA key generation initiated for key: " # keyName # 
                ". Use getICPPublicKey() to retrieve the public key once generated.")
        } catch (e) {
            #err(#SignatureError)
        }
    };

    // Get public key from ICP ECDSA canister
    public shared func getICPPublicKey(keyName: Text) : async Result.Result<PublicKey, SigningError> {
        try {
            // Create key ID for the specified key name
            let keyId: EcdsaKeyId = {
                curve = #secp256k1;
                name = keyName;
            };
            
            // Derivation path for this canister (using canister principal)
            let canisterPrincipal = Principal.fromActor(KaspaTransactionSigner);
            let derivationPath: [Blob] = [Principal.toBlob(canisterPrincipal)];
            
            // Call the local ICP ECDSA API through the management canister
            // The SDK automatically provides this API locally
            let ecdsaCanister = actor("aaaaa-aa") : actor {
                ecdsa_public_key : ({
                    canister_id : ?Principal;
                    derivation_path : [Blob];
                    key_id : EcdsaKeyId;
                }) -> async { public_key : Blob; chain_code : Blob };
            };
            
            let result = await ecdsaCanister.ecdsa_public_key({
                canister_id = ?canisterPrincipal;
                derivation_path = derivationPath;
                key_id = keyId;
            });
            
            // Convert the returned public key blob to our PublicKey format
            let publicKeyBytes = Blob.toArray(result.public_key);
            let publicKey: PublicKey = { bytes = publicKeyBytes };
            
            #ok(publicKey)
        } catch (e) {
            #err(#SignatureError)
        }
    };

    // Generate Kaspa address using ICP ECDSA public key
    public shared func generateKaspaAddressFromICP(keyName: Text) : async Result.Result<KaspaAddress, SigningError> {
        switch (await getICPPublicKey(keyName)) {
            case (#ok(publicKey)) {
                switch (await hashPublicKey(publicKey)) {
                    case (#ok(publicKeyHash)) {
                        // Use Kaspa mainnet prefix (0x76 = 118)
                        await createP2PKHAddress(publicKeyHash, 118)
                    };
                    case (#err(e)) #err(e);
                };
            };
            case (#err(e)) #err(e);
        }
    };

    // Sign transaction using ICP ECDSA
    public shared func signTransactionWithICP(
        tx: KaspaTransaction,
        inputIndex: Nat,
        keyName: Text,
        previousScript: [Nat8],
        sigHashType: SigHashType
    ) : async Result.Result<[Nat8], SigningError> {
        
        // Calculate signature hash
        switch (await calculateSignatureHash(tx, inputIndex, previousScript, sigHashType)) {
            case (#ok(hash)) {
                try {
                    // Create key ID for the specified key name
                    let keyId: EcdsaKeyId = {
                        curve = #secp256k1;
                        name = keyName;
                    };
                    
                    // Derivation path for this canister
                    let canisterPrincipal = Principal.fromActor(KaspaTransactionSigner);
                    let derivationPath: [Blob] = [Principal.toBlob(canisterPrincipal)];
                    
                    // Convert hash to Blob for ICP ECDSA API
                    let messageHash = Blob.fromArray(hash);
                    
                    // Call the local ICP ECDSA API through the management canister
                    // The SDK automatically provides this API locally
                    let ecdsaCanister = actor("aaaaa-aa") : actor {
                        sign_with_ecdsa : ({
                            message_hash : Blob;
                            derivation_path : [Blob];
                            key_id : EcdsaKeyId;
                        }) -> async { signature : Blob };
                    };
                    
                    let result = await ecdsaCanister.sign_with_ecdsa({
                        message_hash = messageHash;
                        derivation_path = derivationPath;
                        key_id = keyId;
                    });
                    
                    // Convert the returned signature blob to our format
                    let signatureArray = Blob.toArray(result.signature);
                    
                    // Append sig hash type byte
                    let sigHashTypeByte = switch (sigHashType) {
                        case (#SIGHASH_ALL) 1;
                        case (#SIGHASH_NONE) 2;
                        case (#SIGHASH_SINGLE) 3;
                        case (#SIGHASH_ANYONECANPAY) 0x80;
                    };
                    
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

    // Complete workflow: Generate ICP key and create Kaspa address
    public shared func generateICPKeyAndAddress(keyName: Text) : async Text {
        switch (await generateICPKey(keyName)) {
            case (#ok(_)) {
                switch (await generateKaspaAddressFromICP(keyName)) {
                    case (#ok(address)) {
                        "Successfully generated ICP ECDSA key '" # keyName # "' and Kaspa address with version: " # 
                        Nat8.toText(address.version) # ", payload length: " # Nat.toText(address.payload.size()) # " bytes";
                    };
                    case (#err(e)) {
                        "Generated ICP key but failed to create Kaspa address: " # debug_show(e);
                    };
                };
            };
            case (#err(e)) {
                "Failed to generate ICP ECDSA key: " # debug_show(e);
            };
        };
    };

    // Get available ICP ECDSA keys (based on documentation)
    public query func getAvailableICPKeys() : async Text {
        "Available ICP ECDSA keys:\n" #
        "- Test keys: (secp256k1, test_key_1) - for development/testing\n" #
        "- Production keys: (secp256k1, key_1) - for production use\n" #
        "Note: Test keys are on 13-node subnets, production keys on high-replication subnets.\n" #
        "Fees: Test key signing costs 10B cycles (~$0.013), Production key signing costs ~26B cycles (~$0.035)";
    };

    // Convert Kaspa address to readable format
    public query func formatKaspaAddress(address: KaspaAddress) : async Text {
        // Convert payload bytes to individual byte values for readability
        let payloadBytes = Array.foldLeft<Nat8, Text>(
            address.payload,
            "",
            func(acc: Text, byte: Nat8) : Text {
                acc # (if (acc == "") "" else " ") # Nat8.toText(byte)
            }
        );
        
        // Format: version:payload for readability
        "Kaspa Address:\n" #
        "Version: " # Nat8.toText(address.version) # " (0x" # Nat8.toText(address.version) # ")\n" #
        "Payload Bytes: [" # payloadBytes # "]\n" #
        "Total Length: " # Nat.toText(address.payload.size()) # " bytes";
    };

    // Generate and format Kaspa address from ICP key
    public shared func generateAndFormatKaspaAddress(keyName: Text) : async Text {
        switch (await generateKaspaAddressFromICP(keyName)) {

            
            case (#ok(address)) {
                let formattedAddress = await formatKaspaAddress(address);
                "✅ Successfully generated Kaspa address from ICP ECDSA key '" # keyName # "'\n\n" # formattedAddress
            };
            case (#err(e)) {
                "❌ Failed to generate Kaspa address: " # debug_show(e)
            };
        };
    };

    // Convert Kaspa address to proper kaspa: format using Base58 encoding
    public query func toKaspaAddressFormat(address: KaspaAddress) : async Text {
        try {
            // Create the data to encode: version + payload
            let dataToEncode = Array.append([address.version], address.payload);
            
            // Convert to Base58 using the BaseX package
            let base58Encoded = BaseX.toBase58(dataToEncode.vals());
            
            // Add kaspa: prefix
            "kaspa:" # base58Encoded
        } catch (e) {
            "Error encoding address"
        }
    };



    // Generate Kaspa address in proper format from ICP key
    public shared func generateKaspaAddressFormatted(keyName: Text) : async Text {
        switch (await generateKaspaAddressFromICP(keyName)) {
            case (#ok(address)) {
                let kaspaAddress = await toKaspaAddressFormat(address);
                "✅ Generated Kaspa address from ICP ECDSA key '" # keyName # "':\n" # kaspaAddress
            };
            case (#err(e)) {
                "❌ Failed to generate Kaspa address: " # debug_show(e)
            };
        };
    };
};