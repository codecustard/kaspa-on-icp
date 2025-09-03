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
import Error "mo:base/Error";
import Cycles "mo:base/ExperimentalCycles";

persistent actor KaspaTransactionSigner {

    public type TransactionInput = {
        previousOutpoint: Outpoint;
        signatureScript: [Nat8];
        sequence: Nat64;
        sigOpCount: Nat8;
    };

    public type TransactionOutput = {
        value: Nat64;
        scriptPublicKey: ScriptPublicKey;
    };

    public type Outpoint = {
        transactionId: [Nat8]; // 32 bytes
        index: Nat32;
    };

    public type ScriptPublicKey = {
        version: Nat16;
        script: [Nat8];
    };

    public type KaspaTransaction = {
        version: Nat16;
        inputs: [TransactionInput];
        outputs: [TransactionOutput];
        lockTime: Nat64;
        subnetworkId: [Nat8]; // 20 bytes
        gas: Nat64;
        payload: [Nat8];
    };

    public type SigHashType = {
        #SIGHASH_ALL;
        #SIGHASH_NONE;
        #SIGHASH_SINGLE;
        #SIGHASH_ALL_ANYONECANPAY;
    };

    public type PublicKey = {
        bytes: [Nat8]; // 33 bytes (compressed)
    };

    public type KaspaAddress = {
        version: Nat8; // 8 for P2PKH-ECDSA mainnet
        payload: [Nat8]; // 20 bytes
    };

    public type SigningError = {
        #InvalidTransaction;
        #InvalidInput;
        #HashingError;
        #SignatureError;
        #InvalidAddress;
    };

    public type EcdsaKeyId = {
        curve: { #secp256k1 };
        name: Text;
    };

    private func natToVarint(n: Nat) : [Nat8] {
        if (n < 0xFD) { [Nat8.fromNat(n)] }
        else if (n <= 0xFFFF) {
            let n16 = Nat16.fromNat(n);
            [0xFD, Nat8.fromNat(Nat16.toNat(n16 % 256)), Nat8.fromNat(Nat16.toNat(n16 / 256))]
        } else if (n <= 0xFFFFFFFF) {
            let n32 = Nat32.fromNat(n);
            [
                0xFE,
                Nat8.fromNat(Nat32.toNat(n32 % 256)),
                Nat8.fromNat(Nat32.toNat((n32 / 256) % 256)),
                Nat8.fromNat(Nat32.toNat((n32 / 65536) % 256)),
                Nat8.fromNat(Nat32.toNat(n32 / 16777216))
            ]
        } else {
            let n64 = Nat64.fromNat(n);
            [
                0xFF,
                Nat8.fromNat(Nat64.toNat(n64 % 256)),
                Nat8.fromNat(Nat64.toNat((n64 / 256) % 256)),
                Nat8.fromNat(Nat64.toNat((n64 / 65536) % 256)),
                Nat8.fromNat(Nat64.toNat((n64 / 16777216) % 256)),
                Nat8.fromNat(Nat64.toNat((n64 / 4294967296) % 256)),
                Nat8.fromNat(Nat64.toNat((n64 / 1099511627776) % 256)),
                Nat8.fromNat(Nat64.toNat((n64 / 281474976710656) % 256)),
                Nat8.fromNat(Nat64.toNat(n64 / 72057594037927936))
            ]
        }
    };

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
            Nat8.fromNat(val / 16777216)
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
            Nat8.fromNat(val / 72057594037927936)
        ]
    };

    private func compressPublicKey(uncompressed: [Nat8]) : Result.Result<PublicKey, SigningError> {
        if (uncompressed.size() != 64) {
            return #err(#InvalidInput);
        };
        let x = Array.subArray(uncompressed, 0, 32);
        let yLastByte = uncompressed[63];
        let prefix = Nat8.fromNat(if (yLastByte % 2 == 0) { 0x02 } else { 0x03 });
        #ok({ bytes = Array.append([prefix], x) })
    };

    public query func hashPublicKey(publicKey: PublicKey) : async Result.Result<[Nat8], SigningError> {
        if (publicKey.bytes.size() != 33) {
            return #err(#InvalidInput);
        };
        let publicKeyBlob = Blob.fromArray(publicKey.bytes);
        let blake2bHash = Blake2b.hash(publicKeyBlob, ?{digest_length = 32; key = null; personal = null; salt = null});
        let blake2bArray = Blob.toArray(blake2bHash);
        let ripemdHash = Ripemd160.RIPEMD160().hash(blake2bArray);
        #ok(ripemdHash)
    };

    public query func createP2PKHAddress(publicKeyHash: [Nat8]) : async Result.Result<KaspaAddress, SigningError> {
        if (publicKeyHash.size() != 20) {
            return #err(#InvalidAddress);
        };
        #ok({
            version = 8; // P2PKH-ECDSA mainnet
            payload = publicKeyHash;
        })
    };

    private func base58CheckEncode(data: [Nat8]) : Result.Result<Text, SigningError> {
        let dataBlob = Blob.fromArray(data);
        let checksum = Array.subArray(Blob.toArray(Blake2b.hash(dataBlob, ?{digest_length = 32; key = null; personal = null; salt = null})), 0, 4);
        let fullData = Array.append(data, checksum);
        let base58Encoded = BaseX.toBase58(fullData.vals());
        #ok("kaspa:" # base58Encoded)
    };

    public query func toKaspaAddressFormat(address: KaspaAddress) : async Result.Result<Text, SigningError> {
        if (address.payload.size() != 20) {
            return #err(#InvalidAddress);
        };
        let dataToEncode = Array.append([address.version], address.payload);
        base58CheckEncode(dataToEncode)
    };

    private func serializeTransactionForSigning(
        tx: KaspaTransaction,
        inputIndex: Nat,
        previousScript: [Nat8],
        sigHashType: SigHashType
    ) : Result.Result<[Nat8], SigningError> {
        if (inputIndex >= tx.inputs.size()) {
            return #err(#InvalidInput);
        };
        let buffer = Buffer.Buffer<Nat8>(1024);

        buffer.append(Buffer.fromArray(nat16ToBytes(tx.version)));
        buffer.append(Buffer.fromArray(natToVarint(tx.inputs.size())));

        for (i in tx.inputs.keys()) {
            let input = tx.inputs[i];
            buffer.append(Buffer.fromArray(input.previousOutpoint.transactionId));
            buffer.append(Buffer.fromArray(nat32ToBytes(input.previousOutpoint.index)));
            if (i == inputIndex) {
                buffer.append(Buffer.fromArray(natToVarint(previousScript.size())));
                buffer.append(Buffer.fromArray(previousScript));
            } else {
                buffer.append(Buffer.fromArray([Nat8.fromNat(0)]));
            };
            buffer.append(Buffer.fromArray(nat64ToBytes(input.sequence)));
        };

        buffer.append(Buffer.fromArray(natToVarint(tx.outputs.size())));

        switch (sigHashType) {
            case (#SIGHASH_NONE) {};
            case (#SIGHASH_SINGLE) {
                if (inputIndex < tx.outputs.size()) {
                    buffer.append(Buffer.fromArray([Nat8.fromNat(1)]));
                    let output = tx.outputs[inputIndex];
                    buffer.append(Buffer.fromArray(nat64ToBytes(output.value)));
                    buffer.append(Buffer.fromArray(nat16ToBytes(output.scriptPublicKey.version)));
                    buffer.append(Buffer.fromArray(natToVarint(output.scriptPublicKey.script.size())));
                    buffer.append(Buffer.fromArray(output.scriptPublicKey.script));
                } else {
                    buffer.append(Buffer.fromArray([Nat8.fromNat(0)]));
                };
            };
            case (#SIGHASH_ALL or #SIGHASH_ALL_ANYONECANPAY) {
                buffer.append(Buffer.fromArray(natToVarint(tx.outputs.size())));
                for (output in tx.outputs.vals()) {
                    buffer.append(Buffer.fromArray(nat64ToBytes(output.value)));
                    buffer.append(Buffer.fromArray(nat16ToBytes(output.scriptPublicKey.version)));
                    buffer.append(Buffer.fromArray(natToVarint(output.scriptPublicKey.script.size())));
                    buffer.append(Buffer.fromArray(output.scriptPublicKey.script));
                };
            };
        };

        buffer.append(Buffer.fromArray(nat64ToBytes(tx.lockTime)));
        buffer.append(Buffer.fromArray(tx.subnetworkId));
        buffer.append(Buffer.fromArray(nat64ToBytes(tx.gas)));
        buffer.append(Buffer.fromArray(natToVarint(tx.payload.size())));
        buffer.append(Buffer.fromArray(tx.payload));

        let sigHashByte : Nat8 = switch (sigHashType) {
            case (#SIGHASH_ALL) 1;
            case (#SIGHASH_NONE) 2;
            case (#SIGHASH_SINGLE) 3;
            case (#SIGHASH_ALL_ANYONECANPAY) 129;
        };
        buffer.add(sigHashByte);

        #ok(Buffer.toArray(buffer))
    };

    public shared func calculateSignatureHash(
        tx: KaspaTransaction,
        inputIndex: Nat,
        previousScript: [Nat8],
        sigHashType: SigHashType
    ) : async Result.Result<[Nat8], SigningError> {
        switch (serializeTransactionForSigning(tx, inputIndex, previousScript, sigHashType)) {
            case (#ok(serialized)) {
                try {
                    let serializedBlob = Blob.fromArray(serialized);
                    Debug.print("Serialized data size: " # Nat.toText(serialized.size()) # " bytes");
                    let hash = Blake2b.hash(serializedBlob, ?{digest_length = 32; key = null; personal = null; salt = null});
                    let hashBytes = Blob.toArray(hash);
                    Debug.print("Hash size: " # Nat.toText(hashBytes.size()) # " bytes, content: " # debug_show(hashBytes));
                    if (hashBytes.size() != 32) {
                        Debug.print("Invalid hash size: " # Nat.toText(hashBytes.size()) # ", expected 32 bytes");
                        return #err(#HashingError);
                    };
                    #ok(hashBytes)
                } catch (e) {
                    Debug.print("Hashing error: " # Error.message(e));
                    #err(#HashingError)
                }
            };
            case (#err(e)) #err(e);
        }
    };

    private func encodeDER(r: [Nat8], s: [Nat8]) : [Nat8] {
        if (r.size() != 32 or s.size() != 32) {
            return [];
        };
        let rPrefix = if (r[0] >= 0x80) { [0x00 : Nat8] } else { [] : [Nat8] };
        let sPrefix = if (s[0] >= 0x80) { [0x00 : Nat8] } else { [] : [Nat8] };
        let rData = Array.append(rPrefix, r);
        let sData = Array.append(sPrefix, s);
        let totalLen = 4 + rData.size() + sData.size();
        
        let rHeader = [0x02 : Nat8, Nat8.fromNat(rData.size())];
        let sHeader = [0x02 : Nat8, Nat8.fromNat(sData.size())];
        let derHeader = [0x30 : Nat8, Nat8.fromNat(totalLen)];
        
        Array.append(
            Array.append(
                Array.append(derHeader, rHeader),
                rData
            ),
            Array.append(sHeader, sData)
        )
    };

    public shared func signTransactionWithICP(
    tx: KaspaTransaction,
    inputIndex: Nat,
    keyName: Text,
    previousScript: [Nat8],
    sigHashType: SigHashType
) : async Result.Result<[Nat8], SigningError> {
    switch (await calculateSignatureHash(tx, inputIndex, previousScript, sigHashType)) {
        case (#ok(hash)) {
            if (hash.size() != 32) {
                Debug.print("Invalid hash size: " # Nat.toText(hash.size()) # ", expected 32 bytes for ECDSA");
                return #err(#HashingError);
            };
            try {
                let keyId: EcdsaKeyId = { curve = #secp256k1; name = keyName };
                let derivationPath: [Blob] = [];
                let messageHash = Blob.fromArray(hash);
                Debug.print("Preparing sign_with_ecdsa call:");
                Debug.print("  Key ID: curve=secp256k1, name=" # keyName);
                Debug.print("  Message hash: " # debug_show(hash));
                Debug.print("  Derivation path: " # debug_show(derivationPath));
                
                let ecdsaCanister = actor("aaaaa-aa") : actor {
                    sign_with_ecdsa : ({
                        message_hash : Blob;
                        derivation_path : [Blob];
                        key_id : EcdsaKeyId;
                    }) -> async { signature : Blob };
                };
                Debug.print("Calling sign_with_ecdsa with args: " # debug_show({
                    message_hash = messageHash;
                    derivation_path = derivationPath;
                    key_id = keyId;
                }));
                // Attach required cycles for local replica
                let cyclesRequired: Nat = 26_153_846_153;
                Debug.print("Attaching cycles: " # Nat.toText(cyclesRequired));
                Cycles.add<system>(cyclesRequired);
                let result = await ecdsaCanister.sign_with_ecdsa({
                    message_hash = messageHash;
                    derivation_path = derivationPath;
                    key_id = keyId;
                });
                let rawSig = Blob.toArray(result.signature);
                Debug.print("Signature length: " # Nat.toText(rawSig.size()) # ", content: " # debug_show(rawSig));
                if (rawSig.size() != 64) {
                    Debug.print("Invalid signature size: expected 64 bytes, got " # Nat.toText(rawSig.size()));
                    return #err(#SignatureError);
                };
                let r = Array.subArray(rawSig, 0, 32);
                let s = Array.subArray(rawSig, 32, 32);
                let derSig = encodeDER(r, s);
                let sigHashByte : Nat8 = switch (sigHashType) {
                    case (#SIGHASH_ALL) 1;
                    case (#SIGHASH_NONE) 2;
                    case (#SIGHASH_SINGLE) 3;
                    case (#SIGHASH_ALL_ANYONECANPAY) 129;
                };
                #ok(Array.append(derSig, [sigHashByte]))
            } catch (e) {
                Debug.print("ECDSA signing error: " # Error.message(e));
                #err(#SignatureError)
            }
        };
        case (#err(e)) #err(e);
    }
};

    public query func createP2PKHTransaction(
        inputs: [TransactionInput],
        outputs: [TransactionOutput],
        lockTime: Nat64
    ) : async Result.Result<KaspaTransaction, SigningError> {
        if (inputs.size() == 0 or outputs.size() == 0) {
            return #err(#InvalidTransaction);
        };
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

    public shared func serializeSignedTransaction(tx: KaspaTransaction) : async Result.Result<[Nat8], SigningError> {
        let buffer = Buffer.Buffer<Nat8>(1024);
        buffer.append(Buffer.fromArray(nat16ToBytes(tx.version)));
        buffer.append(Buffer.fromArray(natToVarint(tx.inputs.size())));
        for (input in tx.inputs.vals()) {
            buffer.append(Buffer.fromArray(input.previousOutpoint.transactionId));
            buffer.append(Buffer.fromArray(nat32ToBytes(input.previousOutpoint.index)));
            buffer.append(Buffer.fromArray(natToVarint(input.signatureScript.size())));
            buffer.append(Buffer.fromArray(input.signatureScript));
            buffer.append(Buffer.fromArray(nat64ToBytes(input.sequence)));
            buffer.add(input.sigOpCount);
        };
        buffer.append(Buffer.fromArray(natToVarint(tx.outputs.size())));
        for (output in tx.outputs.vals()) {
            buffer.append(Buffer.fromArray(nat64ToBytes(output.value)));
            buffer.append(Buffer.fromArray(nat16ToBytes(output.scriptPublicKey.version)));
            buffer.append(Buffer.fromArray(natToVarint(output.scriptPublicKey.script.size())));
            buffer.append(Buffer.fromArray(output.scriptPublicKey.script));
        };
        buffer.append(Buffer.fromArray(nat64ToBytes(tx.lockTime)));
        buffer.append(Buffer.fromArray(tx.subnetworkId));
        buffer.append(Buffer.fromArray(nat64ToBytes(tx.gas)));
        buffer.append(Buffer.fromArray(natToVarint(tx.payload.size())));
        buffer.append(Buffer.fromArray(tx.payload));
        #ok(Buffer.toArray(buffer))
    };

    public shared func generateKaspaAddressFromICP(keyName: Text) : async Result.Result<KaspaAddress, SigningError> {
        try {
            let keyId: EcdsaKeyId = { curve = #secp256k1; name = keyName };
            let canisterPrincipal = Principal.fromActor(KaspaTransactionSigner);
            let derivationPath: [Blob] = [Principal.toBlob(canisterPrincipal)];
            let ecdsaCanister = actor("aaaaa-aa") : actor {
                ecdsa_public_key : ({
                    canister_id : ?Principal;
                    derivation_path : [Blob];
                    key_id : EcdsaKeyId;
                }) -> async { public_key : Blob; chain_code : Blob };
            };
            Debug.print("Calling ecdsa_public_key with key: " # keyName);
            let result = await ecdsaCanister.ecdsa_public_key({
                canister_id = ?canisterPrincipal;
                derivation_path = derivationPath;
                key_id = keyId;
            });
            let publicKeyBytes = Blob.toArray(result.public_key);
            
            if (publicKeyBytes.size() != 33) {
                Debug.print("Invalid public key size: expected 33 bytes, got " # Nat.toText(publicKeyBytes.size()));
                return #err(#InvalidInput);
            };
            
            let compressedPubKey: PublicKey = { bytes = publicKeyBytes };
            
            switch (await hashPublicKey(compressedPubKey)) {
                case (#ok(pubKeyHash)) {
                    await createP2PKHAddress(pubKeyHash)
                };
                case (#err(e)) #err(e);
            };
        } catch (e) {
            Debug.print("ECDSA public key error: " # Error.message(e));
            #err(#SignatureError)
        }
    };

    public shared func createAndSignP2PKHTransaction(
        inputs: [TransactionInput],
        outputs: [TransactionOutput],
        lockTime: Nat64,
        keyName: Text
    ) : async Result.Result<[Nat8], SigningError> {
        switch (await createP2PKHTransaction(inputs, outputs, lockTime)) {
            case (#ok(tx)) {
                try {
                    let keyId: EcdsaKeyId = { curve = #secp256k1; name = keyName };
                    let canisterPrincipal = Principal.fromActor(KaspaTransactionSigner);
                    let derivationPath: [Blob] = [Principal.toBlob(canisterPrincipal)];
                    let ecdsaCanister = actor("aaaaa-aa") : actor {
                        ecdsa_public_key : ({
                            canister_id : ?Principal;
                            derivation_path : [Blob];
                            key_id : EcdsaKeyId;
                        }) -> async { public_key : Blob; chain_code : Blob };
                    };
                    Debug.print("Calling ecdsa_public_key for signing with key: " # keyName);
                    let pubKeyResult = await ecdsaCanister.ecdsa_public_key({
                        canister_id = ?canisterPrincipal;
                        derivation_path = derivationPath;
                        key_id = keyId;
                    });
                    let publicKeyBytes = Blob.toArray(pubKeyResult.public_key);
                    
                    if (publicKeyBytes.size() != 33) {
                        Debug.print("Invalid public key size: expected 33 bytes, got " # Nat.toText(publicKeyBytes.size()));
                        return #err(#InvalidInput);
                    };
                    
                    let compressedPubKey: PublicKey = { bytes = publicKeyBytes };
                    
                    switch (await hashPublicKey(compressedPubKey)) {
                        case (#ok(pubKeyHash)) {
                            let p2pkhPrefix : [Nat8] = [0x76, 0xa9, 0x14];
                            let p2pkhSuffix : [Nat8] = [0x88, 0xac];
                            let previousScript = Array.append(p2pkhPrefix, Array.append(pubKeyHash, p2pkhSuffix));
                            
                            let signedInputs = Array.thaw<TransactionInput>(tx.inputs);
                            for (i in tx.inputs.keys()) {
                                switch (await signTransactionWithICP(tx, i, keyName, previousScript, #SIGHASH_ALL)) {
                                    case (#ok(signature)) {
                                        let signatureScript = Array.append(
                                            Array.append([Nat8.fromNat(signature.size())], signature),
                                            Array.append([Nat8.fromNat(compressedPubKey.bytes.size())], compressedPubKey.bytes)
                                        );
                                        signedInputs[i] := {
                                            previousOutpoint = tx.inputs[i].previousOutpoint;
                                            signatureScript = signatureScript;
                                            sequence = tx.inputs[i].sequence;
                                            sigOpCount = 1;
                                        };
                                    };
                                    case (#err(e)) {
                                        Debug.print("Signing input " # Nat.toText(i) # " failed: " # debug_show(e));
                                        return #err(e);
                                    };
                                };
                            };
                            let signedTx = { tx with inputs = Array.freeze(signedInputs) };
                            await serializeSignedTransaction(signedTx)
                        };
                        case (#err(e)) {
                            Debug.print("Hash public key error: " # debug_show(e));
                            #err(e);
                        };
                    };
                } catch (e) {
                    Debug.print("Public key retrieval error: " # Error.message(e));
                    #err(#SignatureError)
                }
            };
            case (#err(e)) #err(e);
        }
    };

    public shared func demonstrateKaspaSigning(keyName: Text) : async Text {
        try {
            switch (await generateKaspaAddressFromICP(keyName)) {
                case (#ok(address)) {
                    let sampleInput: TransactionInput = {
                        previousOutpoint = {
                            transactionId = Array.tabulate<Nat8>(32, func(i) = Nat8.fromNat(i));
                            index = 0;
                        };
                        signatureScript = [];
                        sequence = 0xFFFFFFFFFFFFFFFF;
                        sigOpCount = 1;
                    };

                    let p2pkhPrefix : [Nat8] = [0x76, 0xa9, 0x14];
                    let p2pkhSuffix : [Nat8] = [0x88, 0xac];
                    let p2pkhScript = Array.append(p2pkhPrefix, Array.append(address.payload, p2pkhSuffix));
                    
                    let sampleOutput: TransactionOutput = {
                        value = 100000000;
                        scriptPublicKey = {
                            version = 0;
                            script = p2pkhScript;
                        };
                    };

                    switch (await createAndSignP2PKHTransaction([sampleInput], [sampleOutput], 0, keyName)) {
                        case (#ok(signedTx)) {
                            let addressText = await formatKaspaAddress(address);
                            "✅ Successfully created and signed Kaspa transaction!\n" #
                            "📦 Signed Tx Length: " # Nat.toText(signedTx.size()) # " bytes\n" #
                            "🔑 " # addressText # "\n" #
                            "💰 Transaction Value: 1.0 KAS (100000000 sompi)\n" #
                            "🎯 Key Name: " # keyName
                        };
                        case (#err(e)) {
                            let addressText = await formatKaspaAddress(address);
                            "❌ Error signing transaction: " # debug_show(e) # "\n" #
                            "🏠 But address generation worked: " # addressText
                        };
                    };
                };
                case (#err(e)) {
                    "❌ Error generating address: " # debug_show(e)
                };
            };
        } catch (e) {
            "💥 Caught exception: " # Error.message(e)
        }
    };

    public shared func formatKaspaAddress(address: KaspaAddress) : async Text {
        switch (await toKaspaAddressFormat(address)) {
            case (#ok(encoded)) {
                "Kaspa Address:\n" #
                "Version: " # Nat8.toText(address.version) # "\n" #
                "Encoded: " # encoded
            };
            case (#err(_)) {
                "Error formatting address"
            };
        }
    };

    public shared func debugGenerateKaspaAddress(keyName: Text) : async Text {
        try {
            let keyId: EcdsaKeyId = { curve = #secp256k1; name = keyName };
            let canisterPrincipal = Principal.fromActor(KaspaTransactionSigner);
            let derivationPath: [Blob] = [Principal.toBlob(canisterPrincipal)];
            let ecdsaCanister = actor("aaaaa-aa") : actor {
                ecdsa_public_key : ({
                    canister_id : ?Principal;
                    derivation_path : [Blob];
                    key_id : EcdsaKeyId;
                }) -> async { public_key : Blob; chain_code : Blob };
            };
            Debug.print("Calling ecdsa_public_key with key: " # keyName);
            let result = await ecdsaCanister.ecdsa_public_key({
                canister_id = ?canisterPrincipal;
                derivation_path = derivationPath;
                key_id = keyId;
            });
            let publicKeyBytes = Blob.toArray(result.public_key);
            
            let step1 = "Step 1 - Got public key: " # Nat.toText(publicKeyBytes.size()) # " bytes\n";
            
            if (publicKeyBytes.size() != 33) {
                return step1 # "Error: Expected 33 bytes, got " # Nat.toText(publicKeyBytes.size());
            };
            
            let compressedPubKey: PublicKey = { bytes = publicKeyBytes };
            let step2 = step1 # "Step 2 - Created PublicKey structure\n";
            
            switch (await hashPublicKey(compressedPubKey)) {
                case (#ok(pubKeyHash)) {
                    let step3 = step2 # "Step 3 - Hashed public key, got " # Nat.toText(pubKeyHash.size()) # " bytes\n";
                    
                    switch (await createP2PKHAddress(pubKeyHash)) {
                        case (#ok(address)) {
                            step3 # "Step 4 - Successfully created address!\n" #
                            "Address version: " # Nat8.toText(address.version) # "\n" #
                            "Payload size: " # Nat.toText(address.payload.size())
                        };
                        case (#err(e)) {
                            step3 # "Step 4 - Error creating P2PKH address: " # debug_show(e)
                        };
                    };
                };
                case (#err(e)) {
                    step2 # "Step 3 - Error hashing public key: " # debug_show(e)
                };
            };
        } catch (e) {
            "Caught exception: " # Error.message(e)
        }
    };
}