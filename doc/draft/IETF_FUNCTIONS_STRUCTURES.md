# Composite ML-DSA Core Functions & Structures

## API Functions (Section 3, 4)

### 1. Key Generation
**Function**: `Composite-ML-DSA<OID>.KeyGen() -> (pk, sk)`
- Input: None (generates fresh random keys for both components)
- Output: Composite public key pk, Composite private key sk
- Process:
  1. Generate ML-DSA key: mldsaSeed = Random(32), (mldsaPK, mldsaSK) = ML-DSA.KeyGen_internal(mldsaSeed)
  2. Generate Traditional key: (tradPK, tradSK) = Trad.KeyGen()
  3. Serialize and return both
- **Critical**: Keys MUST NOT be reused between composite/standalone or between multiple composites

### 2. Sign
**Function**: `Composite-ML-DSA<OID>.Sign(sk, M, ctx) -> s`
- Input: sk (composite private key), M (message), ctx (context, default empty)
- Output: s (composite signature value)
- Process:
  1. Validate ctx length ≤ 255 bytes
  2. Construct message representative M' = Prefix || Label || len(ctx) || ctx || PH(M)
  3. Deserialize sk → (mldsaSeed, tradSK)
  4. Sign with both components:
     - mldsaSig = ML-DSA.Sign(mldsaSK, M', mldsa_ctx=Label)
     - tradSig = Trad.Sign(tradSK, M')
  5. Serialize and return combined signature

### 3. Verify
**Function**: `Composite-ML-DSA<OID>.Verify(pk, M, s, ctx) -> bool`
- Input: pk (composite public key), M (message), s (signature), ctx (context)
- Output: true if signature valid, false otherwise
- Process:
  1. Deserialize pk → (mldsaPK, tradPK)
  2. Deserialize s → (mldsaSig, tradSig)
  3. Construct M' = Prefix || Label || len(ctx) || ctx || PH(M)
  4. Verify both components (AND mode):
     - ML-DSA.Verify(mldsaPK, M', mldsaSig, Label) must pass
     - Trad.Verify(tradPK, M', tradSig) must pass
  5. Return true iff BOTH passed

## Serialization Functions (Section 4)

### 4. SerializePublicKey
**Function**: `Composite-ML-DSA.SerializePublicKey(mldsaPK, tradPK) -> bytes`
- Output: mldsaPK || tradPK (simple concatenation)
- ML-DSA key is fixed-size (1312/1952/2592 bytes)

### 5. DeserializePublicKey
**Function**: `Composite-ML-DSA<OID>.DeserializePublicKey(bytes) -> (mldsaPK, tradPK)`
- Input: Serialized composite public key
- Split based on ML-DSA variant:
  - ML-DSA-44: bytes[:1312] || bytes[1312:]
  - ML-DSA-65: bytes[:1952] || bytes[1952:]
  - ML-DSA-87: bytes[:2592] || bytes[2592:]

### 6. SerializePrivateKey
**Function**: `Composite-ML-DSA.SerializePrivateKey(mldsaSeed, tradSK) -> bytes`
- Output: mldsaSeed || tradSK (simple concatenation)
- ML-DSA seed is always 32 bytes

### 7. DeserializePrivateKey
**Function**: `Composite-ML-DSA.DeserializePrivateKey(bytes) -> (mldsaSeed, tradSK)`
- Output: bytes[:32] || bytes[32:] (ML-DSA seed is fixed 32 bytes)

### 8. SerializeSignatureValue
**Function**: `Composite-ML-DSA.SerializeSignatureValue(mldsaSig, tradSig) -> bytes`
- Output: mldsaSig || tradSig (simple concatenation)
- ML-DSA signature is fixed-size (2420/3309/4627 bytes)

### 9. DeserializeSignatureValue
**Function**: `Composite-ML-DSA<OID>.DeserializeSignatureValue(bytes) -> (mldsaSig, tradSig)`
- Input: Serialized composite signature
- Split based on ML-DSA variant:
  - ML-DSA-44: bytes[:2420] || bytes[2420:]
  - ML-DSA-65: bytes[:3309] || bytes[3309:]
  - ML-DSA-87: bytes[:4627] || bytes[4627:]

## Message Representative Construction (Section 2.2)

**Formula**: `M' := Prefix || Label || len(ctx) || ctx || PH(M)`

- **Prefix** (fixed): "CompositeAlgorithmSignatures2025" in hex: 
  `436F6D706F73697465416C676F726974686D5369676E61747572657332303235` (34 bytes)
- **Label**: Algorithm-specific (e.g., "COMPSIG-MLDSA65-ECDSA-P256-SHA512")
- **len(ctx)**: Single unsigned byte (0-255)
- **ctx**: Application context (0-255 bytes)
- **PH(M)**: Pre-hashed message using algorithm-specific hash function

## Pre-hashing Function (Section 2.1)

- Composite ML-DSA uses pre-hashing internally (mirrors ML-DSA Algorithm 4)
- Allows: message streaming optimization, digest caching, multiple signatures per hash
- Pre-hash function PH is algorithm-specific (SHA256/SHA512/SHAKE256)
- Externalizable in Section 10.5 for HSM scenarios

## Key Sizes (Fixed-Length Vectors)

| ML-DSA Variant | Public Key | Private Key (Seed) | Signature |
|---|---|---|---|
| ML-DSA-44 | 1312 bytes | 32 bytes | 2420 bytes |
| ML-DSA-65 | 1952 bytes | 32 bytes | 3309 bytes |
| ML-DSA-87 | 2592 bytes | 32 bytes | 4627 bytes |

### Composite Maximum Sizes (Appendix A)
- MLDSA44+RSA2048+SHA256: pk=1582*, sk=1226*, sig=2676 bytes
- MLDSA65+ECDSA-P256+SHA512: pk=2017, sk=83, sig=3381* bytes (RECOMMENDED)
- MLDSA87+ECDSA-P521+SHA512: pk=2725, sk=114, sig=4766* bytes
