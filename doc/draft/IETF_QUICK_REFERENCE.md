# Quick Reference & Search Index

## Key Acronyms & Terms

| Term | Definition | Context |
|------|-----------|---------|
| **EUF-CMA** | Existential Unforgeability under Chosen Message Attack | Security property (weaker) |
| **SUF-CMA** | Strong Unforgeability under Chosen Message Attack | Security property (stronger) - NOT supported |
| **PQ/T** | Post-Quantum/Traditional | Hybrid cryptography paradigm |
| **WNS** | Weak Non-Separability | Cannot remove component without evidence |
| **SNS** | Strong Non-Separability | Cannot extract component for arbitrary message |
| **FIPS** | Federal Information Processing Standards | US govt cryptography standards |
| **DRBG** | Deterministic Random Bit Generator | FIPS-approved random source |
| **DER** | Distinguished Encoding Rules | ASN.1 binary encoding format |
| **HSM** | Hardware Security Module | External signing device |
| **PKCS#8** | Public Key Cryptography Standard #8 | Private key format (OneAsymmetricKey) |
| **RFC** | Request For Comments | IETF standards documents |
| **OID** | Object Identifier | ASN.1 unique algorithm identifier |
| **IOC** | Information Object Class | ASN.1 compact definition pattern |

## File Reference Map

| File | Focus | Use Case |
|------|-------|----------|
| **IETF_DRAFT_STRUCTURE.md** | Document structure | Find where section is located |
| **IETF_18_ALGORITHMS.md** | Algorithm listing | Look up OIDs and recommendations |
| **IETF_FUNCTIONS_STRUCTURES.md** | API & serialization | Implement KeyGen/Sign/Verify |
| **IETF_SECURITY_OPERATIONAL.md** | Security properties | Understand EUF-CMA, SUF-CMA, key reuse |
| **IETF_X509_ASN1_DER.md** | X.509 integration | X.509 certificates and ASN.1 |
| **IETF_TESTVECTORS_APPENDICES.md** | Test data | Algorithm sizing, test vectors |
| **IETF_QUICK_REFERENCE.md** | Fast lookup | Quick answers |

## Fast Lookup by Question

### Algorithm Selection
- **"Which algorithm should I use?"** → IETF_18_ALGORITHMS.md (Profiling section)
  - Answer: `id-MLDSA65-ECDSA-P256-SHA512` (OID 45)
- **"What are all 18 algorithms?"** → IETF_18_ALGORITHMS.md (Complete list table)
- **"What's the OID for MLDSA65-ECDSA-P256?"** → IETF_18_ALGORITHMS.md (table row 9)

### Implementation
- **"How do I implement KeyGen?"** → IETF_FUNCTIONS_STRUCTURES.md (Function 1)
- **"How do I implement Sign()?"** → IETF_FUNCTIONS_STRUCTURES.md (Function 2)
- **"How do I implement Verify()?"** → IETF_FUNCTIONS_STRUCTURES.md (Function 3)
- **"How do I serialize/deserialize?"** → IETF_FUNCTIONS_STRUCTURES.md (Functions 4-9)
- **"What's the Message Representative M'?"** → IETF_FUNCTIONS_STRUCTURES.md (Message Representative section)
- **"What's the Prefix value?"** → IETF_FUNCTIONS_STRUCTURES.md → 34-byte hex

### Security
- **"Is Composite ML-DSA EUF-CMA secure?"** → IETF_SECURITY_OPERATIONAL.md (EUF-CMA section)
  - Answer: YES - if ≥1 component is EUF-CMA secure
- **"Is Composite ML-DSA SUF-CMA secure?"** → IETF_SECURITY_OPERATIONAL.md (SUF-CMA section)
  - Answer: NO - NOT SUF-CMA against quantum adversaries
- **"Can I reuse keys?"** → IETF_SECURITY_OPERATIONAL.md (Key Reuse Prohibition section)
  - Answer: NO - PROHIBITED, critical risk
- **"What about component extraction?"** → IETF_SECURITY_OPERATIONAL.md (Non-Separability section)

### X.509 & Certificates
- **"How do I use in X.509?"** → IETF_X509_ASN1_DER.md (X.509 & PKIX Use section)
- **"What Key Usage bits are allowed?"** → IETF_X509_ASN1_DER.md (Key Usage Bits section)
  - Answer: digitalSignature, nonRepudiation, keyCertSign, cRLSign only
- **"How do I store private keys?"** → IETF_X509_ASN1_DER.md (OneAsymmetricKey section)
- **"What are DER encodings?"** → IETF_X509_ASN1_DER.md (AlgorithmIdentifier DER Examples)

### Data Sizes
- **"What are max key/signature sizes?"** → IETF_TESTVECTORS_APPENDICES.md (Appendix A)
- **"How big is ML-DSA-65 key?"** → IETF_FUNCTIONS_STRUCTURES.md (Key Sizes table)
  - Answer: pk=1952, sk=32, sig=3309 bytes

### Component Algorithms
- **"What are component OIDs?"** → IETF_TESTVECTORS_APPENDICES.md (Appendix B)
- **"How do I reconstruct SubjectPublicKeyInfo?"** → IETF_X509_ASN1_DER.md (Component Reconstruction)

### Backwards Compatibility
- **"Will this work with legacy systems?"** → IETF_SECURITY_OPERATIONAL.md (Backwards Compatibility section)
  - Answer: NO - protocol-level only, not app-level
- **"What's the migration path?"** → IETF_SECURITY_OPERATIONAL.md (Backwards Compatibility → Migration Path)

### FIPS & Compliance
- **"Can I FIPS-certify this?"** → IETF_SECURITY_OPERATIONAL.md (FIPS Certification Guidance)
  - Answer: YES - if ≥1 component FIPS-validated
- **"How do I handle deprecated algorithms?"** → IETF_SECURITY_OPERATIONAL.md (Deprecated Algorithm Handling)

### Test Vectors
- **"Are there test vectors?"** → IETF_TESTVECTORS_APPENDICES.md (Test Vector Overview)
- **"How do I construct message representative M'?"** → IETF_TESTVECTORS_APPENDICES.md (Appendix D Examples)

## OID Quick Lookup

**Range**: 1.3.6.1.5.5.7.6.37-54 (18 algorithms)

### By ML-DSA Level
- **Level 128 (ML-DSA-44)**: OIDs 37-40 (4 algorithms)
- **Level 192 (ML-DSA-65)**: OIDs 41-48 (8 algorithms) ⭐ BEST
- **Level 256 (ML-DSA-87)**: OIDs 49-54 (6 algorithms)

### By Traditional Algorithm
- **RSA**: OIDs 37, 38, 41-44, 52-53 (8 algorithms)
- **ECDSA**: OIDs 40, 45-47, 49-50, 54 (6 algorithms) ⭐ MOST USED
- **EdDSA**: OIDs 39, 48, 51 (3 algorithms)

### Recommended Primary
- **OID 1.3.6.1.5.5.7.6.45**: `id-MLDSA65-ECDSA-P256-SHA512`

## Key Technical Constants

| Constant | Value | Use |
|----------|-------|-----|
| **Prefix (hex)** | `436F6D706F73697465416C676F726974686D5369676E61747572657332303235` | Message representative binding |
| **Prefix (ASCII)** | `CompositeAlgorithmSignatures2025` | Human readable prefix |
| **Prefix (bytes)** | 34 | Fixed length |
| **ML-DSA seed** | 32 bytes | Private key format (all variants) |
| **Max ctx length** | 255 bytes | len(ctx) is single byte |
| **Prefix Year** | 2025 | Design timestamp |

## One-Line Definitions

- **Composite ML-DSA**: Signature scheme combining ML-DSA + traditional via fixed message representative
- **Hybrid**: Multi-algorithm scheme with ≥1 PQ + ≥1 traditional algorithm
- **Non-Separability**: Cannot extract component without evidence of composite
- **Key Reuse**: FORBIDDEN practice of using component keys outside composite (breaks security)
- **Profiling**: Selecting subset of 18 algorithms for organizational use case
- **Protocol Backwards Compatibility**: New algorithms fit existing extension points

## Document Metadata

- **Title**: Composite Module-Lattice-Based Digital Signature Algorithm (ML-DSA) for use in X.509 PKI
- **Status**: Standards Track Internet-Draft
- **Expires**: 11 October 2026
- **Published**: 9 April 2026
- **Revision**: draft-18
- **Goals**: 
  1. Dual-algorithm protection (PQ/T hybrid)
  2. Codebase migration flexibility
  3. FIPS certification with mixed components
  4. Regulatory PQ/T requirements
