# Test Vectors & Appendices

## Test Vector Overview (Appendix E)

### Global Message
- **Message**: "The quick brown fox jumps over the lazy dog."
- **Message (base64)**: `VGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZy4=`
- **Context**: "The lethargic, colorless dog sat beneath the energetic, stationary fox."
- **Context (base64)**: `VGhlIGxldGhhcmdpYywgY29sb3JsZXNzIGRvZyBzYXQgYmVuZWF0aCB0aGUgZW5lcmdldGljLCBzdGF0aW9uYXJ5IGZveC4=`

### Test Vector Structure
For each algorithm, provides:
- `tcId`: Algorithm name identifier
- `pk`: Raw verification public key (base64)
- `x5c`: Self-signed X.509 certificate (base64)
- `sk`: Raw signing private key (base64)
- `sk_pkcs8`: Private key in PKCS#8 structure (base64)
- `s`: Signature value with empty ctx (base64)
- `sWithContext`: Signature value with provided ctx (base64)

### Test Vector Usage
1. Load public key pk or certificate x5c
2. Verify signature s over message m
3. Validate self-signed certificate x5c
4. Load private key sk or sk_pkcs8
5. Generate new signature (should verify against provided pk/x5c)
6. All test vectors must pass for conformance

### Provided Test Cases
- `id-ML-DSA-44`: ML-DSA-44 test vectors (pure reference)
- `id-ML-DSA-65`: ML-DSA-65 test vectors (pure reference)
- [Additional composite vectors follow same format]

## Appendix A: Maximum Key and Signature Sizes

### Pure ML-DSA (Reference)
- **id-ML-DSA-44**: pk=1312, sk=32, sig=2420 bytes
- **id-ML-DSA-65**: pk=1952, sk=32, sig=3309 bytes
- **id-ML-DSA-87**: pk=2592, sk=32, sig=4627 bytes

### ML-DSA-44 Composites
- **MLDSA44-RSA2048-PSS-SHA256**: pk=1582*, sk=1226*, sig=2676
- **MLDSA44-RSA2048-PKCS15-SHA256**: pk=1582*, sk=1226*, sig=2676
- **MLDSA44-Ed25519-SHA512**: pk=1344, sk=64, sig=2484
- **MLDSA44-ECDSA-P256-SHA256**: pk=1377, sk=83, sig=2492*

### ML-DSA-65 Composites
- **MLDSA65-RSA3072-PSS-SHA512**: pk=2350*, sk=1802*, sig=3693
- **MLDSA65-RSA3072-PKCS15-SHA512**: pk=2350*, sk=1802*, sig=3693
- **MLDSA65-RSA4096-PSS-SHA512**: pk=2478*, sk=2383*, sig=3821
- **MLDSA65-RSA4096-PKCS15-SHA512**: pk=2478*, sk=2383*, sig=3821
- **MLDSA65-ECDSA-P256-SHA512**: pk=2017, sk=83, sig=3381* ⭐ RECOMMENDED
- **MLDSA65-ECDSA-P384-SHA512**: pk=2049, sk=96, sig=3413*
- **MLDSA65-ECDSA-brainpoolP256r1-SHA512**: pk=2017, sk=84, sig=3381*
- **MLDSA65-Ed25519-SHA512**: pk=1984, sk=64, sig=3373

### ML-DSA-87 Composites
- **MLDSA87-ECDSA-P384-SHA512**: pk=2689, sk=96, sig=4731*
- **MLDSA87-ECDSA-brainpoolP384r1-SHA512**: pk=2689, sk=100, sig=4731*
- **MLDSA87-Ed448-SHAKE256**: pk=2649, sk=89, sig=4741
- **MLDSA87-RSA3072-PSS-SHA512**: pk=2990*, sk=1802*, sig=5011
- **MLDSA87-RSA4096-PSS-SHA512**: pk=3118*, sk=2383*, sig=5139
- **MLDSA87-ECDSA-P521-SHA512**: pk=2725, sk=114, sig=4766*

**Note**: Sizes marked with * (asterisk) are maximum possible, not truly fixed. Due to:
- Compressed vs uncompressed EC points
- Variable RSA exponent e size (3 to n-1, table assumes e=65537)
- Leading zeros dropped in DER integer encoding

## Appendix B: Component Algorithm Reference

### ML-DSA Variants
- **id-ML-DSA-44**: OID 2.16.840.1.101.3.4.3.17 [FIPS.204]
- **id-ML-DSA-65**: OID 2.16.840.1.101.3.4.3.18 [FIPS.204]
- **id-ML-DSA-87**: OID 2.16.840.1.101.3.4.3.19 [FIPS.204]

### EdDSA
- **id-Ed25519**: OID 1.3.101.112 [RFC8032, RFC8410]
- **id-Ed448**: OID 1.3.101.113 [RFC8032, RFC8410]

### ECDSA
- **ecdsa-with-SHA256**: OID 1.2.840.10045.4.3.2
- **ecdsa-with-SHA384**: OID 1.2.840.10045.4.3.3
- **ecdsa-with-SHA512**: OID 1.2.840.10045.4.3.4

### RSA
- **sha256WithRSAEncryption**: OID 1.2.840.113549.1.1.11 [RFC8017]
- **sha384WithRSAEncryption**: OID 1.2.840.113549.1.1.12 [RFC8017]
- **id-RSASSA-PSS**: OID 1.2.840.113549.1.1.10 [RFC8017]

### Elliptic Curves
- **secp256r1**: OID 1.2.840.10045.3.1.7
- **secp384r1**: OID 1.3.132.0.34
- **secp521r1**: OID 1.3.132.0.35
- **brainpoolP256r1**: OID 1.3.36.3.3.2.8.1.1.7
- **brainpoolP384r1**: OID 1.3.36.3.3.2.8.1.1.11

### Hash Functions
- **id-sha256**: OID 2.16.840.1.101.3.4.2.1 [RFC6234]
- **id-sha384**: OID 2.16.840.1.101.3.4.2.2 [RFC6234]
- **id-sha512**: OID 2.16.840.1.101.3.4.2.3 [RFC6234]
- **id-shake256**: OID 2.16.840.1.101.3.4.2.18 [FIPS.202]
- **id-mgf1**: OID 1.2.840.113549.1.1.8 [RFC8017]

## Appendix D: Message Representative Examples

### Example 1: Empty Context

**Inputs**:
- M: `00010203040506070809` (hex)
- ctx: (empty)

**Components of M'**:
- Prefix: `436F6D706F73697465416C676F726974686D5369676E61747572657332303235`
- Label: `COMPSIG-MLDSA65-ECDSA-P256-SHA512`
- len(ctx): `00`
- ctx: (empty)
- PH(M): SHA512 hash of message

**Result**: M' = Prefix || Label || 00 || (empty) || PH(M)

### Example 2: With Context

**Inputs**:
- M: `00010203040506070809` (hex)
- ctx: `0813061205162623` (8 bytes)

**Components of M'**:
- Prefix: `436F6D706F73697465416C676F726974686D5369676E61747572657332303235`
- Label: `COMPSIG-MLDSA65-ECDSA-P256-SHA512`
- len(ctx): `08` (length of context)
- ctx: `0813061205162623`
- PH(M): SHA512 hash of message

**Result**: M' = Prefix || Label || 08 || 0813061205162623 || PH(M)

## Appendix F: Contributors and Acknowledgements

Authors and contributors to draft-ietf-lamps-pq-composite-sigs specification (see Section 11 references).

## References

### Normative (Core Implementation)
- FIPS.204: Module-Lattice-Based Digital Signature Standard (ML-DSA)
- FIPS.186-5: Digital Signature Standard (ECDSA)
- RFC 5280: X.509 PKI Certificate & CRL Profile
- RFC 8017: PKCS #1 RSA Cryptography Specifications
- RFC 8032: EdDSA (Ed25519, Ed448)
- RFC 8410: Algorithm Identifiers for EdDSA
- RFC 5958: Asymmetric Key Packages (OneAsymmetricKey)
- X.690: ASN.1 Encoding Rules (DER)

### Informative (Context & Guidance)
- RFC 9794: Terminology for PQ/T Hybrid Schemes
- RFC 9881: Algorithm Identifiers for ML-DSA
- BSI 2021: Quantum-safe cryptography paper
- ANSSI 2024: Position Paper on QKD
- Bindel 2017: Transitioning to quantum-resistant PKI
