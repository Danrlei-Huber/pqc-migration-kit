# X.509, PKIX, ASN.1 & DER Integration

## X.509 & PKIX Use (Section 5)

### Encoding to DER (Section 5.1)
- Serialization routines produce raw binary (concatenated component encodings)
- When placed in DER structures (X.509 subjectPublicKey, signatureValue BIT STRING):
  - Wrap raw bytes in BIT STRING or OCTET STRING
  - No additional DER encoding on top
- DER encoding: All ASN.1 objects use Distinguished Encoding Rules

### Key Usage Bits (Section 5.2)

**Allowed Key Usage Extensions** (MUST have at least one):
- `digitalSignature` - Digital signatures on certs/CRLs
- `nonRepudiation` - Non-repudiation service
- `keyCertSign` - Signing certificates
- `cRLSign` - Signing CRLs, entity authentication, data origin auth, integrity

**Prohibited Key Usage Extensions** (MUST NOT have):
- `keyEncipherment` - Key encryption (ML-DSA doesn't support)
- `dataEncipherment` - Data encryption
- `keyAgreement` - Key agreement/establishment
- `encipherOnly` - Encryption only
- `decipherOnly` - Decryption only

**Reason**: ML-DSA signature-only, not for encryption or key establishment

### Dual-Usage Prohibition
- ❌ Components NOT used separately within composite
- ❌ Even if traditional component supports sign+encrypt, composite does NOT
- Composite enforces signing-only operation mode

## ASN.1 Module (Section 5.3, 7)

### Information Object Classes
Two IOCs defined for compact representation:

```asn1
pk-CompositeSignature {OBJECT IDENTIFIER:id} PUBLIC-KEY ::= {
  IDENTIFIER id
  -- KEY: no ASN.1 wrapping (raw bytes)
  PARAMS ARE absent
  CERT-KEY-USAGE { digitalSignature, nonRepudiation, keyCertSign, cRLSign}
  -- PRIVATE-KEY: no ASN.1 wrapping (raw bytes)
}

sa-CompositeSignature {OBJECT IDENTIFIER:id, PUBLIC-KEY:publicKeyType} 
  SIGNATURE-ALGORITHM ::= {
    IDENTIFIER id
    -- VALUE: no ASN.1 wrapping (raw bytes)
    PARAMS ARE absent
    PUBLIC-KEYS {publicKeyType}
    SMIME-CAPS { IDENTIFIED BY id }
  }
```

### Example Definition Usage
```asn1
id-MLDSA44-ECDSA-P256-SHA256 OBJECT IDENTIFIER ::= {
  iso(1) identified-organization(3) dod(6) internet(1) security(5)
  mechanisms(5) pkix(7) alg(6) 40 }

pk-MLDSA44-ECDSA-P256-SHA256 PUBLIC-KEY ::=
  pk-CompositeSignature{ id-MLDSA44-ECDSA-P256-SHA256 }

sa-MLDSA44-ECDSA-P256-SHA256 SIGNATURE-ALGORITHM ::=
  sa-CompositeSignature{
    id-MLDSA44-ECDSA-P256-SHA256,
    pk-MLDSA44-ECDSA-P256-SHA256 }
```

### OneAsymmetricKey Structure (PKCS#8)

**When composite private key in OneAsymmetricKey** (RFC 5958):
- `privateKeyAlgorithm`: Composite algorithm OID from Section 6
- `privateKeyAlgorithm.parameters`: MUST be absent
- `privateKey`: OCTET STRING containing serialized composite private key (Section 4.2)
- `publicKey` [1]: OPTIONAL, if present must be composite public key

**Use Cases**:
- PKCS#12 private key storage
- CMP (Certificate Management Protocol)
- CRMF (Certificate Request Message Format)

## AlgorithmIdentifier DER Examples (Appendix C)

### ML-DSA-44
```
ASN.1: algorithm { algorithm id-ML-DSA-44 (2.16.840.1.101.3.4.3.17) }
DER: 30 0B 06 09 60 86 48 01 65 03 04 03 11
```

### ML-DSA-65
```
ASN.1: algorithm { algorithm id-ML-DSA-65 (2.16.840.1.101.3.4.3.18) }
DER: 30 0B 06 09 60 86 48 01 65 03 04 03 12
```

### ML-DSA-87
```
ASN.1: algorithm { algorithm id-ML-DSA-87 (2.16.840.1.101.3.4.3.19) }
DER: 30 0B 06 09 60 86 48 01 65 03 04 03 13
```

### RSASSA-PSS 2048 & 3072
**Public Key**:
```
DER: 30 0B 06 09 2A 86 48 86 F7 0D 01 01 0A
```

**Signature (with SHA-256, MGF1-SHA256, saltLen=32)**:
```
DER: 30 41 06 09 2A 86 48 86 F7 0D 01 01 0A 30 34 A0 0F ... 
```

### RSASSA-PSS 4096
**Signature (with SHA-384, MGF1-SHA384, saltLen=48)**:
```
DER: 30 41 06 09 2A 86 48 86 F7 0D 01 01 0A 30 34 A0 0F ... 
```

### ECDSA P-256
**Public Key**:
```
DER: 30 13 06 07 2A 86 48 CE 3D 02 01 06 08 2A 86 48 CE 3D 03 01 07
```

**Signature (with SHA-256)**:
```
DER: 30 0A 06 08 2A 86 48 CE 3D 04 03 02
```

### ECDSA P-384
**Public Key**:
```
DER: 30 10 06 07 2A 86 48 CE 3D 02 01 06 05 2B 81 04 00 22
```

**Signature (with SHA-384)**:
```
DER: 30 0A 06 08 2A 86 48 CE 3D 04 03 03
```

### ECDSA P-521
**Public Key**:
```
DER: 30 10 06 07 2A 86 48 CE 3D 02 01 06 05 2B 81 04 00 23
```

**Signature (with SHA-512)**:
```
DER: 30 0A 06 08 2A 86 48 CE 3D 04 03 04
```

### ECDSA Brainpool-P256
**Public Key**:
```
DER: 30 14 06 07 2A 86 48 CE 3D 02 01 06 09 2B 24 03 03 02 08 01 01 07
```

**Signature (with SHA-256)**:
```
DER: 30 0A 06 08 2A 86 48 CE 3D 04 03 02
```

### ECDSA Brainpool-P384
**Public Key**:
```
DER: 30 14 06 07 2A 86 48 CE 3D 02 01 06 09 2B 24 03 03 02 08 01 01 0B
```

**Signature (with SHA-384)**:
```
DER: 30 0A 06 08 2A 86 48 CE 3D 04 03 03
```

### Ed25519
**Public Key & Signature**:
```
DER: 30 05 06 03 2B 65 70
```

### Ed448
**Public Key & Signature**:
```
DER: 30 05 06 03 2B 65 71
```

## Component Reconstruction

Organizations embedding composite keys in X.509-focused libraries may need to reconstruct SubjectPublicKeyInfo for each component. Section 6 & Appendix B provide mapping tables for reconstructing component AlgorithmIdentifiers.

**Reconstruction Steps**:
1. Parse composite public key using composite algorithm OID
2. Deserialize into component keys
3. Wrap each component in its own SubjectPublicKeyInfo structure
4. Use standard library interfaces with component AlgorithmIdentifiers

## Hybrid PQC Extensions Implementation

### Implemented Extensions

This library implements the following X.509 v3 extensions for hybrid PQC certificates:

| OID | Extension | Description |
|-----|-----------|-------------|
| 2.5.29.62 | altSignatureAlgorithm | PQC algorithm identifier |
| 2.5.29.63 | altSignatureValue | PQC signature over TBSCertificate |
| 2.5.29.72 | subjectAltPublicKeyInfo | PQC public key in SubjectPublicKeyInfo format |

### ASN.1 Structure

```asn1
PQCExtensions ::= SEQUENCE {
    altSignatureAlgorithm  AlgorithmIdentifier,
    altSignatureValue       BIT STRING,
    subjectAltPublicKeyInfo SubjectPublicKeyInfo
}
```

### DER Encoding Examples

**altSignatureAlgorithm (ML-DSA-65)**:
```
30 0B 06 09 60 86 48 01 65 03 04 03 12
```
- `30 0B` - SEQUENCE, 11 bytes
- `06 09` - OID, 9 bytes
- `60 86 48 01 65 03 04 03 12` - OID for ML-DSA-65

### Implementation Classes

| Class | Purpose |
|-------|---------|
| `PQCExtensionsStructure` | ASN.1 structure for PQC extensions |
| `HybridX509CertificateBuilder` | Certificate builder with PQC support |
| `HybridCertificateValidator` | Validates PQC extensions |
| `HybridCertificateInfo` | Model for extracted certificate info |

### Usage Example

```java
// Build certificate with PQC extensions
X509Certificate cert = HybridX509CertificateBuilder.builder(config, keyPair)
    .withPQCExtensions(true)
    .build();

// Validate PQC extensions
boolean valid = HybridCertificateValidator.validatePQCExtensions(certificate);

// Extract PQC info
String pqcOID = HybridCertificateValidator.extractPQCAlgorithmOID(certificate);
byte[] pqcSig = HybridCertificateValidator.extractPQCSignature(certificate);
byte[] pqcKey = HybridCertificateValidator.extractPQCPublicKey(certificate);
```
