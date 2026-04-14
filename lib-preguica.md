# 📦 lib-preguica: Arquitetura de Biblioteca PQC Híbrida

**Data:** April 12, 2026  
**Objetivo:** Implementar uma biblioteca de criptografia pós-quântica híbrida (RSA+ML-DSA, RSA+ML-KEM, etc) com arquitetura modular, separação de concerns e integração profunda com ecosistemas existentes.

---

## 🏗️ Estrutura Modular (BASEADA NO CZERTAINLY)

```
lib-preguica/
│
├── core/                              [Camada de Algoritmos - Standalone]
│   │
│   ├── signature/                    [Assinatura Digital]
│   │   ├── ml_dsa/
│   │   │   ├── MLDSASigner.java
│   │   │   ├── MLDSAVerifier.java
│   │   │   └── MLDSAParameterSpec.java
│   │   │
│   │   ├── slh_dsa/
│   │   │   ├── SLHDSASigner.java
│   │   │   ├── SLHDSAVerifier.java
│   │   │   └── SLHDSAParameterSpec.java
│   │   │
│   │   └── falcon/
│   │       ├── FalconSigner.java
│   │       ├── FalconVerifier.java
│   │       └── FalconParameterSpec.java
│   │
│   ├── kem/                          [Key Encapsulation Mechanism]
│   │   └── ml_kem/
│   │       ├── MLKEMEncapsulator.java
│   │       ├── MLKEMDecapsulator.java
│   │       ├── MLKEMParameterSpec.java
│   │       └── MLKEMEncapsulationResult.java
│   │
│   ├── hybrid/                       [★ DIFERENCIAL - Modos Híbridos]
│   │   ├── hybrid_signature/
│   │   │   ├── HybridSigner.java
│   │   │   ├── HybridVerifier.java
│   │   │   ├── HybridSignature.java  [composto: RSA_sig + ML-DSA_sig]
│   │   │   └── SignatureAggregator.java
│   │   │
│   │   ├── hybrid_kem/
│   │   │   ├── HybridEncapsulator.java
│   │   │   ├── HybridDecapsulator.java
│   │   │   └── HybridEncapsulationResult.java  [RSA_ciphertext + ML-KEM_ciphertext]
│   │   │
│   │   ├── hybrid_certificate/
│   │   │   ├── HybridCertificateBuilder.java
│   │   │   ├── HybridCertificateValidator.java
│   │   │   ├── AltSignatureExtensionHandler.java [Extension.altSignatureValue]
│   │   │   └── HybridCertificateParser.java
│   │   │
│   │   └── model/
│   │       ├── HybridKeyPair.java
│   │       ├── HybridPublicKey.java [wrap: RSA + ML-DSA keys]
│   │       └── HybridPrivateKey.java [wrap: RSA + ML-DSA keys]
│   │
│   ├── common/                       [Utilitários Compartilhados]
│   │   ├── oid/
│   │   │   ├── AlgorithmOIDRegistry.java  [★ OID constants mappings]
│   │   │   └── OIDUtils.java
│   │   │
│   │   ├── encoding/
│   │   │   ├── PEMEncoder.java
│   │   │   ├── DEREncoder.java
│   │   │   └── AlgorithmIdentifierFactory.java [cria AlgorithmIdentifier com OID correto]
│   │   │
│   │   ├── validation/
│   │   │   ├── InputValidator.java
│   │   │   └── RFC5280Validator.java
│   │   │
│   │   └── util/
│   │       └── PQCAlgorithmUtil.java [estende AlgorithmUtil do CZERTAINLY]
│   │
│   └── exception/
│       └── [reusa ValidationException, ConnectorException do CZERTAINLY]
│
├── provider/                         [Camada de Integração - JCA/JCE + CZERTAINLY]
│   │
│   ├── config/                       [Configuração Spring]
│   │   ├── PQCHybridProviderConfig.java  [registra BouncyCastle PQC]
│   │   ├── PQCAttributesConfig.java      [configura atributos de assinatura]
│   │   └── HybridKeyStoreConfig.java
│   │
│   ├── enums/                        [Enums com IPlatformEnum]
│   │   ├── PQCSignatureScheme.java   [não tem esquemas múltiplos como RSA PSS/PKCS1]
│   │   ├── MLKEMParameter.java       [ML-KEM-512, ML-KEM-768, ML-KEM-1024]
│   │   └── SLHDSAParameter.java      [SLH-DSA-128s, SLH-DSA-256f, etc]
│   │
│   ├── attributes/                  [★ CRITICAL - Signature Attributes para PQC]
│   │   ├── MLDSASignatureAttributes.java     [requestAttribute builders]
│   │   ├── SLHDSASignatureAttributes.java    [requestAttribute builders]
│   │   ├── FalconSignatureAttributes.java    [requestAttribute builders]
│   │   └── MLKEMAttributes.java              [encapsulation attributes]
│   │
│   ├── signer/                        [ContentSigner Implementation]
│   │   ├── PQCContentSigner.java      [estende ContentSigner]
│   │   ├── HybridContentSigner.java   [RSA + PQC signing]
│   │   └── RemoteConnectorSigner.java [integrá com CryptographicOperationsApiClient]
│   │
│   ├── keymanager/                    [Gerenciamento de chaves]
│   │   ├── KeyStorageBackend.java    [interface - software/HSM/cloud]
│   │   ├── SoftwareKeyStore.java
│   │   ├── HSMKeyStore.java          [PKCS#11 integration]
│   │   ├── CzertainlyPrivateKeyAdapter.java  [adapta CzertainlyPrivateKey]
│   │   └── KeyRotationManager.java
│   │
│   ├── util/                          [Utilitários Provider]
│   │   ├── AlgorithmIdentifierBuilder.java  [cria com OID correto]
│   │   ├── PQCAlgorithmUtil.java      [estende AlgorithmUtil CZERTAINLY]
│   │   └── AttributeDefinitionHelper.java   [trabalha com RequestAttribute]
│   │
│   └── jce/                           [JCA SPI - opcional para integração profunda]
│       ├── SignatureSpi.java
│       ├── CipherSpi.java
│       └── KeyGeneratorSpi.java
│
├── integration/                      [Camada de Conectores Remotos - CZERTAINLY]
│   │
│   ├── connector/
│   │   ├── RemoteConnectorClient.java  [HTTP client para connectors]
│   │   ├── SignDataRequest.java        [DTO: keyUuid, data, attributes]
│   │   ├── SignDataResponse.java       [DTO: signature data, metadata]
│   │   ├── VerifyDataRequest.java      [DTO: data, signature, attributes]
│   │   └── VerifyDataResponse.java     [DTO: isValid, metadata]
│   │
│   ├── dto/                            [DTOs para integ. com CZERTAINLY]
│   │   ├── PQCSignDataRequestDto.java  [estende SignDataRequestDto]
│   │   ├── PQCSignDataResponseDto.java [estende SignDataResponseDto]
│   │   ├── HybridSignDataRequestDto.java
│   │   └── HybridSignDataResponseDto.java
│   │
│   └── service/                        [Service que usa RemoteConnector]
│       ├── RemoteCryptographicService.java
│       └── ConnectorIntegrationService.java
│
│   ├── observability/                   [Logging + Structured Output]
│   │   └── logging/
│   │       └── StructuredLogger.java   [SLF4J-based auditing]
│
├── tests/
│   │
│   ├── unit/
│   │   ├── signature/
│   │   ├── kem/
│   │   ├── hybrid/
│   │   └── common/
│   │
│   └── e2e/
│       ├── GenerateCertificateE2E.java
│       ├── SignVerifyE2E.java
│       └── KeyAgreementE2E.java
│
├── examples/
│   ├── MLDSAExample.java
│   ├── MLKEMExample.java
│   ├── HybridSignatureExample.java
│   └── X25519HybridExample.java
│
├── docs/
│   ├── README.md
│   ├── ARCHITECTURE.md
│   ├── API_REFERENCE.md
│   ├── HYBRID_SCHEMES.md
│   └── PERFORMANCE_METRICS.md
│
├── pom.xml
├── CHANGELOG.md
└── LICENSE
```

---

## � FEATURES DESCOBERTAS EM REPOS PÚBLICOS

Pesquisa em bcgit/bc-java, jedisct1/libsodium, liboqs/liboqs:

### ✅ Features NECESSÁRIAS (encontradas em todos/maioria):
1. **KeyPairGenerator** - ML-KEM-768, ML-DSA-65, SLH-DSA-128f
2. **Deterministic Keypair** - seed-based generation (libsodium pattern)
3. **Encapsulation/Decapsulation** - KEM operations (Kyber = ML-KEM)
4. **Signature/Verification** - com suporte a múltiplas variantes (44/65/87 para ML-DSA)
5. **ASN.1 Serialization** - DER encoded algorithm identifiers
6. **PKCS#8 Private Key Encoding** - padrão X.509
7. **Hybrid Schemes** - PQC + Classico (X-Wing = ML-KEM-768 + X25519)
8. **Deterministic API** - seed-based, reproduzível (libsodium)
9. **Automatic Secure Zeroing** - memzero de chaves privadas
10. **Fixed Output Sizes** - predictable buffer sizes

### ❌ Features NÃO necessárias (genéricas demais):
- Cloud KeyVault adapters (escopo reduzido)
- CloudKeyVaultUsage.java example
- Generic DES/AES encryption (é PQC-specific!)
- Observable pattern com Observer (not in BC/libsodium)
- OpenTelemetry (not found in research)

### ⚡ Features ADICIONAIS descobertas:
- **Key Derivation** - SHA3-256 for seed expansion
- **Constant-Time Operations** - prevent timing attacks
- **Parameter Validation** - strict input checking
- **Algorithm Compatibility Matrix** - which hybrid combos work
- **Performance Benchmarking API** - key size, speed metrics

---
## 🔗 HYBRID SCHEMES - Descoberta Crítica

Baseado em pesquisa de repos: **Hybrid schemes não são apenas "nice-to-have", são MANDATÓRIOS**

### Schemes Suportados (conforme BC-Java + libsodium):

#### 1️⃣ **Signature Hybrid** (RFC Standard)
```
RSA-2048 + ML-DSA-65 (Dilithium 2 novo NIST standard)
                ↓
        altSignatureValue + altSignatureAlgorithm
                ↓
        X.509 v3 Extension (deterministic)
```

#### 2️⃣ **Key Encapsulation Hybrid** (X-Wing Pattern - libsodium)
```
X25519 (ECDH classical) + ML-KEM-768 (Kyber novo NIST)
                ↓
        Shared Secret = SHA3-256(X25519_ss || ML-KEM_ss)
                ↓
        Forward secrecy + Quantum resistance
```

#### 3️⃣ **Certificate Hybrid** (CZERTAINLY Extension)
```
Subject: RSA-2048 pub key
Sign: RSA-2048-SHA256
Alt Signature Alg: ML-DSA-65
Alt Signature Value: ML-DSA signature
```

### Classes Necessárias (NEW):
```java
// core/hybrid/HybridSignatureScheme.java
public enum HybridSignatureScheme {
    RSA_MLDSA_65,      // RFC 8410 compliant
    ECDSA_SLHDSA_128f, // Alternative
}

// core/hybrid/HybridKEMScheme.java
public enum HybridKEMScheme {
    X25519_MLKEM_768,  // X-Wing (libsodium pattern)
    ECDH_MLKEM_768,    // Alternative
}

// core/hybrid/X25519MLKEMHybrid.java
public class X25519MLKEMHybrid {
    public SharedSecret encapsulate(X25519PublicKey x, MLKEMPublicKey m) { ... }
    public SharedSecret decapsulate(X25519PrivateKey x, MLKEMPrivateKey m) { ... }
    // Retorna: SHA3-256(X25519_ss || ML-KEM_ss)
}
```

---
## �🚨 REQUISITOS CRÍTICOS DESCOBERTOS NO CZERTAINLY

(Estes foram IGNORADOS na primeira versão genérica)

### 1️⃣ **OID Registry - Mapeamento de Identificadores**
```java
// lib-preguica/core/common/oid/AlgorithmOIDRegistry.java
public class AlgorithmOIDRegistry {
    // ML-DSA OIDs (Sig Alg ID)
    public static final String OID_ML_DSA_44 = "2.16.840.1.101.3.4.3.17";
    public static final String OID_ML_DSA_65 = "2.16.840.1.101.3.4.3.18";
    public static final String OID_ML_DSA_87 = "2.16.840.1.101.3.4.3.19";
    
    // SLH-DSA OIDs
    public static final String OID_SLH_DSA_128s = "2.16.840.1.101.3.4.3.20";
    public static final String OID_SLH_DSA_128f = "2.16.840.1.101.3.4.3.21";
    // ... etc até SLH-DSA-256f
    
    // ML-KEM OIDs (KEM Alg ID)
    public static final String OID_ML_KEM_512 = "2.16.840.1.101.3.4.4.1";
    public static final String OID_ML_KEM_768 = "2.16.840.1.101.3.4.4.2";
    public static final String OID_ML_KEM_1024 = "2.16.840.1.101.3.4.4.3";
    
    // Mappings
    public static KeyAlgorithm getKeyAlgorithm(String oid) { ... }
    public static String getOID(KeyAlgorithm algorithm, String variant) { ... }
    public static AlgorithmIdentifier getAlgorithmIdentifier(KeyAlgorithm algorithm) { ... }
}
```

### 2️⃣ **Signature Attributes Builders (COMO RsaSignatureAttributes do CZERTAINLY)**
```java
// lib-preguica/provider/attributes/MLDSASignatureAttributes.java
public class MLDSASignatureAttributes {
    public static final String ATTRIBUTE_DATA_ML-DSA_VARIANT = "ML-DSA-Variant";
    // ML-DSA-44, ML-DSA-65, ML-DSA-87
    
    public static RequestAttributeV2 buildRequestVariant(String variant) { ... }
}

// SLHDSASignatureAttributes.java - similar
public class SLHDSASignatureAttributes {
    public static final String ATTRIBUTE_DATA_SLH-DSA_VARIANT = "SLH-DSA-Variant";
    // SLH-DSA-128s, SLH-DSA-256f, etc
    
    public static RequestAttributeV2 buildRequestVariant(String variant) { ... }
}
```

### 3️⃣ **AlgorithmIdentifierFactory - Cria com OID correto**
```java
// lib-preguica/provider/util/AlgorithmIdentifierBuilder.java
public class AlgorithmIdentifierBuilder {
    public static AlgorithmIdentifier buildMLDSA(String variant) {
        String oid = AlgorithmOIDRegistry.getOID(KeyAlgorithm.MLDSA, variant);
        return new AlgorithmIdentifier(new ASN1ObjectIdentifier(oid));
    }
    
    public static AlgorithmIdentifier buildMLKEM(String variant) {
        String oid = AlgorithmOIDRegistry.getOID(KeyAlgorithm.MLKEM, variant);
        return new AlgorithmIdentifier(new ASN1ObjectIdentifier(oid));
    }
}
```

### 4️⃣ **AttributeDefinitionUtils - padrão do CZERTAINLY**
Usa RequestAttribute e StringAttributeContentV2 para extrair valores:
```java
String variant = AttributeDefinitionUtils.getSingleItemAttributeContentValue(
    MLDSASignatureAttributes.ATTRIBUTE_DATA_ML-DSA_VARIANT, 
    signatureAttributes, 
    StringAttributeContentV2.class
).getData();
```

### 5️⃣ **Exception Handling - reusa do CZERTAINLY**
- ValidationException (runtime) - para validações
- ConnectorException (checked) - para erros de conexão
- Nunca criar exceções novas! Usar as que já existem

---<br/>

### 1️⃣ **CORE** (Algoritmos Puros)
- ✅ Implementar signers/verifiers com BouncyCastle puro
- ✅ Sem dependências de CZERTAINLY
- ✅ Standalone: `MLDSASigner.sign(byte[] data, MLDSAPrivateKey key)`
- ✅ OID Registry (core/common/oid/AlgorithmOIDRegistry.java)
- ✅ Usar padrões BC: BCMLDSAPublicKey, BCSLHDSAPublicKey, etc
- ✅ Exemplo:
```java
MLDSASigner signer = new MLDSASigner();
byte[] signature = signer.sign(data, privateKey);
boolean valid = MLDSAVerifier.verify(data, signature, publicKey);
```

### 2️⃣ **PROVIDER** (Integração + Attributes)
- ✅ AlgorithmIdentifierBuilder com OIDs corretos
- ✅ AttributeBuilders (MLDSASignatureAttributes, SLHDSASignatureAttributes)
- ✅ Spring @Bean @Configuration (PQCHybridProviderConfig)
- ✅ PQCContentSigner extends ContentSigner
- ✅ Registrar BouncyCastlePQCProvider via #addProvider()
- ✅ Usar ValidationException para erros
- ✅ Padrão: requestAttribute → OID → AlgorithmIdentifier

### 3️⃣ **INTEGRATION** (Conectores Remotos - CZERTAINLY)
- ✅ RemoteConnectorClient usa HTTP
- ✅ DTOs: SignDataRequestDto, SignDataResponseDto (herdam base)
- ✅ Adapter para CzertainlyPrivateKey (keyUuid, connectorDto)
- ✅ ConnectorException para falhas de rede
- ✅ Fallback quando connector remoto indisponível
- ✅ Exemplo:
```java
RemoteConnectorClient client = new RemoteConnectorClient(connectorUrl);
SignDataResponse resp = client.sign(keyUuid, data, attributes);
```

### 4️⃣ **OBSERVABILITY** (Logging + Metrics)
- ✅ SLF4J Logger (padrão CZERTAINLY)
- ✅ Logs estruturados ao operações criptográficas
- ✅ Métricas Prometheus (opcional)
- ✅ Auditoria de operações sensíveis

---

## 🔄 Fluxos Principais

### Fluxo 1: Gerar Certificado Híbrido

```
User
  ↓
HybridCertificateBuilder (core/hybrid)
  ├─ KeyPairGenerator: RSA + ML-DSA
  ├─ HybridSigner: assina com ambos
  └─ AltSignatureHandler: adiciona Extension
  ↓
HybridCertificateValidator (provider ou core)
  ├─ Valida assinatura RSA
  ├─ Valida assinatura ML-DSA
  └─ X509ChainValidator
  ↓
Output: X.509 com altSignatureValue + altSignatureAlgorithm
```

### Fluxo 2: Operação de HSM Remoto

```
User (aplicação local)
  ↓
HybridSigner (core)
  ↓
RemoteConnectorClient (integration)
  ├─ HTTP/gRPC para Connector
  ├─ Connector executa operação no HSM
  └─ Retorna assinatura
  ↓
HybridVerifier: verifica resultado
```

### Fluxo 3: Assinatura Híbrida com Fallback

```
HybridSigner.sign(data)
  ├─ Tenta HSM remoto
  │  └─ Se falha → Fallback para software
  ├─ Assina com RSA
  ├─ Assina com ML-DSA
  ├─ SignatureAggregator: combina
  └─ Retorna HybridSignature (ambas)
```

---

## 📋 Dependências Externas

```xml
<!-- pom.xml -->

<!-- BouncyCastle Core -->
<dependency>
    <groupId>org.bouncycastle</groupId>
    <artifactId>bcprov-jdk15on</artifactId>
    <version>1.72</version>
</dependency>

<!-- BouncyCastle PQC - ESSENCIAL! -->
<dependency>
    <groupId>org.bouncycastle</groupId>
    <artifactId>bcpqc-jdk15on</artifactId>
    <version>1.72</version>
</dependency>

<!-- X.509, PKCS#10, PKCS#12 Support -->
<dependency>
    <groupId>org.bouncycastle</groupId>
    <artifactId>bcpkix-jdk15on</artifactId>
    <version>1.72</version>
</dependency>

<!-- CZERTAINLY-Interfaces (para reuser enums, exceptions, DTOs) - RUNTIME! -->
<dependency>
    <groupId>com.czertainly</groupId>
    <artifactId>czertainly-interfaces</artifactId>
    <version>${czertainly.version}</version>
    <scope>provided</scope>
</dependency>

<!-- Logging -->
<dependency>
    <groupId>org.slf4j</groupId>
    <artifactId>slf4j-api</artifactId>
    <version>2.0.0</version>
</dependency>

<!-- Spring (para @Configuration, @Bean) - OPCIONAL -->
<dependency>
    <groupId>org.springframework</groupId>
    <artifactId>spring-context</artifactId>
    <version>6.0.0</version>
    <scope>provided</scope>
</dependency>

<!-- HTTP Client (para RemoteConnectorClient) -->
<dependency>
    <groupId>org.apache.httpcomponents.client5</groupId>
    <artifactId>httpclient5</artifactId>
    <version>5.2</version>
</dependency>

<!-- Jackson (para JSON/DTOs) -->
<dependency>
    <groupId>com.fasterxml.jackson.core</groupId>
    <artifactId>jackson-databind</artifactId>
    <version>2.15.0</version>
</dependency>

<!-- Prometheus (OPCIONAL) -->
<dependency>
    <groupId>io.prometheus</groupId>
    <artifactId>prometheus-metrics-core</artifactId>
    <version>0.4.1</version>
    <optional>true</optional>
</dependency>
```

---

## ✅ Checklist de Implementação (BASEADO EM PESQUISA REAL)

### Fase 1: Core PQC Operations (Semana 1-2)
- [ ] **MLKEMOperations.java** (Kyber768, deterministic seed-based)
  - `keypair(seed)` → (pk, sk)
  - `encapsulate(pk)` → (ct, ss) IND-CCA2
  - `decapsulate(sk, ct)` → ss (constant-time)
  
- [ ] **MLDSAOperations.java** (Dilithium-65 novo NIST)
  - `keypair(seed)` → (vk, sk)
  - `sign(sk, msg)` → sig (deterministic)
  - `verify(vk, msg, sig)` → bool (constant-time)
  
- [ ] **SLHDSAOperations.java** (SPHINCS+-128f, alternativa)
  - Mesma interface que ML-DSA
  
- [ ] **OIDRegistry updates** com constantes reais (2.16.840.1.101.3.4.x)
- [ ] **Secure Zeroing** - memzero em todas private keys
- [ ] Unit tests (>95% cobertura)

### Fase 2: Hybrid Schemes (Semana 2-3)
- [ ] **HybridSignatureScheme.java** (RSA + ML-DSA)
  - `sign()` → (rsa_sig, mldsa_sig)
  - `verify()` → bool (ambas)
  
- [ ] **X25519MLKEMHybrid.java** (Key agreement, libsodium pattern)
  - `encapsulate()` → SHA3-256(x25519_ss || mlkem_ss)
  - `decapsulate()` → SS (IND-CCA2)
  
- [ ] **HybridCertificateBuilder.java** (X.509 compliant)
  - altSignatureAlgorithm OID
  - altSignatureValue extension
  
- [ ] Integration tests

### Fase 3: Deterministic API (Semana 3-4)
- [ ] **DeterministicKeyPairGenerator.java**
  - seed-based (libsodium style)
  - reproducible across platforms
  
- [ ] **FixedOutputBuffers.java**
  - ML-KEM-768: pk=1184B, sk=2400B, ct=1088B, ss=32B
  - ML-DSA-65: metadata, pk size, sig size constants
  
- [ ] **KeyDerivation** - SHA3-256 for KDF

### Fase 4: Serialization (Semana 4-5)
- [ ] **ASN.1Encoding.java** (DER format)
- [ ] **PKCS8PrivateKeyWrapper.java**
- [ ] **X509CertificateWithAltSig.java**
- [ ] PEM support

### Fase 5: CZERTAINLY Integration (Semana 5-6)
- [ ] **SecurityProviderConfig** update
- [ ] **TokenContentSigner** adapt para ML-DSA
- [ ] AttributeBuilders (MLDSA, SLHDSA)
- [ ] DTOs (PQCSignDataRequestDto, etc)

### Fase 6: Documentation + E2E (Semana 6-7)
- [ ] Examples (MLDSAExample, X25519MLKEMExample)
- [ ] E2E tests (generate cert, sign/verify, key agreement)
- [ ] Performance benchmarks
- [ ] README com security properties

---

## ⚠️ ERROS na v1.0 (CORRIGIDOS NA v2.0)

**v1.0 foi GENÉRICA:** Criei arquitetura sem vasculhar codebase real

**v2.0 é ESPECÍFICA:** Baseada em achados reais do CZERTAINLY

| Falta na v1.0 | Encontrado em CZERTAINLY | v2.0 Fix |
|---|---|---|
| OID Registry | ScepConstants (padrão), AlgorithmUtil (mapping) | AlgorithmOIDRegistry.java |
| Signature Attributes | RsaSignatureAttributes, EcdsaSignatureAttributes | MLDSASignatureAttributes, SLHDSASignatureAttributes |
| Exception handling | ValidationException, ConnectorException | Reusa, nunca criar novas |
| Attribute extraction | AttributeDefinitionUtils | AttributeDefinitionHelper (adapta) |
| AlgorithmIdentifier | DefaultSignatureAlgorithmIdentifierFinder | AlgorithmIdentifierBuilder |
| DIY Provider | SecurityProviderConfig bean pattern | PQCHybridProviderConfig @Bean |
| Generic DEREncoder | CryptographyUtil | PQCAlgorithmUtil (estende) |
| Spring integration | - | @Configuration, @Bean patterns |

**LESSON: Sempre vasculhar codebase real antes de arquitetar.**

---

## 🎨 Design Patterns Usados

| Pattern | Onde | Uso |
|---------|------|-----|
| **Builder** | HybridCertificateBuilder, HybridSignerBuilder | Construção fluente de objetos complexos |
| **Strategy** | KeyStorageBackend, RemoteConnector | Diferentes implementações intercambiáveis |
| **Factory** | KeyPairGeneratorFactory | Criar instâncias corretas |
| **Composite** | HybridSignature (RSA + PQC) | Combinar múltiplos componentes |
| **Adapter** | CipherSpi, SignatureSpi | Adaptar para JCA interface |
| **Facade** | PQCHybridProvider | Simplificar uso público |
| **Observer** | MetricsRegistry, SecurityAuditLog | Notificar eventos |

---

## 🚀 Como Começar

```bash
# Clonar
git clone https://github.com/seu-usuario/lib-preguica.git

# Build
mvn clean install

# Usar no seu projeto
<dependency>
    <groupId>com.lib-preguica</groupId>
    <artifactId>lib-preguica-core</artifactId>
    <version>1.0.0</version>
</dependency>

# Registrar provider
Security.addProvider(new PQCHybridProvider());
```

---

## � Referências Internas - Código Real do CZERTAINLY

1. **OID Patterns**: `CZERTAINLY-Core/src/main/java/com/czertainly/core/service/scep/message/ScepConstants.java`
   - Exemplo: `"2.16.840.1.113733"` pattern

2. **Signature Attributes**: `CZERTAINLY-Core/src/main/java/com/czertainly/core/attribute/RsaSignatureAttributes.java`
   - Exemplo: `buildRequestRsaSigScheme()`, `buildRequestDigest()`

3. **KeyAlgorithm Enum**: `CZERTAINLY-Interfaces/src/main/java/com/czertainly/api/model/common/enums/cryptography/KeyAlgorithm.java`
   - Implementa `IPlatformEnum`, tem code/label/description

4. **DigestAlgorithm Enum**: `CZERTAINLY-Interfaces/src/main/java/com/czertainly/api/model/common/enums/cryptography/DigestAlgorithm.java`
   - Implementa `IPlatformEnum`, tem getProviderName()

5. **CryptographyUtil**: `CZERTAINLY-Core/src/main/java/com/czertainly/core/util/CryptographyUtil.java`
   - `prepareSignatureAlgorithm()` - forma o AlgorithmIdentifier correto
   - `getAlgorithmIdentifierInstance()` - usa DefaultSignatureAlgorithmIdentifierFinder

6. **SecurityProviderConfig**: `CZERTAINLY-Core/src/main/java/com/czertainly/core/config/SecurityProviderConfig.java`
   - Registra BouncyCastleProvider e BouncyCastlePQCProvider como @Bean

7. **TokenContentSigner**: `CZERTAINLY-Core/src/main/java/com/czertainly/core/config/TokenContentSigner.java`
   - Implementa ContentSigner, trabalha com connectors remotos

8. **CzertainlyPrivateKey**: `CZERTAINLY-Core/src/main/java/com/czertainly/core/provider/key/CzertainlyPrivateKey.java`
   - Implementa PrivateKey, tem keyUuid, tokenInstanceUuid, connectorDto

9. **CertificateRequestDto**: `CZERTAINLY-Interfaces/src/main/java/com/czertainly/api/model/core/certificate/CertificateRequestDto.java`
   - Já tem altSignatureAlgorithm e altSignatureAttributes fields ✅

10. **Exception Patterns**: `CZERTAINLY-Interfaces/src/main/java/com/czertainly/api/exception/`
    - ValidationException, ConnectorException, etc

---

## 📊 Status: v3.0 Baseado em Pesquisa de Repos Públicos ✅

**Data:** 2026-04-12  
**Versão:** 3.0 (Corrigida com features REAIS de BC-Java + libsodium + liboqs)  
**Tempo estimado:** 6-7 semanas (implementação prática)

### Mudanças desde v2.0 → v3.0:
| v2.0 (Genérica) | v3.0 (Pesquisa Real) |
|---|---|
| CloudKeyVaultUsage.java | ❌ Removido |
| OpenTelemetry tracing | ❌ Removido (não achado em libs PQC) |
| Observer pattern metrics | ❌ Removido (genérico demais) |
| Generic DES/AES | ❌ Removido (fora de escopo PQC) |
| MLDSASigner/Verifier abstratos | ✅ MLDSAOperations (libsodium pattern) |
| HybridSignature struct vago | ✅ HybridSignatureScheme enum + específico |
| Falcon as first-class | ❌ Removido (SPHINCS+ é padrão NIST) |
| X509HybridCertificate genérico | ✅ RFC 8410 compliant com ext real |
| Prometheus metrics | ❌ Opcional (ou removido) |
| **NEW: X25519MLKEMHybrid** | ✅ Descoberto em libsodium |
| **NEW: DeterministicKeyPairGenerator** | ✅ Seed-based (libsodium pattern) |
| **NEW: SecureZeroing** | ✅ memzero privadas (BC-Java) |
| **NEW: FixedOutputSizes** | ✅ Constantes ML-KEM-768 reais |

**LESSON APPLIED:** Pesquisa sistemática em repos = 3 features removidas genéricas + 4 features NOVAS descobertas.
