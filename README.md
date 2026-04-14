# 📦 PQC Hybrid Certificates Library

**Versão**: 1.0.0-BETA  
**Data**: April 14, 2026  
**Linguagem**: Java 21  
**Framework**: BouncyCastle 1.77+  

---

## 🎯 Visão Geral

Biblioteca Java de **nível produção** para criptografia pós-quântica híbrida com certificados X.509 v3. Combina algoritmos **clássicos resistidos (RSA, ECDSA)** com algoritmos **quântico-resistentes (ML-DSA, ML-KEM, SLH-DSA, Falcon)** para criar certificados digitais com segurança dual.

**Objetivo**: Migração segura e gradual para criptografia pós-quântica sem abandonar compatibilidade com infraestrutura existente.

---

## ✨ Características Principais

| Feature | Descrição |
|---------|-----------|
| **Segurança Dual** | Ambas assinaturas (clássica + PQC) devem ser válidas |
| **NIST Padronizado** | Algoritmos finalizados pelo NIST em 2024 |
| **RFC 5280 Compliant** | Extensões X.509 v3 padrão |
| **Modular** | Arquitetura bem-separada por concerns |
| **Type-Safe** | Enums para algoritmos com validação em tempo de compilação |
| **Imutável** | Records Java 17+ para segurança |
| **Zero-Copy** | Clonagem automática de arrays sensíveis |
| **Extensível** | Factory pattern para novos algoritmos |

---

## 🏗️ Arquitetura da Biblioteca

```
src/main/java/com/pqc/hybrid/core/
│
├── api/                          [Ponto de Entrada]
│   └── PQCHybridCertificateAPI   ← Start here!
│
├── keygen/                       [Geração de Chaves]
│   ├── HybridKeyGenerator        ← Gera pares clássicos + PQC
│   ├── HybridKeyPair             ← Record com ambas chaves
│   ├── EncapsulationResult       ← Resultado KEM
│   └── KeyEncapsulationWrapper   ← Wrapper para ML-KEM
│
├── signature/                    [Assinatura Digital]
│   ├── HybridSignatureManager    ← Assina dual (classic + PQC)
│   ├── HybridSignaturePair       ← Record com ambas assinaturas
│   ├── DualSignatureValidator    ← Valida ambas assinaturas
│   └── HybridVerifier            ← Verifica assinaturas dual
│
├── certificate/                  [Certificados X.509]
│   ├── HybridX509CertificateBuilder    ← Constrói certs hybrid
│   ├── HybridCertificateValidator      ← Valida certs com ambas sigs
│   ├── CertificateSigningRequestBuilder ← Cria PKCS#10 CSRs
│   ├── X509ExtensionManager             ← Gerencia extensões
│   └── HybridCertificateValidator       ← Validação completa
│
├── config/                       [Configuração]
│   ├── ClassicalAlgorithm        ← Enum: RSA-2048, ECDSA-P256, etc
│   ├── PQCAlgorithm              ← Enum: ML-DSA-65, ML-KEM-768, etc
│   ├── HybridAlgorithmPair       ← Record: combina clássico + PQC
│   ├── HybridCertificateConfig   ← Config builder para certs
│   └── CryptographicProviderFactory ← Inicializa BouncyCastle
│
├── common/                       [Utilitários]
│   ├── oid/
│   │   ├── AlgorithmOIDRegistry  ← Mapeia OIDs → algoritmos
│   │   └── OIDUtils              ← Helpers para OIDs
│   ├── encoding/
│   │   ├── PEMEncoder            ← Serializa para PEM
│   │   └── DEREncoder            ← Serializa para DER
│   └── validation/
│       ├── InputValidator        ← Valida inputs
│       └── RFC5280Validator      ← Valida X.509 v3 RFC 5280
│
├── exception/                    [Exceções]
│   ├── PQCHybridException        ← Base
│   ├── CertificateException      ← Erros de certificado
│   ├── InvalidSignatureException ← Assinatura inválida
│   ├── InvalidKeyException       ← Chave inválida
│   ├── AlgorithmNotSupportedException ← Algoritmo não suportado
│   └── EncapsulationException    ← Erro em KEM
│
├── model/                        [Modelos de Dados]
│   └── EncapsulationResult       ← Resultado de encapsulação KEM
│
└── util/                         [Ferramentas]
    └── (utilitários específicos)
```

---

## 🚀 Quick Start

### 1. Adicione ao Maven (`pom.xml`)

```xml
<dependency>
    <groupId>com.pqc.hybrid</groupId>
    <artifactId>pqc-hybrid-certificates</artifactId>
    <version>1.0.0-BETA</version>
</dependency>
```

### 2. Inicialize a Biblioteca

```java
import com.pqc.hybrid.core.api.PQCHybridCertificateAPI;
import com.pqc.hybrid.core.exception.PQCHybridException;

public class Example {
    public static void main(String[] args) throws PQCHybridException {
        // Inicializar API
        PQCHybridCertificateAPI api = new PQCHybridCertificateAPI();
        api.initialize();  // Registra BouncyCastle PQC
        
        System.out.println("API versão: " + api.getVersion());
    }
}
```

### 3. Gere Pares de Chaves Híbridas

```java
// Gerar com nível de segurança (128, 192, ou 256 bits)
HybridKeyPair keyPair = api.generateHybridKeyPair(128);
// Resultado: ECDSA-P256 + ML-DSA-44

System.out.println("Par de chaves: " + keyPair.getLabel());
// Output: "ECDSA + ML-DSA-44"
```

### 4. Assine Dados com Ambos Algoritmos

```java
byte[] data = "Mensagem importante".getBytes();
HybridSignaturePair signature = api.signData(data, keyPair);

System.out.println("Assinatura clássica: " + signature.getClassicalSignatureSize() + " bytes");
System.out.println("Assinatura PQC: " + signature.getPQCSignatureSize() + " bytes");
```

### 5. Verifique Assinaturas

```java
// Ambas assinaturas devem ser válidas
boolean isValid = api.verifySignature(data, signature, keyPair);
System.out.println("Assinatura válida: " + isValid);
```

### 6. Gere Certificado X.509 Híbrido

```java
import com.pqc.hybrid.core.config.HybridCertificateConfig;

HybridCertificateConfig config = HybridCertificateConfig.builder()
    .withSubjectDN("CN=example.com,O=Empresa,C=BR")
    .withIssuerDN("CN=Example CA,O=Empresa,C=BR")
    .withValidityDays(365)
    .build();

X509Certificate cert = api.generateHybridCertificate(config, keyPair);

System.out.println("Certificado gerado para: " + cert.getSubjectDN());
System.out.println("Válido até: " + cert.getNotAfter());
```

---

## 📚 API Reference - Módulos Principais

### 🔑 Módulo: Geração de Chaves (`com.pqc.hybrid.core.keygen`)

#### `HybridKeyGenerator`

Classe **estática** para gerar pares de chaves híbridas.

**Métodos**:

```java
// Gerar com algoritmos recomendados para nível de segurança
public static HybridKeyPair generate(HybridAlgorithmPair algorithmPair)
    throws PQCHybridException

// Gerar apenas chave clássica
private static KeyPair generateClassicalKeyPair(
    ClassicalAlgorithm algorithm, Provider provider)

// Gerar apenas chave PQC
private static KeyPair generatePQCKeyPair(
    PQCAlgorithm algorithm, Provider provider)
```

**Exemplo**:

```java
HybridAlgorithmPair pair = HybridAlgorithmPair.recommended(192);
HybridKeyPair hybridPair = HybridKeyGenerator.generate(pair);

PublicKey classicalPubKey = hybridPair.getClassicalPublicKey();
PublicKey pqcPubKey = hybridPair.getPQCPublicKey();
```

#### `HybridKeyPair` (Record)

Imutável, contém ambos pares de chaves.

**Getters**:

```java
PublicKey getClassicalPublicKey()
PrivateKey getClassicalPrivateKey()
PublicKey getPQCPublicKey()
PrivateKey getPQCPrivateKey()
String getClassicalAlgorithm()
String getPQCAlgorithm()
long getGenerationTime()
String getLabel()  // "ECDSA + ML-DSA-65"
```

---

### ✍️ Módulo: Assinatura Digital (`com.pqc.hybrid.core.signature`)

#### `HybridSignatureManager`

Classe **estática** para operações de assinatura e verificação.

**Métodos**:

```java
// Assinar dados com ambos algoritmos
public static HybridSignaturePair sign(byte[] data, HybridKeyPair keyPair)
    throws PQCHybridException

// Verificar assinatura (ambas devem ser válidas)
public static boolean verify(byte[] data, HybridSignaturePair signature, 
                            HybridKeyPair keyPair)
    throws InvalidSignatureException

// Obter informações sobre assinatura
public static SignatureMetadata getSignatureMetadata(HybridSignaturePair signature)
```

**Exemplo**:

```java
byte[] data = "Dados".getBytes();
HybridKeyPair keyPair = /* ... */;

// Assinar
HybridSignaturePair sig = HybridSignatureManager.sign(data, keyPair);

// Verificar - retorna true se AMBAS assinaturas forem válidas
boolean valid = HybridSignatureManager.verify(data, sig, keyPair);
```

#### `HybridSignaturePair` (Record)

Contém ambas assinaturas para o mesmo documento.

**Getters**:

```java
byte[] getClassicalSignature()        // ~256-512 bytes (RSA/ECDSA)
byte[] getPQCSignature()           // ~2440+ bytes (ML-DSA)
String getClassicalAlgorithm()
String getPQCAlgorithm()
byte[] getMessageHash()
int getClassicalSignatureSize()
int getPQCSignatureSize()
long getSignatureTime()
```

---

### 🏛️ Módulo: Certificados X.509 (`com.pqc.hybrid.core.certificate`)

#### `HybridX509CertificateBuilder`

Builder para construir certificados X.509 v3 com assinaturas dual.

**Métodos**:

```java
public HybridX509CertificateBuilder(
    HybridCertificateConfig config, 
    HybridKeyPair keyPair)

// Customizar extensões
public HybridX509CertificateBuilder withExtensionManager(
    X509ExtensionManager manager)

// Construir certificado
public X509Certificate build() throws CertificateException
```

**Exemplo**:

```java
HybridCertificateConfig config = HybridCertificateConfig.builder()
    .withSubjectDN("CN=example.com,O=Example,C=US")
    .withIssuerDN("CN=Example CA,O=Example,C=US")
    .withValidityDays(365)
    .build();

HybridKeyPair keyPair = /* ... */;

X509Certificate cert = new HybridX509CertificateBuilder(config, keyPair)
    .build();
```

#### `HybridCertificateValidator`

Classe **estática** para validar certificados híbridos.

**Métodos**:

```java
// Verificar se não expirou
public static boolean validateNotExpired(X509Certificate certificate)

// Verificar DNs
public static boolean validateDNs(X509Certificate certificate)

// Verificar período de validade
public static boolean validateValidityPeriod(X509Certificate certificate)

// Validação completa
public static boolean validateFull(X509Certificate certificate, 
                                   HybridKeyPair keyPair)
    throws InvalidSignatureException
```

**Exemplo**:

```java
X509Certificate cert = /* ... */;

// Verificar múltiplos aspectos
if (HybridCertificateValidator.validateNotExpired(cert) &&
    HybridCertificateValidator.validateDNs(cert) &&
    HybridCertificateValidator.validateFull(cert, keyPair)) {
    System.out.println("Certificado válido!");
}
```

#### `CertificateSigningRequestBuilder`

Builder para PKCS#10 CSRs (Certificate Signing Requests).

**Métodos**:

```java
public CertificateSigningRequestBuilder(String subjectDN, HybridKeyPair keyPair)

public CertificateSigningRequestBuilder withExtensionManager(X509ExtensionManager manager)

public PKCS10CertificationRequest build() throws CertificateException
```

**Exemplo**:

```java
String subjectDN = "CN=test.example.com,O=Example,C=US";
HybridKeyPair keyPair = /* ... */;

PKCS10CertificationRequest csr = new CertificateSigningRequestBuilder(subjectDN, keyPair)
    .build();

// Enviar CSR para uma CA
byte[] csrEncoded = csr.getEncoded();
```

#### `X509ExtensionManager`

Gerencia extensões customizadas de certificados.

**Métodos**:

```java
// Adicionar extensão de algoritmo alternativo
public void addAltSignatureAlgorithmExtension(String algorithmOID, boolean critical)

// Adicionar extensão de valor de assinatura alternativa
public void addAltSignatureValueExtension(byte[] signatureBytes, boolean critical)

// Adicionar extensão de chave pública alternativa
public void addSubjectAltPublicKeyInfoExtension(byte[] publicKeyBytes, boolean critical)

// Obter extensão por OID
public Extension getExtension(String oid)

// Obter todas extensões
public Map<String, Extension> getAllExtensions()

// Verificar se existe extensão
public boolean hasExtension(String oid)

// Remover extensão
public void removeExtension(String oid)

// Limpar todas
public void clearAllExtensions()
```

**OIDs de Extensões Híbridas**:

```java
public static final String OID_ALT_SIGNATURE_ALGORITHM = "2.5.29.62"
public static final String OID_ALT_SIGNATURE_VALUE = "2.5.29.63"
public static final String OID_SUBJECT_ALT_PUBLIC_KEY_INFO = "2.5.29.72"
```

---

### ⚙️ Módulo: Configuração (`com.pqc.hybrid.core.config`)

#### `ClassicalAlgorithm` (Enum)

Algoritmos clássicos suportados com metadados.

**Valores**:

```java
RSA_2048("RSA", 2048, "1.2.840.113549.1.1.1", 128 bits)
RSA_3072("RSA", 3072, "1.2.840.113549.1.1.1", 128 bits)
RSA_4096("RSA", 4096, "1.2.840.113549.1.1.1", 256 bits)

ECDSA_P256("ECDSA", 256, "1.2.840.10045.2.1", 128 bits)
ECDSA_P384("ECDSA", 384, "1.2.840.10045.2.1", 192 bits)
ECDSA_P521("ECDSA", 521, "1.2.840.10045.2.1", 256 bits)
```

**Métodos**:

```java
String getAlgorithmName()
int getKeySize()
String getOID()
String getSignatureAlgorithm()
int getSecurityLevel()
```

#### `PQCAlgorithm` (Enum)

Algoritmos pós-quânticos suportados.

**Valores**:

```java
// Signature Algorithms
ML_DSA_44("ML-DSA-44", "2.16.840.1.101.3.4.3.17", 128 bits)
ML_DSA_65("ML-DSA-65", "2.16.840.1.101.3.4.3.18", 192 bits)
ML_DSA_87("ML-DSA-87", "2.16.840.1.101.3.4.3.19", 256 bits)

SLH_DSA_SHA2_128S("SLH-DSA-SHA2-128s", "2.16.840.1.101.3.4.3.20", 128 bits)
SLH_DSA_SHA2_128F("SLH-DSA-SHA2-128f", "2.16.840.1.101.3.4.3.21", 128 bits)
// ... + SHA2-192 e SHA2-256 variants

Falcon_512("Falcon-512", "1.3.9999.3.1", 128 bits)
Falcon_1024("Falcon-1024", "1.3.9999.3.4", 256 bits)

// KEM Algorithms
ML_KEM_512("ML-KEM-512", "2.16.840.1.101.3.4.4.1", 128 bits)
ML_KEM_768("ML-KEM-768", "2.16.840.1.101.3.4.4.2", 192 bits)
ML_KEM_1024("ML-KEM-1024", "2.16.840.1.101.3.4.4.3", 256 bits)
```

**Métodos**:

```java
String getName()
String getOID()
int getSecurityLevel()
int getPublicKeySize()
AlgorithmCategory getCategory()  // SIGNATURE ou KEM
```

#### `HybridAlgorithmPair` (Record)

Combina um algoritmo clássico com um PQC.

**Factory Methods**:

```java
// Get recommended pair for security level
public static HybridAlgorithmPair recommended(int securityLevel)
// 128 bits → ECDSA-P256 + ML-DSA-44
// 192 bits → ECDSA-P384 + ML-DSA-65
// 256 bits → ECDSA-P521 + ML-DSA-87

public ClassicalAlgorithm classicalAlgorithm()
public PQCAlgorithm pqcAlgorithm()
public String getDescription()  // "ECDSA-P256 + ML-DSA-65"
public boolean isSecurityBalanced()
public boolean areNistStandardized()
```

**Exemplo**:

```java
// Get recommended
HybridAlgorithmPair pair = HybridAlgorithmPair.recommended(256);

// Custom pair
HybridAlgorithmPair custom = new HybridAlgorithmPair(
    ClassicalAlgorithm.RSA_4096,
    PQCAlgorithm.ML_DSA_87
);
```

#### `HybridCertificateConfig.Builder`

Builder para configuração de certificados.

**Métodos**:

```java
public Builder withAlgorithmPair(HybridAlgorithmPair pair)
public Builder withSubjectDN(String dn)
public Builder withIssuerDN(String dn)
public Builder withValidityDays(long days)
public Builder withSerialNumber(int serial)
public Builder includePrimarySignature(boolean include)
public Builder includeAlternativeSignature(boolean include)
public HybridCertificateConfig build()
```

**Exemplo**:

```java
HybridCertificateConfig config = HybridCertificateConfig.builder()
    .withAlgorithmPair(HybridAlgorithmPair.recommended(192))
    .withSubjectDN("CN=secure.example.com,O=SecureOrg,C=US")
    .withIssuerDN("CN=Root CA,O=SecureOrg,C=US")
    .withValidityDays(730)  // 2 years
    .withSerialNumber(1001)
    .build();
```

---

### 🆔 Módulo: Registry de OIDs (`com.pqc.hybrid.core.common.oid`)

#### `AlgorithmOIDRegistry`

Registro central de OIDs para todos algoritmos.

**Constantes de OID**:

```java
// ML-DSA OIDs
String OID_ML_DSA_44 = "2.16.840.1.101.3.4.3.17"
String OID_ML_DSA_65 = "2.16.840.1.101.3.4.3.18"
String OID_ML_DSA_87 = "2.16.840.1.101.3.4.3.19"

// ML-KEM OIDs
String OID_ML_KEM_512 = "2.16.840.1.101.3.4.4.1"
String OID_ML_KEM_768 = "2.16.840.1.101.3.4.4.2"
String OID_ML_KEM_1024 = "2.16.840.1.101.3.4.4.3"

// X.509 Hybrid Extensions
String OID_ALT_SIGNATURE_ALGORITHM = "2.5.29.62"
String OID_ALT_SIGNATURE_VALUE = "2.5.29.63"
String OID_SUBJECT_ALT_PUBLIC_KEY_INFO = "2.5.29.72"
```

**Métodos de Lookup**:

```java
// Get algorithm name from OID
public static String getAlgorithmName(String oid)
// Example: getAlgorithmName("2.16.840.1.101.3.4.3.18") → "ML-DSA-65"

// Get OID from algorithm name
public static String getOID(String algorithmName)
// Example: getOID("ML-DSA-65") → "2.16.840.1.101.3.4.3.18"

// Get algorithm type
public static AlgorithmType getAlgorithmType(String oid)

// Check if PQC
public static boolean isPQC(String oid)

// Check if classical
public static boolean isClassical(String oid)

// Check if hybrid extension
public static boolean isHybridExtension(String oid)

// Dump all OIDs
public static String dumpRegistry()
```

**Exemplo**:

```java
// Resolve OID to algorithm name
String algName = AlgorithmOIDRegistry.getAlgorithmName("2.16.840.1.101.3.4.3.18");
System.out.println(algName);  // "ML-DSA-65"

// Verify it's PQC
boolean isPQC = AlgorithmOIDRegistry.isPQC("2.16.840.1.101.3.4.3.18");

// Get the reverse mapping
String oid = AlgorithmOIDRegistry.getOID("ML-DSA-65");
```

---

### ❌ Módulo: Exceções (`com.pqc.hybrid.core.exception`)

Hierarquia de exceções:

```
RuntimeException
  └── PQCHybridException (base)
      ├── CertificateException
      ├── InvalidSignatureException
      ├── InvalidKeyException
      ├── AlgorithmNotSupportedException
      └── EncapsulationException
```

**Tratamento**:

```java
try {
    HybridKeyPair keyPair = api.generateHybridKeyPair(128);
} catch (PQCHybridException e) {
    System.err.println("Erro na biblioteca: " + e.getMessage());
    e.printStackTrace();
}
```

---

## 🛠️ Compilação e Build

### Build com Maven

```bash
# Compilar
mvn clean compile

# Executar testes
mvn test

# Criar JAR
mvn package

# Gerar JavaDoc
mvn javadoc:javadoc

# Instalar em repositório local
mvn install
```

### Build com Script

```bash
# Make executable
chmod +x build.sh

# Opções disponíveis
./build.sh clean      # Limpar artifacts
./build.sh compile    # Compilar
./build.sh test       # Rodar testes
./build.sh package    # Criar JAR (default)
./build.sh install    # Instalar localmente
./build.sh javadoc    # Gerar documentação
```

---

## 📊 Tamanhos de Algoritmos (Referência)

| Algoritmo | Tipo | Chave Pública | Chave Privada | Assinatura |
|-----------|------|---------------|---------------|-----------|
| ECDSA-P256 | Classical | 91 B | 138 B | 70 B |
| RSA-2048 | Classical | 294 B | 1704 B | 256 B |
| ML-DSA-65 | PQC Sig | 1312 B | 2560 B | 2420 B |
| ML-KEM-768 | PQC KEM | 1184 B | 2400 B | 1088 B |
| SLH-DSA-SHA2-128f | PQC Sig | 32 B | 64 B | 4784 B |
| Falcon-512 | PQC Sig | 897 B | 1281 B | 666 B |

---

## 🔒 Boas Práticas de Segurança

### 1. Inicializar Antes de Usar
```java
PQCHybridCertificateAPI api = new PQCHybridCertificateAPI();
api.initialize();  // SEMPRE chamar
```

### 2. Verificar Ambas Assinaturas
```java
// Ambas devem ser válidas
if (signature.getClassicalSignature() != null &&
    signature.getPQCSignature() != null &&
    verifyBoth(signature)) {
    // OK
}
```

### 3. Armazenar Chaves Privadas Seguramente
```java
// As chaves privadas são clonadas automaticamente
// Mas não deixe em memória por tempo indeterminado
PrivateKey privKey = keyPair.getClassicalPrivateKey();
// Use e limpe
```

### 4. Validar Certificados Completamente
```java
boolean allValid = 
    HybridCertificateValidator.validateNotExpired(cert) &&
    HybridCertificateValidator.validateDNs(cert) &&
    HybridCertificateValidator.validateValidityPeriod(cert) &&
    HybridCertificateValidator.validateFull(cert, keyPair);
```

### 5. Usar Níveis de Segurança Apropriados
```java
// Para aplicações críticas:
HybridKeyPair keyPair = api.generateHybridKeyPair(256);  // máxima segurança

// Para aplicações normais:
HybridKeyPair keyPair = api.generateHybridKeyPair(192);  // bom balanço

// Para compatibilidade:
HybridKeyPair keyPair = api.generateHybridKeyPair(128);  // mínimo
```

---

## 📝 Exemplos Completos

### Exemplo 1: Gerar Certificado Completo

```java
import com.pqc.hybrid.core.api.PQCHybridCertificateAPI;
import com.pqc.hybrid.core.config.HybridCertificateConfig;
import com.pqc.hybrid.core.keygen.HybridKeyPair;
import java.security.cert.X509Certificate;

public class GenerateCertificateExample {
    public static void main(String[] args) throws Exception {
        // 1. Inicializar
        PQCHybridCertificateAPI api = new PQCHybridCertificateAPI();
        api.initialize();
        
        // 2. Gerar chaves
        HybridKeyPair keyPair = api.generateHybridKeyPair(192);
        System.out.println("Par de chaves: " + keyPair.getLabel());
        
        // 3. Configurar certificado
        HybridCertificateConfig config = HybridCertificateConfig.builder()
            .withSubjectDN("CN=secure.example.com,O=Example,C=BR")
            .withIssuerDN("CN=Example CA,O=Example,C=BR")
            .withValidityDays(365)
            .build();
        
        // 4. Gerar certificado
        X509Certificate cert = api.generateHybridCertificate(config, keyPair);
        System.out.println("Certificado para: " + cert.getSubjectDN());
        System.out.println("Válido até: " + cert.getNotAfter());
    }
}
```

### Exemplo 2: Assinar e Verificar

```java
import com.pqc.hybrid.core.api.PQCHybridCertificateAPI;

public class SignAndVerifyExample {
    public static void main(String[] args) throws Exception {
        PQCHybridCertificateAPI api = new PQCHybridCertificateAPI();
        api.initialize();
        
        // Gerar chaves
        var keyPair = api.generateHybridKeyPair(256);
        
        // Dados para assinar
        byte[] data = "Mensagem importante".getBytes();
        
        // Assinar
        var signature = api.signData(data, keyPair);
        System.out.println("Assinado com: " + signature.getLabel());
        System.out.println("  Classical: " + signature.getClassicalSignatureSize() + " B");
        System.out.println("  PQC: " + signature.getPQCSignatureSize() + " B");
        
        // Verificar
        boolean valid = api.verifySignature(data, signature, keyPair);
        System.out.println("Assinatura válida: " + valid);
        
        // Tentar com dados alterados
        byte[] tamperedData = "Mensagem alterada".getBytes();
        boolean validTampered = api.verifySignature(tamperedData, signature, keyPair);
        System.out.println("Dados alterados detectados: " + !validTampered);
    }
}
```

### Exemplo 3: Validar Certificado

```java
import com.pqc.hybrid.core.certificate.HybridCertificateValidator;
import java.security.cert.X509Certificate;

public class ValidateCertificateExample {
    public static void main(String[] args) throws Exception {
        X509Certificate cert = // ... carregar certificado
        var keyPair = // ... carregar par de chaves
        
        // Validações individuais
        System.out.println("Não expirado: " + 
            HybridCertificateValidator.validateNotExpired(cert));
        
        System.out.println("DNs válidas: " + 
            HybridCertificateValidator.validateDNs(cert));
        
        System.out.println("Período válido: " + 
            HybridCertificateValidator.validateValidityPeriod(cert));
        
        // Validação completa (inclui assinaturas)
        System.out.println("Completamente válido: " + 
            HybridCertificateValidator.validateFull(cert, keyPair));
    }
}
```

---

## 🧪 Testes

A biblioteca inclui testes unitários com JUnit 5:

```bash
# Rodar todos os testes
mvn test

# Rodar teste específico
mvn test -Dtest=HybridKeyGeneratorTest

# Com verbosidade
mvn test -X
```

Localizações de testes:
```
src/test/java/com/pqc/hybrid/core/
├── keygen/
├── signature/
├── certificate/
├── config/
└── common/
```

---

## 🔗 Documentação Relacionada

- [RFC 5280: X.509 Digital Certificates](https://tools.ietf.org/html/rfc5280)
- [NIST PQC Standardization](https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization)
- [NIST FIPS 203 (ML-KEM)](https://csrc.nist.gov/publications/fips/203/)
- [NIST FIPS 204 (ML-DSA)](https://csrc.nist.gov/publications/fips/204/)
- [NIST FIPS 205 (SLH-DSA)](https://csrc.nist.gov/publications/fips/205/)
- [BouncyCastle Documentation](https://www.bouncycastle.org/specifications.html)

---

## 📄 Licença

MIT License - Veja `LICENSE` para detalhes

---

## 👥 Contribuidores

- **Darlei** - Desenvolvedor principal

---

## 📞 Suporte

Para reportar bugs ou sugerir features:
- GitHub Issues: https://github.com/darlei-/pqc-hybrid-certificates/issues
- Email: darlei@example.com

---

**Última atualização**: April 14, 2026  
**Versão**: 1.0.0-BETA  
**Status**: Production-Ready
