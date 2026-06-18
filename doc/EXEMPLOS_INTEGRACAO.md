# Exemplos de Integração — Consumindo a API por outros projetos

Este documento mostra, de ponta a ponta, como um projeto externo consome a biblioteca
`pqc-hybrid-certificates`. Todos os trechos são alinhados ao **código atual** (não ao
Quick Start do README, que ainda mostra `signData` retornando `HybridSignaturePair` — hoje
ele retorna `byte[]`).

## O que a biblioteca entrega

- Certificados **X.509 híbridos** no modelo **Catalyst** (ITU-T X.509:2019): uma assinatura
  **clássica** (RSA/ECDSA) no campo padrão + uma assinatura **alternativa pós-quântica**
  (ML-DSA) carregada nas extensões `subjectAltPublicKeyInfo` (`2.5.29.72`),
  `altSignatureAlgorithm` (`2.5.29.73`) e `altSignatureValue` (`2.5.29.74`).
- Geração de chaves híbridas, assinatura/verificação de dados, geração de certificados e
  CSRs, criação de CA raiz, emissão e validação de cadeias.

### Requisitos do consumidor

| Item | Versão |
|------|--------|
| Java | 21+ |
| BouncyCastle | 1.84 (transitivo: `bcprov-jdk18on`, `bcpkix-jdk18on`, `bctls-jdk18on`) |

---

## Setup Maven

```xml
<dependency>
    <groupId>com.pqc.hybrid</groupId>
    <artifactId>pqc-hybrid-certificates</artifactId>
    <version>1.0.0-BETA</version>
</dependency>
```

Como a versão `1.0.0-BETA` ainda **não está publicada** em um repositório central, instale-a
no repositório Maven local a partir do checkout do projeto:

```bash
mvn -DskipTests install
```

O BouncyCastle entra como dependência transitiva — o consumidor não precisa declará-lo.

### Inicialização (uma vez por aplicação)

```java
import com.pqc.hybrid.core.api.PQCHybridCertificateAPI;
import com.pqc.hybrid.core.exception.PQCHybridException;

PQCHybridCertificateAPI api = new PQCHybridCertificateAPI();
api.initialize(); // registra o provider BouncyCastle (PQC) — chame antes de qualquer operação
System.out.println("API v" + api.getVersion()); // 1.0.0-BETA
```

> A facade `PQCHybridCertificateAPI` é o ponto de entrada de mais alto nível. Os exemplos
> abaixo reutilizam a mesma instância `api` já inicializada.

---

## Cenário 1 — Cripto core (serviço de assinatura/verificação)

Caso de uso típico: outro serviço usa a biblioteca como um "serviço de assinatura híbrida"
para proteger documentos, tokens ou payloads de mensageria.

```java
import com.pqc.hybrid.core.keygen.HybridKeyPair;
import com.pqc.hybrid.core.config.HybridAlgorithmPair;
import com.pqc.hybrid.core.config.ClassicalAlgorithm;
import com.pqc.hybrid.core.config.PQCAlgorithm;
import com.pqc.hybrid.core.exception.InvalidSignatureException;
import java.nio.charset.StandardCharsets;

// 1) Gerar par de chaves híbrido por nível de segurança (128, 192 ou 256 bits)
HybridKeyPair keyPair = api.generateHybridKeyPair(192);
// 192 -> ECDSA-P384 + ML-DSA-65
System.out.println("Par: " + keyPair.getLabel());

// (alternativa) escolher o par de algoritmos explicitamente
HybridAlgorithmPair par = new HybridAlgorithmPair(
        ClassicalAlgorithm.ECDSA_P384, PQCAlgorithm.ML_DSA_65);
HybridKeyPair keyPair2 = api.generateHybridKeyPair(par);

// 2) Assinar dados — retorna byte[] com encoding length-prefixed
//    [4 bytes BE: tamanho da assinatura clássica][sig clássica][sig PQC]
byte[] data = "documento importante".getBytes(StandardCharsets.UTF_8);
byte[] signature = api.signData(data, keyPair);

// 3) Verificar — true somente se a assinatura clássica E a PQC forem válidas (semântica AND)
boolean ok = api.verifySignature(data, signature, keyPair);
System.out.println("válida? " + ok); // true

// 4) Detecção de adulteração
byte[] forjado = "documento adulterado".getBytes(StandardCharsets.UTF_8);
boolean tampered = api.verifySignature(forjado, signature, keyPair);
System.out.println("adulterado válido? " + tampered); // false

// 5) Limpeza das chaves privadas ao terminar (best-effort)
keyPair.destroy();
```

### Assinatura com contexto (domain separation)

Útil para amarrar uma assinatura a um propósito específico (ex.: `"v1:auth"`). O contexto é
limitado a 255 bytes e precisa coincidir na verificação.

```java
byte[] ctx = "v1:auth".getBytes(StandardCharsets.UTF_8);
byte[] sig = api.signData(data, keyPair, ctx);
boolean ok = api.verifySignature(data, sig, keyPair, ctx); // mesmo ctx
```

**Exceções:** operações lançam `PQCHybridException` (base, unchecked) e, na verificação
estrutural, `InvalidSignatureException`.

---

## Cenário 2 — Certificados & CSR

### Gerar um certificado X.509 híbrido (self-signed)

```java
import com.pqc.hybrid.core.config.HybridCertificateConfig;
import com.pqc.hybrid.core.certificate.HybridCertificateValidator;
import com.pqc.hybrid.core.model.HybridCertificateInfo;
import java.security.cert.X509Certificate;

HybridCertificateConfig config = HybridCertificateConfig.builder()
        .withAlgorithmPair(HybridAlgorithmPair.recommended(192)) // ECDSA-P384 + ML-DSA-65
        .withSubjectDN("CN=servico.exemplo.com,O=Minha Empresa,C=BR")
        .withIssuerDN("CN=servico.exemplo.com,O=Minha Empresa,C=BR")
        .withValidityDays(365)
        .build();

X509Certificate cert = api.generateHybridCertificate(config, keyPair);
System.out.println("Subject: " + cert.getSubjectX500Principal().getName());
System.out.println("Válido até: " + cert.getNotAfter());
```

### Inspecionar e validar

```java
// Metadados híbridos (algoritmos, tamanhos das assinaturas/chaves, OIDs)
HybridCertificateInfo info = api.getCertificateInfo(cert, keyPair);
System.out.println("Clássico: " + info.getClassicalAlgorithm());
System.out.println("PQC: " + info.getPQCAlgorithm() + " (" + info.getPQCAlgorithmOID() + ")");

// Há as três extensões PQC (Catalyst)?
boolean temPqc = api.validatePQCExtensions(cert);

// Validação abrangente — para self-signed passe issuerPublicKey = null
HybridCertificateValidator.ValidationResult r = api.validateCertificate(cert, null);
System.out.println("clássico válido? " + r.isSignatureValid());
System.out.println("híbrido totalmente válido? " + r.isHybridFullyValid());
```

### Gerar um CSR (PKCS#10)

```java
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

PKCS10CertificationRequest csr =
        api.generateCertificateSigningRequest("CN=servico.exemplo.com,O=Minha Empresa,C=BR", keyPair);
// csr.getEncoded() para exportar em DER
```

---

## Cenário 3 — PKI / cadeias de CA

Cria uma CA raiz híbrida, emite um certificado folha e valida a cadeia completa nas duas
dimensões (clássica via PKIX e pós-quântica).

```java
import com.pqc.hybrid.core.certificate.HybridCertificateAuthority;
import java.util.List;

// 1) Chaves da CA e da folha
HybridKeyPair caKeyPair   = api.generateHybridKeyPair(192);
HybridKeyPair leafKeyPair = api.generateHybridKeyPair(192);

// 2) Config da CA raiz (note asCertificateAuthority(true))
HybridCertificateConfig caConfig = HybridCertificateConfig.builder()
        .withAlgorithmPair(HybridAlgorithmPair.recommended(192))
        .withSubjectDN("CN=Minha Root CA,O=Minha Empresa,C=BR")
        .withIssuerDN("CN=Minha Root CA,O=Minha Empresa,C=BR")
        .asCertificateAuthority(true)
        .withValidityDays(3650)
        .build();

HybridCertificateAuthority ca = api.createRootCA(caConfig, caKeyPair);

// 3) Config da folha e emissão pela CA
HybridCertificateConfig leafConfig = HybridCertificateConfig.builder()
        .withAlgorithmPair(HybridAlgorithmPair.recommended(192))
        .withSubjectDN("CN=app.exemplo.com,O=Minha Empresa,C=BR")
        .withIssuerDN("CN=Minha Root CA,O=Minha Empresa,C=BR")
        .withValidityDays(365)
        .build();

X509Certificate leaf = api.issueCertificate(ca, leafConfig, leafKeyPair);

// 4) Validar a cadeia (folha -> ... -> raiz)
HybridCertificateValidator.HybridChainValidationResult chain =
        api.validateCertificateChain(List.of(leaf, ca.getCertificate()));

System.out.println("cadeia clássica válida? " + chain.classicalValid());
System.out.println("cadeia PQC válida? "      + chain.pqcValid());
System.out.println("cadeia válida? "          + chain.isValid());
```

> Para uma **sub-CA intermediária**, emita um cert de CA pela raiz e embrulhe-o em
> `new HybridCertificateAuthority(interKeyPair, interCert)`, depois emita as folhas a partir
> dela. Veja `src/test/java/com/pqc/hybrid/core/certificate/HybridCertificateAuthorityTest.java`.

---

## Cenário 4 — HSM / KMS (Layer 1, signer-agnostic)

A biblioteca tem uma camada de baixo nível ("Layer 1") que depende **apenas** da abstração
`org.bouncycastle.operator.ContentSigner`. Isso significa que **as chaves privadas não
precisam estar em memória** — podem viver em HSM, token PKCS#11 ou um serviço de assinatura
remoto. O consumidor fornece os signers; a biblioteca apenas monta a estrutura híbrida.

Os dois signers (clássico + PQC) são agrupados em um `HybridSigner`:
- `HybridSigner.of(classical, pqc)` — híbrido completo;
- `HybridSigner.classicalOnly(classical)` — só-clássico (sem extensões PQC).

```java
import com.pqc.hybrid.core.certificate.HybridSigner;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import java.security.PublicKey;

// Exemplo "in-memory" (substitua por TokenContentSigner/HSM no caso real).
// Aqui usamos um keyPair só para extrair as chaves privadas/públicas do EMISSOR.
ContentSigner classicalSigner = new JcaContentSignerBuilder("SHA384withECDSA")
        .setProvider("BC")
        .build(caKeyPair.getClassicalPrivateKey());

ContentSigner pqcSigner = new JcaContentSignerBuilder("ML-DSA-65")
        .setProvider("BC")
        .build(caKeyPair.getPQCPrivateKey());

HybridSigner issuerSigner = HybridSigner.of(classicalSigner, pqcSigner);

// Chaves PÚBLICAS do sujeito (vindas, p.ex., de um CSR recebido)
PublicKey subjectClassicalPub = leafKeyPair.getClassicalPublicKey();
PublicKey subjectPqcPub       = leafKeyPair.getPQCPublicKey();

// Emite o certificado SEM precisar das chaves privadas do sujeito em memória
X509Certificate leaf = api.generateHybridCertificate(
        leafConfig,
        subjectClassicalPub,
        subjectPqcPub,
        issuerSigner,
        ca.getCertificate());   // certificado do emissor
```

### CSR via Layer 1

```java
PKCS10CertificationRequest csr = api.generateCertificateSigningRequest(
        "CN=app.exemplo.com,O=Minha Empresa,C=BR",
        subjectClassicalPub,
        subjectPqcPub,
        HybridSigner.of(classicalSigner, pqcSigner));
```

> **Caso real:** no CZERTAINLY-Core os dois `ContentSigner` seriam instâncias de
> `TokenContentSigner` que delegam a um conector criptográfico externo — exatamente o
> padrão que esta Layer 1 habilita (ver Javadoc de `HybridSigner`). Para o caminho
> só-clássico, use `HybridSigner.classicalOnly(classicalSigner)`.

---

## Apêndice

### Pares de algoritmos recomendados (`HybridAlgorithmPair.recommended(n)`)

| Nível de segurança | Clássico | PQC |
|--------------------|----------|-----|
| 128 | ECDSA-P256 | ML-DSA-44 |
| 192 | ECDSA-P384 | ML-DSA-65 |
| 256 | ECDSA-P521 | ML-DSA-87 |

`ClassicalAlgorithm` também oferece `RSA_2048`, `RSA_3072`, `RSA_4096`. `PQCAlgorithm` inclui
ainda variantes SLH-DSA e Falcon, além dos ML-KEM (encapsulamento, não-assinatura).

### OIDs das extensões Catalyst

| Extensão | OID |
|----------|-----|
| `subjectAltPublicKeyInfo` | `2.5.29.72` |
| `altSignatureAlgorithm` | `2.5.29.73` |
| `altSignatureValue` | `2.5.29.74` |

### Exemplos executáveis no repositório

- `src/main/java/com/pqc/hybrid/examples/GenerateCertificateExample.java`
- `src/main/java/com/pqc/hybrid/examples/SignAndVerifyExample.java`
- `src/main/java/com/pqc/hybrid/examples/HybridCertificateGenerationExample.java`
- `src/main/java/com/pqc/hybrid/examples/AlgorithmExplorerExample.java`

E os testes de integração em `src/test/java/com/pqc/hybrid/core/api/PQCHybridCertificateAPITest.java`
servem como referência viva de uso ponta a ponta.
