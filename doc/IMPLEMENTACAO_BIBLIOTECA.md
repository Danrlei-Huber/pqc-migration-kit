# 5. Implementação da Biblioteca Criptográfica

> **Base de documentação para o Capítulo 5 do TCC.** Cada seção responde a um item do
> roteiro (5.1 a 5.6) e está ancorada em classes reais do repositório `pqc-migration-kit`.
> Marcadores `[medir]` indicam números que dependem de execução de benchmark e devem ser
> preenchidos quando os medidores forem rodados (ver Apêndice B).

---

## 5.1 Visão Geral da Implementação

### 5.1.1 Objetivo

A biblioteca `pqc-migration-kit` foi concebida para **apoiar a transição da infraestrutura de
chave pública (PKI) baseada em X.509 para algoritmos resistentes a computação quântica** (PQC), sem
romper a compatibilidade com a base instalada de verificadores clássicos. Em vez de substituir os
algoritmos clássicos (RSA, ECDSA), a abordagem é **carregar, no mesmo certificado X.509v3, uma
segunda chave e uma segunda assinatura pós-quânticas**, de modo que a autenticidade do certificado
sobrevive tanto à quebra futura da criptografia clássica (cenário "Q-Day") quanto à descoberta de
vulnerabilidades nos algoritmos PQC ainda jovens — só é necessário que **um dos dois ramos**
permaneça seguro.

### 5.1.2 Escopo

A biblioteca, entregue como JAR Maven (sem dependências de containers, banco de dados ou
servidores de aplicação), implementa:

- **Geração de pares de chaves híbridos** (clássica + PQC) em uma única operação;
- **Emissão de certificados X.509v3 híbridos** segundo o modelo *Catalyst* (ITU-T X.509 2019);
- **Emissão de requisições PKCS#10 (CSR) híbridas**;
- **Operação como Autoridade Certificadora (CA) híbrida**, com raiz auto-assinada e emissão de
  certificados subordinados (sub-CAs e end-entity);
- **Validação ponto a ponto** (validade temporal, DN, chave pública, assinatura clássica,
  presença e validade das extensões PQC, assinatura PQC alternativa);
- **Validação de cadeia de confiança** em duas dimensões: PKIX clássico do JDK + caminho
  pós-quântico via verificação iterativa da alt-signature;
- **Operações criptográficas avulsas**: assinatura híbrida (dupla) sobre dados arbitrários,
  verificação correspondente;
- **Exportação** de certificados nos formatos PEM e DER;
- **Integração com signatários externos** (HSM, KMS, tokens) via uma camada signer-agnostic
  ("Layer 1") na qual a chave privada nunca precisa entrar na JVM.

Estão **fora do escopo** desta versão:

- Serialização de pares híbridos em PKCS#12 / JKS — os formatos legados não modelam
  canonicamente chaves ML-DSA, e o cenário-alvo (Layer 1) é o de chaves residentes em HSM;
- Encapsulamento de chave (KEM) ligado ao caminho de certificado — o algoritmo ML-KEM (FIPS 203)
  está presente como infraestrutura experimental, mas não é exercitado pela API principal;
- Protocolos de gerenciamento (ACME, SCEP, CMP) — a biblioteca é signer-agnostic e foi
  desenhada para ser consumida por essas camadas, não para implementá-las;
- Caminho híbrido alternativo *Composite* (draft IETF lamps-pq-composite-sigs-18) — implementado
  em paralelo como referência de pesquisa, porém **não ligado** à API pública.

### 5.1.3 Tecnologias utilizadas

| Camada | Tecnologia | Versão | Papel |
|---|---|---|---|
| Linguagem | Java | 21 LTS | Records, sealed types, pattern matching |
| Build | Maven | 3.9.x | Lifecycle padrão; JAR único |
| Cripto-padrão (API) | JCA / JCE | JDK 21 | `java.security.Signature`, `KeyPairGenerator`, `CertPathValidator` |
| Provider criptográfico | BouncyCastle (`bcprov-jdk18on`, `bcpkix-jdk18on`) | 1.84 | Implementação de ML-DSA, ML-KEM, SLH-DSA, RSA, ECDSA, X.509v3 builder |
| Cobertura | JaCoCo | 0.8.10 | Gate de 75% linha por pacote/bundle |
| Testes | JUnit 5, AssertJ | — | 246 testes (234 unit + 12 integração) |
| Benchmarks | JMH (OpenJDK) | — | `AbstractPQCBenchmark` baseado em `@State`/`@Warmup`/`@Measurement`/`@Fork` |
| Logging | `java.util.logging` | — | Sem dependência de framework externo |

A escolha do **BouncyCastle 1.84** como provider único é estratégica: é a implementação Java mais
madura dos algoritmos NIST 2024 (FIPS 203/204/205) e expõe as duas APIs necessárias — JCA padrão
(`Signature`, `KeyPairGenerator`) e a camada de construção X.509v3 com suporte nativo a *alternative
signature* via `X509v3CertificateBuilder.build(primary, true, altSigner)`.

### 5.1.4 Requisitos funcionais e não funcionais

**Requisitos funcionais (RF).** A biblioteca deve permitir ao consumidor:

| ID | Requisito | Implementação |
|---|---|---|
| RF1 | Gerar par de chaves híbrido a partir de um par de algoritmos | `HybridKeyGenerator.generate(HybridAlgorithmPair)` |
| RF2 | Emitir certificado X.509v3 auto-assinado e assinado por CA | `HybridX509CertificateBuilder`, `HybridCertificateAuthority` |
| RF3 | Emitir CSR PKCS#10 híbrido | `CertificateSigningRequestBuilder` |
| RF4 | Assinar dados arbitrários com assinatura dupla | `HybridSignatureManager.sign` |
| RF5 | Verificar assinatura dupla (ambos os ramos devem validar) | `HybridSignatureManager.verify` |
| RF6 | Validar um certificado de forma compreensiva | `HybridCertificateValidator.validateComprehensive` |
| RF7 | Validar uma cadeia de certificados em dois eixos (clássico + PQC) | `HybridCertificateValidator.validateHybridChain` |
| RF8 | Exportar certificado em PEM ou DER | `CertificateExporter` |
| RF9 | Aceitar signatários externos (HSM/KMS/token) sem expor a chave privada | API Layer 1: `HybridSigner` (record com dois `ContentSigner`) |

**Requisitos não funcionais (RNF).**

| ID | Requisito | Como é atendido |
|---|---|---|
| RNF1 | Conformidade com FIPS 204 (ML-DSA) | Algoritmo PQC via JCA + provider BC; nomes canônicos `ML-DSA-44/65/87` |
| RNF2 | Conformidade com ITU-T X.509 (2019) *alternative signature* | OIDs `2.5.29.72/.73/.74`; assinatura alt sobre o *pre-TBS* |
| RNF3 | Cobertura de testes ≥ 75% | Gate JaCoCo enforça por pacote e por bundle (estado atual: ~83% linha) |
| RNF4 | Provedor criptográfico abstraído | `CryptographicProviderFactory` com inicialização idempotente |
| RNF5 | Thread-safety | Caminho ativo composto por classes utilitárias estáticas e *records* — sem estado mutável compartilhado |
| RNF6 | API estável e versionada | Pacote raiz `com.pqc.hybrid.core.api`; versão `1.0.0-BETA` no `pom.xml` |
| RNF7 | Falha rápida na ausência de algoritmo crítico | `CryptographicProviderFactory.validateRequiredAlgorithms()` consulta a JCA durante `initialize()` |

---

## 5.2 Arquitetura da Solução

### 5.2.1 Visão em alto nível

A biblioteca é estratificada em quatro camadas conceituais. Cada camada **só conhece** a imediata
abaixo, o que mantém o acoplamento baixo e permite trocar o provedor BC por outro sem mexer no
núcleo da lógica de negócio.

```
┌────────────────────────────────────────────────────────────────────────┐
│  APLICAÇÃO CONSUMIDORA                                                 │
└────────────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
┌────────────────────────────────────────────────────────────────────────┐
│  CAMADA DE FACHADA (API pública)                                       │
│                                                                        │
│     PQCHybridCertificateAPI                                            │
│     · initialize / isInitialized                                       │
│     · generateHybridKeyPair(securityLevel | algorithmPair)             │
│     · signData / verifySignature                                       │
│     · generateHybridCertificate (Layer 1 + Layer 2)                    │
│     · generateCertificateSigningRequest (Layer 1 + Layer 2)            │
│     · createRootCA / issueCertificate                                  │
│     · validateCertificate / validateCertificateChain                   │
│                                                                        │
└────────────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
┌────────────────────────────────────────────────────────────────────────┐
│  CAMADA CORE (lógica híbrida)                                          │
│                                                                        │
│   ┌──────────────────────┐   ┌─────────────────────────────────────┐  │
│   │ HybridKeyGenerator    │   │ HybridX509CertificateBuilder         │  │
│   │ (par clássico + PQC)  │   │ Catalyst, Layer 1 + Layer 2          │  │
│   └──────────────────────┘   └─────────────────────────────────────┘  │
│   ┌──────────────────────┐   ┌─────────────────────────────────────┐  │
│   │ HybridSignatureMgr   │    │ HybridCertificateValidator           │  │
│   │ (Dual, sobre dados)   │   │ (validação ponto a ponto + cadeia)   │  │
│   └──────────────────────┘   └─────────────────────────────────────┘  │
│   ┌──────────────────────┐   ┌─────────────────────────────────────┐  │
│   │ CertificateSigning    │   │ HybridCertificateAuthority           │  │
│   │ RequestBuilder (CSR)  │   │ (createRoot, issueCertificate)       │  │
│   └──────────────────────┘   └─────────────────────────────────────┘  │
│                                                                        │
│   Strategy:                                                            │
│      HybridSignatureStrategy ── DualSignatureStrategy       (ATIVA)    │
│                              └─ CompositeSignatureStrategy  (EXPERIM.) │
└────────────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
┌────────────────────────────────────────────────────────────────────────┐
│  CAMADA CRIPTO-PRIMITIVA (operações PQC centralizadas)                 │
│                                                                        │
│     MLDSASigner / MLDSAVerifier                                        │
│     (fonte única de ML-DSA: variante explícita ML-DSA-44/65/87)        │
│                                                                        │
└────────────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
┌────────────────────────────────────────────────────────────────────────┐
│  CAMADA DE PROVEDOR CRIPTOGRÁFICO                                      │
│                                                                        │
│     CryptographicProviderFactory  →  BouncyCastleProvider 1.84         │
│     (java.security.Signature / KeyPairGenerator / Cipher via JCA)      │
│                                                                        │
└────────────────────────────────────────────────────────────────────────┘
```

### 5.2.2 Camadas

**Fachada (`com.pqc.hybrid.core.api`).** Ponto único de entrada. `PQCHybridCertificateAPI` é
uma classe regular instanciável (não singleton) que carrega uma estratégia de assinatura híbrida
e exige `initialize()` antes do uso — esse `initialize` registra o provedor BC e valida a
disponibilidade dos algoritmos necessários. A fachada não contém lógica criptográfica; apenas
delega.

**Core (`com.pqc.hybrid.core.{certificate,signature,keygen,model,config}`).** Reúne a lógica
de negócio híbrida: como gerar um par classical+PQC, como construir um cert X.509v3 com as três
extensões Catalyst, como validar cada peça de um cert, como percorrer uma cadeia em dois eixos.
Tudo dessa camada é stateless ou usa imutáveis (*records* e *builders*).

**Cripto-primitiva (`com.pqc.hybrid.core.signature.ml_dsa`).** Concentra as chamadas ML-DSA do
projeto. Sua existência reduz triplicação: antes da centralização, três pontos do core chamavam
`Signature.getInstance("ML-DSA-…")` independentemente; hoje todos delegam a `MLDSASigner` /
`MLDSAVerifier`, que assumem a variante específica (44, 65 ou 87) explícita.

**Provedor (`com.pqc.hybrid.core.config.CryptographicProviderFactory`).** Único ponto de contato
com o BouncyCastle. Registra `BouncyCastleProvider`, cacheia a referência, e expõe
`getProvider()` ao restante do código. `validateRequiredAlgorithms()` verifica a presença de
ML-DSA-44/65/87 e falha cedo se o provider estiver mal-configurado.

### 5.2.3 Padrões de projeto utilizados

Foram aplicados padrões clássicos do GoF e idiomáticos da plataforma Java, sempre com **propósito
funcional** (não decorativo).

| Padrão | Onde aparece | Função no projeto |
|---|---|---|
| **Strategy** | `HybridSignatureStrategy` (interface) com `DualSignatureStrategy` (ativa) e `CompositeSignatureStrategy` (experimental) | Permite trocar a álgebra híbrida (assinatura dupla independente vs. assinatura composta segundo IETF) sem mexer na fachada; a fachada pode receber a estratégia por construtor |
| **Factory (Singleton-like)** | `CryptographicProviderFactory.initialize() / getProvider()` | Centraliza o registro do BouncyCastle; idempotente, cacheia a referência |
| **Factory Method (JCA)** | `Signature.getInstance(name, provider)`, `KeyPairGenerator.getInstance(name, provider)` (usados via `MLDSASigner`, `HybridSignatureManager`, `HybridKeyGenerator`) | Criação de objetos cripto sem que o chamador conheça o provider concreto |
| **Builder** | `HybridCertificateConfig.builder()`; `HybridX509CertificateBuilder` (API de instância); `HybridCertificateInfo.builder()`; `HybridCertificateValidator.ValidationResult.Builder` | Construção declarativa de objetos com muitos parâmetros opcionais (DNs, validade, SANs, flag de CA, *path length*, etc.) |
| **Adapter** | `HybridSigner` (record agrega dois `ContentSigner` do BC numa abstração de assinatura híbrida); `MLDSASigner`/`MLDSAVerifier` (adaptam o contrato interno da lib a `java.security.Signature` da JCA); `CompositeSigner` (caminho experimental, adapta para a primitiva composta do BC) | Mantém a API da lib estável independentemente da evolução do BC; viabiliza signers externos (HSM, KMS, token) sem o BC saber disso |
| **Facade** | `PQCHybridCertificateAPI` | Reduz ~10 classes do core a ~20 métodos de uma única classe pública |
| **Static Utility (com construtor proibido)** | `HybridSignatureManager`, `HybridCertificateValidator`, `MLDSASigner`, `MLDSAVerifier`, `HybridKeyGenerator` | Operações puras; thread-safety natural; sem ciclo de vida a gerenciar |
| **Record (imutável)** | `HybridSigner`, `EncapsulationResult`, `HybridChainValidationResult` | Valor imutável com `equals/hashCode/toString` derivados, idiomático em Java 21 |
| **Two-Layer API** (variante de *Bridge*) | `HybridX509CertificateBuilder` expõe um método estático *Layer 1* (signatário externo, sem chave privada na JVM) e uma API de instância *Layer 2* (conveniência, signers in-memory derivados de `HybridKeyPair`) | Atende dois cenários — produção (HSM) e desenvolvimento/teste (in-memory) — sem duplicação |

---

## 5.3 Modelagem dos Certificados Híbridos

### 5.3.1 Estrutura do certificado X.509v3 tradicional

O ITU-T X.509 / RFC 5280 define o certificado como uma estrutura ASN.1:

```
Certificate ::= SEQUENCE {
    tbsCertificate       TBSCertificate,         -- payload assinado
    signatureAlgorithm   AlgorithmIdentifier,    -- algoritmo da assinatura primária
    signatureValue       BIT STRING              -- bytes da assinatura primária
}

TBSCertificate ::= SEQUENCE {
    version           [0]  Version DEFAULT v1,   -- v3 para este projeto
    serialNumber           CertificateSerialNumber,
    signature              AlgorithmIdentifier,  -- redundante com o de fora
    issuer                 Name,
    validity               Validity,             -- notBefore, notAfter
    subject                Name,
    subjectPublicKeyInfo   SubjectPublicKeyInfo, -- chave PRIMÁRIA (clássica)
    issuerUniqueID    [1]  IMPLICIT BIT STRING OPTIONAL,
    subjectUniqueID   [2]  IMPLICIT BIT STRING OPTIONAL,
    extensions        [3]  EXPLICIT Extensions OPTIONAL  -- 0..n extensões
}
```

A biblioteca emite cada certificado como **v3** (com `extensions`) e popula um conjunto fixo de
extensões clássicas via `HybridX509CertificateBuilder.addExtensions`:

| Extensão | OID | Criticality | Conteúdo |
|---|---|---|---|
| Subject Key Identifier | 2.5.29.14 | non-critical | hash da chave pública clássica do *subject* |
| Authority Key Identifier | 2.5.29.35 | non-critical | hash da chave pública do *issuer* (do cert do issuer, ou autodef.) |
| Key Usage | 2.5.29.15 | **critical** | `digitalSignature` + (CA: `keyCertSign`/`cRLSign`) ou (leaf: `nonRepudiation`) |
| Basic Constraints | 2.5.29.19 | **critical** | `CA=true` para CA com *path length* configurável; `CA=false` para leaf |
| Extended Key Usage | 2.5.29.37 | non-critical | apenas em leaf: `serverAuth` + `clientAuth` |
| Subject Alternative Name | 2.5.29.17 | non-critical | DNS names e endereços IP (IPv4/IPv6 inferidos por *regex*) |

### 5.3.2 Extensões adotadas para o caminho pós-quântico (modelo *Catalyst*)

A estratégia híbrida adotada pela biblioteca segue o modelo **ITU-T X.509 (2019) — Catalyst /
alternative signature**, que adiciona três extensões X.509v3 ao certificado:

| Extensão | OID | Conteúdo | Onde |
|---|---|---|---|
| `subjectAltPublicKeyInfo` | **2.5.29.72** | `SubjectPublicKeyInfo` (RFC 5280) carregando a chave pública **pós-quântica** do *subject* | adicionada explicitamente pelo builder |
| `altSignatureAlgorithm` | **2.5.29.73** | `AlgorithmIdentifier` da assinatura PQC alternativa | emitida automaticamente pelo BC ao usar `build(primary, true, altSigner)` |
| `altSignatureValue` | **2.5.29.74** | `BIT STRING` com a assinatura PQC sobre o *pre-TBS* | idem |

O **pre-TBS** é uma variante do TBSCertificate que omite o campo `signature` (`AlgorithmIdentifier`)
e a própria extensão `altSignatureValue` — caso contrário, a assinatura cobriria a si mesma. A
reconstrução desse pre-TBS para validação é feita em
`HybridCertificateValidator.reconstructPreTBS()` usando `V3TBSCertificateGenerator.generatePreTBSCertificate()`
do BC, removendo a extensão `altSignatureValue` antes da regeneração.

### 5.3.3 Estratégia híbrida adotada

Existem três estratégias híbridas frequentemente discutidas na literatura. A biblioteca adota a
primeira e mantém referência à segunda; a terceira está fora do escopo de certificados.

| Estratégia | Como funciona | Onde está no projeto |
|---|---|---|
| **Assinatura dupla independente (*Dual* / Catalyst)** | Duas chaves separadas, duas assinaturas separadas. O certificado é válido se **ambas** as assinaturas verificarem. Sobrevive à quebra de qualquer um dos dois algoritmos. | **Caminho ativo.** `DualSignatureStrategy`, `HybridX509CertificateBuilder` (Catalyst), `HybridSignatureManager`, `MLDSASigner`/`MLDSAVerifier` |
| **Assinatura composta (*Composite*)** | Uma chave composta (par clássico + PQC concatenado) e uma assinatura composta única, computada por uma função de domínio próprio (draft IETF `lamps-pq-composite-sigs-18`). Resistente ao chamado *stripping attack*. | Caminho **experimental**. `CompositeSignatureStrategy`, `CompositeSigner`, `CompositeVerifier`, `CompositeKeyGenerator` — não ligado à API pública |
| **Encapsulamento de chave híbrida (KEM)** | Mecanismo de **troca de chaves**, não de assinatura. Combina X25519/ECDH com ML-KEM. | Caminho **experimental** e **não relacionado a certificados**. `kem.ml_kem.MLKEMEncapsulator/Decapsulator`, `KeyEncapsulationWrapper` |

A escolha do modelo Catalyst foi orientada por três fatores:

1. **Compatibilidade transicional com PKIX**: a assinatura primária permanece sendo a clássica, no
   campo `signature` padrão do X.509; verificadores PKIX que ignoram as extensões críticas .73/.74
   continuam interpretando o certificado normalmente como um cert clássico.
2. **Independência criptográfica**: as duas chaves são geradas e usadas independentemente, sem
   dependência de uma função de derivação ad-hoc (como a de Composite, ainda em padronização).
3. **Suporte nativo no BouncyCastle 1.84**: a sobrecarga `X509v3CertificateBuilder.build(primary,
   useAltSig=true, altSigner)` faz a maior parte do trabalho de codificação do pre-TBS e da emissão
   das extensões .73/.74.

### 5.3.4 Representação interna na biblioteca

Os principais tipos do modelo de dados:

```
HybridKeyPair                           HybridSignaturePair
  · classicalPublicKey                    · classicalSignature  byte[]
  · classicalPrivateKey                   · pqcSignature        byte[]
  · pqcPublicKey                          · classicalAlgorithm
  · pqcPrivateKey                         · pqcAlgorithm
  · classicalAlgorithm (String)           · dataHash            byte[]
  · pqcAlgorithm       (String)

HybridSigner (record)                   HybridCertificateConfig (Builder)
  · classical : ContentSigner             · subjectDN / issuerDN
  · pqc       : ContentSigner (nullable)  · validityDays / serialNumber
                                          · algorithmPair
                                          · subjectAltNames (DNS/IP)
                                          · isCertificateAuthority + pathLen

HybridCertificateInfo                   ValidationResult / HybridChainValidationResult
  · certificate                           · 7 booleans por checagem + isAllValid()
  · classical/pqc algorithm               · classicalValid + pqcValid + isValid()
  · pqcPublicKeyBytes
  · pqcSignature
  · pqcExtensions (PQCExtensionsStructure)
```

---

## 5.4 Seleção e Integração de Algoritmos PQC

### 5.4.1 Critérios de escolha

| Critério | Como foi aplicado |
|---|---|
| **Padronização (NIST PQC 2024)** | Priorizamos algoritmos efetivamente finalizados em padrão FIPS antes de algoritmos em draft. Em ordem de maturidade: **ML-DSA (FIPS 204)**, **ML-KEM (FIPS 203)**, **SLH-DSA (FIPS 205)**, Falcon (FIPS 206 — em draft no momento da escrita). |
| **Performance** | Para assinatura digital em certificado, ML-DSA oferece o melhor *trade-off* tamanho × velocidade × maturidade. SLH-DSA, embora conservador (baseado em hash, não em problemas matemáticos potencialmente vulneráveis), tem assinaturas uma ordem de grandeza maiores e custo de assinatura significativamente superior. Falcon tem assinatura compacta mas implementação delicada (*Gaussian sampling*, *floating point*) e maturidade menor no ecossistema Java. |
| **Segurança / paralelismo com clássicos** | ML-DSA tem três variantes mapeadas aos níveis de segurança NIST (categoria 2/3/5), o que permite parear naturalmente com RSA-2048/3072/4096 e curvas P-256/P-384/P-521. |

### 5.4.2 Algoritmos efetivamente adotados

**Caminho ativo da biblioteca:**

| Tipo | Algoritmo | Variantes implementadas | Padrão |
|---|---|---|---|
| Assinatura clássica | **RSA** | RSA-2048, RSA-3072, RSA-4096 (com SHA-256, SHA-384, SHA-512) | PKCS #1 v2.1 |
| Assinatura clássica | **ECDSA** | secp256r1 (P-256), secp384r1 (P-384), secp521r1 (P-521) | ANSI X9.62 / FIPS 186-4 |
| Assinatura PQC | **ML-DSA** | ML-DSA-44, ML-DSA-65, ML-DSA-87 | **FIPS 204** (formalmente Dilithium nos drafts iniciais) |

**Algoritmos disponíveis no enum `PQCAlgorithm` mas não exercitados pelo caminho ativo:**

| Algoritmo | Estado | Localização |
|---|---|---|
| ML-KEM (ex-Kyber) | KEM, **experimental**, não ligado ao path de cert | `kem.ml_kem.MLKEMEncapsulator/Decapsulator` |
| SLH-DSA (ex-SPHINCS+) | enum presente, sem teste de uso no path ativo | `config.PQCAlgorithm` |
| Falcon | enum presente, sem teste de uso no path ativo | `config.PQCAlgorithm` |

Os pares classical+PQC recomendados são fornecidos por
`HybridAlgorithmPair.recommended(securityBits)`:

```
128 bits → ECDSA P-256 + ML-DSA-44
192 bits → ECDSA P-384 + ML-DSA-65
256 bits → ECDSA P-521 + ML-DSA-87
```

### 5.4.3 Integração com bibliotecas externas

Toda a cripto-primitiva é acessada **exclusivamente pela JCA**:

```java
// Geração — em HybridKeyGenerator.generatePQCKeyPair
KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-DSA-44", provider);
KeyPair pqcKeyPair = kpg.generateKeyPair();

// Assinatura — em MLDSASigner.sign
Signature signer = Signature.getInstance(algorithm, provider);
signer.initSign(privateKey);
signer.update(data);
byte[] sig = signer.sign();
```

O `provider` é a referência cacheada por `CryptographicProviderFactory`, que **registra o
`BouncyCastleProvider` apenas se ainda não estiver registrado** e exposta exclusivamente após
`initialize()`. Essa indireção é o que isola toda a biblioteca de detalhes do BC: trocar o provider
no futuro (por exemplo, por um provider PKCS#11 ou por um provider FIPS-certificado) exige editar
**uma única classe**.

Para a construção do certificado, a biblioteca usa a camada `bcpkix` do BC (X.509v3 builder,
PKCS#10 builder), porque a JCA padrão não expõe a sobrecarga *alternative signature*. Essa
dependência é encapsulada por `HybridX509CertificateBuilder` e por `CertificateSigningRequestBuilder`.

---

## 5.5 Implementação dos Módulos Principais

### 5.5.1 Geração de Chaves

**Fluxo geral**:

```
HybridAlgorithmPair(ClassicalAlgorithm, PQCAlgorithm)
        │
        ▼
HybridKeyGenerator.generate()
        │
        ├── generateClassicalKeyPair() ─── JCA KeyPairGenerator.getInstance("RSA"|"ECDSA", BC)
        │       · RSA: initialize(keySize, SecureRandom)
        │       · ECDSA: initialize(ECGenParameterSpec(curveName), SecureRandom)
        │       └── KeyPair (clássico)
        │
        └── generatePQCKeyPair() ──────── JCA KeyPairGenerator.getInstance("ML-DSA-…", BC)
                · sem .initialize() — BC usa parâmetros internos da variante
                └── KeyPair (PQC)
        │
        ▼
HybridKeyPair (classical pub/priv + pqc pub/priv + nomes dos algoritmos)
```

**Armazenamento.** A biblioteca não persiste pares de chaves híbridos. O `HybridKeyPair` é um
objeto Java imutável; o consumidor decide a estratégia de armazenamento. Para o cenário de
**produção com HSM/KMS**, a biblioteca oferece a API Layer 1: o consumidor fornece dois
`ContentSigner` (encapsulando o acesso ao HSM) e a biblioteca nunca toca a chave privada.

Para o cenário de **desenvolvimento/teste**, o `CertificateExporter` exporta o certificado em
PEM (texto base64 com `-----BEGIN CERTIFICATE-----`) e DER (binário ASN.1) — porém **não** exporta
a chave privada, decisão consciente discutida em 5.6.2.

### 5.5.2 Emissão de Certificados

**Criação de CSR (PKCS#10 híbrido).** `CertificateSigningRequestBuilder` produz uma requisição de
assinatura PKCS#10 contendo (i) a chave pública clássica do *subject* no campo padrão; (ii) a chave
pública PQC no atributo *altSubjectPublicKeyInfo*; (iii) a assinatura clássica primária; (iv) a
assinatura alternativa PQC sobre o `CertificationRequestInfo` modificado. O BC fornece a sobrecarga
`PKCS10CertificationRequestBuilder.build(primary, altSPKI, altSigner)`.

**Inclusão das extensões PQC e assinatura híbrida** (em `HybridX509CertificateBuilder.build`):

```
1. JcaX509v3CertificateBuilder(issuer, serial, notBefore, notAfter,
                               subject, classicalPublicKey)
2. Adiciona extensões clássicas (SKI, AKI, KeyUsage, BasicConstraints,
                                 ExtendedKeyUsage [leaf only], SAN)
3. Adiciona subjectAltPublicKeyInfo (2.5.29.72) com SPKI da chave PQC
4. holder = certBuilder.build(classicalContentSigner, /*useAltSig=*/true,
                              pqcContentSigner)
   ↑ BC nativo:
     · computa assinatura primária sobre TBSCertificate
     · computa assinatura alternativa sobre pre-TBS (sem signature field e
       sem altSignatureValue)
     · emite altSignatureAlgorithm (2.5.29.73) com o AlgorithmIdentifier
       extraído do pqcContentSigner
     · emite altSignatureValue (2.5.29.74) com a assinatura alternativa
5. JcaX509CertificateConverter.getCertificate(holder)  → X509Certificate
```

**Layer 1 vs Layer 2.** O mesmo método tem duas portas de entrada:

- **Layer 1 (estático)**: `HybridX509CertificateBuilder.build(config, classicalPubKey, pqcPubKey,
  HybridSigner, issuerCert)` — o consumidor fornece os `ContentSigner` já prontos. Em produção
  esses signatários geralmente vivem dentro de um HSM ou token. O caso `pqc == null` produz
  certificado clássico-só (sem as extensões Catalyst).
- **Layer 2 (instância)**: `new HybridX509CertificateBuilder(config, keyPair).build()` — a
  biblioteca constrói `JcaContentSigner` em memória a partir das chaves privadas do
  `HybridKeyPair` e chama Layer 1. Conveniente para testes e ferramentas internas.

**CA híbrida.** `HybridCertificateAuthority`:

- `createRoot(caConfig, caKeyPair)` — emite o certificado raiz auto-assinado (com
  `BasicConstraints CA=true`).
- `issueCertificate(subjectConfig, subjectKeyPair)` — emite um cert assinado por esta CA
  (`withIssuer(caKeyPair, caCertificate)` no builder). Aceita tanto sub-CAs (basta
  `subjectConfig.asCertificateAuthority(true)` com *path length*) quanto certificados end-entity.

### 5.5.3 Validação de Certificados

**Verificações ponto a ponto** (todas em `HybridCertificateValidator`, métodos estáticos, retornando
`boolean`):

| Método | O que verifica |
|---|---|
| `validateNotExpired(cert)` | `cert.checkValidity()` do JDK (fail-fast para expirado / ainda-não-válido) |
| `validateDNs(cert)` | Subject e Issuer DN não vazios (via `getSubjectX500Principal()`) |
| `validateValidityPeriod(cert)` | agora ∈ [`notBefore`, `notAfter`] |
| `validatePublicKey(cert)` | chave pública não-nula, codificável |
| `validateSignature(cert, issuerPubKey)` | `cert.verify(issuerPubKey)` — assinatura **clássica** |
| `validatePQCExtensions(cert)` | presença das três extensões Catalyst (.72, .73, .74) |
| `verifyAltSignature(cert, issuerAltPubKey)` | reconstrói o pre-TBS e verifica a assinatura PQC via `MLDSAVerifier` |

**Validação agregada.** `validateComprehensive(cert, issuerPublicKey?, hybridKeyPair?)` retorna um
`ValidationResult` (objeto-valor com sete *booleans* e um `isAllValid()` agregado).

**Cadeia de confiança híbrida** (`validateHybridChain(chain)` →
`HybridChainValidationResult(classicalValid, pqcValid)`):

- **Eixo clássico**: usa `CertPathValidator.getInstance("PKIX", "BC")` do JDK com um
  `PKIXCertPathChecker` customizado (`HybridExtensionChecker`) que registra as três OIDs Catalyst
  como *handled*. Sem esse checker, o PKIX rejeitaria a cadeia por *unhandled critical extension*
  (o BC marca .73/.74 como critical).
- **Eixo pós-quântico**: walk explícito leaf→root. Em cada elo, extrai a *alternative public key*
  do issuer (`subjectAltPublicKeyInfo` do cert do issuer) e verifica a alt-signature do filho via
  `MLDSAVerifier.verify(preTBS, altSig, issuerAltKey, algorithmName)`.

A cadeia é considerada válida apenas se **ambos os eixos** verificarem.

**Compatibilidade com sistemas legados.** Verifiers PKIX que **não** registram as três OIDs como
*handled* (caso de `openssl verify` e da maioria das ferramentas de produção atuais) rejeitarão a
cadeia. Essa é uma limitação consciente do BC nativo (que marca as extensões como críticas) e é
discutida em 5.6.1.

### 5.5.4 Operações Criptográficas

**Assinatura digital híbrida (dupla) sobre dados arbitrários**
(`HybridSignatureManager.sign(data, keyPair)`):

```
1. classicalAlgorithm = ClassicalAlgorithm.getSignatureAlgorithmForName(name)
   sigC = Signature.getInstance(classicalAlgorithm, BC)
   sigC.initSign(classicalPrivateKey); sigC.update(data)
   classicalSignature = sigC.sign()

2. pqcSignature = MLDSASigner.sign(data, pqcPrivateKey, pqcAlgorithmName)
   ↓ delega para: Signature.getInstance("ML-DSA-44|65|87", BC)

3. return new HybridSignaturePair(classicalSignature, pqcSignature,
                                  classicalAlgo, pqcAlgo, sha256(data))
```

**Verificação correspondente** (`HybridSignatureManager.verify`): retorna
`classicalValid && pqcValid`. A falha em **qualquer** dos dois ramos invalida o conjunto. Esta é
a propriedade central da assinatura híbrida: ela resiste à quebra de **um** dos algoritmos.

**Troca de chaves via KEM (experimental).** Caminho não ligado ao path de cert.
`MLKEMEncapsulator.encapsulate(publicKey)` → `EncapsulationResult(ciphertext, sharedSecret)`;
`MLKEMDecapsulator.decapsulate(ciphertext, privateKey)` → `sharedSecret`. Caso de uso típico:
TLS 1.3 hybrid key-exchange (X25519+ML-KEM), fora do escopo do certificado em si.

---

## 5.6 Desafios e Soluções Adotadas

### 5.6.1 Compatibilidade com X.509 e PKIX

**Desafio.** ITU-T X.509 (2019) introduz as três extensões Catalyst mas deixa **ambígua** a
criticality recomendada. O BouncyCastle 1.84 marca `altSignatureAlgorithm` (.73) e
`altSignatureValue` (.74) como **critical** quando o certificado é construído pela sobrecarga
nativa `build(primary, true, altSigner)`. Verificadores PKIX clássicos (RFC 5280 §4.2) **rejeitam**
qualquer extensão crítica desconhecida — incluindo essas duas — com erro do tipo `unhandled
critical extension`. O `openssl verify` é o exemplo prático mais relevante: reporta erro 34.

**Solução.** A biblioteca registra um `PKIXCertPathChecker` customizado
(`HybridCertificateValidator.HybridExtensionChecker`) que declara as três OIDs como handled:

```java
private static final class HybridExtensionChecker extends PKIXCertPathChecker {
    private static final Set<String> SUPPORTED = Set.of(
        AlgorithmOIDRegistry.OID_ALT_SIGNATURE_ALGORITHM,
        AlgorithmOIDRegistry.OID_ALT_SIGNATURE_VALUE,
        AlgorithmOIDRegistry.OID_SUBJECT_ALT_PUBLIC_KEY_INFO);
    @Override public Set<String> getSupportedExtensions() { return SUPPORTED; }
    @Override public void check(Certificate cert, Collection<String> unresolvedCritExts) {
        if (unresolvedCritExts != null) unresolvedCritExts.removeAll(SUPPORTED);
    }
}
```

A consequência é que **o verificador interno** desta biblioteca aceita certificados Catalyst, mas
**verificadores externos clássicos continuam rejeitando-os**. Esta é uma limitação consciente da
versão atual. Uma evolução futura precisaria construir o certificado manualmente (sem usar a
sobrecarga nativa do BC) para marcar .73/.74 como **non-critical** — a estrutura existe em
`X509ExtensionManager.addPQCExtensions`, mas tem um *bug* documentado de *round-trip* do SPKI
(documentado em `HybridCertificateValidator` → `WARNING: Failed to build PQC extensions structure`).

### 5.6.2 Limitações das bibliotecas existentes

| Limitação | Mitigação adotada |
|---|---|
| **BC nativo não expõe toggle de criticality** para .73/.74 | Workaround via `PKIXCertPathChecker` interno; correção definitiva exige reescrever o caminho de construção do cert (não feito nesta versão) |
| **PKCS#12 / JKS não modelam pares híbridos ML-DSA** | Decisão de **não fornecer** serialização de chave privada nesta versão; o caso de produção é Layer 1 (chave em HSM) |
| **JCA `Signature.getInstance("ML-DSA")` aceita o nome genérico**, mas o caminho ativo precisa da variante específica para consistência | Centralização em `MLDSASigner`/`MLDSAVerifier`, que sempre recebem o nome explícito (`ML-DSA-44/65/87`) |
| **`Mockito` não consegue mockar `X509Certificate`** no JDK 21 (proibição interna) | Os testes constroem certificados reais via `HybridKeyGenerator` + `HybridX509CertificateBuilder` — mais lento, mas testa o cenário real ponta a ponta |
| **`X509ExtensionManager.buildPQCExtensionsStructure()` tem *round-trip* quebrado** (SPKI re-envelopado como `DEROctetString`) | Caminho não usado pelo path ativo (BC-native); documentado como *bug* latente |
| **Composite (draft IETF lamps-pq-composite-sigs-18) ainda em evolução** | Implementação paralela coexiste em `CompositeSignatureStrategy`, mas **não** ligada à API pública — preserva pesquisa sem comprometer o caminho de produção |

### 5.6.3 Tamanho de chaves e certificados

Valores de referência (especificação) versus medidos no projeto:

| Componente | Clássico (P-256) | PQC (ML-DSA-44) | Total híbrido |
|---|---|---|---|
| Chave pública (referência) | ~91 B (codificada) | **1312 B** (FIPS 204) | ~1403 B |
| Chave privada (referência) | ~121 B | **2560 B** (FIPS 204) | ~2681 B |
| Assinatura (referência) | ~71 B | **2420 B** (FIPS 204) | ~2491 B |
| Certificado X.509 PEM (estimado para leaf típico) | ~1 KB | n/a | **~6–8 KB** `[medir]` |

Comparativamente, **um certificado híbrido é tipicamente 5–8 vezes maior** que um certificado
clássico de mesma finalidade. Implicações:

- **TLS handshake**: cada certificado da cadeia se traduz em mais bytes no `Certificate` message
  do handshake. Em uma cadeia de três certificados (root → intermediate → leaf), o tráfego do
  servidor cresce de poucos KB para ~20–30 KB. Negociável em conexões persistentes; relevante em
  TLS 1.3 com handshake-resumption desativado.
- **Armazenamento**: irrelevante para casos típicos (CAs, servidores). Pode tornar-se relevante
  para *constrained devices* (IoT, smartcards).
- **Logs e auditoria**: o `CertificateEventHistory` (em sistemas como o CZERTAINLY) precisa lidar
  com payloads ~5× maiores na inserção.

### 5.6.4 Performance

A arquitetura de benchmarks da biblioteca usa **JMH** (Java Microbenchmark Harness, do OpenJDK):

```java
@State(Scope.Thread)
@BenchmarkMode({Mode.AverageTime, Mode.Throughput, Mode.SampleTime})
@OutputTimeUnit(TimeUnit.MILLISECONDS)
@Warmup(iterations = 3, time = 1, timeUnit = TimeUnit.SECONDS)
@Measurement(iterations = 5, time = 1, timeUnit = TimeUnit.SECONDS)
@Fork(value = 2, jvmArgs = {"-Xms512m", "-Xmx1024m"})
@Timeout(time = 10, timeUnit = TimeUnit.MINUTES)
public abstract class AbstractPQCBenchmark extends BaseBenchmark { … }
```

O *scaffolding* (classe base, `@State`, `@Warmup`/`@Measurement`/`@Fork`/`@Timeout`) está pronto
para benchmarks justos (com aquecimento, *forks* independentes para medir variância de JIT, etc.).
Os benchmarks concretos atualmente existentes são `ClassicalKeyGenerationBenchmark` e
`ECDSASignatureOperationsBenchmark`; os benchmarks ML-DSA específicos ainda **não** foram escritos
nesta versão da biblioteca (ver `doc/IMPLEMENTATION_PHASES.md`).

**Ordens de grandeza esperadas** (literatura, BC 1.84, x86_64):

| Operação | ML-DSA-44 | ML-DSA-65 | ML-DSA-87 |
|---|---|---|---|
| Keygen | ~0,1 ms `[medir]` | `[medir]` | `[medir]` |
| Sign | ~0,3 ms `[medir]` | `[medir]` | `[medir]` |
| Verify | ~0,1 ms `[medir]` | `[medir]` | `[medir]` |

**Decisões com impacto em performance** já implementadas:

- **Provider BC inicializado uma vez** (`CryptographicProviderFactory.initialize()` é
  idempotente);
- **Validação clássica reusa o `PKIX` do JDK** (compilado em C2, otimizado pelo *runtime*),
  apenas anexa um *checker* estático leve;
- **Camada cripto-primitiva sem estado mutável** (`MLDSASigner`/`MLDSAVerifier` são static
  utilities) — escala horizontalmente sem locks;
- **Certificados são construídos por uma única passagem** sobre o BC (`build(primary, true,
  altSigner)`), evitando reconstrução manual do pre-TBS na emissão.

---

## Apêndice A — Mapeamento código → seções

| Seção | Classe / Pacote | Arquivo |
|---|---|---|
| 5.2 Fachada | `PQCHybridCertificateAPI` | `core/api/PQCHybridCertificateAPI.java` |
| 5.2 Strategy | `HybridSignatureStrategy`, `DualSignatureStrategy`, `CompositeSignatureStrategy` | `core/api/`, `core/signature/` |
| 5.2 Adapter (signer externo) | `HybridSigner` (record) | `core/certificate/HybridSigner.java` |
| 5.2 Factory (provider) | `CryptographicProviderFactory` | `core/config/CryptographicProviderFactory.java` |
| 5.3 Builder de cert | `HybridX509CertificateBuilder` (Layer 1 + Layer 2) | `core/certificate/HybridX509CertificateBuilder.java` |
| 5.3 Representação | `HybridCertificateInfo`, `HybridKeyPair`, `HybridSignaturePair`, `HybridCertificateConfig` | `core/model/`, `core/keygen/`, `core/signature/`, `core/config/` |
| 5.3 Extensões PQC | `X509ExtensionManager`, `PQCExtensionsStructure` | `core/certificate/`, `core/certificate/asn1/` |
| 5.4 OIDs e nomes | `AlgorithmOIDRegistry`, `PQCAlgorithm`, `ClassicalAlgorithm`, `HybridAlgorithmPair` | `core/common/oid/`, `core/config/` |
| 5.5 Geração de chaves | `HybridKeyGenerator` | `core/keygen/HybridKeyGenerator.java` |
| 5.5 CSR | `CertificateSigningRequestBuilder` | `core/certificate/CertificateSigningRequestBuilder.java` |
| 5.5 CA | `HybridCertificateAuthority` | `core/certificate/HybridCertificateAuthority.java` |
| 5.5 Validação ponto a ponto e cadeia | `HybridCertificateValidator` (`HybridExtensionChecker`, `HybridChainValidationResult`) | `core/certificate/HybridCertificateValidator.java` |
| 5.5 Operações híbridas (dados) | `HybridSignatureManager` | `core/signature/HybridSignatureManager.java` |
| 5.5 Cripto-primitiva PQC | `MLDSASigner`, `MLDSAVerifier` | `core/signature/ml_dsa/` |
| 5.5 KEM (experimental) | `MLKEMEncapsulator`, `MLKEMDecapsulator`, `KeyEncapsulationWrapper` | `core/kem/ml_kem/`, `core/keygen/KeyEncapsulationWrapper.java` |
| 5.5 Exportação | `CertificateExporter` (PEM / DER) | `core/util/export/CertificateExporter.java` |
| 5.6 Benchmarks | `AbstractPQCBenchmark`, `BaseBenchmark` (JMH) | `src/test/.../benchmark/` |
| Exceções | `PQCHybridException`, `CertificateException`, `InvalidSignatureException`, `InvalidKeyException`, `AlgorithmNotSupportedException`, `EncapsulationException` | `core/exception/` |

## Apêndice B — Cobertura de testes (estado atual)

| Métrica | Valor |
|---|---|
| Testes unitários (Surefire) | **234**, 0 falhas |
| Testes de integração (Failsafe) | **12**, 0 falhas |
| **Total** | **246**, 0 falhas |
| Cobertura **bundle** (linha) | **~83%** |
| Cobertura **bundle** (instrução) | **~84%** |
| Cobertura pacote `signature.ml_dsa` | **~86%** linha |
| Gate JaCoCo | 75% linha por pacote + por bundle |
| Pacotes excluídos do gate (experimentais/demonstração) | `examples/`, `util/printer/`, `util/export/`, `kem/ml_kem/`, `keygen/KeyEncapsulationWrapper`, `migration/` |

---

## Apêndice C — Referências normativas

- **FIPS 203** — Module-Lattice-Based Key-Encapsulation Mechanism Standard (ML-KEM). NIST, 2024.
- **FIPS 204** — Module-Lattice-Based Digital Signature Standard (ML-DSA). NIST, 2024.
- **FIPS 205** — Stateless Hash-Based Digital Signature Standard (SLH-DSA). NIST, 2024.
- **RFC 5280** — Internet X.509 Public Key Infrastructure Certificate and CRL Profile. IETF, 2008.
- **RFC 2986** — PKCS #10: Certification Request Syntax Specification. IETF, 2000.
- **ITU-T X.509 (10/2019)** — Information technology — Open Systems Interconnection — The
  Directory: Public-key and attribute certificate frameworks. (Modelo "alternative signature".)
- **draft-ietf-lamps-pq-composite-sigs-18** — Composite ML-DSA For use in X.509 Public Key
  Infrastructure (referência do caminho experimental; **não** seguida à risca neste projeto).
