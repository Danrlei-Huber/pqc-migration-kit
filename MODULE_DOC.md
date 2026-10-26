# PQC Hybrid Certificates Library — Documentação do Módulo

**Versão**: `1.0.0-BETA` | **Java**: 21 | **Runtime**: BouncyCastle 1.84

---

## Índice

- [Visão Geral](#visão-geral)
- [Pacotes](#pacotes)
- [API de Entrada — `PQCHybridCertificateAPI`](#api-de-entrada--pqchybridcertificateapi)
- [Configuração — `config`](#configuração--config)
- [Geração de Chaves — `keygen`](#geração-de-chaves--keygen)
- [Assinatura Digital — `signature`](#assinatura-digital--signature)
- [Certificados Digitais — `certificate`](#certificados-digitais--certificate)
- [Registro de OIDs — `common.oid`](#registro-de-oids--commonoid)
- [Modelos de Dados — `model`](#modelos-de-dados--model)
- [Exceções — `exception`](#exceções--exception)
- [Utilitários — `util`](#utilitários--util)
- [Exemplos — `examples`](#exemplos--examples)
- [Serviços Auxiliares — `migration`](#serviços-auxiliares--migration)

---

## Visão Geral

Biblioteca para geração de **certificados digitais X.509v3 com assinatura dupla (híbrida)**: uma assinatura **clássica** (RSA/ECDSA) para compatibilidade retroativa, e uma assinatura **PQC** (**ML-DSA**) para resistência quântica. Ambas as assinaturas precisam ser válidas para o certificado ser considerado autêntico (lógica **AND**). ML-DSA é o único esquema PQC do módulo; ML-KEM, SLH-DSA e Falcon estão fora do escopo.

Segue o padrão **NIST FIPS 204** (ML-DSA) e o rascunho **draft-ietf-lamps-pq-composite-sigs-18**.

```
┌────────────────────────────────────────────────────────┐
│                   PQCHybridCertificateAPI              │
│                      (Facade)                          │
├──────────┬──────────┬──────────────┬───────────────────┤
│ keygen   │signature │ certificate  │ config            │
│ Chaves   │Dupla     │ X.509v3      │ Algoritmos,       │
│ híbridas │assinatura│ com extensões│ períodos, OIDs    │
└──────────┴──────────┴──────────────┴───────────────────┘
```

---

## Pacotes

| Pacote | Descrição |
|--------|-----------|
| `com.pqc.hybrid.core.api` | Fachada única de entrada para todas as operações |
| `com.pqc.hybrid.core.config` | Enums de algoritmos, pares híbridos, config de certificado, provider BC |
| `com.pqc.hybrid.core.keygen` | Geração de pares de chave híbridos (clássica + PQC) |
| `com.pqc.hybrid.core.signature` | Assinatura dupla: criação, verificação e validação estrutural |
| `com.pqc.hybrid.core.signature.ml_dsa` | Wrappers especializados para ML-DSA |
| `com.pqc.hybrid.core.certificate` | Construção e validação de certificados X.509v3 híbridos, CSR |
| `com.pqc.hybrid.core.certificate.asn1` | Estrutura ASN.1 das extensões PQC |
| `com.pqc.hybrid.core.common.oid` | Registro centralizado de OIDs |
| `com.pqc.hybrid.core.model` | Modelos de dados (info do certificado) |
| `com.pqc.hybrid.core.exception` | Hierarquia de exceções (base + 4 especializações) |
| `com.pqc.hybrid.core.util.printer` | Pretty-printers para certificados, chaves e assinaturas |
| `com.pqc.hybrid.core.util.export` | Exportação de certificados para PEM/DER |
| `com.pqc.hybrid.examples` | Exemplos executáveis |
| `com.pqc.hybrid.migration` | Serviço de migração de certificados legados para híbridos (**experimental**) |

---

## API de Entrada — `PQCHybridCertificateAPI`

Classe principal do módulo. Deve ser instanciada e inicializada antes de qualquer operação.

### `initialize()`
Registra o provider BouncyCastle (`BC`) no JCA Security e valida se todos os algoritmos PQC obrigatórios estão disponíveis. É idempotente — pode ser chamada múltiplas vezes.

### `generateHybridKeyPair(securityLevel)`
Gera um par de chaves híbrido usando algoritmos recomendados para o nível de segurança:
- **128 bits**: ECDSA P-256 + ML-DSA-44
- **192 bits**: ECDSA P-384 + ML-DSA-65
- **256 bits**: ECDSA P-521 + ML-DSA-87

Alternativa: `generateHybridKeyPair(HybridAlgorithmPair)` permite escolher algoritmos manualmente.

### `signData(data, keyPair)`
Assina os dados com ambos os algoritmos (clássico e PQC). Retorna um `HybridSignaturePair` contendo ambas as assinaturas, os nomes dos algoritmos e um hash SHA-256 dos dados originais.

### `verifySignature(data, signature, keyPair)`
Verifica **ambas** as assinaturas. Retorna `true` **apenas se** a assinatura clássica **e** a PQC forem válidas simultaneamente.

### `validateSignatureStructure(signature)`
Valida a integridade estrutural de uma assinatura híbrida: presença de ambos os componentes, tamanhos dentro de faixas esperadas, consistência de mensagem e compatibilidade de algoritmos.

### `generateHybridCertificate(config, keyPair)`
Constrói um certificado X.509v3 híbrido no modelo Catalyst (ITU-T X.509 (2019)), usando
o suporte nativo do BouncyCastle (`build(primarySigner, true, altSigner)`):
1. Monta o TBS com a `SubjectPublicKeyInfo` clássica, as extensões básicas e a extensão
   `2.5.29.72` (subjectAltPublicKeyInfo) com a chave pública PQC.
2. O BouncyCastle adiciona:
   - `2.5.29.73` (altSignatureAlgorithm) — OID do algoritmo PQC
   - `2.5.29.74` (altSignatureValue) — assinatura PQC calculada sobre o **pre-TBS**
     (o TBS sem a própria extensão `altSignatureValue`), ligando a chave/algoritmo alternativos
3. Aplica a assinatura clássica (primária) sobre o TBS final.

### `generateHybridCertificateWithPQCExtensions(config, keyPair, include)`
Similar ao anterior, mas permite controlar se as extensões PQC serão incluídas.

### `validateCertificate(certificate, issuerPublicKey)`
Validação abrangente do certificado híbrido: expiração, DNs, período de validade, chave pública, assinatura clássica, presença de extensões PQC e assinatura PQC. Retorna um `ValidationResult` com 7 flags booleanas.

### `getCertificateInfo(certificate, keyPair)`
Extrai metadados completos do certificado híbrido: algoritmos, OIDs, assinaturas, chaves públicas, estrutura das extensões PQC.

### `validatePQCExtensions(certificate)`
Verifica se as três extensões PQC obrigatórias estão presentes no certificado.

### `validatePQCSignature(certificate, keyPair)`
Verifica se a assinatura PQC armazenada na extensão `2.5.29.74` (altSignatureValue) é válida sobre o pre-TBS reconstruído.

### `generateCertificateSigningRequest(subjectDN, keyPair)`
Gera um PKCS#10 CSR assinado com a chave privada clássica.

### `generateCompleteHybridCertificate(securityLevel, subjectDN, issuerDN, validityDays)`
Fluxo completo em um único método: gera chaves → cria configuração → constrói certificado → valida. Ideal para testes rápidos.

---

## Configuração — `config`

### `ClassicalAlgorithm` (enum)
Algoritmos clássicos suportados: `RSA_2048`, `RSA_3072`, `RSA_4096`, `ECDSA_P256`, `ECDSA_P384`, `ECDSA_P521`.

Cada valor carrega: nome do algoritmo, tamanho da chave (bits), OID, nome do algoritmo de assinatura Java (`SHA256withRSA`, `SHA256withECDSA`, etc.) e nível de segurança.

Métodos úteis:
- `getSignatureAlgorithmForName(name)` — retorna o nome correto para `Signature.getInstance()` a partir de "RSA" ou "ECDSA"
- `fromNameAndSize(name, keySize)` — busca por nome e tamanho

### `PQCAlgorithm` (enum)
Algoritmo PQC suportado:
- **ML-DSA** (Digital Signature): `ML_DSA_44`, `ML_DSA_65`, `ML_DSA_87`

Cada valor carrega: nome, OID, nível de segurança e tamanho da chave pública (bytes).

### `HybridAlgorithmPair` (record)
Par imutável de um algoritmo clássico + um PQC. Valida que o PQC é de assinatura (não KEM). Métodos:
- `recommended(128|192|256)` — pares recomendados por nível de segurança
- `allRecommended()` — todos os pares recomendados
- `isSecurityBalanced()` — verifica se os níveis de segurança são próximos

### `HybridCertificateConfig`
Configuração imutável para geração de certificados. Construtor via `Builder`:
- `withAlgorithmPair(pair)` — algoritmos a usar
- `withSubjectDN(dn)` / `withIssuerDN(dn)` — Distinguished Names
- `withValidityDays(days)` — período de validade (default: 365)
- `withSerialNumber(serial)` — serial number BigInteger (se não fornecido, gera 160-bit aleatório)
- `withIncludePrimarySignature(boolean)` / `withIncludeAlternativeSignature(boolean)`

### `CryptographicProviderFactory`
Inicializador thread-safe do provider BouncyCastle. Registra o `BouncyCastleProvider` no `Security`. Métodos:
- `initialize()` — idempotente, registra o provider BC
- `getProvider()` — retorna o provider "BC"
- `isAlgorithmAvailable(name)` — verifica se um algoritmo está disponível
- `validateRequiredAlgorithms()` — valida que todos os PQC obrigatórios existem

---

## Geração de Chaves — `keygen`

### `HybridKeyGenerator`
Gerador estático de pares de chave híbridos. Opera via `KeyPairGenerator` do JCA com provider BC:
- `generate(HybridAlgorithmPair)` — gera par clássico + PQC e retorna `HybridKeyPair`
- `generateClassicalKeyPair(ClassicalAlgorithm)` — apenas chave clássica
- `generatePQCKeyPair(PQCAlgorithm)` — apenas chave PQC
- `validate(HybridKeyPair)` — verifica se nenhuma das 4 chaves é nula

### `HybridKeyPair`
Contêiner imutável com as 4 chaves:
- `getClassicalPublicKey()` / `getClassicalPrivateKey()`
- `getPQCPublicKey()` / `getPQCPrivateKey()`
- `getClassicalAlgorithm()` / `getPQCAlgorithm()` — nomes dos algoritmos
- `getGenerationTime()` — timestamp de criação
- `getLabel()` — ex: `"ECDSA + ML-DSA-65"`
- `destroy()` — tentativa de destruir chaves privadas via `Destroyable.destroy()`
- `equals()` / `hashCode()` — baseados nos algoritmos e chaves públicas

---

## Assinatura Digital — `signature`

### `HybridSignatureManager`
Gerenciador estático de assinatura dupla. Assina e verifica com ambos os algoritmos:
- `sign(data, keyPair)` — assina com clássico + PQC, retorna `HybridSignaturePair`
- `verify(data, signaturePair, keyPair)` — verifica ambos (lógica AND)
- `verifyClassicalOnly(data, signaturePair, keyPair)` — apenas a componente clássica

### `HybridSignaturePair`
Contêiner imutável da assinatura dupla:
- `getClassicalSignature()` / `getPQCSignature()` — bytes da assinatura (cópias defensivas)
- `getClassicalAlgorithm()` / `getPQCAlgorithm()`
- `getMessageHash()` — hash SHA-256 dos dados originais
- `getClassicalSignatureSize()` / `getPQCSignatureSize()` / `getTotalSize()`
- `wipeSignatures()` — zera os bytes das assinaturas em memória

### `DualSignatureValidator`
Validador estrutural de assinaturas híbridas:
- `validatePresence()` — ambas as assinaturas existem e não são vazias
- `validateSizes()` — tamanhos dentro de faixas esperadas (64-1024B clássica, 100-8192B PQC)
- `validateMessageConsistency()` — se o hash está disponível, verifica consistência
- `validateAlgorithmCompatibility()` — algoritmos são de categorias diferentes (clássico ≠ PQC)
- `validateComprehensive()` — todas as validações acima em um único resultado

### `signature.ml_dsa.MLDSASigner` / `MLDSAVerifier`
Wrappers de baixo nível para ML-DSA via `Signature.getInstance("ML-DSA", "BC")`. Úteis quando se deseja operar apenas com ML-DSA sem o contexto híbrido.

---

## Certificados Digitais — `certificate`

### `HybridX509CertificateBuilder`
Construtor de certificados X.509v3 híbridos (Catalyst). Adiciona as extensões básicas
(SubjectKeyIdentifier, KeyUsage `digitalSignature + nonRepudiation`, ExtendedKeyUsage
`serverAuth + clientAuth`, BasicConstraints) e a extensão `subjectAltPublicKeyInfo`, e
delega a `X509v3CertificateBuilder.build(primarySigner, true, altSigner)` do BouncyCastle,
que gera as extensões `altSignatureAlgorithm`/`altSignatureValue` com a assinatura PQC
sobre o pre-TBS. Use `withPQCExtensions(false)` para emitir apenas com a assinatura clássica.

### `HybridCertificateValidator`
Validador abrangente de certificados híbridos (pacote `certificate`). Métodos estáticos:
- `validateNotExpired()` — verifica validade temporal
- `validateDNs()` — subject/issuer DN não vazios
- `validateValidityPeriod()` — data atual dentro do período
- `validatePublicKey()` — chave pública presente e codificável
- `validateSignature()` — assinatura clássica via `X509Certificate.verify()`
- `validatePQCExtensions()` — as 3 extensões PQC estão presentes
- `validatePQCSignature()` — assinatura PQC (`altSignatureValue`) é válida sobre o pre-TBS reconstruído
- `extractPQCExtensions()` / `extractPQCAlgorithmOID()` / `extractPQCSignature()` / `extractPQCPublicKey()` — extração dos dados PQC
- `extractCertificateInfo()` — constrói `HybridCertificateInfo` completo
- `validateComprehensive()` — todas as validações em um `ValidationResult` com 7 flags:
  - `notExpiredValid`, `dnsValid`, `validityPeriodValid`, `publicKeyValid`, `signatureValid`, `pqcExtensionsValid`, `pqcSignatureValid`
  - `isAllValid()` — todas verdadeiras
  - `isHybridFullyValid()` — extensões + assinatura PQC válidas

### `CertificateSigningRequestBuilder`
Gera um PKCS#10 CSR híbrido: assinatura clássica primária + chave pública e assinatura
alternativas (PQC), via `build(primarySigner, altSPKI, altSigner)` do BouncyCastle.

### `X509ExtensionManager`
Gerencia as extensões X.509v3 PQC: adicionar, remover, consultar e construir a estrutura ASN.1 completa das três extensões híbridas.

### `certificate.asn1.PQCExtensionsStructure`
Estrutura ASN.1 que serializa/deserializa as três extensões PQC em formato DER. Contém: `AlgorithmIdentifier` (algoritmo alternativo), `byte[]` (assinatura alternativa), `SubjectPublicKeyInfo` (chave pública alternativa). Usa padrão Builder.

---

## Registro de OIDs — `common.oid`

### `AlgorithmOIDRegistry`
Registro central com todos os OIDs NIST e IETF usados no módulo:

| Algoritmo | OID |
|-----------|-----|
| ML-DSA-44 | `2.16.840.1.101.3.4.3.17` |
| ML-DSA-65 | `2.16.840.1.101.3.4.3.18` |
| ML-DSA-87 | `2.16.840.1.101.3.4.3.19` |
| subjectAltPublicKeyInfo | `2.5.29.72` |
| altSignatureAlgorithm | `2.5.29.73` |
| altSignatureValue | `2.5.29.74` |

Métodos: `getOID(name)`, `getAlgorithmName(oid)`, `getAlgorithmType(oid)`, `isPQC(oid)`, `isClassical(oid)`, `isHybridExtension(oid)`, `dumpRegistry()`.

---

## Modelos de Dados — `model`

### `HybridCertificateInfo`
Modelo completo de informações de um certificado híbrido. Construído via `Builder`:
- `getCertificate()` — o certificado X.509
- `getClassicalAlgorithm()` / `getPQCAlgorithm()` / `getPQCAlgorithmOID()`
- `getClassicalSignature()` / `getPQCSignature()` — bytes das assinaturas
- `getClassicalPublicKeyBytes()` / `getPQCPublicKeyBytes()`
- `getPQCExtensions()` — estrutura ASN.1 das extensões
- `hasPQCExtensions()` / `hasPQCSignature()`

---

## Exceções — `exception`

Todas estendem `RuntimeException` (exceções não verificadas):

| Exceção | Uso |
|---------|-----|
| `PQCHybridException` | Base — erro geral da biblioteca |
| `CertificateException` | Falha em operações de certificado |
| `InvalidSignatureException` | Falha inesperada na verificação de assinatura |
| `InvalidKeyException` | Chave inválida (formato, tamanho, tipo) |
| `AlgorithmNotSupportedException` | Algoritmo solicitado não está disponível |

---

## Utilitários — `util`

### `util.printer.CertificatePrinter`
Pretty-printer de certificados X.509 com formatação em árvore: subject, issuer, validade, chave pública, extensões.

### `util.printer.HybridCertificateInspector`
Inspetor especializado para certificados híbridos: detecta esquema duplo de assinatura, analisa extensões PQC, exibe relatório detalhado com caracteres Unicode.

### `util.printer.SignaturePrinter`
Exibe informações de assinatura híbrida: tamanhos, comparação (clássico vs PQC), estatísticas.

### `util.printer.KeyInfoPrinter`
Exibe detalhes de chaves criptográficas: algoritmo, tamanho, formato, preview base64.

### `util.export.CertificateExporter`
Exporta certificados para:
- **PEM**: `exportCertificateToPEM(cert, path)` ou `exportCertificateToPEMString(cert)`
- **DER**: `exportCertificateToDER(cert, path)` ou `exportCertificateToDERBytes(cert)`

---

## Exemplos — `examples`

| Classe | Demonstra |
|--------|-----------|
| `GenerateCertificateExample` | Fluxo completo: init → chaves → config → certificado → display |
| `HybridCertificateGenerationExample` | Geração básica de chaves |
| `HybridCertificateHelper` | CLI com subcomandos: `generate`, `inspect`, `export`, `help` |
| `SignAndVerifyExample` | Assinatura e verificação com detecção de adulteração |
| `AlgorithmExplorerExample` | Lista algoritmos, pares recomendados, performance de geração |

---

## Serviços Auxiliares — `migration`

> **Experimental / fora do escopo estável.** Veja a seção "Componentes Experimentais"
> do README.

### `migration.LegacyCertificateMigrator`
Esqueleto do serviço de migração de certificados legados (X.509 tradicionais) para o formato híbrido PQC. **Status: placeholder** — a lógica real não está implementada (retorna bytes vazios).

### `migration.MigrationConfig`
Configuração para migração: algoritmo PQC (default ML-DSA-65), algoritmo clássico (default RSA-2048), preservar cadeia, formato de saída, dias de validade.
