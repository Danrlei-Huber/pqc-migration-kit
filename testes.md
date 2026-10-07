# Resumo das funcionalidades do módulo

**Biblioteca:** *PQC Hybrid Certificates* `1.0.0-BETA` (`pqc-migration-kit`)

> Documento levantado a partir do código-fonte, não da documentação anterior.
> Estado descrito: commit `fdccc5d` mais as alterações da árvore de trabalho
> (correções de seleção de *digest*, extração de extensões, validação de emissor,
> contexto FIPS 204 e testes de compatibilidade com verificador legado).

---

## Propósito

Emitir e validar certificados X.509v3 que carregam simultaneamente uma credencial
criptográfica clássica e uma pós-quântica, segundo o modelo *Catalyst* de assinatura
alternativa descrito na recomendação ITU-T X.509 (2019), preservando a aceitação por
verificadores que desconhecem criptografia pós-quântica.

## Pilha tecnológica

| Camada | Tecnologia | Versão |
|---|---|---|
| Linguagem | Java | 21 LTS |
| Build | Maven | 3.9.x |
| API criptográfica | JCA / JCE | JDK 21 |
| Provedor | Bouncy Castle (`bcprov-jdk18on`, `bcpkix-jdk18on`) | 1.84 |
| Testes | JUnit 5 + AssertJ | — |
| Cobertura | JaCoCo (gate de 75%) | 0.8.10 |

59 arquivos Java de produção distribuídos em 14 pacotes.

## Arquitetura

Três camadas, cada uma dependendo apenas da imediatamente inferior:

1. **Fachada** — `PQCHybridCertificateAPI`, cerca de 29 métodos públicos; ponto de entrada
   único para aplicações consumidoras.
2. **Núcleo de negócio** — lógica híbrida, padrão *Strategy* para o esquema de assinatura
   (`HybridSignatureStrategy`) e *Builder* para configuração de certificados.
3. **Provedor criptográfico** — `CryptographicProviderFactory` isola o Bouncy Castle atrás
   da arquitetura JCA/JCE, mantendo a dependência do provedor encapsulada.

---

## 1. Geração de material criptográfico

`HybridKeyGenerator` produz um `HybridKeyPair` (clássico + pós-quântico) em uma única
operação.

- **Algoritmos clássicos:** RSA-2048/3072/4096 e ECDSA P-256/P-384/P-521 (seis variantes).
- **Algoritmo pós-quântico:** ML-DSA-44/65/87 (FIPS 204) — único esquema PQC no fluxo ativo.
- **Pares recomendados**, balanceados por construção, via `HybridAlgorithmPair.recommended(nível)`:

  | Nível | Par |
  |---|---|
  | 128 bits | ECDSA P-256 + ML-DSA-44 |
  | 192 bits | ECDSA P-384 + ML-DSA-65 |
  | 256 bits | ECDSA P-521 + ML-DSA-87 |

- `isSecurityBalanced()` reporta o equilíbrio entre as metades segundo os níveis
  equivalentes do NIST SP 800-57 Part 1 Rev 5.
- `HybridKeyPair.destroy()` faz destruição *best-effort* do material privado.

## 2. Emissão de certificados híbridos

`HybridX509CertificateBuilder` implementa a ordem de operações que o modelo Catalyst exige:

1. chave pública clássica nos campos tradicionais do TBS;
2. chave pública PQC na extensão `2.5.29.72` (`subjectAltPublicKeyInfo`);
3. assinatura PQC calculada sobre o **pre-TBS** (com a `72`, sem as `73`/`74`);
4. extensões `2.5.29.73` (`altSignatureAlgorithm`) e `2.5.29.74` (`altSignatureValue`);
5. assinatura clássica sobre o TBS completo.

**Duas camadas de uso:**

- **Layer 1 (*signer-agnostic*)** — recebe dois `ContentSigner` externos; a chave privada
  nunca precisa ser carregada na JVM. É o ponto de integração com HSM, KMS e tokens
  criptográficos.
- **Layer 2 (conveniência)** — constrói os assinadores a partir de um `HybridKeyPair` e
  delega à Layer 1.

**Extensões emitidas:** `SubjectKeyIdentifier`, `AuthorityKeyIdentifier`, `KeyUsage`,
`BasicConstraints`, `ExtendedKeyUsage` (apenas em folhas), `SubjectAlternativeName`
(DNS e IP), além das três extensões do Catalyst.

A criticidade de `2.5.29.73`/`74` é parametrizável por
`withAltSignatureExtensionsCritical(boolean)` e é **não crítica por padrão** — é o ponto de
controle do compromisso de fase de migração entre compatibilidade retroativa e prevenção de
*downgrade*.

**Configuração** via `HybridCertificateConfig.builder()`: par de algoritmos, DNs de sujeito e
emissor, dias de validade, número serial, *Subject Alternative Names*, flag de CA,
`pathLenConstraint` e criticidade das extensões alternativas.

## 3. Autoridade Certificadora

`HybridCertificateAuthority` oferece operação como CA híbrida:

- `createRoot(...)` — raiz autoassinada;
- `issueCertificate(...)` — certificados subordinados, tanto sub-CAs quanto entidade final.

## 4. Requisições PKCS#10 híbridas

`CertificateSigningRequestBuilder` gera CSRs híbridas: a chave pública clássica ocupa o campo
convencional, a chave PQC vai no atributo `altSubjectPublicKeyInfo`, e a requisição carrega
uma assinatura clássica principal mais uma assinatura alternativa pós-quântica. Disponível
nas mesmas duas camadas (assinadores externos ou `HybridKeyPair`).

## 5. Assinatura de dados arbitrários

`HybridSignatureManager` e `DualSignatureStrategy` cobrem operações criptográficas avulsas:

- assinatura dupla independente, empacotada no envelope
  `[prefixo de 4 bytes com o tamanho clássico][assinatura clássica][assinatura PQC]`;
- verificação sob lógica **E** — o resultado só é positivo se ambas as metades verificarem;
- `verifyClassicalOnly()` para checagem de compatibilidade com a via clássica;
- **contexto FIPS 204** (`ctx`, até 255 bytes) vinculado à metade pós-quântica, o que dá
  separação de domínio ao par: uma assinatura produzida sob um contexto não verifica sob
  outro.

## 6. Validação

**Por certificado:**

- `validateCertificate(cert, issuerPublicKey)` — validade temporal, presença dos DNs,
  integridade da chave pública, assinatura clássica, presença das extensões PQC e validade da
  assinatura alternativa reconstruída sobre o pre-TBS. Quando nenhuma chave de emissor é
  fornecida, verifica a autoassinatura contra a própria chave pública do certificado.
- `validateCertificateAgainstIssuer(cert, issuerCert)` — valida um elo emissor/sujeito
  tirando todas as credenciais do certificado do emissor: assinatura clássica com a chave
  pública do emissor, assinatura alternativa com o `subjectAltPublicKeyInfo` do emissor, e
  encadeamento de nomes conforme RFC 5280 §6.1.3(a)(4). Não envolve material privado.

**De cadeia** — `validateCertificateChain(chain)` valida em **duas dimensões independentes**:

1. caminho PKIX clássico, pelo `CertPathValidator` da plataforma Java;
2. caminho pós-quântico, percorrendo cada elo e verificando a assinatura alternativa contra
   a chave alternativa do emissor.

A cadeia só é considerada válida quando ambas as dimensões passam.

## 7. Exportação e inspeção

`CertificateExporter` exporta certificados em **PEM** e **DER**, para arquivo ou em memória.
A **exportação de chaves privadas não é suportada**, por decisão de projeto, para reduzir o
risco de exposição indevida de material criptográfico.

`HybridCertificateInspector`, `CertificatePrinter`, `KeyInfoPrinter` e `SignaturePrinter`
produzem relatórios legíveis: detecção automática de certificado híbrido, tamanhos reais das
extensões em DER, e comparação entre as metades clássica e pós-quântica.

## 8. Provedor e diagnóstico

`CryptographicProviderFactory` faz inicialização idempotente e *thread-safe* do provedor,
consulta de disponibilidade de algoritmos e `validateRequiredAlgorithms()`, que falha rápido
na inicialização caso ML-DSA-44/65/87 não estejam disponíveis.

---

## Fronteiras de escopo

Componentes deliberadamente fora da via de produção:

| Componente | Estado |
|---|---|
| `LegacyCertificateMigrator` | Esqueleto. `migrateToHybrid` devolve resultado com certificado vazio; a lógica de migração não está implementada |
| `CompositeSignatureStrategy`, `CompositeSigner`, `CompositeVerifier` | Funcionais, porém **desligados da fachada**. Exploração do *draft-ietf-lamps-pq-composite-sigs*, mantida para comparação arquitetural |
| ML-KEM, SLH-DSA, Falcon | Removidos do suporte no commit `fdccc5d`; o fluxo ativo concentra-se em ML-DSA |
| Integração com a plataforma CZERTAINLY | Não realizada. A biblioteca foi desenvolvida e validada como artefato autônomo |

## Estado de qualidade

- **270 testes**, 0 falhas.
- Gate de cobertura JaCoCo de 75% atendido (exclui `examples`, `util/printer`, `util/export`,
  `migration` e `exception`).
- A compatibilidade retroativa está travada por testes automatizados contra **dois
  verificadores externos independentes** — `openssl verify` e o `CertPathValidator` puro do
  JDK, este último sem o `HybridExtensionChecker` da própria biblioteca. Cada teste de
  aceitação tem um controle negativo que exige rejeição quando as extensões alternativas são
  emitidas como críticas, o que impede que a evidência passe pelo motivo errado.
