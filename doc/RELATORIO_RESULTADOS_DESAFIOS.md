# Relatório Técnico — Base para os Capítulos de *Resultados e Discussão* e *Desafios de Desenvolvimento*

> **Propósito.** Este documento consolida, de forma rastreável e verificada contra o
> código-fonte, as evidências necessárias para redigir (a) o capítulo de *Resultados e
> Discussão* e (b) o capítulo de *Desafios de Desenvolvimento* do TCC. Cada afirmação é
> ancorada em `arquivo:linha` ou em mensagem de *commit*. É **matéria-prima**: o texto
> abaixo já está em registro acadêmico, mas deve ser adaptado ao estilo e à argumentação
> da monografia.

---

## 0. Identificação técnica do artefato

| Item | Valor |
|------|-------|
| Artefato | `com.pqc.hybrid:pqc-hybrid-certificates` |
| Versão | `1.0.0-BETA` (versionamento semântico — `pom.xml:10`) |
| Plataforma | Java 21 (LTS) |
| Provedor criptográfico | Bouncy Castle 1.84 (`bcprov-jdk18on`, `bcpkix-jdk18on`, `bctls-jdk18on`) |
| Modelo de hibridização | *Catalyst* / assinatura alternativa ITU-T X.509 (2019) |
| Pacote público (fachada) | `com.pqc.hybrid.core.api` → `PQCHybridCertificateAPI` |
| Testes | 33 classes de teste; **234 testes executados** (188 métodos `@Test` + expansões `@ParameterizedTest`); 0 ignorados |
| Cobertura (JaCoCo) | **83,1 % de linhas** (1450/1744) e **61,2 % de *branches*** (330/539) |
| Gate de qualidade | JaCoCo `verify` falha o *build* abaixo de 75 % de linhas por *bundle* e por pacote |

**Nota de nomenclatura (relevante para a redação).** A documentação antiga e a especificação
de requisitos referem-se às classes pelo prefixo `Hybrid…`. A verificação contra o código
confirma que **os nomes das classes públicas foram preservados** (`HybridKeyGenerator`,
`HybridX509CertificateBuilder`, `HybridSignatureManager`, etc.). A migração registrada no
histórico (*"Hybrid→Dual/Catalyst"*) atingiu a **estratégia interna** de assinatura
(`core/hybrid` foi removido e substituído por `DualSignatureStrategy`, modelo *Catalyst*),
não os nomes da API pública. Portanto, as Tabelas de requisitos do TCC permanecem fiéis ao
código entregue.

---

# PARTE I — RESULTADOS E DISCUSSÃO

## 1. Resultados dos Requisitos Funcionais (RF)

### 1.1 Matriz de rastreabilidade (RF → implementação → status)

| ID | Requisito | Classe/método real | Arquivo | Status |
|----|-----------|--------------------|---------|--------|
| **RF1** | Gerar pares de chaves híbridos a partir de um par de algoritmos | `HybridKeyGenerator.generate(HybridAlgorithmPair)` | `core/keygen/HybridKeyGenerator.java:44` | ✅ Atendido |
| **RF2** | Emitir certificados X.509v3 autoassinados ou assinados por CA | `HybridX509CertificateBuilder` + `HybridCertificateAuthority` | `core/certificate/HybridX509CertificateBuilder.java:107,155`; `…/HybridCertificateAuthority.java:49,68` | ✅ Atendido |
| **RF3** | Emitir requisições PKCS#10 (CSR) híbridas | `CertificateSigningRequestBuilder` | `core/certificate/CertificateSigningRequestBuilder.java:66,100` | ✅ Atendido |
| **RF4** | Assinar dados arbitrários com assinatura híbrida | `HybridSignatureManager.sign(byte[], HybridKeyPair)` | `core/signature/HybridSignatureManager.java:50` | ✅ Atendido |
| **RF5** | Verificar assinaturas híbridas exigindo os dois ramos | `HybridSignatureManager.verify(...)` | `core/signature/HybridSignatureManager.java:92` | ✅ Atendido |
| **RF6** | Validar certificados de forma abrangente | `HybridCertificateValidator.validateComprehensive(...)` | `core/certificate/HybridCertificateValidator.java:418,423` | ✅ Atendido |
| **RF7** | Validar cadeias nos domínios clássico e pós-quântico | `HybridCertificateValidator.validateHybridChain(List<X509Certificate>)` | `core/certificate/HybridCertificateValidator.java:477` | ✅ Atendido |
| **RF8** | Exportar certificados em PEM e DER | `CertificateExporter` | `core/util/export/CertificateExporter.java:53,84,107,125` | ✅ Atendido |
| **RF9** | Integrar signatários externos (HSM/KMS/token) sem expor chaves privadas | `HybridSigner` + sobrecargas *Layer 1* | `core/certificate/HybridSigner.java`; builders *Layer 1* | ✅ Atendido |

**Resultado agregado: 9/9 requisitos funcionais plenamente atendidos.**

### 1.2 Discussão por requisito

**RF1 — Geração de chaves híbridas.** `HybridKeyGenerator.generate` recebe um
`HybridAlgorithmPair` (um *record* imutável que combina um algoritmo clássico — RSA/ECDSA —
com um algoritmo PQC — ML-DSA/Falcon/SLH-DSA) e produz um `HybridKeyPair` encapsulando
**quatro chaves independentes** (clássica pública/privada e PQC pública/privada). As duas
gerações são realizadas separadamente (`generateClassicalKeyPair`, `generatePQCKeyPair`,
`HybridKeyGenerator.java:83–151`); falhas são encapsuladas em `PQCHybridException`. *Ponto de
discussão*: a independência criptográfica das chaves é uma decisão arquitetural deliberada do
modelo *Catalyst* (ver Parte II, §2).

**RF2 — Emissão de certificados.** A biblioteca oferece **dois pontos de entrada
complementares**: (i) `HybridX509CertificateBuilder`, para emissão direta a partir de
`HybridKeyPair`, com modo autoassinado (`build()`) e modo assinado por CA
(`withIssuer(caKeyPair, caCert)`, `:96`); e (ii) `HybridCertificateAuthority`, fachada que
materializa o papel de Autoridade Certificadora (`createRoot`, `:49`; `issueCertificate`,
`:68`). Em ambos os casos o certificado emitido segue o modelo *Catalyst*: assinatura
clássica primária no corpo do certificado e as três extensões de assinatura alternativa PQC
(2.5.29.72/73/74). *Ponto de discussão*: a coexistência de uma assinatura clássica "real" com
uma assinatura PQC "alternativa" garante **retrocompatibilidade** — clientes que ignoram as
extensões alternativas continuam validando o certificado pela via clássica.

**RF3 — CSR híbrido.** `CertificateSigningRequestBuilder` produz um `PKCS10CertificationRequest`
com a chave clássica no corpo e a chave PQC veiculada em extensão alternativa, delegando à
sobrecarga nativa do Bouncy Castle. Quando o ramo PQC do signatário é nulo, o resultado é um
CSR puramente clássico (`:100–141`) — degradação graciosa.

**RF4 / RF5 — Assinatura e verificação de dados.** `sign` retorna um `HybridSignaturePair`
com as duas assinaturas (clássica via JCA; PQC via `MLDSASigner`). `verify` impõe **lógica
conjuntiva (AND)**: só retorna `true` se *ambos* os ramos forem válidos
(`HybridSignatureManager.java:109`). Há ainda `verifyClassicalOnly` para cenários de
compatibilidade. *Ponto de discussão central da monografia*: a exigência dos dois ramos é o
que confere a propriedade de segurança híbrida — a falsificação exige quebrar **tanto** o
esquema clássico **quanto** o pós-quântico.

**RF6 — Validação abrangente.** `validateComprehensive` executa um *checklist* de sete
dimensões: não-expiração, consistência de DNs, período de validade, integridade da chave
pública, assinatura clássica contra a chave do emissor, presença das três extensões
*Catalyst* e, por fim, verificação da assinatura alternativa PQC
(`HybridCertificateValidator.java:57–251`). O resultado é um `ValidationResult` com
`isAllValid()` / `isHybridFullyValid()` (`:584–653`), permitindo ao chamador distinguir
validade clássica de validade híbrida completa.

**RF7 — Validação de cadeia em dois domínios.** `validateHybridChain` valida a cadeia
*folha → raiz* em **duas dimensões independentes**: (i) a dimensão clássica via
`CertPathValidator` PKIX do JDK, e (ii) a dimensão PQC percorrendo a cadeia e verificando
cada assinatura alternativa contra a chave alternativa do emissor (`:488–538`). O retorno é
um `HybridChainValidationResult(classicalValid, pqcValid)` cujo `isValid()` exige ambos.
*Ponto de discussão*: a reutilização do PKIX maduro do JDK para o ramo clássico foi possível
graças a um `PKIXCertPathChecker` customizado (ver Parte II, §4).

**RF8 — Exportação.** `CertificateExporter` oferece quatro métodos cobrindo PEM e DER, com e
sem E/S em arquivo (`exportCertificateToPEM`, `…ToDER`, `…ToPEMString`, `…ToDERBytes`),
atendendo tanto a persistência quanto a manipulação em memória.

**RF9 — Signatários externos sem exposição de chave.** Este é o requisito de maior valor
arquitetural. A abstração `HybridSigner` é um *record* sobre dois `ContentSigner` do Bouncy
Castle (`classical` obrigatório, `pqc` opcional). Como `ContentSigner` apenas **assina** sem
expor material de chave, a biblioteca aceita signatários respaldados por HSM, KMS ou *tokens*
(p. ex. o `TokenContentSigner` do CZERTAINLY) sem que a chave privada jamais transite pela
JVM. As sobrecargas **Layer 1** dos *builders* e da fachada
(`PQCHybridCertificateAPI.generateHybridCertificate(...)`, `:333`;
`generateCertificateSigningRequest(...)`, `:413`) recebem apenas chaves públicas + um
`HybridSigner`. *Ponto de discussão*: a separação **Layer 1 (agnóstica a signatário)** vs.
**Layer 2 (conveniência em memória)** é o que viabiliza adoção corporativa real.

### 1.3 Síntese arquitetural (para a Discussão)

Três padrões transversais emergem dos resultados e merecem destaque analítico:

1. **Modelo de duas camadas (Layer 1 / Layer 2).** Toda operação de emissão expõe uma
   variante *agnóstica a signatário* (chaves públicas + `HybridSigner`) e uma variante de
   *conveniência* (`HybridKeyPair` em memória). Isso concilia ergonomia de prototipagem com
   requisitos de segurança de produção (RF9).
2. **Validação conjuntiva sistemática.** RF5, RF6 e RF7 implementam lógica AND entre o ramo
   clássico e o ramo PQC. A segurança híbrida só se sustenta se a verificação rejeitar quando
   *qualquer* ramo falhar.
3. **Isolamento do provedor.** Todas as chamadas a algoritmos ML-DSA passam por
   `MLDSASigner`/`MLDSAVerifier`, e o provedor é gerenciado por
   `CryptographicProviderFactory`. A API da biblioteca permanece estável ainda que a API do
   Bouncy Castle evolua.

---

## 2. Resultados dos Requisitos Não-Funcionais (RNF)

### 2.1 Matriz de rastreabilidade

| ID | Requisito | Evidência principal | Localização |
|----|-----------|---------------------|-------------|
| **RNF1** | Conformidade FIPS 204 (ML-DSA) | OIDs canônicos NIST + delegação JCA/BC | `common/oid/AlgorithmOIDRegistry.java:34–41`; `signature/ml_dsa/MLDSASigner.java`, `MLDSAVerifier.java` |
| **RNF2** | Conformidade ITU-T X.509 (2019), assinatura alternativa | Extensões 2.5.29.72/73/74 sobre o pré-TBS | `certificate/X509ExtensionManager.java:55–157`; `certificate/asn1/PQCExtensionsStructure.java` |
| **RNF3** | Cobertura mínima de 75 % | Gate JaCoCo por *bundle* e por pacote | `pom.xml:197–278` |
| **RNF4** | Abstração do provedor criptográfico | Factory *singleton* idempotente | `config/CryptographicProviderFactory.java:45–99` |
| **RNF5** | *Thread-safety* | *Double-check locking* + *records* imutáveis + utilitários estáticos | `config/CryptographicProviderFactory.java:28,51–54`; *records* diversos |
| **RNF6** | API estável e versionada | Pacote público + SemVer | `core/api/…`; `pom.xml:10` |
| **RNF7** | Falha rápida sem algoritmos críticos | `validateRequiredAlgorithms()` na inicialização | `config/CryptographicProviderFactory.java:106–137` (chamado em `api/PQCHybridCertificateAPI.java:128–129`) |

**Resultado agregado: 7/7 requisitos não-funcionais atendidos.**

### 2.2 Discussão por requisito

**RNF1 — FIPS 204.** Os identificadores canônicos NIST estão centralizados em
`AlgorithmOIDRegistry`: ML-DSA-44 = `2.16.840.1.101.3.4.3.17`, ML-DSA-65 = `…18`,
ML-DSA-87 = `…19` (`:34–41`). As operações de assinatura/verificação delegam integralmente à
JCA com o provedor Bouncy Castle (`Signature.getInstance(algorithm, provider)`), sem
reimplementação criptográfica própria — o que sustenta a alegação de conformidade.

**RNF2 — ITU-T X.509 (2019) / *Catalyst*.** As três extensões alternativas são emitidas com
os OIDs exatos `2.5.29.72` (`subjectAltPublicKeyInfo`), `2.5.29.73` (`altSignatureAlgorithm`)
e `2.5.29.74` (`altSignatureValue`), via `X509ExtensionManager.addPQCExtensions`
(`:70–105`) e estruturadas em ASN.1/DER por `PQCExtensionsStructure`. A assinatura
alternativa é computada sobre o **pré-TBS** (ver Parte II, §4, onde a complexidade desse
ponto é discutida como desafio).

**RNF3 — Cobertura ≥ 75 %.** O gate é configurado em três regras JaCoCo (`pom.xml:237–273`):
*bundle* ≥ 0,75, *package* ≥ 0,75 e pacotes de exceção ≥ 0,40. A cobertura **medida**
atualmente é **83,1 % de linhas** (1450/1744) e **61,2 % de *branches*** — folga confortável
sobre o gate. *Observação metodológica honesta para a Discussão*: o gate só se tornou
factível após excluir do cálculo o código de demonstração (`examples`, *printers*,
*exporters*) e os componentes **experimentais não ligados ao caminho de produção** (`ml_kem`,
`KeyEncapsulationWrapper`, `migration`) — ver Parte II, §3 e §6.

**RNF4 — Abstração do provedor.** `CryptographicProviderFactory` é um *singleton* final com
construtor privado, `initialize()` idempotente protegido por *double-check locking*
(`:45–66`) e `getProvider()` que falha se não inicializado. Todos os pontos criptográficos
chamam `initialize()` defensivamente, de modo que o usuário não precisa orquestrar a
inicialização manualmente.

**RNF5 — *Thread-safety*.** A estratégia não é baseada em locks de granularidade fina, mas em
**ausência de estado mutável compartilhado**: (i) o único estado global —
o flag `initialized` da factory — é `volatile` e protegido por `synchronized` (`:28,51–54`);
(ii) os tipos de dados são *records* Java 21 imutáveis (`HybridAlgorithmPair`, `HybridSigner`,
`HybridChainValidationResult`, `EncapsulationResult`) ou classes com campos `final`
(`HybridKeyPair`); (iii) `MLDSASigner`/`MLDSAVerifier` e validadores são utilitários
*stateless* com métodos estáticos puros. Essa abordagem é mais simples de auditar do que
sincronização explícita.

**RNF6 — API estável e versionada.** O contrato público vive em `com.pqc.hybrid.core.api`
(`PQCHybridCertificateAPI` como ponto de entrada; `HybridSignatureStrategy` como ponto de
extensão). O versionamento segue SemVer (`1.0.0-BETA`), exposto tanto no `pom.xml:10` quanto
em `PQCHybridCertificateAPI.getVersion()`. O sufixo `-BETA` é coerente com o estado de
maturidade declarado.

**RNF7 — Falha rápida.** `validateRequiredAlgorithms()` (`:106–137`) testa a disponibilidade
de 10 algoritmos críticos (ML-KEM-512/768/1024, ML-DSA-44/65/87, SLH-DSA-SHA2-128s/128f,
Falcon/Falcon-512) e lança `PQCHybridException` descritiva ao primeiro ausente. É invocado já
em `PQCHybridCertificateAPI.initialize()` (`:128–129`), de modo que um ambiente mal
configurado falha na inicialização — e não em produção, no meio de uma emissão.

---

## 3. Verificação e métricas (evidência empírica para os Resultados)

| Métrica | Valor | Fonte |
|---------|-------|-------|
| Classes de teste | 33 | `find src/test -name "*Test.java"` |
| Métodos `@Test` | 188 (+ 4 `@ParameterizedTest`) | `grep` em `src/test` |
| Testes executados | **234** | relatórios Surefire |
| Testes ignorados/`@Disabled` | **0** | nenhum teste foi desativado |
| Cobertura de linhas | **83,1 %** (1450/1744) | `target/jacoco-report/jacoco.csv` |
| Cobertura de *branches* | **61,2 %** (330/539) | idem |
| Resultado de `mvn verify` | *build* verde, gate satisfeito | histórico de *commits* |

*Discussão*: a diferença entre 188 anotações `@Test` e 234 execuções deve-se à expansão dos
testes parametrizados. A cobertura de *branches* (61,2 %) é naturalmente inferior à de linhas
e concentra-se em ramos defensivos (validação de entrada, *fast-fail*), o que é aceitável e
pode ser discutido como limitação metodológica.

---

# PARTE II — DESAFIOS DE DESENVOLVIMENTO

> Esta parte reúne, com honestidade, os obstáculos técnicos atravessados. Todos têm lastro no
> histórico de *commits* e em comentários do próprio código. É o material para um capítulo que
> demonstra maturidade de engenharia — reconhecer o que foi difícil, o que mudou de rumo e o
> que ficou de fora.

## 1. Desafio 1 — Reescrita arquitetural da abstração de hibridização

A primeira arquitetura de "híbrido" (pacote `core/hybrid`, com `HybridSigner`,
`HybridVerifier`, `HybridSignatureScheme`) **não vingou e foi descartada**. O *commit*
`ba44468` (*"refactor: consolida migração Hybrid→Dual/Catalyst; remove core/hybrid e rfc"*) é
a maior refatoração do repositório (≈40 arquivos), substituindo ~620 linhas do antigo pacote
por `DualSignatureStrategy` (modelo *Catalyst*). O mesmo *commit* removeu **código de
rascunho deixado na raiz** (`TestConstructor.java`, `TestNullOID.java`, `lib-preguica.md` com
691 linhas) e um pacote `rfc` inteiro de monitoramento de *drafts* IETF (~390 linhas). *Lição
para o capítulo*: a primeira abstração foi um beco sem saída; convergir para um modelo padrão
(*Catalyst*) exigiu reescrever a fundação e fazer faxina de artefatos exploratórios.

## 2. Desafio 2 — Duas álgebras de hibridização; apenas uma viável (Catalyst × Composite)

O projeto chegou a implementar **dois** modelos híbridos sob a mesma interface
`HybridSignatureStrategy`:

- ***Catalyst* / `DualSignatureStrategy`** (produção) — chaves clássica e PQC totalmente
  independentes, assinatura alternativa via extensões X.509.
- **Composite / `CompositeSignatureStrategy`** (experimental, **não ligado à API**) —
  *commit* `cae3103` adicionou 9 classes (821 linhas) implementando o
  `draft-ietf-lamps-pq-composite-sigs`.

A via Composite foi **deliberadamente mantida fora da API pública**. O motivo está
documentado em `doc/IMPLEMENTACAO_BIBLIOTECA.md:285–286`: o Catalyst foi escolhido pela
*independência criptográfica* das chaves, evitando a "função de derivação ad-hoc (como a de
Composite, **ainda em padronização**)". A complexidade do Composite é visível em
`MessageRepresentativeBuilder.java`, que exige montar um *message representative* com prefixo
de domínio fixo (`"CompositeAlgorithmSignatures2025"`), rótulo por algoritmo, contexto
limitado a 255 bytes e pré-*hash* — maquinaria de serialização que o Catalyst dispensa. Os
Javadoc dessas classes marcam explicitamente *"EXPERIMENTAL … not wired into
PQCHybridCertificateAPI … may change without notice"*. *Lição*: depender de um *draft* IETF
não finalizado é risco de manutenção; o projeto optou por um padrão estável (ITU-T 2019) e
arquivou o outro como trabalho futuro.

## 3. Desafio 3 — Dependência crítica e isolamento do Bouncy Castle 1.84

A emissão *Catalyst* depende de uma sobrecarga **relativamente nova** do Bouncy Castle:
`X509v3CertificateBuilder.build(primarySigner, useAltSig=true, altSigner)`, que faz boa parte
da codificação do pré-TBS e emite as extensões `.73`/`.74`
(`doc/IMPLEMENTACAO_BIBLIOTECA.md:287–289`). Isso fixou a dependência em **BC 1.84**
(`pom.xml:21`) e tornou a biblioteca sensível à evolução do provedor. Dois mecanismos de
mitigação foram adotados:

1. **Camada *Adapter*.** Toda chamada ML-DSA foi centralizada em
   `MLDSASigner`/`MLDSAVerifier`, evitando espalhar `Signature.getInstance("ML-DSA-…")` pelo
   código — *"mantém a API da lib estável independentemente da evolução do BC"*
   (`doc/IMPLEMENTACAO_BIBLIOTECA.md:205`).
2. **Normalização de nomes legados.** `HybridX509CertificateBuilder.java:295–303` converte os
   nomes antigos `Dilithium2/3/5` para os canônicos `ML-DSA-44/65/87`, absorvendo a transição
   de nomenclatura do ecossistema.

*Lição*: trabalhar na fronteira da padronização PQC significa depender de APIs ainda em
amadurecimento; o projeto respondeu com isolamento (Adapter) e *fail-fast* na disponibilidade
de algoritmos (RNF7).

## 4. Desafio 4 — Reconstrução manual do pré-TBS na verificação (o problema ASN.1/DER central)

Este é o obstáculo tecnicamente mais delicado. Na **emissão**, o Bouncy Castle cuida do
pré-TBS. Mas na **verificação** da assinatura alternativa não há atalho: é preciso
**reconstruir exatamente o mesmo pré-TBS que foi assinado**. O método
`HybridCertificateValidator.reconstructPreTBS()` (`:319–357`) evidencia as armadilhas:

- **Remover a extensão `altSignatureValue` (.74)** antes de re-serializar — uma assinatura não
  pode cobrir a si mesma (`:332`).
- **Omitir intencionalmente o campo `signature` (AlgorithmIdentifier)** — o comentário em
  `:336–337` é explícito: *"the signature field is intentionally NOT set —
  generatePreTBSCertificate() omits it (and rejects the structure if it is present)"*. Setar
  esse campo quebra a verificação inteira.
- **Preservar `issuerUniqueId`/`subjectUniqueId`** com os *pad bits* corretos (`:345–352`).
- **Re-codificar em DER explícito** (`getEncoded(ASN1Encoding.DER)`, `:356`) — qualquer
  divergência de ordem ou *encoding* invalida a assinatura.

*Lição*: a interoperabilidade de assinaturas alternativas é extremamente sensível à
serialização canônica; "quase igual" significa "inválido".

### 4.1 Desafio correlato — PKIX hostil a extensões críticas desconhecidas

As extensões `.72/.73/.74` são marcadas como **críticas**, e o `CertPathValidator` PKIX padrão
do JDK **rejeita** certificados com extensões críticas que não reconhece. Foi necessário
implementar um `PKIXCertPathChecker` customizado —
`HybridCertificateValidator.HybridExtensionChecker` (`:550–582`) — que declara as três OIDs
como tratadas e as remove de `unresolvedCritExts`. Comentário em `:506`: *"The Catalyst
alt-signature extensions are marked critical; tell PKIX they are handled."* Só assim foi
possível **reusar o PKIX maduro do JDK** para o ramo clássico em vez de reimplementar
validação de caminho.

## 5. Desafio 5 — Cobertura de testes desabada por ruído experimental

O gate de 75 % inicialmente **derrubou a métrica para 32 %** porque contava código de
demonstração e componentes experimentais não ligados ao caminho *Catalyst* (*commit*
`b898302` — *"fix(build): exclui código demo/experimental do gate JaCoCo"*). A solução teve
duas frentes: (i) **excluir** do gate os pacotes `examples`, *printers*, *exporters*,
`ml_kem`, `KeyEncapsulationWrapper` e `migration` (`pom.xml:202+`); e (ii) um esforço
**retroativo** grande de testes — *commit* `a68ed02` adicionou **1201 linhas de teste de uma
só vez**, cobrindo model/keygen/signature/config/oid/certificate e a fachada ponta-a-ponta,
levando a cobertura efetiva a ~83 %. *Lição (e ponto de honestidade metodológica)*: a métrica
de 83 % refere-se ao **núcleo de produção**; a exclusão deliberada de código experimental
deve ser declarada para não superestimar a maturidade global.

## 6. Desafio 6 — Escopo cortado com honestidade (limitações declaradas)

Vários subsistemas sugeridos pelo nome do repositório (*pqc-migration-kit*) ficaram como
**esqueleto ou aspiração**, e isso está documentado no próprio código — material valioso para
a seção de *Limitações e Trabalhos Futuros*:

- **Migração de certificados legados** — `migration/LegacyCertificateMigrator.java:6` declara
  *"EXPERIMENTAL / PLACEHOLDER"*; `:31` *"real migration is not implemented"*. É apenas um
  esqueleto.
- **Encapsulamento de chave (ML-KEM)** — `KeyEncapsulationWrapper.java:88–121` e
  `MLKEMEncapsulator/Decapsulator` contêm *"simplified representation … not yet fully
  implemented"* e lançam exceção. O KEM PQC é *placeholder*.
- **Interoperabilidade OpenSSL** — o *commit* `23591bc` removeu um `docker-compose.yml` cuja
  configuração de interop era *"aspiracional"* (apontava para caminhos inexistentes, nenhum
  teste a consumia). `doc/IMPLEMENTATION_PHASES.md:184` admite *"OpenSSL interop and RFC
  tracker not implemented"*.
- **Protocolos ACME/SCEP/CMP, PKCS#12/JKS, Composite** — listados explicitamente como **fora
  de escopo** em `doc/IMPLEMENTACAO_BIBLIOTECA.md:43–52` (formatos legados *"não modelam
  canonicamente chaves ML-DSA"*).
- **OIDs Falcon provisórios** — `AlgorithmOIDRegistry.java:85` marca Falcon como *"Not yet NIST
  standardized (provisional): 1.3.9999.3.x"*; Falcon foi despriorizado por *"implementação
  delicada (Gaussian sampling, floating point) e menor maturidade no ecossistema Java"*
  (`doc/IMPLEMENTACAO_BIBLIOTECA.md:328`).

## 7. Desafio 7 — Robustez do *parsing* do envelope de assinatura (achado de execução)

Descoberto ao **executar** o exemplo de assinatura (ver Parte III, §1): o envelope híbrido do
`DualSignatureStrategy` serializa os dois ramos com um prefixo de comprimento de 4 bytes
(`DualSignatureStrategy.java:50–55`). Disso decorrem **dois regimes de corrupção**: a corrupção
do **conteúdo** das assinaturas faz a verificação falhar de forma limpa retornando `false`;
já a corrupção do **prefixo de comprimento (framing)** impede o desmembramento dos ramos e a
biblioteca lança `InvalidSignatureException: "bad classical length"` (`DualSignatureStrategy.java:71–72`).

*Decisão de engenharia (e por que a biblioteca não foi alterada).* O lançamento de exceção em
*encoding* malformado **é deliberado e está coberto por teste** (`DualSignatureStrategyTest:46`),
além de ser coerente com a JCA (`Signature.verify` também lança em *encoding* inválido). Em
termos de **segurança** os dois regimes são equivalentes — nenhuma assinatura inválida é aceita.
A divergência é apenas de **contrato de API** (booleano `false` × exceção). Por isso a correção
foi feita no **código de exemplo**, não na biblioteca: o Passo 5 passou a corromper o *payload*
(demonstrando o retorno `false`) e a envolver a chamada em `try/catch` por robustez
(`SignAndVerifyExample.java:97–113`), de modo que o exemplo agora roda até o resumo final.
*Lição*: desserializar dados não confiáveis exige decidir conscientemente entre "exceção" e
"valor de falha", e manter esse contrato consistente e documentado. *Trabalho futuro opcional*:
unificar o contrato de `verify`, normalizando a falha de *framing* para `false` e reservando a
exceção a diagnóstico interno.

---

# PARTE III — EXEMPLOS DE EXECUÇÃO E RETORNOS REAIS

> Todas as saídas desta parte foram **capturadas de execução real** em 2026-06-10, rodando as
> classes de exemplo do pacote `com.pqc.hybrid.examples` sobre Java 21 + Bouncy Castle 1.84.
> Os exemplos são reproduzíveis a partir do classpath do projeto:
>
> ```bash
> mvn -q compile
> mvn -q dependency:build-classpath -Dmdep.outputFile=target/cp.txt
> CP="target/classes:$(cat target/cp.txt)"
> java -cp "$CP" com.pqc.hybrid.examples.<NomeDoExemplo>
> ```
>
> As linhas iniciadas por `INFO:` são *logs* da própria biblioteca (`java.util.logging`) e
> servem como evidência viva de RNF4 (inicialização do provedor) e RNF7 (*fail-fast* na
> validação de algoritmos).

## 1. Exemplo: assinatura e verificação híbrida (RF4, RF5)

**Classe:** `SignAndVerifyExample` — gera par de chaves de 256 bits (ECDSA-521 + ML-DSA-87),
assina um documento, verifica a assinatura válida e tenta detectar (a) dado adulterado e
(b) assinatura corrompida.

### 1.1 Comando

```bash
java -cp "$CP" com.pqc.hybrid.examples.SignAndVerifyExample
```

### 1.2 Saída real

```text
╔════════════════════════════════════════════════════════════╗
║  PQC Hybrid Certificates - Sign & Verify Example            ║
╚════════════════════════════════════════════════════════════╝

📦 Step 1: Initialize API and Generate Keys...
INFO: BouncyCastle provider initialized
INFO: All required PQC algorithms are available
INFO: PQCHybridCertificateAPI initialized successfully (v1.0.0-BETA)
INFO: Generated hybrid key pair: ECDSA + ML-DSA-87
   ✅ Generated key pair: ECDSA + ML-DSA-87
   Classical Algorithm: ECDSA
   PQC Algorithm: ML-DSA-87

✍️  Step 2: Sign Important Data...
   Data to sign: This is a critical document that needs dual-algorithm protection
   Data size: 64 bytes
INFO: Signed data with hybrid signature: ECDSA + ML-DSA-87
   ✅ Signature generated: 4770 bytes
      Signing time: 32 ms

   Signature (Base64, first 80 chars):
      AAAAizCBiAJCAYJjXOUqARNcVMu274IbzuHIkQF+iEklBTfBOeRbwOCoPXxrxaoBYuxIMPHl/louLkLR...

✅ Step 3: Verify Valid Signature...
   Verification result: ✅ VALID
   Verification time: 16 ms
   ⚠️  NOTE: Both classical AND PQC signatures must be valid for success

🔍 Step 4: Detect Tampered Data...
   Tampered data: This is a FORGED document
   Verification result: ❌ INVALID (TAMPERING DETECTED)
   Verification time: 5 ms

🔍 Step 5: Detect Corrupted Signature...
   Note: Modified last byte of signature
   Verification result: ❌ INVALID (CORRUPTION DETECTED)
   Verification time: 2 ms

📊 Summary:
   ✅ Original signature: VALID
   ✅ Tampered data: DETECTED
   ✅ Corrupted signature: DETECTED

✅ Sign & Verify example completed successfully!
```

### 1.3 Leitura dos resultados (para a Discussão)

| Observação | Valor medido | Interpretação |
|------------|--------------|---------------|
| Algoritmos selecionados em 256 bits | ECDSA + **ML-DSA-87** | A fachada mapeia "256 bits" para o par recomendado de nível NIST 5 |
| Envelope da assinatura híbrida | **4770 bytes** | Domina o componente PQC (ML-DSA-87); a ordem de grandeza é a esperada para PQC |
| Tempo de assinatura / verificação | **32 ms / 16 ms** | Latência baixa; coerente com ML-DSA ser eficiente |
| Detecção de dado adulterado (RF5) | **❌ INVALID** em 5 ms | A verificação conjuntiva rejeita o documento forjado — comportamento correto |
| Assinatura corrompida (último byte invertido) | **❌ INVALID (CORRUPTION DETECTED)** em 2 ms | Rejeição graciosa via `false` — ver discussão abaixo |

> **Discussão — dois regimes de corrupção e o contrato de `verify` (Desafio 7).** O envelope
> híbrido do `DualSignatureStrategy` serializa os dois ramos com um **prefixo de comprimento de
> 4 bytes** (`[len classical][classical][pqc]`, `DualSignatureStrategy.java:50–55`). Disso
> decorre uma distinção de comportamento, **intencional e coberta por teste**
> (`DualSignatureStrategyTest:46`):
>
> - **Corrupção no *payload* das assinaturas** (caso deste Passo 5, último byte): os dois ramos
>   ainda são separáveis, a verificação ML-DSA/ECDSA simplesmente não confere e `verify`
>   retorna **`false`** — rejeição graciosa.
> - **Corrupção no *enquadramento (framing)*** (p. ex. inverter o 1º byte, parte do prefixo de
>   comprimento): o envelope sequer pode ser desmembrado e a biblioteca lança
>   **`InvalidSignatureException: "bad classical length"`** (`DualSignatureStrategy.java:71–72`).
>   Isso é coerente com a JCA (`Signature.verify` também lança em *encoding* inválido) e está
>   assertado em teste.
>
> *Implicação para a redação*: em **segurança** os dois regimes são equivalentes (nenhuma
> assinatura inválida é aceita); a diferença é de **contrato de API**. Por isso o código de
> exemplo foi endurecido para tratar **ambos** os caminhos como "corrupção detectada"
> (corrompendo o *payload* para demonstrar o retorno `false` e envolvendo a chamada em
> `try/catch` por robustez — `SignAndVerifyExample.java:97–113`). A biblioteca **não** foi
> alterada, pois o lançamento de exceção em *encoding* malformado é deliberado e testado.
> Fica como **trabalho futuro** opcional unificar o contrato (normalizar a falha de *framing*
> para `false`, reservando a exceção para diagnóstico interno).

## 2. Exemplo: emissão de certificado X.509 híbrido (RF2, RNF2)

**Classe:** `GenerateCertificateExample` — nível 192 bits (ECDSA-384 + ML-DSA-65), emissão
*Catalyst* com as extensões alternativas.

### 2.1 Comando

```bash
java -cp "$CP" com.pqc.hybrid.examples.GenerateCertificateExample
```

### 2.2 Saída real

```text
╔════════════════════════════════════════════════════════════╗
║  PQC Hybrid Certificates - Certificate Generation Example   ║
╚════════════════════════════════════════════════════════════╝

📦 Step 1: Initialize PQC Hybrid Library...
INFO: BouncyCastle provider initialized
INFO: All required PQC algorithms are available
INFO: PQCHybridCertificateAPI initialized successfully (v1.0.0-BETA)
   ✅ API initialized (v1.0.0-BETA)

🔐 Step 2: Choose Security Level...
   Selected security level: 192 bits
   Algorithms: ECDSA-384 + ML-DSA-65
   Balanced: true
   NIST Standardized: true

🔑 Step 3: Generate Hybrid Key Pair...
INFO: Generated hybrid key pair: ECDSA + ML-DSA-65
   ✅ Key pair generated: ECDSA + ML-DSA-65
   Generation time: 29 ms
   Classical algorithm: ECDSA
   PQC algorithm: ML-DSA-65

📋 Step 4: Configure Certificate Parameters...
   Subject DN: CN=secure.example.com,O=Example Organization,C=BR
   Issuer DN:  CN=Example CA,O=Example Organization,C=BR
   Validity: 365 days

🏗️  Step 5: Build Hybrid X.509 Certificate...
INFO: Issued hybrid certificate for CN=secure.example.com,O=Example Organization,C=BR (issuer: CN=Example CA,O=Example Organization,C=BR)
   ✅ Certificate built successfully
   Build time: 81 ms

📜 Certificate Information:
   Subject: CN=secure.example.com,O=Example Organization,C=BR
   Issuer:  CN=Example CA,O=Example Organization,C=BR
   Serial#: 848110492604328987250583565748936529989842470757
   Valid From: Wed Jun 10 20:10:44 UTC 2026
   Valid Until: Thu Jun 10 20:10:44 UTC 2027
   Signature Algorithm: SHA256WITHECDSA
   Public Key Algorithm: EC
   Extensions: 8 total (4 critical)
   PQC alt-signature extensions present: true

📊 Hybrid Signature Details:
   Primary Signature Size: 103 bytes

✅ Certificate generation example completed successfully!
```

### 2.3 Leitura dos resultados (para a Discussão)

| Observação | Valor medido | Interpretação |
|------------|--------------|---------------|
| Par para 192 bits | ECDSA-384 + ML-DSA-65 | Nível NIST 3, criptograficamente balanceado |
| Tempo de geração de chave | **29 ms** | |
| Tempo de emissão do certificado | **81 ms** | Inclui a assinatura clássica + a assinatura alternativa PQC sobre o pré-TBS |
| `Signature Algorithm` | **`SHA256WITHECDSA`** | Confirma o modelo *Catalyst*: a assinatura **primária** é clássica; a PQC vai nas extensões `.73/.74` |
| `Extensions` | **8 no total (4 críticas)** | Inclui as três extensões *Catalyst* além de SKI/AKI/KeyUsage/BasicConstraints etc. |
| `PQC alt-signature extensions present` | **`true`** | Evidência direta de RNF2: as três OIDs `2.5.29.72/73/74` estão presentes no certificado emitido |
| `Primary Signature Size` | **103 bytes** | Tamanho típico de uma assinatura ECDSA-384 em DER — é só o ramo primário (varia ±2 bytes) |
| Número de série | 160 bits aleatórios | Ex.: `1337542714804124559528790915500245188128160026162` |

> **Nota.** O exemplo foi ajustado para imprimir a **contagem real de extensões** e uma
> verificação booleana da presença das três extensões *Catalyst*
> (`GenerateCertificateExample.java:106–113`), substituindo a antiga linha que exibia por
> engano a referência de um `byte[]`. A saída acima já reflete o exemplo corrigido e serve
> como evidência executável de RNF2.

## 3. Exemplo: catálogo de algoritmos e desempenho de geração (RNF1)

**Classe:** `AlgorithmExplorerExample` — lista os algoritmos clássicos e PQC suportados (com
tamanhos reais), os pares recomendados por nível e mede a geração de chaves nos três níveis.

### 3.1 Saída real (trecho)

```text
🔐 CLASSICAL ALGORITHMS:
   Algorithm       Key Size   Security Level
   --------------------------------------------------
   RSA             2048       128
   RSA             3072       128
   RSA             4096       256
   ECDSA           256        128
   ECDSA           384        192
   ECDSA           521        256

📋 PQC SIGNATURE ALGORITHMS:
   Algorithm            Security Level  Public Key (B)
   -------------------------------------------------------
   ML-DSA-44            128             1312
   ML-DSA-65            192             1952
   ML-DSA-87            256             2592
   SLH-DSA-SHA2-128s    128             2144
   SLH-DSA-SHA2-128f    128             4784
   SLH-DSA-SHA2-192s    192             3104
   SLH-DSA-SHA2-192f    192             7036
   SLH-DSA-SHA2-256s    256             4784
   SLH-DSA-SHA2-256f    256             9076
   Falcon-512           128             666
   Falcon-1024          256             1280

🎯 RECOMMENDED HYBRID PAIRS BY SECURITY LEVEL:
   Security Level: 128 bits → ECDSA-256 + ML-DSA-44   (Balanced: Yes, NIST: Yes)
   Security Level: 192 bits → ECDSA-384 + ML-DSA-65   (Balanced: Yes, NIST: Yes)
   Security Level: 256 bits → ECDSA-521 + ML-DSA-87   (Balanced: Yes, NIST: Yes)

📊 KEY GENERATION PERFORMANCE:
   Security Level  Algorithm Pair  Time (ms)       Status
   -----------------------------------------------------------------
   128             ECDSA-256 + ML- 24              ✅ Generated
   192             ECDSA-384 + ML- 16              ✅ Generated
   256             ECDSA-521 + ML- 18              ✅ Generated
```

### 3.2 Leitura dos resultados (para a Discussão)

- **Tabela de tamanhos de chave pública** confirma o *trade-off* central do PQC: as chaves
  ML-DSA (1312–2592 B) e SLH-DSA (até 9076 B) são ordens de grandeza maiores que ECDSA. É um
  dado quantitativo forte para discutir o custo de banda/armazenamento da migração híbrida.
- **Falcon** aparece no catálogo (666–1280 B, as menores chaves PQC), mas — conforme a Parte
  II, §6 — usa OIDs provisórios e é despriorizado; não é o par recomendado em nenhum nível.
- **Geração de chave consistentemente rápida** (16–24 ms nos três níveis): o custo de gerar o
  par híbrido é dominado pela curva elíptica + ML-DSA, ambos eficientes.

> **Nota (correção de metadado aplicada).** A tabela "PQC KEM ALGORITHMS" reportava por engano
> `ML-KEM-512` com *security level* `256`. O valor foi corrigido para **`128`**
> (ML-KEM-512 é nível NIST 1, ~128 bits), em linha com o comentário canônico do próprio
> `AlgorithmOIDRegistry.java:49`. A saída executada agora exibe:
>
> ```text
> 🔑 PQC KEM ALGORITHMS:
>    Algorithm            Security Level  Public Key (B)
>    -------------------------------------------------------
>    ML-KEM-512           128             768
>    ML-KEM-768           192             1088
>    ML-KEM-1024          256             1568
> ```
>
> Ressalva: o KEM continua pertencendo ao caminho **experimental excluído do gate** (Parte II,
> §3 e §6) e não é usado na emissão *Catalyst* — permanece como trabalho futuro. (Observação
> adicional, não corrigida por estar fora de escopo: os valores na coluna "Public Key (B)" do
> ML-KEM correspondem, na verdade, ao tamanho do *ciphertext*, não ao da chave pública; por
> isso a tabela de KEM não deve ser usada como resultado quantitativo na monografia.)

## 4. Síntese das medições (números prontos para citar)

| Operação | Par de algoritmos | Tempo medido |
|----------|-------------------|--------------|
| Geração de chave (128 bits) | ECDSA-256 + ML-DSA-44 | 24 ms |
| Geração de chave (192 bits) | ECDSA-384 + ML-DSA-65 | 16–29 ms |
| Geração de chave (256 bits) | ECDSA-521 + ML-DSA-87 | 18 ms |
| Assinatura de dados (256 bits) | ECDSA + ML-DSA-87 | 32 ms |
| Verificação de assinatura | ECDSA + ML-DSA-87 | 16 ms |
| Rejeição de dado adulterado | ECDSA + ML-DSA-87 | 5 ms |
| Emissão de certificado (192 bits) | ECDSA-384 + ML-DSA-65 | 81 ms |

*Ressalva metodológica*: são medições de **execução única**, em ambiente de desenvolvimento,
com JVM "fria" (sem *warm-up* nem JMH). Servem para demonstrar **ordem de grandeza** e
viabilidade prática, não como *benchmark* estatístico. Se a banca exigir rigor de desempenho,
recomenda-se repetir com JMH e reportar média ± desvio.

---

## 7. Recomendações para a redação do TCC

1. **Resultados — abra com a matriz de rastreabilidade** (§1.1 e §2.1) e depois aprofunde os
   RF/RNF de maior densidade técnica (RF5, RF7, RF9; RNF1, RNF2). Use os números de §3 como
   evidência empírica.
2. **Discussão — três eixos analíticos**: (i) o modelo de duas camadas e seu valor para adoção
   corporativa (RF9); (ii) a validação conjuntiva AND como fundamento da segurança híbrida;
   (iii) o isolamento do provedor como resposta à imaturidade do ecossistema PQC.
3. **Desafios — narre a trajetória, não só o estado final**: a reescrita `core/hybrid`→
   *Catalyst* (Desafio 1), a bifurcação Catalyst/Composite (Desafio 2) e a reconstrução do
   pré-TBS (Desafio 4) são as três histórias mais fortes.
4. **Limitações — seja explícito** sobre KEM, migração legada e interop OpenSSL como trabalho
   futuro (Desafio 6); isso reforça a credibilidade do trabalho.
5. **Ameaça à validade da métrica de cobertura**: declare que os 83 % excluem código
   experimental/demo (§2.2 RNF3 e Desafio 5).

---

*Documento gerado a partir de verificação direta do código-fonte, do `pom.xml`, dos
relatórios JaCoCo/Surefire e do histórico git em 2026-06-10. Todas as referências
`arquivo:linha` apontam para `src/main/java/com/pqc/hybrid/…` salvo indicação contrária.*
