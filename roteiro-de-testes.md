# Roteiro de testes das evidências

Este roteiro lista, na ordem em que rodam, os testes que produzem as duas campanhas de evidência
versionadas no kit:

- `evidencias/01..09`: campanha da biblioteca, gerada pelo perfil Maven `validacao`;
- `integracao/evidencias`: integração com o core (OmniTrustILM), gerada por
  `integracao/coletar-evidencias-core.sh`.

A ordem dos testes dentro de cada campanha é a ordem **observada** na última rodada versionada. Na
biblioteca ela sai da sequência de casos em `evidencias/manifesto.json`. No core sai dos relatórios
do Surefire em `integracao/evidencias/surefire`. Nenhuma das campanhas fixa a ordem com `@Order` ou
`runOrder`, então ela pode mudar entre JVMs ou sistemas de arquivos. Nenhum teste depende de outro.

---

## Visão geral da sequência

| Passo | Onde | Comando | Testes | Saída |
|---|---|---|---:|---|
| 1 | kit | `mvn test -Pvalidacao` | 28 | `evidencias/01..09`, `MANIFESTO.md`, `manifesto.json`, `SHA256SUMS`, `ambiente.txt` |
| 2 | kit | `mvn install` | — | jar `pqc-hybrid-certificates-1.0.0-BETA.jar` em `~/.m2`, consumido pelo core |
| 3 | core | (manual) copiar `raiz.der`/`folha.der` da área 09 para `src/test/resources/pqc/politica-validacao/<cenário>/` e versionar no core | — | fixtures do core |
| 4 | kit | `integracao/coletar-evidencias-core.sh [caminho-do-core]` | 6 + 156 + 136 | `integracao/evidencias/` |

O passo 3 só é necessário quando a área 09 é regenerada. As chaves da campanha são novas a cada
rodada, então os certificados mudam de bytes. O script do passo 4 compara os SHA-256 dos dois lados
e aborta se divergirem.

---

## 1. Campanha da biblioteca: `mvn test -Pvalidacao`

**Pré-requisitos:** Java 21, Maven 3.9 e `openssl` no `PATH` (só a área 09 o usa; sem ele, a
coluna `openssl verify` sai como `n/d`).

```bash
mvn test -Pvalidacao                                  # grava em evidencias/
mvn test -Pvalidacao -Dvalidacao.saida=/outro/dir     # grava em outro diretório
```

**Como funciona:**

- Todas as classes estendem `ValidationTestBase`, marcada com `@Tag("validacao")`. O build padrão
  exclui essa tag (`surefire.excludedGroups=validacao` no `pom.xml`), e o perfil `validacao` a
  inverte para que só ela rode. O Failsafe também a exclui.
- Cada teste **afirma** o comportamento e **grava** os bytes que o sustentam, via
  `EvidenceRecorder`. Uma regressão falha a rodada em vez de gerar evidência errada.
- Ao fim da sessão do JUnit, o `EvidenceRecorder` (um `CloseableResource`) grava o
  `MANIFESTO.md`, o `manifesto.json` e o `SHA256SUMS` com `ManifestWriter`, e o `ambiente.txt` com
  `EnvironmentProbe`.
- Nenhuma chave privada é gravada: o próprio gravador recusa nomes que sugiram material privado
  (testado em 7.4).

**Resultado da última rodada** (`evidencias/MANIFESTO.md`): 28 testes, 52 casos, 0 pulados, 214
artefatos. Commit `bb5a973`, BC 1.84, OpenSSL 3.0.13 e Temurin 21.0.11.

### Ordem de execução

As classes rodaram nesta ordem: **A5 → A2 → A4 → A7 → A6 → A1 → A3 → A9 → A8**. Os casos de evidência
(pastas em `evidencias/<área>/<caso>/`) aparecem na ordem em que foram gravados.

#### 1.1 `A5AssinaturaDadosValidationTest`, área 05: assinatura de dados

| # | Teste | O que comprova | Casos gravados |
|---|---|---|---|
| 1 | `envelope_hibrido` | O envelope híbrido separa as duas assinaturas por um prefixo de tamanho de 4 bytes | `envelope-hibrido` |
| 2 | `verificacao_apenas_classica` | A via clássica isolada continua conferível, para compatibilidade | `verificacao-apenas-classica` |
| 3 | `separacao_por_contexto` | O contexto FIPS 204 separa domínios de uso da mesma chave | `separacao-por-contexto` |
| 4 | `logica_e_sob_adulteracao` | A lógica E rejeita a adulteração do dado e de qualquer uma das metades | `logica-e-adulteracao` |

#### 1.2 `A2EmissaoCertificadosValidationTest`, área 02: emissão de certificados híbridos

| # | Teste | O que comprova | Casos gravados |
|---|---|---|---|
| 1 | `criticidade_configuravel` | A criticidade das extensões 73/74 é o ponto de controle da migração | `criticidade-compativel`, `criticidade-estrita` |
| 2 | `emissao_por_nivel` | Cada nível emite um certificado com as três extensões Catalyst (72/73/74) | `nivel-128`, `nivel-192`, `nivel-256` |
| 3 | `ordem_de_assinatura` | A ordem de assinatura do Catalyst é observável no certificado emitido | `ordem-de-assinatura` |
| 4 | `layer1_signer_externo` | A Layer 1 emite sem que o construtor conheça a chave privada (`ContentSigner` externo) | `layer1-signer-externo` |

#### 1.3 `A4CsrValidationTest`, área 04: requisições PKCS#10 híbridas

| # | Teste | O que comprova | Casos gravados |
|---|---|---|---|
| 1 | `csr_por_nivel` | A CSR é emitida para os três níveis recomendados | `csr-nivel-128`, `csr-nivel-192`, `csr-nivel-256`, `resumo-csr` |
| 2 | `csr_hibrida` | A CSR híbrida carrega as duas chaves e as duas assinaturas | `csr-hibrida-192` |

#### 1.4 `A7ExportacaoInspecaoValidationTest`, área 07: exportação e inspeção

| # | Teste | O que comprova | Casos gravados |
|---|---|---|---|
| 1 | `chave_privada_nao_e_exportavel` | A biblioteca não oferece exportação de chave privada | `sem-exportacao-de-chave-privada` |
| 2 | `pem_equivale_a_der` | PEM e DER carregam exatamente o mesmo certificado | `pem-equivale-der` |
| 3 | `relatorios_de_inspecao` | Os quatro relatórios de inspeção são gerados sobre os objetos reais | `relatorios-de-inspecao` |
| 4 | `gravador_recusa_material_privado` | O gravador de evidência recusa nomes que sugiram material privado | `guarda-material-privado` |

#### 1.5 `A6ValidacaoValidationTest`, área 06: validação

| # | Teste | O que comprova | Casos gravados |
|---|---|---|---|
| 1 | `cadeia_em_duas_dimensoes` | A cadeia é avaliada em duas dimensões independentes (clássica e pós-quântica) | `cadeia-duas-dimensoes` |
| 2 | `modos_de_falha` | Cada modo de falha é detectado e registrado | `modos-de-falha` |
| 3 | `caminho_feliz` | Um certificado legítimo é aprovado em todas as verificações | `caminho-feliz` |

#### 1.6 `A1GeracaoChavesValidationTest`, área 01: geração de chaves

| # | Teste | O que comprova | Casos gravados |
|---|---|---|---|
| 1 | `variantes_ml_dsa` | Cada variante ML-DSA produz uma chave pública do tamanho definido no FIPS 204 | `ml-dsa-44`, `ml-dsa-65`, `ml-dsa-87`, `resumo-ml-dsa` |
| 2 | `balanco_dos_pares_prontos` | Nem todo par pronto é balanceado, e o relatório diz qual não é | `balanco-pares-prontos` |
| 3 | `pares_recomendados` | Os três pares recomendados são gerados e reportados como balanceados | `par-recomendado-128`, `-192`, `-256`, `resumo-pares` |
| 4 | `variantes_classicas` | Cada variante clássica produz uma chave pública do tamanho esperado | `rsa-2048`, `rsa-3072`, `rsa-4096`, `ecdsa-p256`, `ecdsa-p384`, `ecdsa-p521`, `resumo-classicos` |

#### 1.7 `A3AutoridadeCertificadoraValidationTest`, área 03: autoridade certificadora

| # | Teste | O que comprova | Casos gravados |
|---|---|---|---|
| 1 | `cadeia_quebrada_e_rejeitada` | A cadeia é rejeitada quando um elo é substituído por outro emissor | `cadeia-com-ancora-trocada` |
| 2 | `encadeamento_de_nomes` | O encadeamento de nomes é verificado contra o emissor (RFC 5280 §6.1.3(a)(4)) | `encadeamento-de-nomes` |
| 3 | `cadeia_de_tres_niveis` | Uma cadeia raiz → sub-CA → folha valida nas duas dimensões | `cadeia-tres-niveis` |

#### 1.8 `A9PoliticaValidacaoValidationTest`, área 09: política de validação

Um único teste, `matriz_de_politica`, percorre seis cenários. Em cada um, mede o
`CertPathValidator` puro do JDK (sem Bouncy Castle) e o `openssl verify`, e **afirma** o veredito da
biblioteca em três políticas: `strict()`, `REQUIRE_BOTH {ML-DSA-65, ML-DSA-87}` e `CLASSICAL_ONLY`.
O JDK e o OpenSSL são só registrados; quem é afirmado é a biblioteca.

| # | Cenário (caso gravado) | Descrição |
|---|---|---|
| 1 | `integro` | Cadeia híbrida legítima |
| 2 | `assinadores-misturados` | Assinatura clássica da AC com ML-DSA do atacante |
| 3 | `stripping` | Extensões alternativas removidas; só a assinatura clássica, com a chave da AC |
| 4 | `algoritmo-fora-da-lista` | Assinatura alternativa em ML-DSA-44, fora de {65, 87} |
| 5 | `assinatura-classica-invalida` | Assinatura clássica do atacante com ML-DSA da AC |
| 6 | `emissor-sem-chave-alternativa` | AC só clássica |
| — | `matriz` | Tabela-resumo: verificadores legados × política da biblioteca |

Cada cenário grava `raiz.der` e `folha.der`, que viram as **fixtures do core** (passo 3).

#### 1.9 `A8ProvedorValidationTest`, área 08: provedor e diagnóstico

| # | Teste | O que comprova | Casos gravados |
|---|---|---|---|
| 1 | `validacao_de_algoritmos_obrigatorios` | A inicialização falha rápido se faltar um algoritmo obrigatório | `algoritmos-obrigatorios` |
| 2 | `provedor_em_uso` | O provedor em uso é identificado e registrado | `provedor-em-uso` |
| 3 | `disponibilidade_de_algoritmos` | Todos os algoritmos do fluxo ativo estão disponíveis | `disponibilidade-algoritmos` |

---

## 2. Instalação do jar: `mvn install`

O core declara `com.pqc.hybrid:pqc-hybrid-certificates:1.0.0-BETA` e o resolve do repositório
local. O script do passo 4 grava o SHA-256 desse jar em `integracao/evidencias/ambiente.txt`
(`~/.m2/repository/com/pqc/hybrid/pqc-hybrid-certificates/1.0.0-BETA/`). O jar sai com `LICENSE` e
`NOTICE` e sem o pacote `examples`.

---

## 3. Fixtures do core

O core lê os certificados da área 09 em
`src/test/resources/pqc/politica-validacao/<cenário>/{raiz,folha}.der`, nos mesmos seis cenários.
O sétimo cenário, `cadeia-classica` (controle puramente clássico, ECDSA P-256), não vem do kit:
`PqcPolicyFixtures.generateClassicalChain()` o gera em memória no próprio core.

---

## 4. Integração com o core: `integracao/coletar-evidencias-core.sh`

```bash
integracao/coletar-evidencias-core.sh                 # core em ../core
integracao/coletar-evidencias-core.sh /caminho/do/core
COMMIT_ANTES=<sha> integracao/coletar-evidencias-core.sh   # outra linha de base (padrão cf583bcf)
```

**Ramo do core:** `poc/pqc-migration-kit`. A árvore do core precisa estar limpa, ou o script aborta.

O script executa estas etapas, em ordem:

| Etapa | Ação | Falha se |
|---|---|---|
| 4.0 | Confere se a árvore do core está limpa | houver alterações no core |
| 4.1 | Compara o SHA-256 de `*/raiz.der` e `*/folha.der` da área 09 com as fixtures do core e grava `fixtures.sha256` | os bytes divergirem |
| 4.2 | **Linha de base antes da integração:** cria um `git worktree` no commit `COMMIT_ANTES` (validador original) e roda `PqcNativeBaselineITest` | — (o código de saída vai para `ambiente.txt`) |
| 4.3 | **Testes da integração** no commit atual: `mvn clean test` com as seis classes abaixo | — (idem) |
| 4.4 | Compara byte a byte a linha de base de 4.2 com o modo `native` de 4.3 e grava `equivalencia-native.txt` | — (o diff fica registrado) |
| 4.5 | **Regras de arquitetura do core:** `mvn test -Dtest='com.otilm.core.architecture.*Test'` | — (idem) |
| 4.6 | Remove `<properties>` dos XML do Surefire e procura e-mails nas evidências | sobrar algum endereço de e-mail |
| 4.7 | Monta `comparacao.md` (área 09 do kit × modos do core), `ambiente.txt` e `SHA256SUMS` | — |
| — | Código de saída final | qualquer um dos três `mvn` ter falhado |

Só as linhas `Tests run:`, `BUILD …` e `[ERROR]` do log do Maven são guardadas, porque o log
completo traz e-mails e caminhos locais.

### 4.2 Linha de base no commit anterior ao adaptador

`PqcNativeBaselineITest`, no commit `cf583bcf`: **6 testes**, saída em
`resultado-testes-antes-da-integracao.txt` e `linha-de-base-antes-da-integracao/`.

| # | Teste | Cenário |
|---|---|---|
| 1–6 | `recordNativeValidation(String)` | `integro`, `assinadores-misturados`, `stripping`, `algoritmo-fora-da-lista`, `assinatura-classica-invalida`, `emissor-sem-chave-alternativa` |

O teste **mede sem afirmar**. Ele importa a raiz como AC confiável, importa a folha, valida as duas
com o validador original do core e grava um relatório por cenário mais `matriz-nativa.md`.

### 4.3 Testes da integração no commit atual

Comando: `mvn -B clean test -Dtest=PqcNativeBaselineITest,PqcHybridValidationITest,PqcTwinIssuerITest,HybridAltSignatureCheckTest,PqcValidationSettingsTest,CertificateValidationITest`.
O `clean` é obrigatório: as regras de arquitetura conferem nomes de lambdas sintéticas, e classes de
uma compilação incremental anterior podem divergir do código-fonte.

Última rodada: **156 testes**, 0 falhas, `BUILD SUCCESS`. Core `1ebe8e67`, kit `029e488`, BC 1.85.
As classes rodaram nesta ordem:

#### 4.3.1 `PqcHybridValidationITest`: 35 testes, saída em `matriz-politicas/`

`leafStatus(scenario, configuration)` cruza 7 cenários × 5 configurações. Em cada combinação,
troca a política em tempo de execução (`PqcValidationPolicyProvider.replace`), faz o upload e o
encadeamento, valida pelo `X509CertificateValidator` e **afirma** o status persistido da folha.
Depois de cada teste, restaura o modo `native`.

| Cenário | native | strict | hybrid-issuer | hybrid-issuer {65,87} | classical-only |
|---|---|---|---|---|---|
| `integro` | VALID | VALID | VALID | VALID | VALID |
| `assinadores-misturados` | INVALID | INVALID | INVALID | INVALID | VALID |
| `stripping` | VALID | INVALID | INVALID | INVALID | VALID |
| `algoritmo-fora-da-lista` | VALID | VALID | VALID | INVALID | VALID |
| `assinatura-classica-invalida` | INVALID | INVALID | INVALID | INVALID | INVALID |
| `emissor-sem-chave-alternativa` | INVALID | INVALID | INVALID | INVALID | VALID |
| `cadeia-classica` (controle) | VALID | INVALID | VALID | VALID | VALID |

Os índices `[1]..[35]` do Surefire seguem a ordem desta tabela, linha a linha.

#### 4.3.2 `PqcNativeBaselineITest`: 6 testes, saída em `linha-de-base-modo-native/`

A mesma classe de 4.2, agora no commit atual, com o modo padrão `native`. A etapa 4.4 exige que os
relatórios saiam idênticos aos da linha de base. Na última rodada saíram: "Idênticos: os relatórios
da linha de base no commit cf583bcf (antes do adaptador) e no modo native do commit atual."

#### 4.3.3 `PqcTwinIssuerITest`: 48 testes, saída em `emissor-gemeo/`

`recordTwinIssuerValidation(leaf, importOrder, configuration)` cruza 2 folhas × 4 ordens de
importação × 6 configurações. O teste mede a regra `hybrid-issuer` quando o inventário guarda dois
certificados da mesma AC: a raiz híbrida (de `integro`) e a gêmea só clássica (de
`emissor-sem-chave-alternativa`), com o mesmo nome e a mesma chave clássica. Ele **registra sem
afirmar** a qual raiz a folha foi ligada.

- Folhas: `integro` e `stripping`.
- Ordens: `classica-primeiro` e `hibrida-primeiro` importam as duas raízes antes da folha.
  `fixada-na-classica` e `fixada-na-hibrida` validam a folha com só uma raiz no inventário, importam
  a outra e validam de novo, porque o core não religa uma folha que já tem emissor.
- Configurações: as cinco de 4.3.1 mais `hybrid-authorities`, que lista a impressão digital da raiz
  híbrida.

#### 4.3.4 `CertificateValidationITest`: 21 testes

A suíte de validação que o core já tinha, rodada para provar que a integração não a quebrou. Ela
cobre CRL e delta CRL, OCSP, montagem e download de cadeia, AIA, referência circular e
autoassinados. Dois testes tocam o caminho híbrido: `testValidateHybridCertificate` e
`testVerifyAlt`.

#### 4.3.5 `PqcValidationSettingsTest`: 8 testes unitários

São os testes da leitura da configuração PQC:

1. `hybridAuthoritiesModeNeedsAtLeastOneAuthority`
2. `replacementIsVisibleToLaterReads`
3. `rejectsUnknownMode`
4. `defaultsToNativeWithEveryAlgorithm`
5. `parsesModeAndAlgorithmListLeniently`
6. `rejectsMalformedHybridAuthorityFingerprint`
7. `normalizesHybridAuthorityFingerprintsToCoreForm`
8. `rejectsUnknownAlgorithmInsteadOfIgnoringIt`

#### 4.3.6 `HybridAltSignatureCheckTest`: 38 testes unitários

São os testes do adaptador que leva a política do kit ao core:

1. `listedAuthorityAcceptsHybridLeafLinkedToClassicalTwin`
2. `leafAgainstRoot(scenario, settings, expectedCodes)` `[1]..[28]`: 7 cenários × 4 modos
   (`STRICT`, `HYBRID_ISSUER`, `HYBRID_ISSUER` restrito a {65, 87}, `CLASSICAL_ONLY`). Cada caso
   afirma os códigos de `ValidationReason`: `ACCEPTED`, `SIGNATURE_INVALID`, `EXTENSIONS_MISSING`,
   `ALGORITHM_NOT_ALLOWED` ou `ISSUER_KEY_MISSING`.
3. `hybridIssuerEnforcesWhenOnlyTheIssuerIsHybrid`
4. `selfSignedRootsAreJudgedByTheirOwnContent`
5. `restrictedListReachesTheKitPolicy`
6. `nativeModeIsNotAKitPolicy`
7. `listedAuthorityRejectsStrippedLeafLinkedToHybridRoot`
8. `unlistedAuthorityLeavesClassicalLeafToTheClassicalPath`
9. `sameAuthorityNeedsSameNameAndClassicalKey`
10. `listedAuthorityRejectsStrippedLeafLinkedToClassicalTwin`
11. `hybridIssuerFallsBackToClassicalOnlyForPurelyClassicalPair`

Este teste só olha a assinatura alternativa. Por isso `assinatura-classica-invalida` sai `ACCEPTED`
aqui; a rejeição desse cenário vem da verificação clássica do core (ver 4.3.1).

### 4.5 Regras de arquitetura do core

`mvn -B test -Dtest='com.otilm.core.architecture.*Test'`: **136 testes**, 0 falhas, em
`resultado-arquitetura.txt` (só o resumo). São as regras ArchUnit e as guardas do pacote
`com.otilm.core.architecture`, como `SigningEngineIsolationArchTest`,
`TransactionalBoundaryArchTest`, `ObjectMapperCentralizationArchTest`, `ContextSignatureTest` e
`TestClassTaxonomyTest`, entre outras. A integração não pode violar nenhuma delas.

---

## Totais

| Campanha | Execução | Testes | Falhas |
|---|---|---:|---:|
| Biblioteca (`evidencias/`) | `mvn test -Pvalidacao` | 28 | 0 |
| Core, linha de base antes do adaptador | etapa 4.2 | 6 | 0 |
| Core, integração | etapa 4.3 | 156 | 0 |
| Core, arquitetura | etapa 4.5 | 136 | 0 |

## Mapa dos arquivos de `integracao/evidencias`

| Arquivo ou pasta | Produzido por |
|---|---|
| `fixtures.sha256` | etapa 4.1 |
| `resultado-testes-antes-da-integracao.txt`, `linha-de-base-antes-da-integracao/` | 4.2 (`PqcNativeBaselineITest` em `cf583bcf`) |
| `resultado-testes.txt`, `surefire/` | 4.3 |
| `matriz-politicas/` (`matriz-core.md`) | 4.3.1 (`PqcHybridValidationITest`) |
| `linha-de-base-modo-native/` | 4.3.2 (`PqcNativeBaselineITest` no commit atual) |
| `emissor-gemeo/` (`matriz-emissor-gemeo.md`) | 4.3.3 (`PqcTwinIssuerITest`) |
| `equivalencia-native.txt` | 4.4 |
| `resultado-arquitetura.txt` | 4.5 |
| `comparacao.md` | 4.7 (área 09 do kit × `matriz-core.md`) |
| `ambiente.txt`, `SHA256SUMS` | 4.7 |
