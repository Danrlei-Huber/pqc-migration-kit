# Próximas atividades — blindagem para a defesa

Backlog derivado da avaliação de banca (arguição simulada) do TCC
*"Certificados Digitais Pós-Quânticos: Uma Abordagem Híbrida"*.
Consolida o que **separa um "aprovado com ressalvas" de um "aprovado com louvor"**.

Prioridades: 🔴 bloqueiam aprovação · 🟠 fortalecem muito · 🟡 acabamento.
Status: ✅ feito · 🟡 parcial · ⬜ pendente.

Itens correlatos no texto do TCC estão marcados com a caixa `\lacuna{...}`
(definida em `TCC/configuracoes.tex`); para a versão final, basta habilitar
`\renewcommand{\lacuna}[1]{}` para suprimi-las do PDF.

Bugs de implementação (não de banca) seguem em [`TODO.md`](TODO.md).

---

## 🔴 Bloqueiam aprovação

### ✅ 1. Criticidade das extensões 73/74 → não crítica (compatibilidade retroativa)

**Era o *showstopper*:** o código emitia `altSignatureAlgorithm` (2.5.29.73) e
`altSignatureValue` (2.5.29.74) como **críticas**. Pela RFC 5280 §4.2, um verificador
legado rejeita certificado com extensão crítica desconhecida — ou seja, o artefato
contradizia a própria tese de compatibilidade retroativa.

**Feito neste commit:**
- `HybridCertificateConfig`: nova opção `altSignatureExtensionsCritical`
  (**default `false` = não crítica**), com Javadoc descrevendo o *trade-off* de fase
  de migração. Builder: `withAltSignatureExtensionsCritical(boolean)`.
- `HybridX509CertificateBuilder.build(...)`: troca do `true` fixo por
  `config.isAltSignatureExtensionsCritical()` na chamada
  `certBuilder.build(classical, isCritical, pqc)`.
- `HybridCertificateValidator`: comentário atualizado (o *checker* marca as extensões
  como tratadas em ambos os casos, crítico e não crítico).
- Testes: `PQCExtensionsBuildTest` ganhou
  `altSignatureExtensionsAreNonCriticalByDefault` (compat. retroativa) e
  `altSignatureExtensionsCriticalWhenOptedIn` (modo estrito). `mvn` verde.

**Pendente (⬜) — fechar a evidência:**
- [ ] Provar a compatibilidade com um **verificador legado real e externo**
      (`openssl verify` ou `CertPathValidator` puro do JDK, sem o `HybridExtensionChecker`),
      aceitando um cert híbrido com as extensões não críticas.
- [x] Discutir o *trade-off* de criticidade por fase de migração no texto
      (feito em `cap-resultados.tex` §Desafios).

### ⬜ 2. Avaliação de desempenho real (JMH) — a lacuna mais cara

A palavra-chave do trabalho é "Análise de desempenho", mas os Resultados só têm tempos
"indicativos, de execução única, sem aquecimento da JVM". A infra JMH **já existe** no
repositório (`src/test/java/com/pqc/hybrid/core/benchmark/`, ~21 `@Benchmark`).

- [ ] Rodar keygen/assinatura/verificação para ML-DSA-44/65/87 + clássicos, com
      **warmup, forks e estatística**.
- [ ] Substituir os tempos indicativos da §"Demonstração e Validação por Execução"
      por uma **Análise de Desempenho** de verdade (tabela com média/desvio, ambiente fixo).
- [ ] Fixar *commit*, versão de JDK/BC e máquina para reprodutibilidade.
- Texto: `\lacuna` em `cap-resultados.tex` (§Desafios e §Execução).

### ✅ 3. Finalizar Trabalhos Relacionados e a seção Bouncy Castle

- [x] Seção **"Bouncy Castle"** preenchida (`cap-conceitos.tex`).
- [x] **Trabalhos Relacionados**: citações em texto puro convertidas para `\cite`
      (Muzikant, Howe, e os 4 estudos de X.509 híbrido), com 6 entradas novas no `main.bib`.
      Marcadores `## REVER`/`VOU REESCREVER` e fragmento órfão removidos.
- [ ] **Confirmar 3 entradas** do `main.bib` cujos detalhes bibliográficos (autores/venue)
      ficaram marcados como "a confirmar": `hybrid:comparative`, `hybrid:v2x`,
      `hybrid:x509compliant`. (As outras 3 — Muzikant, Howe, Kampanakis — têm URL/fonte.)
- [ ] Menções secundárias a normas em texto puro ("(W3C, 2013)", "(IETF, 2008/2023)",
      "(NIST, 2024)") podem, opcionalmente, virar `\cite` também.

### ✅ 4. Pergunta de pesquisa + objetivo geral + contribuição na Introdução

- [x] Adicionadas as seções **Pergunta de pesquisa**, **Objetivo geral**,
      **Contribuição** e **Organização do trabalho** em `cap-introducao.tex`.
      (Contribuição enquadrada como empírica/engenharia: validador de caminho híbrido +
      reconstrução do pre-TBS + alinhamento de níveis + fachada/OIDs, sobre o BC.)

---

## 🟠 Fortalecem muito

### ✅ 5. Seção de modelo de ameaça

- [x] Seção formal **"Modelo de ameaça e análise de segurança"** (`sec:ameaca`) escrita em
      `cap-resultados.tex`: adversário considerado, *binding* das chaves (assinatura PQC sobre o
      pre-TBS que já contém a SPKI clássica e a chave 2.5.29.72), composição "E" e
      inforjabilidade (cita `bindel:hybrid`/`bindel:pki`), ataque de *stripping*/downgrade e
      mitigação por política do *relying party* + fronteira do artefato.
- [ ] (Opcional) elevar a um tratamento formal de separabilidade no arcabouço de Bindel.

### ✅ 6. Alinhar a tabela de algoritmos à realidade + rebaixar interop

- [x] **Escopo reduzido a ML-DSA (decisão do autor):** ML-KEM, SLH-DSA e Falcon foram
      **removidos do módulo e do texto**. O suporte PQC passa a ser exclusivamente **ML-DSA**
      (+ clássicos RSA/ECDSA), eliminando a distinção "registrado vs. ativo" — tudo que consta
      é ativo. Tabela de algoritmos em `cap-resultados.tex` reescrita.
- [x] Alegação de interop rebaixada em `cap-desenvolvimento.tex` (nenhum navegador valida
      Catalyst; o que se garante é a preservação da estrutura X.509v3 para verificadores
      clássicos).

### ✅ 7. Reposicionar o capítulo da plataforma (CZERTAINLY) + anonimização

- [x] **Reenquadrado** como "levantamento de requisitos a partir de um estudo de caso":
      parágrafos "Natureza deste capítulo" e "Método" adicionados em
      `cap-materiais-e-metodos.tex`, explicitando que a integração não ocorreu e que daí veio o
      desenho *signer-agnostic*.
- [x] **Anonimização resolvida** (decisão do autor): nomear abertamente. Todas as ocorrências
      de "ILM" → **CZERTAINLY** em todo o texto (9 arquivos); 3Key Company / pacotes
      `com.czertainly` mantidos por serem agora consistentes com o nome aberto.
- [ ] (Opcional) **reduzir o volume** do capítulo (~3.200 palavras de engenharia reversa),
      mantendo só o necessário para sustentar os requisitos extraídos.

---

## 🟡 Acabamento

### 🟡 8. Evidência de validação como casos adversariais + forma

- [x] §Execução reescrita: a corretude passa a se apoiar **explicitamente na suíte de testes**
      (`mvn test`) sob entradas adversariais (pre-TBS reconstruído, adulteração de dados/das duas
      assinaturas, algoritmo trocado, extensões ausentes/malformadas), e não em `println`. Nova
      label `sec:verificacao-adulteracao`.
- [x] "Organização do trabalho" e "Trabalhos futuros" adicionados.
- [ ] (Opcional) explicitar no texto cada caso adversarial como um teste nomeado da suíte.
- [ ] Revisão de forma: pontos finais em títulos, padronização de caixa, etc.

### ⬜ 9. Componentes em aberto (do `TODO.md` e da via de pesquisa)

- [x] ML-KEM: **removido do módulo** (escopo reduzido a ML-DSA); deixou de ser pendência.
- [ ] `LegacyCertificateMigrator`: "Real migration logic not implemented".
- [ ] Decidir o destino do código **Composite** (funcional, mas desconectado da fachada):
      manter como exploração rotulada **ou** remover da via "de produção 1.0.0-BETA".

---

**Observações para revisão posterior:** `AlgorithmType.PQC_KEM` e
`PQCAlgorithmDefinition.isKeyEncapsulation()` (hoje sempre `false`) ficaram como membros mortos —
podem ser removidos depois. Mantido: clássicos RSA/ECDSA e a via Composite (baseada em ML-DSA).
