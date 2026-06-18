# 📁 `doc/` — Referências e material de apoio

> **A documentação oficial deste projeto é o [`README.md`](../README.md) na raiz do repositório**
> (junto com o [`MODULE_DOC.md`](../MODULE_DOC.md)). Esta pasta reúne **material de referência e
> estudo** usado durante o TCC — **não descreve, linha a linha, o código desta biblioteca**.

---

## O que é este projeto (resumo fiel)

`pqc-migration-kit` é uma **biblioteca Java 21 + BouncyCastle 1.84** (JAR Maven, sem Spring, sem
REST, sem banco de dados) para emitir e validar **certificados X.509 híbridos** = assinatura
**clássica** (RSA / ECDSA) + **pós-quântica** (**ML-DSA**, FIPS 204).

O modelo de certificado adotado é o **Catalyst / "alternative signature"** (ITU-T X.509 2019),
com as extensões:

- `subjectAltPublicKeyInfo` (`2.5.29.72`)
- `altSignatureAlgorithm` (`2.5.29.73`)
- `altSignatureValue` (`2.5.29.74`)

Ponto de entrada da API: `com.pqc.hybrid.core.api.PQCHybridCertificateAPI`.

---

## Conteúdo desta pasta

| Caminho | O que é | Relação com o código deste repo |
|---|---|---|
| [`ilm/`](ilm/) (20 arquivos, 01–20) | Estudo da plataforma **CZERTAINLY** (gerenciamento de ciclo de vida de certificados, open-source) | **Referência externa.** Não é este repositório. Cada arquivo abre com um aviso de referência. |
| [`draft/`](draft/) | Anotações + texto do **`draft-ietf-lamps-pq-composite-sigs-18`** (Composite ML-DSA) | **Referência IETF.** Descreve o modelo **Composite**, que aqui é o caminho *experimental* (não ligado à API); o ativo é Catalyst. |
| [`IMPLEMENTACAO_BIBLIOTECA.md`](IMPLEMENTACAO_BIBLIOTECA.md) | **Base de documentação do Capítulo 5 do TCC** (Implementação da Biblioteca Criptográfica) — visão geral, arquitetura, modelagem dos certificados, algoritmos, módulos principais, desafios | Ancorado no código real: classes, OIDs, padrões de projeto. |
| [`IMPLEMENTATION_PHASES.md`](IMPLEMENTATION_PHASES.md) | Plano original de melhorias (cobertura, benchmarks, migração, interop OpenSSL) | Ancorado neste repo; **parcialmente implementado** (cobertura ≥75% atingida, base de benchmarks em `src/test/.../benchmark/`, `MigrationService` esqueletado). |

---

## Avisos importantes para quem consulta `ilm/` e `draft/`

- Foram usados como **base de pesquisa, não seguidos à risca**, e podem conter **imprecisões
  herdadas do material original** (datas, RFCs citadas, métricas).
- Onde houver divergência entre estes documentos e o código, **o código + o `README.md` da raiz
  prevalecem**.
- Métricas como **"326 classes Java / 65 entidades JPA / 75+ endpoints REST"**, **Spring Boot**,
  **PostgreSQL**, **RabbitMQ**, **OAuth2/OPA** que aparecem nos arquivos de referência pertencem
  ao **CZERTAINLY**, **não a esta biblioteca**. Esta lib tem ~63 classes, foco em criptografia,
  e nenhuma dessas dependências.
- O `draft.txt` (~12k linhas) é o **texto bruto do RFC draft** e está preservado como está.
