# 📚 Documentação - PQC Hybrid Certificate Library

**Projeto**: tcc/pqc-migration-kit  
**Versão**: 1.0.0-BETA  
**Data**: April 14, 2026  
**Linguagem**: Java 21  
**Stack**: Spring Boot 3.2+ / Hibernate 6.x / PostgreSQL 14+ / Docker / Kubernetes

---

## 🎯 Visão Geral

Biblioteca Java de **nível produção** para criar certificados X.509 com **criptografia híbrida** (algoritmos clássicos + quântico-resistentes). Objetivo: migração segura para PQC sem quebrar compatibilidade com infraestrutura existente.

---

## 📂 Estrutura de Documentação

### 📖 **Seção ILM (20 documentos)**

Análises técnicas em profundidade de cada camada da arquitetura:

| # | Documento | Foco Principal |
|---|-----------|---|
| **01** | `01-fundacoes-arquitetura.md` | Java 21, Maven 4.0.0, decisões estratégicas |
| **02** | `02-seguranca-oauth2-opa-rbac.md` | OAuth2/OIDC, OPA, RBAC, auditoria 3-camadas |
| **03** | `03-domain-model-entities.md` | 65 entidades JPA, relacionamentos, padrões |
| **04** | `04-apis-rest-controllers.md` | ~75 endpoints v1/v2, versioning strategy |
| **05** | `05-camada-servicos.md` | 55+ serviços de negócio, service layer |
| **06** | `06-persistencia-querydsl.md` | QueryDSL 5.1.0, Hibernate 6.x, indexes |
| **07** | `07-messaging-rabbitmq.md` | RabbitMQ, DLQ, async workflows, retry |
| **08** | `08-protocolos-acme-scep-cmp.md` | ACME (RFC 8555), SCEP (RFC 2560), CMP |
| **09** | `09-pqc-falcon-dilithium-sphincs.md` | FALCON, Dilithium (ML-DSA), SPHINCS+ |
| **10** | `10-conectores-plugin-architecture.md` | Plugin architecture distribuída, REST callbacks |
| **11** | `11-deployment-docker-kubernetes.md` | Docker multi-stage, K8s, docker-compose |
| **12** | `12-padroes-codigo-design-patterns.md` | Implementações de design patterns |
| **13** | `13-diagramas-arquitetura.md` | C4 model, state machines, fluxos |
| **14** | `14-conformidade-pqc-consideracoes.md` | Compliance rules, roadmap PQC |
| **15** | `15-sumario-executivo-insights.md` | C-level metrics, strengths/weaknesses |
| **16** | `16-digital-certificate-lifecycle-core.md` | Ciclo de vida, estados, workflows |
| **17** | `17-connectors-providers-architecture.md` | Padrão plugin, registration flow |
| **18** | `18-interface-definitions-contracts.md` | DTOs, enumerações, contratos |
| **19** | `19-analise-completa-certificados-digitais.md` | Visão end-to-end integrada |
| **20** | `20-indice-documentacao.md` | Navigator de documentação |

---

### 📋 **Seção IETF Draft (7 documentos)**

Especificações técnicas de padronização (RFC em progresso):

| Documento | Escopo | Status |
|-----------|--------|--------|
| `IETF_DRAFT_STRUCTURE.md` | draft-ietf-lamps-pq-composite-sigs-18 (8232 linhas) | Expires Oct 2026 |
| `IETF_18_ALGORITHMS.md` | 18 algoritmos compostos (ML-DSA + Classic) | Standards Track |
| `IETF_FUNCTIONS_STRUCTURES.md` | KeyGen, Sign, Verify formais | Specification |
| `IETF_SECURITY_OPERATIONAL.md` | Considerações de segurança | RFC 5280 Compliant |
| `IETF_TESTVECTORS_APPENDICES.md` | Test vectors para validação | Normative |
| `IETF_X509_ASN1_DER.md` | ASN.1 formal encoding | DER encoding |
| `IETF_QUICK_REFERENCE.md` | Quick lookup OIDs e algoritmos | Reference |

---

## 🏗️ Arquitetura Técnica Core

### Camadas

```
┌─────────────────────────────────────────┐
│      REST API (Controllers)             │  ← 75+ endpoints
├─────────────────────────────────────────┤
│   Security Layer                        │  ← OAuth2/OPA/RBAC
│   (Authentication → Authorization      │     (3-camadas)
│    → Audit)                             │
├─────────────────────────────────────────┤
│    Service Layer (55+ services)         │  ← Business logic
├─────────────────────────────────────────┤
│   Data Access Layer (QueryDSL)          │  ← Type-safe queries
├─────────────────────────────────────────┤
│ PostgreSQL + Hibernate 6.x (65 JPA)     │  ← Persistence
└─────────────────────────────────────────┘
```

### Componentes Principais

| Componente | Tecnologia | Propósito |
|-----------|-----------|----------|
| **Autenticação** | OAuth2 + Nimbus JOSE-JWT 10.5 | Identity verification |
| **Autorização** | OPA (Open Policy Agent) | Fine-grained access control |
| **Auditoria** | JSONB structured logs | Compliance forensics (30-year retention) |
| **Persistência** | PostgreSQL 14+ + Hibernate 6.x | ACID transactions |
| **Queries** | QueryDSL 5.1.0 | Type-safe dynamic queries |
| **Messaging** | RabbitMQ 3.12+ + DLQ | Event-driven async workflows |
| **Encryption** | AES-256-GCM | Data at rest + mTLS in transit |

---

## 🔐 PQC (Post-Quantum Cryptography)

### Algoritmos NIST 2024 Finalizados

| Algoritmo | Tipo | Segurança | Vantagem | Desvantagem |
|-----------|------|-----------|----------|-------------|
| **FALCON** | Lattice (NTRU) | 256-bit | Compact (666B sig) | Lento (5ms/sig) |
| **Dilithium (ML-DSA)** | Lattice | 256-bit | Rápido (0.3ms/sig) | Maior (2.5KB sig) |
| **SPHINCS+** | Hash-based | 256-bit | Conservador | Muito lento + grande |
| **Clássicos** (hybrid) | RSA/ECDSA | - | Compatibilidade | Vulnerável a quantum |

### Arquitetura PQC Hybrid

```
PQCHybridCertificateAPI (Ponto de entrada)
  ├── HybridKeyGenerator
  │   └── KeyPair(Classical + PQC)
  ├── HybridSignatureManager
  │   └── Dual signatures (ambas devem validar)
  ├── HybridX509CertificateBuilder
  │   └── X.509 v3 com extensões PQC
  └── DualSignatureValidator
      └── Verifica classical + PQC
```

**Exemplo de Certificado Híbrido**:
- Subject: CN=example.com
- Classical: RSA-2048 (2048B key)
- PQC: FALCON-1024 (1793B key)
- Assinaturas: Ambas devem ser válidas
- OID: Composite OID (draft-ietf-lamps)

---

## 📋 Ciclo de Vida de Certificados (CZERTAINLY-Core)

### Estados

```
NEWLY_CREATED
    ↓ (validação)
ACTIVE (valendo)
    ↓ (expire ou revoke)
REVOKED ou EXPIRED
    ↓ (cleanup)
ARCHIVED
```

### Fluxos Principais

1. **Upload Simples**  
   ```
   POST /api/v2/certificates/upload
   → Validação X.509 (BouncyCastle)
   → Deduplicação de conteúdo
   → Storage em PostgreSQL
   ```

2. **Requisição com Workflow**  
   ```
   CSR → Approval workflow → CA emissão → Storage
   (Async via RabbitMQ)
   ```

3. **Renovação (RENEW)**  
   ```
   Cert antigo → Nova requisição → Emissão → Chain tracking
   ```

4. **Rekey**  
   ```
   Mesma identidade → Nova chave privada → Nova emissão
   ```

5. **Revogação (REVOKE)**  
   ```
   Cert → Reason (Key compromise, etc) → CRL update
   ```

6. **Discovery**  
   ```
   Scanner automático → Import de certificados → Storage
   ```

### Entidades Críticas (Domain Model)

| Entidade | Propósito | Tipo |
|----------|-----------|------|
| **Certificate** | Metadados X.509 | Principal entity |
| **CertificateContent** | Conteúdo DER/PEM | Lazy-loaded, deduplicado |
| **CertificateRequest** | Requisições em processamento | Workflow |
| **RaProfile** | Perfil de CA connector | Reference |
| **ComplianceProfile** | Regras de validação | JSONB rules |
| **Connector** | Plugin para CA externo | Docker REST |
| **CertificateEventHistory** | Auditoria imutável | JSONB audit log |

---

## 🔌 Sistema de Conectores (Plugin Architecture)

### Padrão Distribuído REST

```
┌─────────────────────────────┐
│  CZERTAINLY Core            │
│  (Orquestração + DB)        │
└────────────┬────────────────┘
             │ HTTPS + mTLS
             │
    ┌────────▼────────┐
    │ Connector Docker │
    │ (Discovery)     │
    │ (Health Check)  │
    └────────┬────────┘
             │ PKCS11/REST/gRPC
             │
    ┌────────▼────────┐
    │ CA Backend      │
    │ (EJBCA, Vault,  │
    │  AWS ACM, HSM)  │
    └─────────────────┘
```

### Tipos de Conectores (Function Groups)

- **CA (AUTHORITY_PROVIDER)**: Emissão, revogação de certs
- **KEY_MANAGEMENT**: Geração de chaves (HSM, Vault)
- **DISCOVERY**: Import automático de certificados
- **ENTITY**: Usuários, máquinas, entidades
- **COMPLIANCE**: Validação de regras
- **NOTIFICATION**: Email, SMS, webhooks

### Fluxo de Registro

```
1. POST /api/v2/connectors (registrar)
2. Test connectivity
3. Discovery de endpoints HTTP
4. Detecção de function groups
5. Health check agendado (30s)
```

---

## ✅ Conformidade & Compliance

### Modelo de Compliance (JSONB)

```json
{
  "ruleName": "key_size_requirement",
  "ruleType": "MIN_KEY_SIZE",
  "condition": {
    "keyType": ["RSA", "EC"],
    "minKeySize": 2048
  },
  "violationAction": "BLOCK"
}
```

**Regras Suportadas**:
- `MIN_KEY_SIZE`: enforce >= N bits
- `MAX_VALIDITY`: enforce <= N days
- `ALGORITHM_WHITELIST`: apenas algoritmos aprovados
- `HASH_ALGORITHM`: SHA256+
- Custom rules (polimórficas)

### PQC Readiness Status

| Item | Status | Notas |
|------|--------|-------|
| NIST Algoritmos 2024 | ✅ Implementados | FALCON, Dilithium, SPHINCS+ |
| Hybrid Certificates | ✅ Working | Dual signatures validam |
| Java Ecosystem | ⚠️ In progress | OpenSSL 3.0+, BouncyCastle |
| Performance Benchmarks | ⚠️ Needed | Latency/throughput |
| RFC Standardization | ⚠️ Draft | Expires October 2026 |

---

## 🚀 Protocolos Suportados

| Protocolo | RFC | Propósito | Status |
|-----------|-----|----------|--------|
| **ACME** | 8555 | Automated Certificate Management | ✅ Implementado |
| **SCEP** | 2560 | Simple Certificate Enrollment | ✅ Suportado |
| **CMP** | 4210 | Certificate Management Protocol | ✅ Suportado |
| **REST** | Proprietary | Custom endpoints | ✅ Native |

---

## 📊 Métricas do Projeto

| Métrica | Valor | Insight |
|---------|-------|---------|
| **Classes Java** | 326+ | Maturidade significativa |
| **Entidades JPA** | 65 | Comprehensive domain model |
| **Services** | 55+ | Well-decomposed business logic |
| **Repositories** | 59 | QueryDSL optimization |
| **REST Endpoints** | 75+ | Broad API surface |
| **Test Suites** | 137 | Solid test coverage |
| **PQC Algorithms** | 3 | Hedging de risco |
| **Security Layers** | 6+ | Defense-in-depth |
| **Protocols** | 3 | ACME, SCEP, CMP |

---

## 🛠️ Deployment & Infrastructure

### Docker (Multi-stage Build)

```dockerfile
FROM maven:3.9-eclipse-temurin-21 AS builder
  → Maven build, create JAR

FROM eclipse-temurin:21-jre-alpine AS runtime
  → Non-root user, healthchecks, minimal image
```

### Docker Compose

- **PostgreSQL 15**: Database
- **RabbitMQ 3.12**: Message broker
- **CZERTAINLY Core**: API (port 8080)
- **Prometheus**: Metrics (port 9090)

### Kubernetes

- Stateless Core (Horizontal Pod Autoscaler)
- Pod Disruption Budgets (PDB)
- Health checks (liveness, readiness, startup)
- Graceful shutdown (30s drain period)

---

## 🎓 Principais Insights

### ✅ Pontos Fortes

1. **Modularidade** - Clean architecture, low coupling
2. **Segurança** - 3-camadas (Auth/Authz/Audit)
3. **PQC-Ready** - Algoritmos NIST 2024 implementados
4. **Plug-in System** - Conectores distribuídos via REST
5. **Type-Safety** - QueryDSL, enums, records Java 21
6. **Compliance** - JSONB audit logs, RBAC, OPA policies
7. **Async-First** - RabbitMQ, CompletableFuture, non-blocking

### ⚠️ Áreas de Melhoria

1. **Java Ecosystem** - Validar interop OpenSSL 3.0+, BouncyCastle PQC
2. **Performance** - Benchmarks de latência/throughput PQC vs classical
3. **Test Coverage** - Estimar 70-75%, target 85%+
4. **RFC Finalization** - draft-ietf-lamps... expires October 2026
5. **Migration Tooling** - Scripts para migrar certs legacy → hybrid

---

## 📖 Referências Técnicas

**RFCs & Padrões**:
- [RFC 5280](https://tools.ietf.org/html/rfc5280) - X.509 PKI Certificate Encoding
- [RFC 8555](https://tools.ietf.org/html/rfc8555) - ACME Protocol
- [RFC 2560](https://tools.ietf.org/html/rfc2560) - SCEP
- [RFC 4210](https://tools.ietf.org/html/rfc4210) - CMP

**NIST PQC (2024 Finalized)**:
- [FIPS 203](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf) - ML-KEM
- [FIPS 204](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf) - ML-DSA (Dilithium)
- [FIPS 205](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf) - SLH-DSA (SPHINCS+)

**IETF Drafts**:
- [draft-ietf-lamps-pq-composite-sigs-18](https://datatracker.ietf.org/doc/html/draft-ietf-lamps-pq-composite-sigs-18) - Composite ML-DSA (expires Oct 2026)

---

## 🗂️ Como Navegar Esta Documentação

### Para Arquitetos de Sistema
1. Leia: `15-sumario-executivo-insights.md` (visão executiva)
2. Leia: `13-diagramas-arquitetura.md` (C4 model)
3. Explore: `01-fundacoes-arquitetura.md` (decisões estratégicas)

### Para Desenvolvedores Backend
1. Leia: `03-domain-model-entities.md` (65 entidades JPA)
2. Leia: `04-apis-rest-controllers.md` (endpoints REST)
3. Leia: `06-persistencia-querydsl.md` (queries type-safe)

### Para Especialistas em Segurança
1. Leia: `02-seguranca-oauth2-opa-rbac.md` (autenticação/autorização)
2. Leia: `14-conformidade-pqc-consideracoes.md` (compliance)
3. Leia: IETF drafts (especificações formais)

### Para Engenheiros de DevOps
1. Leia: `11-deployment-docker-kubernetes.md` (Docker/K8s)
2. Leia: `07-messaging-rabbitmq.md` (async infrastructure)
3. Explore: docker-compose.yml, Kubernetes manifests

### Para Pesquisadores PQC
1. Leia: `09-pqc-falcon-dilithium-sphincs.md` (algoritmos)
2. Leia: `14-conformidade-pqc-consideracoes.md` (PQC readiness)
3. Explore: IETF draft files (RFC specifications)

---

## 📅 Timeline & Próximos Passos

### Imediato (Q2 2026)
- [ ] Validar interop com OpenSSL 3.0+
- [ ] Full e2e tests (generation → validation)
- [ ] Performance benchmarks PQC vs classical

### Curto Prazo (Q3-Q4 2026)
- [ ] IANA OID allocation (RFC draft finalization)
- [ ] Compliance profiles para NIST SP 800-131B
- [ ] Migration tooling (legacy certs → hybrid)

### Longo Prazo (2027+)
- [ ] RFC publication (depois de Oct 2026)
- [ ] Ecosystem adoption (OpenSSL, GnuTLS, Java)
- [ ] Production deployments

---

## 📞 Contato & Colaboração

Este projeto está em desenvolvimento ativo. Para contribuições, dúvidas ou feedback técnico, consulte a documentação específica e os RFC drafts relacionados.

**Última atualização**: April 14, 2026

