# Ciclo de Vida de Certificados Digitais - CZERTAINLY-Core

## 1. Visão Geral Arquitetural

O CZERTAINLY-Core é uma plataforma de **Gestão de Ciclo de Vida de Certificados (PLM - PKI Lifecycle Management)** que oferece:

- Criação, renovação, revogação e auditoria de certificados X.509
- Integração com múltiplos conectores de CA (EJBCA, HashiCorp Vault, AWS ACM, etc.)
- Suporte a protocolos ACME, SCEP, CMP
- Conformidade regulatória (PQC, FIPS, etc.)
- Controle de acesso baseado em papéis (RBAC) via OAuth2 + OPA
- Workflows de aprovação estruturados
- Descoberta automática de certificados

### Fluxo de Alto Nível

```
Cliente/Sistema → API REST (v2)
                    ↓
          CertificateService
                    ↓
      Connector (Provider externo)
                    ↓
          CA (PKI Infrastructure)
                    ↓
      Database (Persistência + Auditoria)
```

---

## 2. Entidade Certificate - Estrutura de Dados

### Mapeamento JPA Principal

| Campo | Tipo | Propósito |
|-------|------|----------|
| `uuid` | UUID | Identificador único (PK) |
| `fingerprint` | String (SHA-256) | Identificador único do conteúdo X.509 |
| `commonName` | String | CN (ex: "example.com") |
| `subjectDn` | String | Distinguished Name completo |
| `subjectDnNormalized` | String | DN normalizado para busca |
| `issuerDn` | String | DN do emissor |
| `issuerDnNormalized` | String | DN normalizado do emissor |
| `issuerSerialNumber` | String | Serial number do emissor (chain) |
| `serialNumber` | String | Serial number único do certificado |
| `notBefore` | Date | Data início de validade |
| `notAfter` | Date | Data fim de validade |
| `state` | Enum: CertificateState | ACTIVE, REVOKED, EXPIRED, etc. |
| `validationStatus` | Enum | VALID, INVALID, UNKNOWN, NOT_CHECKED |
| `publicKeyAlgorithm` | String | RSA, ECC, DILITHIUM (pós-quântico) |
| `signatureAlgorithm` | String | SHA256withRSA, SHA256withECDSA, etc. |
| `certificateType` | Enum | X509, custom types |
| `keyUsage` | Integer (bitmap) | digitalSignature, keyEncipherment, etc. (RFC 5280) |
| `extendedKeyUsage` | String | serverAuth, clientAuth, codeSigning, etc. |
| `subjectAlternativeName` | String | SANs (DNS, email, IP) |
| `certificateContentId` (FK) | Long | Referência 1:1 para conteúdo PEM/DER |
| `raProfileUuid` (FK) | UUID | RA Profile associada (CA connector) |
| `keyUuid` | UUID | Chave criptográfica associada (privada) |
| `altKeyUuid` | UUID | Chave alternativa (renovação) |
| `certificateRequestUuid` | UUID | Request que originou o certificado |
| `complianceStatus` | Enum | Resultado de validação de conformidade |
| `complianceResult` | JSONB | Detalhes de validação PQC, FIPS, etc. |
| `attributes` | JSONB | Atributos customizados (extensível) |
| `created` | LocalDateTime | Timestamp de criação |
| `author` | String | Usuário que criou |

### Relacionamentos Críticos

```
Certificate (1) ──── (1) CertificateContent
              │
              ├──── (1) RaProfile (CA)
              │
              ├──── (n) CertificateEventHistory (Auditoria)
              │
              ├──── (n) CertificateLocation (Deploy tracking)
              │
              └──── (n) Group (via group_association)
```

---

## 3. CertificateContent - Deduplicação de Conteúdo

### Propósito

Separar **metadados indexáveis** (Certificate) de **conteúdo binário** (CertificateContent):

```sql
CREATE TABLE certificate_content (
    id BIGINT PRIMARY KEY,
    fingerprint VARCHAR UNIQUE,
    content TEXT -- Normalizado em PEM ou DER
);

CREATE TABLE certificate (
    uuid UUID PRIMARY KEY,
    fingerprint VARCHAR REFERENCES certificate_content(fingerprint),
    -- Outros metadados...
);
```

### Benefícios

1. **Deduplicação automática** - Mesma estrutura de CA = 1 registro CertificateContent
2. **Performance** - Lazy loading do conteúdo (poucas leituras)
3. **Armazenamento eficiente** - Conteúdo compartilhado entre referências

---

## 4. Ciclo de Vida: Upload & Criação

### 4.1. Estratégia A: Upload Simples

```java
POST /api/v2/certificates/upload
{
    "certificate": "-----BEGIN CERTIFICATE-----...",
    "skipCertificateValidation": false,
    "attributes": [...]
}

Fluxo interno:
1. X509Certificate.parse(PEM/DER) ← BouncyCastle
2. Fingerprint = SHA256(certificate bytes)
3. Validar não-existência (unique constraint)
4. uploadCertificateKey() → Importar chave pública
   └─ CryptographicKey.createFrom(x509.getPublicKey())
5. certificateRepository.save(certificate)
6. attributeEngine.updateObjectCustomAttributesContent()
   └─ Armazenar attributes em JSONB
7. addEventHistory(UPLOAD, SUCCESS)
8. publishEvent(CertificateValidationEvent) ← Async
9. Retornar CertificateDetailDto
```

**Validação Assíncrona:**
```
CertificateValidationEvent
  → CertificateValidationEventHandler
    → ICertificateValidator (plugin interface)
      ├─ X509CertificateValidator
      ├─ ComplianceValidator (PQC, FIPS)
      └─ Custom validators
    → validationStatus = VALID|INVALID|UNKNOWN
    → addEventHistory(VALIDATION, SUCCESS|FAILED)
    → publishEvent(CertificateValidatedEvent)
```

### 4.2. Estratégia B: Criação com Owner

```java
POST /api/v2/certificates/create
Fluxo:
1-6. (igual upload)
7. objectAssociationService.setOwnerFromProfile()
   └─ Associa usuário logado como owner (RBAC)
8. certificateComplianceCheck() ← Async compliance
```

### 4.3. Estratégia C: Upload Atômico (Idempotente)

```java
createCertificateAtomic(fingerprint, X509Certificate, owner=true)

Fluxo:
1. Parse X.509
2. certificateContentRepository.insertWithFingerprintConflictResolve()
   ├─ IF fingerprint EXISTS: reutilizar
   └─ ELSE: criar novo
3. certificateRepository.insertWithFingerprintConflictResolve()
   ├─ IF certificado UUID EXISTS: retornar (idempotente)
   └─ ELSE: inserir novo
4. uploadCertificateKey(publicKey)
5. setOwnerFromProfile()
6. certificateComplianceCheck()

Uso: Processamento em lote (discovery, importação)
Garantia: Sem duplicatas, seguro para retentativas
```

---

## 5. Ciclo de Vida: Requisição & Emissão

### 5.1. Fluxo de Requisição com CA

```
POST /api/v2/certificates/request (do cliente)
{
    "raProfileUuid": "...",
    "format": "PKCS10",
    "csr": "-----BEGIN CERTIFICATE REQUEST-----...",
    "requestAttributes": [...]
}

 ↓

CertificateService.requestCertificate()
├─ 1. Validar CSR com AttributeEngine
├─ 2. Criar CertificateRequest entity
│   └─ status = PENDING
├─ 3. Buscar ApprovalProfileRelation
│   └─ Requer aprovação? (workflow de aprovação)
├─ 4. SE requer aprovação:
│   ├─ Criar Approval entity (status=PENDING)
│   ├─ PublicarApprovalRequestedEvent
│   └─ PARAR aqui
├─ 5. SE aprovado OU sem requisito:
│   ├─ RaProfile → Connector provider
│   ├─ Enviar CSR para CA via connector
│   │   POST {connector.url}/v1/authorityProvider/authorities/{id}/certificates/issue
│   ├─ Receber certificado emitido (PEM)
│   ├─ createCertificateAtomic(fingerprint, x509, owner)
│   ├─ certificateRequest.setState(APPROVED)
│   ├─ addEventHistory(ISSUE, SUCCESS)
│   └─ PublicarCertificateIssuedEvent
└─ 6. Retornar CertificateDetailDto
```

### 5.2. Workflow de Aprovação

```java
@Entity
class Approval {
    UUID approvalProfileVersionUuid;     // Qual perfil aplica-se
    UUID creatorUuid;                    // Quem requereu
    UUID objectUuid;                     // Certificate UUID
    Resource resource;                   // CERTIFICATE
    ResourceAction action;               // ISSUE, REVOKE, RENEW
    ApprovalStatusEnum status;           // PENDING, APPROVED, REJECTED
    Date expiryAt;                       // TTL (ex: 7 dias)
    List<ApprovalRecipient> recipients;  // Revisores
    Object objectData;                   // JSONB (snapshot para auditoria)
}

@Entity
class ApprovalProfileRelation {
    UUID approvalProfileUuid;            // Perfil
    Resource resource;                   // CERTIFICATE
    UUID resourceUuid;                   // RA Profile UUID (escopo)
    ResourceAction action;               // ISSUE, REVOKE, RENEW
}

Semântica: "Certificados emitidos com RA Profile X requerem aprovação de Perfil Y"

Decisão de Aprovação:
├─ Approval.status = APPROVED
│   └─ PublishApprovalClosedEvent(APPROVED)
│       └─ Trigger certificado create
└─ Approval.status = REJECTED
    └─ PublishApprovalClosedEvent(REJECTED)
        └─ CertificateRequest.setState(REJECTED)

Expiração:
└─ ApprovalExpiredEvent após TTL
    └─ Approval.status = EXPIRED
    └─ Ação bloqueada
```

---

## 6. Ciclo de Vida: Renovação (Renew)

### Fluxo de Renovação

```
POST /api/v2/certificates/{uuid}/renew
{
    "raProfileUuid": "...",    // (opcional) se muda CA
    "requestAttributes": [...]
}

 ↓

CertificateService.renewCertificate()
├─ 1. Buscar certificado original
├─ 2. Extrair CSR info (subject, extensions)
├─ 3. Gerar novo CSR com mesmos dados
├─ 4. Enviar para CA (via connector)
│   └─ POST {connector.url}/authorities/{id}/certificates/issue
├─ 5. Receber certificado renovado
├─ 6. createCertificateAtomic() (novo UUID, mesmo subject)
├─ 7. Original.setState(RENEWED)
├─ 8. addEventHistory(RENEWAL, SUCCESS)
└─ 9. PublishCertificateRenewedEvent

Garantia: Novo certificado criado, antigo marcado como renovado
Auditoria: Completa com timestamps e autor
```

---

## 7. Ciclo de Vida: Troca de Chave (Rekey)

### Fluxo de Rekey

```
POST /api/v2/certificates/{uuid}/rekey
{
    "raProfileUuid": "...",
    "requestAttributes": [...]
}

 ↓

CertificateService.rekeyCertificate()
├─ 1. Buscar certificado original
├─ 2. Gerar NOVO CSR com:
│   ├─ Mesmo subject/extensions
│   └─ NOVA chave privada
├─ 3. Enviar para CA
├─ 4. Receber novo certificado (nova key, mesmo subject)
├─ 5. Registrar altKeyUuid (chave alternativa)
├─ 6. addEventHistory(REKEY, SUCCESS)
└─ 7. PublishCertificateRekeyedEvent

Diferença RENEW vs REKEY:
├─ RENEW: Mesma chave, estender validade
└─ REKEY: Nova chave, mesmo subject (política de rotação)
```

---

## 8. Ciclo de Vida: Revogação (Revoke)

### Fluxo de Revogação

```
POST /api/v2/certificates/{uuid}/revoke
{
    "reason": "UNSPECIFIED|KEYCOMPROMISE|SUPERSEDED|CESSATIONOFOPERATION"
}

 ↓

CertificateService.revokeCertificate()
├─ 1. Buscar certificado
├─ 2. Validar status (não revogar se já revogado)
├─ 3. Enviar para CA via connector
│   POST {connector.url}/authorities/{id}/certificates/revoke
│   {
│       "serialNumber": "...",
│       "reason": "..."
│   }
├─ 4. Certificate.setState(REVOKED)
├─ 5. Certificate.setRevocationReason(reason)
├─ 6. certificateRepository.save()
├─ 7. addEventHistory(REVOKE, SUCCESS)
└─ 8. PublishCertificateRevokedEvent
        └─ Trigger CRL update, OCSP update

Nota: Status de validação não é atualizado automaticamente com CRL/OCSP
    (Validação é on-demand ou via AcmeReputation service)
```

---

## 9. Validação de Certificados

### 9.1. X509 Validation

```
Executado em upload via CertificateValidationEventHandler

Validações:
├─ Estrutura X.509 válida (BouncyCastle parser)
├─ Assinatura valida
├─ Data de validade (notBefore <= now <= notAfter)
├─ Cadeia de certificados (chain validation)
├─ Extensões críticas compreendidas
└─ Subject DN bem-formado

Status resultante:
├─ VALID: Todas as validações OK
├─ INVALID: Falha em validação crítica
└─ UNKNOWN: Não conseguiu verificar (ex: issuer não em truststore)
```

### 9.2. Compliance Validation

```
Executado assincronamente após upload/criação

Conformidade:
├─ PQC (Post-Quantum Cryptography)
│  ├─ Algoritmos suportados: DILITHIUM, SPHINCS, FALCON
│  └─ Política: Avisar se usados algoritmos clássicos
├─ FIPS 140-2
│  └─ Comprimento mínimo de chave
├─ NIST Guidelines
│  └─ Recomendações de algoritmos
└─ Custom policies (extensível)

Resultado: complianceStatus + complianceResult (JSONB)
```

---

## 10. Descoberta de Certificados (Discovery)

### 10.1. Fluxo de Discovery

```
POST /api/v2/discoveries
{
    "name": "EJBCA Auto-Import",
    "connectorUuid": "...",
    "attributes": [...]
}

 ↓

DiscoveryService.createDiscovery()
├─ Criar Discovery entity (persistent config)
└─ Schedule periodic job

Periodic job (ex: diário):
├─ POST {connector.url}/v1/discoveryProvider/discover
│  └─ Body: discovery attributes
├─ Connector escaneia CA/storage
├─ Retorna array de certificados descobertos
├─ Core importa cada um:
│  ├─ CHECK: Já existe no DB?
│  ├─ IF novo: createCertificateAtomic()
│  ├─ IF renew/rekey: Atualizar relacionamento
│  └─ Status: NEW, IMPORTED, UPDATED, EXPIRED
├─ Análise de conformidade assíncrona
└─ Notificar usuários (se configurado)

Rastreamento:
└─ DiscoveryCertificate entity com metadata
```

---

## 11. Auditoria: CertificateEventHistory

### Estrutura

```java
@Entity
class CertificateEventHistory extends UniquelyIdentifiedAndAudited {
    CertificateEvent event;           // ENUM: UPLOAD, VALIDATION, REVOKE, 
                                      //       RENEWAL, EXPIRATION, REKEY, etc
    CertificateEventStatus status;    // SUCCESS, FAILED, PENDING
    String message;                   // "Certificate uploaded successfully"
    String additionalInformation;     // JSONB com contexto (ex: fingerprint antes/depois)
    UUID certificateUuid;             // FK
    Certificate certificate;          // Lazy loaded
    UUID author;                       // Herdado: usuário que causou evento
    LocalDateTime created;            // Herdado: timestamp do evento
}
```

### Rastreamento de Eventos Principais

| Evento | Triggers | Dados |
|--------|----------|-------|
| **UPLOAD** | upload() | fingerprint, sourceMethod (REST), validationSkipped |
| **VALIDATION** | Async validator | validationStatus, validationErrors (JSON) |
| **COMPLIANCE_CHECK** | Async compliance | complianceStatus, results (JSON) |
| **DISCOVERY** | Discovery job | discoverySource, discoveryTimestamp |
| **APPROVAL_REQUESTED** | requestCertificate() com workflow | approvalProfileUuid, approvers |
| **APPROVAL_DECISION** | Aprovação manual | decision (APPROVED/REJECTED), approver |
| **ISSUE** | Emissão via CA | issuerDn, serialNumber, raProfileUuid |
| **RENEWAL** | renewCertificate() | oldUuid, newUuid |
| **REKEY** | rekeyCertificate() | newKeyUuid |
| **REVOKE** | revokeCertificate() | revocationReason, revokedBy |
| **EXPIRATION** | Scheduled task | expiryDate |

### Consulta de History

```
GET /api/v2/certificates/{uuid}/history
├─ Retorna lista paginada de CertificateEventHistoryDto
├─ Filtros: event type, date range, author
└─ JSON adicional deserializado automaticamente
```

---

## 12. Persistência e Transações

### 12.1. Layer de DAO

```java
Interface: CertificateRepository extends
    ├─ JpaRepository<Certificate, UUID>
    ├─ QuerydslPredicateExecutor<Certificate>
    └─ SecurityFilterRepository<Certificate>

Métodos especializados:
├─ findByFingerprint(fingerprint)
├─ findBySerialNumberAndIssuerDn(sn, issuer)
├─ findByCertificateContentId(contentId)
├─ existsByFingerprint(fingerprint)
└─ findByCertificateContentIdOrderByCreatedDesc()

QueryDSL para queries dinâmicas:
├─ Filtros por: CN, issuer, state, validationStatus, complianceStatus
├─ Paginação eficiente
└─ Security filters aplicados automaticamente
```

### 12.2. Cascade Operations

```
DELETE Certificate
  ├─ ON DELETE CASCADE: CertificateEventHistory (orphan removal)
  ├─ ON DELETE CASCADE: CertificateLocation
  └─ CertificateContent compartilhado (não deletado automaticamente)

UPDATE Certificate status
  └─ Transactional: Grantir consistency
```

### 12.3. Transactional Management

```java
@Service
public class CertificateServiceImpl {
    
    @Transactional  // Spring default: REQUIRED, isolation=DEFAULT
    public CertificateDetailDto createCertificate(...) {
        // BEGIN TRANSACTION
        // Save certificate → INSERT
        // Save event history → INSERT
        // Update attributes → UPDATE attribute_content
        // COMMIT
    }
    
    // Operações atômicas customizadas:
    private synchronized CertificateDetailDto createCertificateAtomic(...) {
        TransactionDefinition txDef = new DefaultTransactionDefinition(
            TransactionDefinition.PROPAGATION_REQUIRES_NEW
        );
        // Isolamento: REPEATABLE_READ (evitar dirty reads)
        // Idempotência garantida por fingerprint unique constraint
    }
}
```

---

## 13. Integrações Externas

### 13.1. Connector Integration

```
POST {connector.url}/v1/authorityProvider/authorities/{id}/certificates/issue
Body: {
    "certificateRequest": {
        "format": "PKCS10",
        "csr": "-----BEGIN CERTIFICATE REQUEST-----...",
        "requestAttributes": [...]
    }
}

Response: {
    "certificate": "-----BEGIN CERTIFICATE-----...",
    "certificateChain": ["..."],
    "metadata": {...}
}

Error (422 Unprocessable): {
    "errors": [
        {"code": "E001", "message": "Invalid CSR", "errorDescription": "..."}
    ]
}
```

### 13.2. Event Pub/Sub

```
RabbitMQ producers/listeners:

├─ CertificateValidationEvent
│  └─ listeners: CertificateValidationEventHandler
│      └─ Executar validação assíncrona + update status
├─ CertificateIssuedEvent
│  └─ listeners: NotificationProducer, AuditLogger
│      └─ Enviar email, webhook, log
├─ CertificateRevokedEvent
│  └─ listeners: CrlUpdater, OcspUpdater
│      └─ Atualizar CRL/OCSP
└─ CertificateExpiredEvent
   └─ listeners: NotificationProducer
       └─ Alertas de expiração iminente
```

### 13.3. Compliance Service

```
ComplianceService.checkCertificateCompliance(Certificate cert)
├─ Executar compliance validators (async)
├─ Validar contra compliance profiles
├─ Retornar: ComplianceStatus, detalhes de falhas
└─ Persistir resultado em JSONB (complianceResult)

Integrações:
├─ PQC Validator → Checar algoritmos pós-quânticos
├─ FIPS Validator → Validar contra FIPS 140-2
└─ Custom validators (extensível)
```

---

## 14. Segurança: RBAC & Authorization

### 14.1. Authorization Checks

```java
@Service
public class CertificateService {
    
    @PostAuthorize("hasPermission(returnValue, 'READ')")
    public CertificateDetailDto getPublicCertificate(UUID uuid) {
        // OPA policy check
        // PermissionEvaluator: certificate.read
    }
    
    @PreAuthorize("hasPermission(#raProfileUuid, 'CERTIFICATE_REQUEST')")
    public CertificateDetailDto requestCertificate(UUID raProfileUuid, ...) {
        // OPA check: pode requisitar cert neste RA Profile?
    }
    
    @PreAuthorize("hasRole('COMPLIANCE_OFFICER')")
    public void revokeCertificate(UUID uuid, ...) {
        // Role-based: requer COMPLIANCE_OFFICER
    }
}
```

### 14.2. Security Filter

```
SecurityFilterRepository applica filtros automaticamente:

GET /api/v2/certificates?state=ACTIVE
├─ queryDSL com predicados de segurança
├─ Aplicar: owner != currentUser ? não retorna
├─ Aplicar: group access check
└─ Retorna apenas certificados com acesso

Owner Association:
├─ setOwnerFromProfile() → usuário logado
├─ RBAC: Usuário = owner OU admin OU grupo do usuário
```

---

## 15. Performance & Caching

### 15.1. Database Indexes

```sql
-- Principais índices criados:
CREATE INDEX idx_certificate_fingerprint ON certificate(fingerprint);
CREATE INDEX idx_certificate_subject_dn ON certificate(subject_dn_normalized);
CREATE INDEX idx_certificate_issuer_dn ON certificate(issuer_dn_normalized);
CREATE INDEX idx_certificate_state ON certificate(state);
CREATE INDEX idx_certificate_validation_status ON certificate(validation_status);
CREATE INDEX idx_certificate_ra_profile_uuid ON certificate(ra_profile_uuid);
CREATE UNIQUE INDEX idx_certificate_content_fingerprint ON certificate_content(fingerprint);
CREATE INDEX idx_cert_event_history_cert_uuid ON certificate_event_history(certificate_uuid);
CREATE INDEX idx_cert_event_history_event ON certificate_event_history(event);
```

### 15.2. Query Optimization

```java
// Lazy loading by default
@OneToOne(fetch = FetchType.LAZY)
private CertificateContent certificateContent;

// Eager load quando necessário:
certificateRepository.findWithContent(uuid)
   .fetchJoin()  // INNER JOIN (QueryDSL)

// Paginação sempre
Pageable paging = PageRequest.of(0, 20, Sort.by("created").descending());
Page<Certificate> page = repository.findAll(predicates, paging);
```

---

## 16. Estados de Certificados - State Machine

```
Estados possíveis: CertificateState enum

REQUESTED
├─ ↓ Aprovação pendente
│  PENDING_APPROVAL
│  ├─ ↓ Aprovado
│  │  PENDING_ISSUE
│  │  ├─ ↓ Emissão com sucesso
│  │  │  ISSUED ✓
│  │  │  ├─ ↓ Renovado
│  │  │  │  RENEWED
│  │  │  ├─ ↓ Revogação solicitada
│  │  │  │  PENDING_REVOKE
│  │  │  │  ├─ ↓ Revogado
│  │  │  │  │  REVOKED ✓
│  │  │  │  └─ ↓ Falha
│  │  │  │     FAILED
│  │  │  └─ ↓ Expirou
│  │  │     EXPIRED
│  │  └─ ↓ Falha na emissão
│  │     FAILED
│  └─ ↓ Rejeitado
│     REJECTED
└─ ↓ Falha na validação CSR
   FAILED

Transições permitidas:
├─ REQUESTED → PENDING_APPROVAL (manual)
├─ PENDING_APPROVAL → PENDING_ISSUE (approval decision)
├─ PENDING_APPROVAL → REJECTED
├─ PENDING_ISSUE → ISSUED (CA issue success)
├─ PENDING_ISSUE → FAILED
├─ ISSUED → PENDING_REVOKE (revoke request)
├─ PENDING_REVOKE → REVOKED
├─ ISSUED → RENEWED
├─ ISSUED → (EXPIRED por task agendada)
└─ Qualquer → FAILED (exception handling)
```

---

## 17. Extensibilidade

### 17.1. Custom Validators

```java
@Component
public class CustomCertificateValidator implements ICertificateValidator {
    
    @Override
    public ValidationResult validate(X509Certificate cert) {
        // Implementar custom logic
        // Retornar: VALID, INVALID, UNKNOWN
        return ValidationResult.VALID;
    }
}

// Registrado automaticamente via plugin discovery
```

### 17.2. Custom Attributes

```java
// RA Profile pode ter atributos customizados
POST /api/v2/raprofiles
{
    "customAttributes": [
        {"name": "department", "value": "Finance"},
        {"name": "costCenter", "value": "CC-123"}
    ]
}

// Armazenados em JSONB e disponíveis em detalhes
GET /api/v2/certificates/{uuid}
{
    "customAttributes": [
        {"name": "department", "value": "Finance"},
        ...
    ]
}
```

---

## 18. Resumo: Fluxo End-to-End

```
┌─────────────────────────────────────────────────────────────┐
│ 1. UPLOAD/CREATE: Cliente envia certificado ou requisita     │
├─────────────────────────────────────────────────────────────┤
│ 2. PARSING: X509 parseado, fingerprint calculado             │
├─────────────────────────────────────────────────────────────┤
│ 3. VALIDATION: X509 + compliance validados (async)          │
├─────────────────────────────────────────────────────────────┤
│ 4. APPROVAL: Workflow de aprovação (se necessário)          │
├─────────────────────────────────────────────────────────────┤
│ 5. PERSISTENCE: Persistido em DB + CertificateEventHistory  │
├─────────────────────────────────────────────────────────────┤
│ 6. EVENTS: Pub/Sub eventos assincronamente                  │
│    ├─ Notificações a usuários                               │
│    ├─ Alertas de conformidade                               │
│    └─ Integrações webhook                                   │
├─────────────────────────────────────────────────────────────┤
│ 7. LIFECYCLE: Renovação, Rekey, Revogação conforme ciclo    │
├─────────────────────────────────────────────────────────────┤
│ 8. AUDIT: Todo evento registrado imutavelmente              │
└─────────────────────────────────────────────────────────────┘
```

---

## Conclusão

O CZERTAINLY-Core implementa um sistema robusto de gestão de ciclo de vida de certificados com:

✓ Suporte a múltiplos conectores (providers)
✓ Validação em várias camadas (X509, conformidade, compliance)
✓ Workflows de aprovação estruturados
✓ Auditoria completa e imutável
✓ RBAC + OPA-based authorization
✓ Descoberta automática de certificados
✓ Event-driven architecture (RabbitMQ)
✓ Extensibilidade via plugins e integrações

