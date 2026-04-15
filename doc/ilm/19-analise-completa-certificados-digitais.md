# Análise Completa: Certificados Digitais em CZERTAINLY

## Sumário Executivo

Esta análise cobre a **implementação de certificados digitais X.509** no ecossistema **CZERTAINLY**, uma plataforma de código aberto para gestão de ciclo de vida de certificados (PKI Lifecycle Management).

**Escopo**: 
- CZERTAINLY-Core (orquestração + persistência)
- CZERTAINLY-Interfaces (contratos de comunicação)
- Conectores externos (providers agnósticos)

**Arquivos gerados**:
1. `16-digital-certificate-lifecycle-core.md` - Ciclo de vida completo
2. `17-connectors-providers-architecture.md` - Arquitetura de provedores
3. `18-interface-definitions-contracts.md` - Definições de interfaces

---

## Arquitetura de Três Camadas

```
┌──────────────────────────────────────────────────────────┐
│              CZERTAINLY-Core                             │
│  (Orquestração, Persistência, Auditoria, Workflows)      │
├──────────────────────────────────────────────────────────┤
│  ├─ CertificateService      (Gestão de certificados)    │
│  ├─ ConnectorService        (Orquestração de providers)  │
│  ├─ ApprovalService         (Workflows)                  │
│  ├─ ComplianceService       (Conformidade)               │
│  ├─ DiscoveryService        (Auto-import)                │
│  ├─ CertificateEventHistory (Auditoria)                  │
│  └─ AttributeEngine         (Schema dinâmico)            │
├──────────────────────────────────────────────────────────┤
│              CZERTAINLY-Interfaces                       │
│  (DTOs, Enums, Exceções, Contratos API)                 │
├──────────────────────────────────────────────────────────┤
│  Conectores Externos (Docker containers)                │
│  ├─ EJBCA Connector                                      │
│  ├─ HashiCorp Vault Connector                            │
│  ├─ AWS ACM Connector                                    │
│  ├─ DigiCert Connector                                   │
│  └─ Custom Connector (implementação própria)             │
└──────────────────────────────────────────────────────────┘
```

---

## 1. Modelo de Dados - Certificado

### Entidade Principal: Certificate

```java
@Entity
class Certificate extends UniquelyIdentifiedAndAudited {
    // Identidade
    UUID uuid;                              // PK
    String fingerprint;                     // SHA256 (unique)
    String serialNumber;                    // SN do X.509
    
    // Sujeito & Emissor (X.500 Names)
    String commonName;                      // CN
    String subjectDn;                       // Full DN
    String subjectDnNormalized;             // Para busca
    String issuerDn;                        // Emissor
    String issuerDnNormalized;              // Normalizado
    String issuerSerialNumber;              // SN do emissor (chain)
    
    // Validade
    LocalDateTime notBefore;
    LocalDateTime notAfter;
    
    // Estado & Validação
    CertificateState state;                 // ACTIVE, REVOKED, EXPIRED
    CertificateValidationStatus validationStatus; // VALID, INVALID, UNKNOWN
    ComplianceStatus complianceStatus;
    
    // Criptografia
    String publicKeyAlgorithm;              // RSA, ECC, DILITHIUM (PQC)
    String signatureAlgorithm;              // SHA256withRSA, etc
    Integer keyUsage;                       // Bitmap (RFC 5280)
    String extendedKeyUsage;                // serverAuth, clientAuth
    String subjectAlternativeName;          // SANs
    
    // Relacionamentos
    Long certificateContentId;              // FK 1:1 (PEM/DER)
    UUID raProfileUuid;                     // CA que emitiu
    UUID keyUuid;                           // Chave privada
    UUID altKeyUuid;                        // Chave alternativa
    UUID certificateRequestUuid;            // Request origem
    
    // Conformidade
    String complianceResult;                // JSONB
    
    // Auditoria
    LocalDateTime created;                  // Herdado
    String author;                          // Herdado
    UUID creatorUuid;                       // Herdado
    LocalDateTime lastModifiedAt;           // Herdado
    
    // Relacionamentos ORM
    @OneToOne(fetch=LAZY)
    CertificateContent certificateContent;
    
    @OneToMany(cascade=REMOVE)
    Set<CertificateEventHistory> eventHistories;
    
    @OneToMany
    Set<CertificateLocation> locations;
    
    @ManyToMany
    Set<Group> groups;
    
    @OneToOne
    OwnerAssociation owner;
}
```

### Tabelas Secundárias

```sql
-- Armazenamento separado de conteúdo (deduplicação)
CREATE TABLE certificate_content (
    id BIGINT PRIMARY KEY,
    fingerprint VARCHAR UNIQUE NOT NULL,
    content TEXT NOT NULL                   -- PEM ou DER
);

-- Histórico de eventos (auditoria imutável)
CREATE TABLE certificate_event_history (
    uuid UUID PRIMARY KEY,
    certificate_uuid UUID NOT NULL,
    event VARCHAR NOT NULL,                 -- UPLOAD, ISSUE, REVOKE, etc
    status VARCHAR NOT NULL,                -- SUCCESS, FAILED
    message TEXT,
    additional_information JSONB,
    created TIMESTAMP NOT NULL,
    author VARCHAR NOT NULL,
    FOREIGN KEY (certificate_uuid) REFERENCES certificate(uuid) 
        ON DELETE CASCADE
);

-- Rastreamento de localização (deployment)
CREATE TABLE certificate_location (
    uuid UUID PRIMARY KEY,
    certificate_uuid UUID NOT NULL,
    location VARCHAR NOT NULL,              -- Endpoint, device, etc
    discovered_at TIMESTAMP,
    FOREIGN KEY (certificate_uuid) REFERENCES certificate(uuid) 
        ON DELETE CASCADE
);

-- Índices críticos
CREATE INDEX idx_cert_fingerprint ON certificate(fingerprint);
CREATE INDEX idx_cert_subject_dn_norm ON certificate(subject_dn_normalized);
CREATE INDEX idx_cert_issuer_dn_norm ON certificate(issuer_dn_normalized);
CREATE INDEX idx_cert_state ON certificate(state);
CREATE INDEX idx_cert_validation_status ON certificate(validation_status);
CREATE INDEX idx_cert_content_id ON certificate(certificate_content_id);
```

---

## 2. Ciclo de Vida: Estados e Transições

```
┌─────────────────────────────────────────────────────────┐
│ REQUESTED (cliente solicita)                            │
├─────────────────────────────────────────────────────────┤
│ Pode ter dois caminhos:                                 │
│                                                         │
│ Caminho A: Sem Approval Workflow                        │
│ └─ ISSUING (enviado para CA)                            │
│    └─ ISSUED ✓ (pronto para uso)                        │
│                                                         │
│ Caminho B: Com Approval Workflow                        │
│ └─ PENDING_APPROVAL (aguardando revisor)                │
│    ├─ APPROVED (por revisor)                            │
│    │  └─ ISSUING                                        │
│    │     └─ ISSUED ✓                                    │
│    │        ├─ RENEWED (renovado)                       │
│    │        ├─ REKEYED (nova chave)                     │
│    │        └─ REVOKED (revogado)                       │
│    │           └─ final ✓                               │
│    └─ REJECTED (reprovado)                              │
│       └─ final ✗                                        │
│                                                         │
│ Terminal States:                                        │
│ ├─ ISSUED (ativo)                                       │
│ ├─ REVOKED (revogado)                                   │
│ ├─ EXPIRED (expirou)                                    │
│ ├─ FAILED (erro na emissão)                             │
│ └─ REJECTED (workflow rejeitou)                         │
└─────────────────────────────────────────────────────────┘
```

---

## 3. Fluxos Principais

### 3.1. Upload de Certificado

```
1. Cliente envia certificado em PEM/DER
2. Core faz parsing com BouncyCastle
3. Calcula fingerprint (SHA256)
4. Valida estrutura X.509 (async)
5. Valida conformidade (PQC, FIPS, etc - async)
6. Persiste em DB (Certificate + CertificateContent)
7. Registra event: UPLOAD SUCCESS
8. Retorna CertificateDetailDto

Garantias:
├─ Fingerprint único (no duplicatas)
├─ Validação completa (X509 + compliance)
├─ Auditoria imutável de upload
└─ Lazy-load de content para performance
```

### 3.2. Requisição com Workflow de Aprovação

```
1. Cliente requer certificado (CSR ou chave pública)
   POST /api/v2/certificates/request
   {raProfileUuid, csr, attributes}

2. Core valida contra ApprovalProfileRelation
   ├─ Tem rule de aprovação? SIM → STEP 4
   └─ Não tem? → STEP 5

3. Criar Approval{status=PENDING, recipients=[]}
   └─ PublishApprovalRequestedEvent
      └─ Notificar revisores

4. Aguardar deciso de aprovação
   ├─ Revisor aprova → Approval.status = APPROVED
   │  └─ PublishApprovalClosedEvent(APPROVED)
   │     └─ STEP 5
   └─ Revisor rejeita → Approval.status = REJECTED
      └─ FINAL (não emitir certificado)

5. Enviar CSR para CA via Connector
   POST {connector.url}/authorities/{id}/certificates/issue
   └─ Response: {certificate PEM, chain, metadata}

6. Persistir certificado novo
   └─ Certificate.setState(ISSUED)

7. Link CertificateRequest → Certificate
   └─ CertificateRequest.setCertificateUuid(newUuid)

8. Publish CertificateIssuedEvent
   └─ Trigger notificações, webhooks, etc

9. Retornar certificado ao cliente
```

### 3.3. Renovação (Renew)

```
1. Cliente solicita renovação de certificado
   POST /api/v2/certificates/{uuid}/renew

2. Core busca certificado original
   └─ Extrai subject, extensions

3. Gera novo CSR com mesmas características
   └─ Envia para CA (mesmo ou diferente RA Profile)

4. CA retorna certificado renovado
   ├─ Mesmo subject
   ├─ Novas datas (notBefore, notAfter)
   └─ Novo serialNumber

5. Persistir novo certificado
   └─ createCertificateAtomic()

6. Marcar original com status especial
   └─ Certificate.setState(RENEWED)
   └─ Certificate.setNextCertificateUuid(newUuid)

7. Publish CertificateRenewedEvent
   └─ Incluir links: oldUuid ← → newUuid

Diferença vs REKEY:
├─ RENEW: Mesma chave, estender validade
└─ REKEY: Nova chave, mesmo subject (rotação PQC)
```

### 3.4. Revogação (Revoke)

```
1. Cliente requer revogação
   POST /api/v2/certificates/{uuid}/revoke
   {reason: KEY_COMPROMISE|SUPERSEDED|...}

2. Resolve provider
   └─ RaProfile → AuthorityInstance → Connector

3. Enviar para CA
   POST {connector.url}/authorities/{id}/certificates/revoke
   {serialNumber, reason}

4. Atualizar status
   └─ Certificate.setState(REVOKED)
   └─ Certificate.setRevocationReason(reason)

5. Publish CertificateRevokedEvent
   ├─ Trigger CRL updater
   └─ Trigger OCSP responder updater

6. Histórico registrado
   └─ CertificateEventHistory{event=REVOKE, status=SUCCESS}
```

### 3.5. Descoberta Automática (Discovery)

```
1. Admin cria config de descoberta
   POST /api/v2/discoveries
   {connectorUuid, name, attributes}

2. Scheduler executa periodicamente (ex: diário)

3. Para cada descoberta:
   POST {connector.url}/discoveryProvider/discover
   {discoveryConfig}

4. Connector escaneia CA/Storage
   └─ Retorna lista de certificados encontrados

5. Para cada certificado descoberto:
   ├─ Já existe no DB?
   │  ├─ SIM: Status = UPDATED ou EXPIRED
   │  └─ NÃO: Status = NEW
   ├─ Validação de conformidade (async)
   └─ Criar DiscoveryCertificate entity

6. Publish DiscoveryCertificatesImportedEvent
   └─ Notificações + auditoria
```

---

## 4. Arquitetura de Conectores (Providers)

### 4.1. Padrão Plugin Distribuído

```
Característica: Core NÃO gerencia CAs diretamente
               Conectores são proxies HTTP/REST

Core inicia HTTP request → Connector
                           ├─ Valida request
                           ├─ Forward para CA real
                           ├─ Parse resposta
                           └─ Retorna para Core

Benefício: Core agnóstico de CA vendor
          Novo CA = novo container, core não muda
```

### 4.2. Tipos de Conectores

| TypeID | Nome | Responsabilidade | Exemplos |
|--------|------|------------------|----------|
| CA | AUTHORITY_PROVIDER | Emitir/revogar certificados | EJBCA, Vault, AWS ACM |
| KEY_MGMT | CRYPTOGRAPHY_PROVIDER | Gerar chaves, assinar | PKCS11 HSM, Vault |
| DISCOVERY | DISCOVERY_PROVIDER | Auto-import certs | Storage scanning |
| ENTITY | ENTITY_PROVIDER | Usuários/máquinas | LDAP, Active Directory |
| COMPLIANCE | COMPLIANCE_PROVIDER | Validar conformidade | Auditores PQC |
| NOTIFICATION | NOTIFICATION_PROVIDER | Enviar notificações | Email, Slack |

### 4.3. Fluxo de Registro de Connector

```
1. POST /api/v2/connectors
   {url, authType, authAttributes}

2. Health check inicial
   GET {url}/api/v1/connector/info
   └─ Esperado: {version: V2, functionGroups: [...]}

3. Discover capabilities
   GET {url}/api/v1/connector/functions
   └─ Parse supported function groups

4. Cache attribute schemas
   GET {url}/api/v1/connector/attributes?fg=CA&fn=ISSUE
   └─ Parse available attributes

5. Health check agendado (a cada 5 minutos)
   └─ Monitorar status UP/DOWN

6. Callbacks do Connector para Core
   POST {core}/api/v1/connector/callbacks/get-attributes
   POST {core}/api/v1/connector/callbacks/validate-attributes
```

### 4.4. Fluxo de Emissão com Provider

```
Client → Core → [RaProfile resolver] → Connector → CA real
                     ↓
            RaProfile
               ↓
            AuthorityInstance
               ↓
            Connector (provider)
               ↓
            POST {url}/v1/authorityProvider/authorities/{id}/certificates/issue
               ↓
            Response: {certificate, chain, metadata}

Tratamento de erro:
├─ 422 Unprocessable: Validação falhou
├─ 503 Service Unavailable: Connector down
├─ 401 Unauthorized: Credencial inválida
└─ Timeout: Retry com backoff exponencial
```

### 4.5. Credencial Management

```
Fluxo de proteção:

1. Armazenagem
   ├─ Validar contra schema do connector
   ├─ Encriptar antes de persister
   └─ Store em JSONB com flag "sensitive"

2. Acesso
   ├─ RBAC via OPA policies
   ├─ Audit logging de cada acesso
   └─ NUNCA retornar passwords em GET

3. Exemplos
   ├─ EJBCA: username + password encriptado
   ├─ Vault: API token encriptado
   ├─ AWS: Access key + secret encriptado
   └─ PKCS11: PIN do HSM encriptado
```

---

## 5. Atributos Dinâmicos (AttributeEngine)

### 5.1. Descoberta de Schema

```
Core → Connector:
GET {url}/api/v1/connector/attributes?functionGroup=CA&functionName=ISSUE

Connector responde com schema dinâmico:
[
    {
        name: "eep_id",                     # End Entity Profile ID
        type: "enum",
        required: true,
        values: ["GENERIC", "WEB_SSL", "CODE_SIGNING"],
        default: "GENERIC"
    },
    {
        name: "cert_validity",
        type: "integer",
        min: 30,
        max: 3650,
        default: 365
    },
    {
        name: "san_list",
        type: "list",
        itemType: "string",
        description: "Subject Alternative Names"
    }
]
```

### 5.2. Validação com Callbacks

```
Cliente submete atributos:
POST /api/v2/raprofiles/{uuid}/validate-attributes
{
    attributes: [
        {name: "eep_id", value: "WEB_SSL"},
        {name: "cert_validity", value: 365}
    ]
}

Core → Connector:
POST {url}/api/v1/connector/callbacks/validate-attributes
{attributes}

Connector valida:
├─ EEP ID existe?
├─ Validade dentro do range?
└─ Combinação de atributos válida?

Response:
{
    valid: true,
    errors: []
}
```

### 5.3. Atributos Polimórficos

```java
RequestAttribute (enviado para CA):
{
    "v": "V2",                              # Versão
    "n": "eep_id",                          # Nome
    "t": "enum",                            # Tipo
    "value": "WEB_SSL"
}

ResponseAttribute (schema do connector):
{
    "v": "V2",
    "n": "eep_id",
    "description": "End Entity Profile",
    "required": true,
    "contentType": "enum",
    "data": {
        "options": ["GENERIC", "WEB_SSL"],
        "selectedOption": "GENERIC"
    }
}

Tipos suportados:
├─ string: Texto livre
├─ integer: Número inteiro
├─ boolean: Verdadeiro/falso
├─ enum: Dropdown
├─ file: Upload de arquivo
├─ secret: Dado sensível (nunca em resposta)
├─ date: Data (ISO 8601)
├─ list: Array de valores
└─ object: Estrutura nested
```

---

## 6. Auditoria: CertificateEventHistory

### 6.1. Eventos Registrados

| Event | When | Data |
|-------|------|------|
| UPLOAD | Certificate imported | fingerprint, source |
| DISCOVERY | Found by discovery job | discoveryId, timestamp |
| VALIDATION | Async validation complete | validationStatus, errors |
| ISSUE | Emitted by CA | serialNumber, raProfileUuid |
| RENEWAL | Renewed | oldUuid, newUuid |
| REKEY | Rekeyed | newKeyUuid |
| REVOKE | Revocation requested | revocationReason |
| REVOKED | Revocation confirmed | confirmedBy |
| APPROVAL_REQUESTED | Workflow initiated | approvalProfileUuid |
| APPROVAL_APPROVED | Reviewer approved | approverUuid |
| APPROVAL_REJECTED | Reviewer rejected | approverUuid, reason |
| COMPLIANCE_CHECK | Compliance validation | complianceStatus |
| EXPIRATION | Certificate expired | expiryDate |

### 6.2. Consulta de History

```
GET /api/v2/certificates/{uuid}/history?eventType=ISSUE&dateFrom=2024-01-01

Response: [
    {
        uuid: "...",
        event: "ISSUE",
        status: "SUCCESS",
        message: "Certificate issued successfully",
        additionalInformation: {
            issuerDn: "CN=Root CA",
            serialNumber: "123456789ABC",
            raProfileName: "Prod Web SSL"
        },
        author: "automation@example.com",
        created: "2024-01-15T10:30:00Z"
    },
    ...
]
```

---

## 7. Conformidade e Validação

### 7.1. Validação X.509

```
Executado via X509CertificateValidator:

Checklist:
├─ Estrutura bem-formada (PEM/DER parser)
├─ Assinatura válida (verificar contra issuer public key)
├─ Datas válidas (notBefore ≤ now ≤ notAfter)
├─ Cadeia de confiança (issuer in truststore?)
├─ Extensões críticas compreendidas
└─ Policy OIDs válidos

Status resultante:
├─ VALID: Todas OK
├─ INVALID: Falha crítica
└─ UNKNOWN: Não conseguiu verificar (ex: issuer não trusted)
```

### 7.2. Conformidade (Compliance)

```
Executado via ComplianceService:

Políticas:
├─ PQC (Post-Quantum Cryptography)
│  ├─ Algoritmos suportados: DILITHIUM, SPHINCS, FALCON
│  └─ Recomendação: Migrar para PQC até 2030
├─ FIPS 140-2
│  ├─ Comprimento mínimo de chave
│  └─ Algoritmos aprovados
├─ NIST Guidelines
│  └─ Recomendações de força
└─ Custom Policies
   └─ Definidas por organização

Resultado armazenado em JSONB:
{
    "pqcCompliant": false,
    "fipsCompliant": true,
    "nisrCompliant": true,
    "warnings": [
        "Algorithm RSA deprecated for new certificates - consider ECC"
    ]
}
```

---

## 8. Workflows de Aprovação

### 8.1. Modelo de Aprovação

```
ApprovalProfile define regras:
{
    name: "Financial Dept",
    approvalSteps: [
        {
            stepId: 1,
            approvers: ["cfو@company.com", "coacoо@company.com"],
            requiredApprovals: 2,              # Ambos devem aprovar
            ttl: 86400                         # 24 hours to decide
        }
    ]
}

ApprovalProfileRelation vincula a ações:
{
    approvalProfileUuid: "...",
    resource: "CERTIFICATE",
    resourceUuid: "{raProfileId}",
    action: "ISSUE"                         # Semântica: 
                                            # Certificados emitidos por este
                                            # RA Profile requerem aprovação
}

Fluxo:
1. Cliente requer certificado
2. Core checa: ApprovalProfileRelation com match?
3. SIM → Criar Approval{status=PENDING}
   └─ Notificar 2 approvers
4. Approver aprova → +1 count
5. Count == requiredApprovals → Approval.status=APPROVED
   └─ Trigger certificate issuance
6. TTL expirado → Approval.status=EXPIRED
   └─ Bloquear requisição
```

### 8.2. Estados de Approval

```
PENDING
├─ ↓ (aprovadores decidem)
├─ APPROVED (count ≥ requiredApprovals)
│  └─ Trigger certificate issuance
├─ REJECTED (qualquer approver rejeita)
│  └─ Bloquear requisição
├─ EXPIRED (após TTL)
│  └─ Requisição expira
└─ UNKNOWN_ERROR (erro processamento)
```

---

## 9. Governança & RBAC

### 9.1. Controle de Acesso

```
Spring Security + OAuth2 + OPA (Open Policy Agent)

Annotation-based:
@PreAuthorize("hasPermission(#raProfileUuid, 'CERTIFICATE_REQUEST')")
public CertificateDetailDto requestCertificate(UUID raProfileUuid, ...) {
    // OPA evaluate: user can request cert on this RA Profile?
}

@PostAuthorize("hasPermission(returnValue, 'READ')")
public CertificateDetailDto getCertificate(UUID uuid) {
    // Load certificate
    // OPA check: user can read this certificate?
}

@PreAuthorize("hasRole('COMPLIANCE_OFFICER')")
public void revokeCertificate(UUID uuid, ...) {
    // Requer papel específico
}

OPA Policies (Rego language):
```
allow_request {
    user.role == "APPROVER"
    input.resourceType == "CERTIFICATE"
    input.action == "APPROVE"
}
```

### 9.2. Ownership & Group Association

```
Certificate owner:
├─ Definido na criação (user que criou)
├─ Pode ser transferido
└─ Owner pode ler/modificar (se não revogado)

Group Association:
├─ Múltiplos grupos por certificado
├─ Usuário no grupo pode acessar
└─ RBAC via group membership

SecurityFilterRepository aplica automaticamente:
```
SELECT * FROM certificate 
WHERE owner_uuid = currentUser.id
   OR certificate_uuid IN (
       SELECT certificate_uuid FROM certificate_group 
       WHERE group_id IN (SELECT group_id FROM user_group WHERE user_id = currentUser.id)
   )
```
```

---

## 10. Interfaces (CZERTAINLY-Interfaces)

### 10.1. Organização de DTOs

```
Estrutura:
├─ client/     : DTOs para cliente REST
├─ connector/  : DTOs para integração com conectores
├─ core/       : DTOs principais
│  ├─ certificate/    (26 arquivos)
│  ├─ authority/      (emissão/revogação)
│  ├─ cryptography/   (chaves criptográficas)
│  ├─ v2/             (operations v2)
│  ├─ acme/           (ACME protocol)
│  ├─ scep/           (SCEP protocol)
│  ├─ cmp/            (CMP protocol)
│  └─ enums/          (CertificateState, etc)
└─ common/    : Atributos dinâmicos, exceções

Versionamento:
└─ /api/v1/ (legacy)
└─ /api/v2/ (current)
   └─ Backward compatible com extensões
```

### 10.2. DTOs Críticos

```java
// Requisição
CertificateRequestDto {
    raProfileUuid,          // CA a usar
    format: PKCS10,
    csr: PEM,
    requestAttributes[],
    signatureAttributes
}

// Resposta
CertificateDetailDto {
    uuid,
    fingerprint,
    commonName,
    serialNumber,
    state: ISSUED,
    validationStatus: VALID,
    certificate: PEM,
    certificateChain[],
    customAttributes[],
    metadata[],
    complianceStatus,
    complianceResult: JSON
}

// Discovery
DiscoveryCertificateDto {
    serialNumber,
    subjectDn,
    certificate: PEM,
    status: NEW|IMPORTED|UPDATED|EXPIRED,
    discoveredAt,
    associateWithProfile: true
}
```

### 10.3. Enumerações

```
CertificateState:
├─ REQUESTED
├─ PENDING_APPROVAL
├─ PENDING_ISSUE
├─ ISSUED
├─ RENEWED
├─ REKEYED
├─ REVOKED
├─ EXPIRED
├─ FAILED
└─ REJECTED

CertificateValidationStatus:
├─ VALID
├─ INVALID
├─ INVALID_EXPIRED
├─ INVALID_NOT_YET_VALID
├─ INVALID_SIGNATURE
├─ INVALID_CHAIN
├─ UNKNOWN
└─ NOT_CHECKED

CertificateEvent:
├─ UPLOAD
├─ DISCOVERY
├─ VALIDATION
├─ ISSUE
├─ RENEWAL
├─ REKEY
├─ REVOKE
├─ REVOKED
├─ APPROVAL_REQUESTED
├─ APPROVAL_APPROVED
├─ APPROVAL_REJECTED
├─ COMPLIANCE_CHECK
└─ EXPIRATION

CertificateProtocol:
├─ ACME
├─ SCEP
├─ CMP
├─ CRMF
├─ REST
└─ EJBCA
```

---

## 11. Performance & Escalabilidade

### 11.1. Estratégias de Performance

```
Indexação:
├─ fingerprint (unique, PK para CertificateContent)
├─ subject_dn_normalized (busca por DN)
├─ issuer_dn_normalized (chain validation)
├─ state (filtro frequente)
├─ validation_status (relatórios)
└─ ra_profile_uuid (por autoridade)

Lazy loading:
├─ CertificateContent (grande, carregado sob demanda)
└─ Histórico de eventos (paginado)

Paginação:
├─ Sempre obrigatória em list endpoints
├─ Default: 20 items por página
└─ Max: 100 items

Caching (configurável):
├─ Attribute schemas (TTL 1 hora)
├─ Connector health status (TTL 5 minutos)
└─ Compliance profiles (TTL 1 dia)
```

### 11.2. Escalabilidade Horizontal

```
Arquitetura:
├─ Stateless Core instances (pode escalar)
├─ PostgreSQL + shared database
├─ RabbitMQ for async events
├─ Redis for distributed cache (optional)

Load balancing:
├─ HTTP requests → LB → Core instances
├─ WebSocket → sticky session (se necesário)

Async processing:
├─ Validação X509 → background job
├─ Compliance check → background job
├─ Discovery → background job
├─ Notifications → background job

Database connection pooling:
├─ HikariCP (default em Spring Boot)
├─ Pool size: 10-20 connections/instance
```

---

## 12. Segurança

### 12.1. Camadas de Proteção

```
Network:
├─ TLS 1.3 para comunicação REST
├─ mTLS (mutual TLS) com conectores
└─ HTTPS obrigatório em produção

Authentication:
├─ OAuth2 com JWT tokens
├─ Integração com LDAP/Active Directory (opcional)
└─ Token refresh via refresh tokens

Authorization:
├─ Spring Security + @PreAuthorize
├─ OPA (Open Policy Agent) para políticas complexas
├─ RBAC baseado em papéis
└─ Ownership model para recursos

Data Protection:
├─ Passwords encriptadas (bcrypt/PBKDF2)
├─ Sensitive fields encriptados (JPA encryption)
├─ Database encryption at rest (opcional)
└─ Audit logging de todas operações

Secrets Management:
├─ Credential passwords encriptados no DB
├─ Nunca retornar secrets em responses
├─ Rotation de credentials (manual por admin)
└─ Integração com HashiCorp Vault (opcional)
```

### 12.2. Proteção de Certificado

```
"Sensitive" fields nunca retornados em GET:
├─ Private keys (stored separately via KeyManagement)
├─ Credential passwords
├─ HSM PINs
└─ API keys

Certificados (publicamente) podem ser listados, mas:
├─ Sujeito a RBAC checks
├─ Ownership verificado
├─ Audit logging de cada acesso
└─ Rate limiting por usuário
```

---

## 13. Extensibilidade

### 13.1. Criar Novo Connector

```
Step 1: Implement REST API
├─ GET /api/v1/connector/info
├─ GET /api/v1/connector/health
├─ GET /api/v1/connector/functions
├─ GET /api/v1/connector/attributes
├─ POST /api/v1/authorityProvider/.../certificates/issue
└─ POST /api/v1/authorityProvider/.../certificates/revoke

Step 2: Containerize
└─ docker build -t my-connector:1.0 .

Step 3: Register with Core
└─ POST /api/v2/connectors
   {name, url, authType, authAttributes}

Step 4: Core discovers automatically
├─ Health check
├─ Function groups
├─ Attribute schemas
└─ Ready to use!

Step 5: Create Authority Instance & RA Profile
└─ Link to connector

Step 6: Issue certificates
└─ Flow automation complete!
```

### 13.2. Custom Validators

```java
Implementar interface:
@Component
public class MyCustomValidator implements ICertificateValidator {
    @Override
    public ValidationResult validate(X509Certificate cert) {
        // Custom logic
        return ValidationResult.VALID;
    }
}

Registrado automaticamente via plugin discovery
```

### 13.3. Custom Compliance Profiles

```
Definir próprias regras de conformidade:
├─ PQC compliance (quais algoritmos aceitar)
├─ FIPS compliance (força mínima)
├─ Custom policies (organizacionais)
└─ Validação customizada de extensões
```

---

## 14. Fluxos de Erro & Resiliência

### 14.1. Tratamento de Erros

```
Validação falha (422 Unprocessable Entity):
{
    errors: [
        {code: "INVALID_CSR", message: "...", errorDescription: "..."},
        {code: "INVALID_SUBJECT", message: "..."}
    ]
}

Connector indisponível (503 Service Unavailable):
├─ Retry com exponential backoff
├─ Marcar connector como DOWN
├─ PublishConnectorStatusChangedEvent
└─ Impedir nova requisição até UP

Timeout (30s default):
├─ Retry automático
├─ Fallback para cache (se disponível)
└─ Notificar admin se persistir

Authentication fails (401 Unauthorized):
├─ Credentials inválidas
├─ Notify admin
└─ Disable connector temporariamente
```

### 14.2. Circuit Breaker Pattern

```
Conectores com muitas falhas:
├─ Contabilizar falhas consecutivas
├─ Circuit CLOSED → aceita requisições (normal)
├─ Circuit OPEN → rejeita requisições (muitas falhas)
│  └─ Timeout (ex: 1 minuto) antes de testar novamente
├─ Circuit HALF-OPEN → testar 1 requisição
│  ├─ Se OK → CLOSED (recuperado)
│  └─ Se falha → OPEN (ainda instável)
└─ PublishConnectorHealthAlert quando mudança
```

---

## 15. Conformidade & Regulamentação

### 15.1. Certificados Pós-Quânticos (PQC)

```
Algoritmos suportados:
├─ Assinatura: DILITHIUM (NIST FIPS 204)
├─ Assinatura: SPHINCS (NIST FIPS 205)
├─ Encapsulamento: FALCON (candidato)
└─ Híbridos: RSA com DILITHIUM

Políticas:
├─ Avisar se certificado usa apenas clássicos
├─ Recomendar migração até 2030
└─ Aceitar migração gradual

Validação:
├─ Detectar algoritmo PQC
├─ Flag em complianceResult
└─ Relatório de readiness PQC
```

### 15.2. FIPS 140-2 Compliance

```
Validações:
├─ Comprimento mínimo de chave pelo algoritmo
│  ├─ RSA: ≥ 2048 bits (ou ≥ 3072 recomendado)
│  ├─ ECC: ≥ 256 bits
│  └─ AES: ≥ 128 bits
├─ Apenas algoritmos aprovados
├─ Encriptação de secrets obrigatória
└─ Hardware security module optional

Certificação:
├─ Core pode rodar em FIPS mode
├─ Validar contra FIPS policy database
└─ Auditoria completa de operações
```

### 15.3. Auditoria & Compliance Reporting

```
Imutabilidade:
├─ EventHistory registrado para TUDO
├─ Não pode ser deletado (cascade apenas com cert)
├─ Timestamps e autor rastreados
└─ Context dados armazenado em JSONB

Reporting:
├─ Certificados expirando, expirados
├─ Revogações por período
├─ Uso por raProfileis
├─ Compliance gaps
└─ Alertas de anomalias
```

---

## Conclusão

O CZERTAINLY implementa um sistema **robusto, extensível e auditável** de gestão de ciclo de vida de certificados com:

✓ **Modelo de dados completo**: Certificate + history + locations
✓ **Múltiplos conectores**: Agnóstico de CA vendor
✓ **Workflows de aprovação**: Controle de governança
✓ **Atributos dinâmicos**: Schema discovery automático
✓ **Conformidade**: PQC, FIPS, custom policies
✓ **Auditoria completa**: Eventos imutáveis, rastreamento
✓ **Segurança em camadas**: TLS, OAuth2, OPA, encriptação
✓ **Escalabilidade**: Stateless, async processing, paginação
✓ **Extensibilidade**: Custom validators, conectores, compliance rules

**Documentação gerada**: 3 arquivos detalhados em `/doc/`

