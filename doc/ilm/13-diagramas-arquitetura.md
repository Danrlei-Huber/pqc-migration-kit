> ⚠️ **Material de referência — não é a documentação deste projeto.**
>
> Este documento é um **estudo da plataforma externa CZERTAINLY** (gerenciamento de ciclo de vida de
> certificados, open-source), feito como pesquisa de apoio ao TCC. Foi usado como **base de
> referência, não seguido à risca**, e **pode conter imprecisões do material original**. Ele **não
> descreve** o código deste repositório — `pqc-migration-kit` é uma biblioteca Java de certificados
> X.509 híbridos (sem Spring/REST/banco). Para o projeto real, veja o
> [README do repositório](../../README.md) e o `MODULE_DOC.md`.

---

# 13. DIAGRAMAS DE ARQUITETURA

## 13.1 Arquitetura do Sistema (High-Level)

```
                ┌───────────────────────────────────────────┐
                │         CLIENT LAYER                       │
                ├───────────────────────────────────────────┤
                │ REST API Clients | ACME | SCEP | CMP      │
                └──────────────────┬──────────────────────────┘
                                   │ HTTPS + TLS
                                   ▼
        ┌──────────────────────────────────────────────────┐
        │   CZERTAINLY CORE (Spring Boot) - Port 8080      │
        ├──────────────────────────────────────────────────┤
        │                                                  │
        │  ┌─────────────────────────────────────────────┐ │
        │  │ API LAYER (Controllers & REST Endpoints)    │ │
        │  │ - 30+ REST Controllers                      │ │
        │  │ - ACME RFC 8555 / SCEP / CMP              │ │
        │  │ - Global Exception Handling                │ │
        │  │ - Request/Response DTOs                    │ │
        │  └────────────────┬────────────────────────────┘ │
        │                   ▼                               │
        │  ┌─────────────────────────────────────────────┐ │
        │  │ SECURITY LAYER                              │ │
        │  │ ┌───────────────────────────────────────┐   │ │
        │  │ │ OAuth2 JWT Decoder                    │   │ │
        │  │ │ - Validate token signature            │   │ │
        │  │ │ - Extract claims (username, roles)    │   │ │
        │  │ └───────────────────────────────────────┘   │ │
        │  │ ┌───────────────────────────────────────┐   │ │
        │  │ │ OPA (Policy Engine) Integration       │   │ │
        │  │ │ - Fine-grained authorization          │   │ │
        │  │ │ - RBAC + attribute-based access       │   │ │
        │  │ └───────────────────────────────────────┘   │ │
        │  │ ┌───────────────────────────────────────┐   │ │
        │  │ │ RBAC Aspect                           │   │ │
        │  │ │ - @OpaSecured annotation              │   │ │
        │  │ │ - @AuthEndpoint interceptor           │   │ │
        │  │ └───────────────────────────────────────┘   │ │
        │  └────────────────┬────────────────────────────┘ │
        │                   ▼                               │
        │  ┌─────────────────────────────────────────────┐ │
        │  │ SERVICE LAYER (Business Logic)              │ │
        │  │ ┌───────────────────────────────────────┐   │ │
        │  │ │ Certificate Services                  │   │ │
        │  │ │ - Lifecycle management                │   │ │
        │  │ │ - Revocation & expiration             │   │ │
        │  │ └───────────────────────────────────────┘   │ │
        │  │ ┌───────────────────────────────────────┐   │ │
        │  │ │ Cryptographic Services                │   │ │
        │  │ │ - Key generation & storage            │   │ │
        │  │ │ - Sign/Verify (local & HSM)          │   │ │
        │  │ │ - PQC algorithm support               │   │ │
        │  │ └───────────────────────────────────────┘   │ │
        │  │ ┌───────────────────────────────────────┐   │ │
        │  │ │ Protocol Services                     │   │ │
        │  │ │ - ACME/SCEP/CMP processing            │   │ │
        │  │ │ - Message validation & encoding       │   │ │
        │  │ └───────────────────────────────────────┘   │ │
        │  │ ┌───────────────────────────────────────┐   │ │
        │  │ │ Compliance & Audit Services           │   │ │
        │  │ │ - Compliance profile checking         │   │ │
        │  │ │ - Audit logging with JSONB            │   │ │
        │  │ └───────────────────────────────────────┘   │ │
        │  │ ┌───────────────────────────────────────┐   │ │
        │  │ │ Connector Services                    │   │ │
        │  │ │ - Plugin registration & discovery     │   │ │
        │  │ │ - Health checks & routing             │   │ │
        │  │ │ - Operation dispatch                  │   │ │
        │  │ └───────────────────────────────────────┘   │ │
        │  └────────────────┬────────────────────────────┘ │
        │                   ▼                               │
        │  ┌─────────────────────────────────────────────┐ │
        │  │ DATA ACCESS LAYER (Repositories)            │ │
        │  │ - 59 Repository interfaces                │ │
        │  │ - Spring Data JPA + QueryDSL             │ │
        │  │ - Row-level security filtering           │ │
        │  │ - Dynamic predicates & pagination        │ │
        │  └────────────────┬────────────────────────────┘ │
        │                   │                               │
        │  ┌────────────────▼────────────────────────────┐ │
        │  │ PERSISTENCE LAYER (ORM)                     │ │
        │  │ - Hibernate 6.x + JPA                     │ │
        │  │ - 65 Entity classes                       │ │
        │  │ - Lifecycle callbacks & auditing          │ │
        │  │ - Lazy/Eager loading strategies           │ │
        │  └────────────────┬────────────────────────────┘ │
        │                   │                               │
        └───────────────────┼───────────────────────────────┘
                            │ JDBC
                            ▼
        ┌──────────────────────────────────────────────────┐
        │        PostgreSQL 14+ Database                   │
        │ ┌────────────────────────────────────────────┐   │
        │ │ 65 Tables (Certificate, Key, Profile...)  │   │
        │ │ - Indexes on frequently searched fields    │   │
        │ │ - Flyway migrations (01_tables, 02_data)   │   │
        │ │ - JSONB columns for dynamic attributes     │   │
        │ │ - Row security policies for multi-tenancy  │   │
        │ └────────────────────────────────────────────┘   │
        └──────────────────────────────────────────────────┘
```

---

## 13.2 Certificate Lifecycle Flow

```
┌─────────────────────────────────────────────────────────────┐
│                    CERTIFICATE LIFECYCLE                     │
└─────────────────────────────────────────────────────────────┘

    ┌──────────────┐
    │  REQUEST     │  CertificateRequest entity created
    │              │  state: PENDING
    └────────┬─────┘
             │
             ▼
    ┌──────────────────────┐
    │  APPROVAL WORKFLOW   │  Create Approval entity
    │  (Optional)          │  state: PENDING_APPROVAL
    └────────┬─────────────┘
             │
    ┌────────▼─────────────────┐
    │  Human Approval Loop     │  ApprovalService.approveStep()
    │  state: PENDING_REVIEW   │  Multi-step workflows
    └────────┬─────────────────┘
             │
    ┌────────▼──────────────────────────┐
    │  CA CONNECTOR CALL                │  ConnectorOperationExecutor
    │  Issue Certificate Request         │  REST call to CA connector
    │  POST /connector/issue             │
    └────────┬──────────────────────────┘
             │
    ┌────────▼──────────────────────────┐
    │  CERTIFICATE ISSUED               │  Certificate entity created
    │  state: ACTIVE                    │  serial, subject, issuer,
    │  Store signature in database      │  validFrom, validTo, state
    └────────┬──────────────────────────┘
             │
    ┌────────▼──────────────────────────────────┐
    │  EVENT PUBLICATION                       │  CertificateIssuedEvent
    │  - Async listeners triggered             │  - Compliance check
    │  - RabbitMQ producers                    │  - Notifications
    │  - Audit log                             │  - Index update
    └────────┬──────────────────────────────────┘
             │
    ┌────────▼──────────────────────────────────┐
    │  ACTIVE MONITORING                       │
    │  - Expiration check scheduled task       │  CertificateExpiringEvent
    │  - Revocation status polling (if OCSP)   │  @Scheduled daily
    │  - Compliance re-evaluation              │
    └────────┬──────────────────────────────────┘
             │
    ┌────────▼──────────────────────────────────┐
    │  RENEWAL / PRE-EXPIRATION                │  Create new CertificateRequest
    │  User initiates renewal                  │  Link old → new
    │  (Goes back to REQUEST state)            │
    └────────┬──────────────────────────────────┘
             │
    ┌────────▼──────────────────────────────────┐
    │  REVOCATION REQUEST                      │  CertificateRevokedEvent
    │  state: REVOKED                          │  RevocationReason stored
    │  - Immediate: Manual revocation          │  - Published to RabbitMQ
    │  - Scheduled: Planned revocation         │  - Notifications sent
    └────────┬──────────────────────────────────┘
             │
    ┌────────▼──────────────────────────────────┐
    │  ARCHIVED                                │  state: ARCHIVED
    │  - Long-term retention (10+ years)       │  - Moved to cold storage
    │  - Still searchable & queryable          │  - Compliance requirements
    │  - No longer actively used               │
    └────────────────────────────────────────────┘

STATE MACHINE:
    REQUEST
        ↓
    PENDING_APPROVAL (optional)
        ↓
    APPROVED
        ↓
    ISSUED / ACTIVE
        ├──────────→ REVOKED ──────────→ ARCHIVED
        │                                    ↑
        └───────────→ RENEWAL ────────► ACTIVE
```

---

## 13.3 Message Flow Architecture (Async Processing)

```
┌─────────────────────────────────────────────────────────────┐
│           RabbitMQ EVENT-DRIVEN ARCHITECTURE                │
└─────────────────────────────────────────────────────────────┘

CZERTAINLY CORE
┌────────────────────────────┐
│ Service Layer              │
│                            │
│ ┌──────────────────────┐   │  1. Publish Event
│ │ CertificateService   │────┐
│ │ .issueCertificate()  │   │
│ └──────────────────────┘   │
│                            │
│ ┌──────────────────────┐   │  2. Domain Event Published
│ │ ApplicationEventPub  │────┐  (CertificateIssuedEvent)
│ └──────────────────────┘   │
│                            │
│ ┌──────────────────────┐   │  3. Spring Event Listeners
│ │ Event Producers      │────┐  Called synchronously
│ │ (RabbitMQ senders)   │   │
│ └──────────────────────┘   │
└────────────────────────────┘
           │
           │ 4. Publish to Exchanges
           ▼
┌────────────────────────────────────────┐
│       RabbitMQ Message Broker          │
├────────────────────────────────────────┤
│                                        │
│  NOTIFICATION-EXCHANGE (Direct)        │
│  ├─[routing-key: notification.*]      │
│  │  └─→ notification-queue            │
│  │                                    │
│  AUDIT-EVENT-EXCHANGE (Direct)         │
│  ├─[routing-key: audit.*]              │
│  │  └─→ audit-event-queue             │
│  │                                    │
│  COMPLIANCE-CHECK-EXCHANGE (Topic)     │
│  ├─[routing-key: compliance.#]         │
│  │  └─→ compliance-queue              │
│  │                                    │
│  DISCOVERY-EXCHANGE (Direct)           │
│  ├─[routing-key: discovery.*]          │
│  │  └─→ discovery-queue               │
│  │                                    │
│  DLQ (Dead Letter Queue - per queue)   │
│  └─→ Stores failed messages            │
│     (retry threshold exceeded)         │
│                                        │
└────────────────────────────────────────┘
           │
           │ 5. Message Consumption
           ▼
CZERTAINLY CORE - Consumers
┌────────────────────────────────────────┐
│ Listener Containers                    │
│ (@RabbitListener decorated beans)      │
│                                        │
│ ┌──────────────────────────────────┐   │
│ │ NotificationListener              │   │
│ │ (concurrency: 3-10)               │   │
│ │ - Process EMAIL/WEBHOOK/IN_APP    │   │
│ │ - Call external notification svc  │   │
│ └──────────────────────────────────┘   │
│                                        │
│ ┌──────────────────────────────────┐   │
│ │ AuditEventListener                │   │
│ │ (concurrency: 3-10)               │   │
│ │ - Index to Elasticsearch          │   │
│ │ - Optional SIEM integration       │   │
│ └──────────────────────────────────┘   │
│                                        │
│ ┌──────────────────────────────────┐   │
│ │ ComplianceCheckListener           │   │
│ │ (concurrency: 3-5)                │   │
│ │ - Execute compliance profiles     │   │
│ │ - Publish non-compliance event    │   │
│ └──────────────────────────────────┘   │
│                                        │
│ ┌──────────────────────────────────┐   │
│ │ DiscoveryListener                 │   │
│ │ (concurrency: 1 - serial)         │   │
│ │ - Call Location.discover          │   │
│ │ - Index found certificates        │   │
│ └──────────────────────────────────┘   │
│                                        │
│ ┌──────────────────────────────────┐   │
│ │ DLQ Handler                       │   │
│ │ - Log failed messages             │   │
│ │ - Alert on repeated failures      │   │
│ │ - Manual intervention required    │   │
│ └──────────────────────────────────┘   │
│                                        │
└────────────────────────────────────────┘
           │
           │ 6. Side Effects
           ├──→ Email sent to user
           ├──→ Elasticsearch indexed
           ├──→ Compliance status updated
           └──→ Location certificates discovered

RETRY & ERROR HANDLING:

Message Processing Failed
    ↓
Negative ACK → Return to Queue
    ↓
Retry Policy (fixed-backoff)
    │ initial-interval: 1000ms
    │ multiplier: 2.0
    │ max-attempts: 3
    ↓
All Retries Exhausted
    ↓
Dead Letter Exchange (DLX)
    ↓
Dead Letter Queue (DLQ)
    ↓
DLQ Handler processes / Manual review
```

---

## 13.4 Entity Relationship Diagram (Simplified)

```
┌──────────────────────────────────────────────────────────────┐
│                    ERD - CZERTAINLY CORE                     │
└──────────────────────────────────────────────────────────────┘

┌─────────────────────┐
│    CERTIFICATE      │
├─────────────────────┤
│ uuid (PK)           │
│ serialNumber (U)    │
│ subject             │
│ issuer              │
│ validFrom           │
│ validTo             │
│ state (enum)        │
│ raProfile_uuid (FK) │
│ revocationReason    │
│ createdAt           │
│ createdBy           │
│ signature (blob)    │
└────────┬────────────┘
         │ 1:N
         │
         ▼
┌──────────────────────────┐
│   CERTIFICATE_ITEM       │
├──────────────────────────┤
│ uuid (PK)                │
│ certificate_uuid (FK)    │
│ content (blob)           │
│ certFormat (enum)        │  → RAW | X509 | PKCS8 | JWK
│ contentContentType       │     (Different formats of same cert)
└──────────────────────────┘


         ┌──────────────────────┐
         │   RA_PROFILE         │
         ├──────────────────────┤
         │ uuid (PK)            │
         │ name                 │
         │ enabled              │
         │ caConnector_uuid(FK) │
         │ authorityInst_uuid   │
         │ acmeEnabled          │
         │ scepEnabled          │
         │ cmpEnabled           │
         └──────────────────────┘
                   │
              1:N  │  1:N
         ┌────────┴────────┐
         │                 │
    ┌────▼──────┐   ┌──────▼──────┐
    │ LOCATION   │   │  GROUP      │
    ├────────────┤   ├─────────────┤
    │ uuid       │   │ uuid        │
    │ name       │   │ name        │
    │ raProfile_ │   │             │
    │   uuid(FK) │   │ M:N rel to  │
    └────────────┘   │ Certificate │
                     └─────────────┘


┌────────────────────┐
│ CRYPTOGRAPHIC_KEY  │
├────────────────────┤
│ uuid (PK)          │
│ name               │
│ keyType (enum)     │  → RSA | EC | FALCON | DILITHIUM | ...
│ state (enum)       │  → ACTIVE | COMPROMISED | ARCHIVED
│ algorithm          │
│ size               │
│ publicKey (blob)   │
│ privateKey (blob)  │
│ isPQC              │
│ pqcAlgorithm       │
│ created_at         │
└────────┬───────────┘
         │ 1:N
         │
         ▼
┌─────────────────────────────┐
│  CRYPTOGRAPHIC_KEY_ITEM     │
├─────────────────────────────┤
│ uuid (PK)                   │
│ key_uuid (FK)               │
│ content (blob)              │
│ format (enum)               │  → RAW | X509 | PKCS8 | JWK
├─────────────────────────────┤
│ Different format variants   │
│ of same key                 │
└─────────────────────────────┘


┌─────────────────────┐
│    CONNECTOR        │
├─────────────────────┤
│ uuid (PK)           │
│ name                │
│ url                 │
│ version             │
│ healthStatus(enum)  │  → UP | DOWN | ERROR
│ healthCheckTime     │
└────────┬────────────┘
         │ 1:N
         │
         ▼
┌─────────────────────┐
│    ENDPOINT         │
├─────────────────────┤
│ uuid (PK)           │
│ connector_uuid(FK)  │
│ name                │
│ context             │
└─────────────────────┘


┌────────────────────────────┐
│    AUDIT_LOG               │
├────────────────────────────┤
│ uuid (PK)                  │
│ module (enum)              │
│ operation (enum)           │
│ actorName                  │
│ operationResult (JSONB)    │
│ objectUuid                 │
│ timestamp                  │
│ ipAddress                  │
│ userAgent                  │
├────────────────────────────┤
│ Structured audit trail     │
│ for compliance             │
└────────────────────────────┘


┌────────────────────────────┐
│    APPROVAL                │
├────────────────────────────┤
│ uuid (PK)                  │
│ approvalProfile_uuid (FK)  │
│ status (enum)              │  → PENDING | APPROVED | REJECTED
│ expiresAt                  │
│ createdAt                  │
└────────┬───────────────────┘
         │ 1:N
         │
         ▼
┌──────────────────────────┐
│  APPROVAL_STEP           │
├──────────────────────────┤
│ uuid (PK)                │
│ approval_uuid (FK)       │
│ stepSequence             │
│ approvedBy               │
│ approvedAt               │
│ comment                  │
└──────────────────────────┘


┌────────────────────────────┐
│  COMPLIANCE_PROFILE        │
├────────────────────────────┤
│ uuid (PK)                  │
│ name                       │
│ description                │
│ rules (JSONB)              │
│ enabled                    │
└────────────────────────────┘


Relationships Summary:
- Certificate 1:N → Certificate_Item (formats)
- Certificate N:1 ← RA_Profile (reference)
- Certificate N:M ← Group (grouping)
- Certificate 1:N → Location (storage)
- RA_Profile 1:N → Approval (workflow)
- Cryptographic_Key 1:N → Key_Item (formats)
- Connector 1:N → Endpoint (discovery)
- Approval 1:N → Approval_Step (workflow)

Multi-tenancy: All entities have @SQLRestriction
ensuring row-level security based on:
- userId (via SecurityContext)
- roleId (via OPA policy evaluation)
```

---

## 13.5 Request/Response Flow (Example: Certificate Issuance)

```
┌─────────────────────────────────────────────────────────────┐
│     REQUEST → PROCESSING → RESPONSE FLOW                    │
└─────────────────────────────────────────────────────────────┘

CLIENT REQUEST
│
├─ POST /api/v2/certificates/issue
├─ Content-Type: application/json
├─ Authorization: Bearer <JWT>
└─ Body:
   {
     "certificateRequest": "-----BEGIN CERTIFICATE REQUEST-----...",
     "raProfileUuid": "550e8400-e29b-41d4-a716-446655440000",
     "attributes": [
       {
         "name": "validity_days",
         "value": "365"
       }
     ]
   }

HTTP REQUEST ENTERS SPRING BOOT
│
└─→ DispatcherServlet
    │
    ├─→ Spring Security Filter Chain
    │   ├─ JWT Decoder validates token
    │   ├─ Extract userId, roles, permissions
    │   └─ Set SecurityContext
    │
    ├─→ URL Routing to Controller
    │   └─→ CertificateManagementControllerImpl
    │
    ├─→ Global ExceptionHandling (wraps response handling)
    │
    ├─→ Aspect AOP Interceptors
    │   ├─ @AuthEndpoint RBAC check (Pointcut)
    │   ├─ @OpaSecured OPA policy evaluation
    │   ├─ @AuditLogged audit aspect
    │   └─ @Cacheable result caching
    │
    ├─→ Controller Method Execution
    │   {
    │     CertificateManagementControllerImpl.issueCertificate()
    │     {
    │       1. Validate input (NotNull, Constraint validators)
    │       2. Resolve DTOs to entity models
    │       3. Call service layer
    │     }
    │   }
    │
    └─→ Service Layer Execution (Transactional)
        {
          CertificateRequestService.submitCertificateRequest()
          {
            1. @Transactional begins DB transaction
            │
            2. Fetch RA_PROFILE (validate exists)
            │  CertificateRepository.findByUuid(raProfileUuid)
            │
            3. Fetch CA_CONNECTOR from RA_PROFILE
            │  Load lazy association (JOIN FETCH)
            │
            4. Parse CSR & validate
            │  X509CertificateFactory.parseCSR()
            │
            5. Create CertificateRequest entity
            │  status: PENDING
            │
            6. Save to database
            │  certificateRepository.save(request)
            │  ├─ INSERT into certificate_request
            │  └─ COMMIT (inner transaction)
            │
            7. Publish domain event
            │  ApplicationEventPublisher.publishEvent(
            │    CertificateRequestCreatedEvent
            │  )
            │
            8. Return response DTO
            │  CertificateRequestDto.from(entity)
            │
            9. @Transactional COMMIT
            │
          }
        }
        │
        ├─→ Event Listeners Triggered (Inside transaction)
        │   ├─ CertificateRequestEventListener
        │   │  @EventListener (synchronous)
        │   │  - Log request created
        │   │  - Update statistics
        │   │
        │   ├─ RabbitMQ Producer
        │   │  @EventListener
        │   │  - Convert to RabbitMQ message
        │   │  - rabbitTemplate.convertAndSend(...)
        │   │  - Publish to exchange
        │   │
        │   └─ Async Listeners (if @Async)
        │      - Long-running work (out of transaction)
        │      - Notification service calls
        │
        ├─→ Audit Aspect Records Operation
        │   └─ INSERT into audit_log
        │
        └─→ Response Built
            {
              "uuid": "550e8400-e29b-41d4-a716-446655440001",
              "status": "PENDING",
              "certificateUuid": null,
              "createdAt": "2024-01-15T10:30:00Z",
              "approvalRequired": true,
              "workflow": {
                "steps": [
                  {"name": "Manager Approval", "sequence": 1},
                  {"name": "Security Review", "sequence": 2}
                ]
              }
            }


HTTP RESPONSE RETURNS TO CLIENT
│
├─ Status: 201 Created
├─ Headers: Content-Type: application/json
│           Location: /api/v2/certificate-requests/{uuid}
│           X-Request-Id: 550e8400-e29b-41d4
│
└─ Body: { JSON response above }


ASYNC PROCESSING CONTINUES (After HTTP response)
│
├─→ RabbitMQ Message Delivered to Queue
│   └─ notificationListener receives message
│       ├─ Check approval workflow
│       ├─ Send notification to approvers
│       └─ Message ACK
│
├─→ Elasticsearch Indexing (if enabled)
│   └─ auditListener indexes operation
│
└─→ Background Tasks (@Scheduled)
    └─ Compliance check scheduled for next day
```

---

## 13.6 Security Layers Flow

```
REQUEST ARRIVES
│
▼
┌─────────────────────────────────────┐
│1. OAUTH2 + JWT VALIDATION           │
├─────────────────────────────────────┤
│ CzertainlyJwtDecoder                │
│ ├─ Extract token from Authorization│
│ ├─ Fetch JWKS from OpenID Discovery│
│ ├─ Verify signature                │
│ ├─ Check token expiration           │
│ ├─ Extract claims:                  │
│ │  - sub (username)                │
│ │  - scope (permissions)            │
│ │  - roles (group membership)       │
│ └─ Set SecurityContext              │
│    └─ Authentication principal set  │
└─────────────────────────────────────┘
│
▼
┌─────────────────────────────────────┐
│2. RBAC ANNOTATION CHECK             │
├─────────────────────────────────────┤
│ @AuthEndpoint("ROLE_ADMIN")         │
│ ├─ Check if user has required role  │
│ └─ Throw AccessDeniedException      │
│    if not authorized                │
└─────────────────────────────────────┘
│
▼
┌─────────────────────────────────────┐
│3. OPA POLICY EVALUATION (Fine-grain)│
├─────────────────────────────────────┤
│ @OpaSecured(action = "list")        │
│ OpaSecurityAspect.checkAccess()     │
│ ├─ Build context: {                 │
│ │   "username": "alice",            │
│ │   "action": "list",               │
│ │   "resource": "Certificate",      │
│ │   "attributes": {...}             │
│ │ }                                 │
│ ├─ POST to OPA:                     │
│ │  POST /v1/data/czertainly/access │
│ │  {context_data}                   │
│ ├─ Receive response:                │
│ │  {"allow": true, "reason": "..."}│
│ └─ Throw ForbiddenException if false│
└─────────────────────────────────────┘
│
▼
┌──────────────────────────────────────┐
│4. ROW-LEVEL SECURITY (DB-level)     │
├──────────────────────────────────────┤
│ @SQLRestriction applied to entities  │
│ ├─ Hibernate automatically adds      │
│ │  WHERE clause:                    │
│ │  "owner_id = ? AND              │
│ │   (status = 'ACTIVE' OR         │
│ │    role = 'VIEWER')"             │
│ ├─ Only rows user has access to   │
│ │  are returned from DB            │
│ └─ Prevents data leakage           │
└──────────────────────────────────────┘
│
▼
┌──────────────────────────────────────┐
│5. CREDENTIAL ENCRYPTION             │
├──────────────────────────────────────┤
│ For sensitive fields (passwords, etc)│
│ ├─ @Convert + CredentialEncryptor   │
│ ├─ AES-256-GCM symmetric encryption │
│ ├─ PBKDF2 key derivation with salt  │
│ │  (KDF iterations: 65536)          │
│ ├─ IV: random 12 bytes per encrypt  │
│ ├─ Tag: authentication (GCM)        │
│ └─ Transparent to customer code     │
│    (getPassword() returns plaintext) │
└──────────────────────────────────────┘
│
▼
┌──────────────────────────────────────┐
│6. AUDIT LOGGING                      │
├──────────────────────────────────────┤
│ @AuditLogged annotation              │
│ ├─ Captures:                         │
│ │  - Operation name                 │
│ │  - Actor (username)               │
│ │  - Timestamp                      │
│ │  - Result (success/failure)       │
│ │  - Resource UUID                  │
│ ├─ Async write to audit_log table   │
│ ├─ JSONB column for details         │
│ └─ Searchable via AuditLogService   │
└──────────────────────────────────────┘

ALLOWED OPERATION PROCEEDS
```

---

## Resumo de Arquitetura

| Componente | Responsabilidade | Tecnologia |
|-----------|-----------------|-----------|
| **API Layer** | HTTP requests, routing | Spring MVC, OpenAPI |
| **Security** | JWT, RBAC, OPA | Spring Security, JWT decoder |
| **Service** | Business logic | Spring beans, transactions |
| **Data Access** | Query building | Spring Data JPA, QueryDSL |
| **Persistence** | Entity mapping | Hibernate, PostgreSQL |
| **Messaging** | Event distribution | RabbitMQ, Spring AMQP |
| **Audit** | Operation logging | JSONB, async processors |

