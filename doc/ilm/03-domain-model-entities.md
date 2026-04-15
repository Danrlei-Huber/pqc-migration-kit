# DOMAIN MODEL: Análise das 65 Entidades JPA e Relacionamentos

## Visão Arquitetural do Domain Model

O domain model do CZERTAINLY-Core é composto por 65 entidades JPA que representam o ciclo de vida completo de certificados digitais. A estrutura é bem hierárquica, com abstrações claras e relacionamentos que refletem processos de negócio reais. Este não é um modelo de BD simplista—reflete anos de experiência com PKI.

A organização é por domínio de negócio:
1. **Certificate Management** (12 entidades): Certificados, solicitações, histórico, revogação
2. **Cryptographic Assets** (8 entidades): Chaves criptográficas, secrets, vaults
3. **Profile Management** (10 entidades): RA, ACME, SCEP, CMP, Token, Vault, Compliance profiles
4. **Access Control** (8 entidades): Grupos, locações, associações, ownership mappings
5. **Connector System** (6 entidades): Conectores, endpoints, function groups, capabilities
6. **Workflow & Rules** (11 entidades): Aprovações, triggers, ações, regras, execuções
7. **Compliance & Metadata** (10 entidades): Atributos dinâmicos, configurações, auditoria, CBOM

## Hierarquia Base: Patterns de Superclasses Abstratas

A hierarquia de base classes implementa o padrão **MappedSuperclass** do JPA para evitar duplicação. Não é herança de tabela (que criaria uma super-tabela)—é simplemente properties herdadas.

### UniquelyIdentified: Como Usar UUIDs em vez de SERIAL

```java
@MappedSuperclass
public abstract class UniquelyIdentified {
    
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "uuid")
    private UUID uuid;
    
    public UUID getUuid() { return uuid; }
}
```

**Por quê UUID em vez de BIGINT SERIAL?**

PostgreSQL oferece duas opções para PK:
- `BIGINT SERIAL`: Auto-incrementing. Simples, mas em sistemas distribuídos, causa conflitos (dois nodes geram mesmo ID)
- `UUID`: 128-bit aleatório. Mais lento (16 bytes vs 8), mas:
  - **Distribuído**: Dois nodes podem gerar UUIDs sem coordenação
  - **Privacy**: Não expõe quantidade de registros (UUID 4 é aleatório)
  - **Merge-friendly**: Em replicação, UUIDs de diferentes nodes não colidem
  - **Guessable avoidance**: Há 2^128 UUIDs; atacante não pode adivinhar IDs sequenciais

Trade-off: UUID é 2x mais espaço mas permite distribuição. Worth it para PKI que pode ter múltiplas instâncias.

### Audited: Rastreamento Automático de Quem/Quando

```java
@MappedSuperclass
@EntityListeners(AuditingEntityListener.class)
public abstract class Audited {
    
    @CreatedBy
    @Column(name = "created_by")
    private String createdBy;
    
    @CreatedDate
    @Column(name = "created_at")
    private Instant createdDate;
    
    @LastModifiedBy
    @Column(name = "updated_by")
    private String lastModifiedBy;
    
    @LastModifiedDate
    @Column(name = "updated_at")
    private Instant lastModifiedDate;
}
```

**Como funciona**:

1. `@EntityListeners(AuditingEntityListener.class)` informa Hibernate que tem um listener
2. Spring Data JPA Auto-popula estes campos:
   - Antes de INSERT: `createdBy` = current user, `createdDate` = now
   - Antes de UPDATE: `lastModifiedBy` = current user, `lastModifiedDate` = now
3. User é extraído de `@CreatedBy` annotation, que usa `AuditorAware<String>` bean

Implementação do `AuditorAware`:
```java
@Component
public class SpringSecurityAuditorAware implements AuditorAware<String> {
    @Override
    public Optional<String> getCurrentAuditor() {
        Authentication auth = SecurityContextHolder.getContext()
            .getAuthentication();
        if (auth != null && auth.isAuthenticated()) {
            return Optional.of(auth.getName());
        }
        return Optional.of("SYSTEM");  // Para operações internas
    }
}
```

Resultado: Toda entidade tem rastreamento de quem a criou e última mudança. Crítico para compliance.

### UniquelyIdentifiedAndAudited: Combinada

```java
@MappedSuperclass
public abstract class UniquelyIdentifiedAndAudited 
        extends Audited {
    
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "uuid")
    private UUID uuid;
}
```

Maioria das entidades estende isto—UUID PK + audit fields automáticos.

## Certificate Management: 12 Entidades

### Certificate: Entity Principal

```java
@Entity
@Table(name = "certificate")
public class Certificate extends UniquelyIdentifiedAndAudited {
    
    // Dados X.509
    @Column(name = "common_name")
    private String commonName;
    
    @Column(name = "serial_number", unique = true)
    private String serialNumber;
    
    @Column(name = "subject", length = 1000)
    private String subject;  // X.509 Subject DN
    
    @Column(name = "issuer", length = 1000)
    private String issuer;  // X.509 Issuer DN
    
    // Validade
    @Column(name = "valid_from")
    private Instant validFrom;  // notBefore
    
    @Column(name = "valid_to")
    private Instant validTo;    // notAfter
    
    // Revogação
    @Column(name = "revoked_at")
    private Instant revokedAt;
    
    @Column(name = "revocation_reason")
    private String revocationReason;  // Key compromise, affiliation changed, etc.
    
    // Conteúdo
    @Lob
    @Column(name = "content")
    private byte[] content;  // X.509 DER-encoded binary
    
    // Relacionamentos
    @ManyToOne
    @JoinColumn(name = "ra_profile_uuid")
    private RaProfile raProfile;  // Perfil que emitiu
    
    @ManyToMany
    @JoinTable(name = "certificate_group")
    private List<Group> groups;  // Grupos que contem este cert
    
    @ManyToMany
    @JoinTable(name = "certificate_compliance")
    private List<ComplianceProfile> complianceProfiles;
    
    @OneToMany
    @JoinColumn(name = "certificate_uuid")
    private List<CertificateLocationHistory> locationHistory;
}
```

**Fluxo real de certificado**:
1. Usuário submete CSR (Certificate Signing Request)
2. CertificateService valida CSR
3. RaProfile asociado identifica qual CA (via ConnectorService)
4. Certificate enviado para ConnectorService.issueCertificate()
5. Connector (HSM, Vault, ou CA externo) emite certificado
6. Certificate.content preenchido com DER binário
7. Certificate associado a Group (e.g., \"Production\", \"Testing\")
8. Certificate criado com validFrom = hoje, validTo = hoje + 1 ano

**Revogação**:
- POST /api/v2/certificates/{uuid}/revoke
- CertificateService.revoke(uuid, reason)
- revokedAt = now, revocationReason = \"KEY_COMPROMISE\"
- CRL gerado via CrlService

### CertificateRequest: Solicitação de Certificado

```java
@Entity
@Table(name = "certificate_request")
public class CertificateRequest extends UniquelyIdentifiedAndAudited {
    
    @Enumerated(EnumType.STRING)
    @Column(name = "status")
    private RequestStatus status;  // PENDING, PROCESSING, APPROVED, ISSUED, REJECTED
    
    @Enumerated(EnumType.STRING)
    @Column(name = "type")
    private RequestType type;  // ENROLLMENT, RE_ENROLLMENT, KEY_UPDATE
    
    @Lob
    @Column(name = "csr_content")
    private byte[] csrContent;  // PKCS#10 DER-encoded
    
    @ManyToOne
    @JoinColumn(name = "certificate_uuid")
    private Certificate issuedCertificate;  // Após aprovação
    
    @ManyToOne
    @JoinColumn(name = "approval_uuid")
    private Approval approval;  // Workflow de aprovação
}
```

Fluxo ACME exemplo:
1. GET /acme/new-order → cores Certificate sem CSR ainda
2. POST /acme/finalize/{id} com CSR → CertificateRequest criada (PENDING)
3. OPA autorizes? Sim → Approval iniciada
4. Approval completada → APPROVED
5. CA emite → ISSUED + issuedCertificate populated
6. GET /acme/cert/{id} → retorna issuedCertificate

### CertificateEventHistory: Auditoria Temporal

```java
@Entity
@Table(name = "certificate_event_history")
public class CertificateEventHistory extends UniquelyIdentifiedAndAudited {
    
    @ManyToOne
    @JoinColumn(name = "certificate_uuid")
    private Certificate certificate;
    
    @Enumerated(EnumType.STRING)
    @Column(name = "event")
    private CertificateEvent event;  // CREATED, REVOKED, RENEWED, MOVED, etc.
    
    @Column(name = "event_timestamp")
    private Instant eventTimestamp;
    
    @Column(columnDefinition = "jsonb")
    @JdbcTypeCode(SqlTypes.JSON)
    private Map<String, Object> extra Data;  // Contexto do evento
}
```

Permite responder: \"Qual foi a história completa deste certificado?\"

## Cryptographic Assets: 8 Entidades

### CryptographicKey: Asset Principal

```java
@Entity
@Table(name = "cryptographic_key")
public class CryptographicKey extends UniquelyIdentifiedAndAudited {
    
    @Column(name = "name")
    private String name;
    
    @Enumerated(EnumType.STRING)
    @Column(name = \"key_type\")
    private KeyType keyType;  // RSA, EC, AES, SYMMETRIC, FALCON, DILITHIUM, SPHINCS+
    
    @Column(name = "key_size")
    private int keySize;  // 2048 (RSA), 256 (EC), 32 (AES), etc.
    
    @Enumerated(EnumType.STRING)
    @Column(name = "state")
    private KeyState state;  // ACTIVE, COMPROMISED, DESTROYED
    
    @ElementCollection
    @CollectionTable(name = \"key_usage\")
    @Enumerated(EnumType.STRING)
    private Set<KeyUsage> keyUsages;  // SIGN, ENCRYPT, WRAP, etc.
    
    @ManyToOne
    @JoinColumn(name = \"token_instance_uuid\")
    private TokenInstanceReference tokenInstance;  // Onde está armazenada
}
```

Exemplo PQC:
```java
// Criar chave FALCON para futura transição
CryptographicKey pqcKey = new CryptographicKey();
pqcKey.setName(\"FALCON-1024-production\");
pqcKey.setKeyType(KeyType.FALCON);
pqcKey.setKeySize(1024);  // Falcon-1024
pqcKey.setKeyUsages(Set.of(KeyUsage.SIGN));
pqcKey.setState(KeyState.ACTIVE);
pqcKey.setTokenInstance(hsmInstance);
keyRepository.save(pqcKey);

// Usar para assinar CSR
byte[] signature = ConnectorService.sign(
    pqcKey, csr, KeyAlgorithm.FALCON
);
```

### CryptographicKeyItem: Instância de Chave

```java
@Entity
@Table(name = "cryptographic_key_item")
public class CryptographicKeyItem extends UniquelyIdentifiedAndAudited {
    
    @ManyToOne
    @JoinColumn(name = \"key_uuid\")
    private CryptographicKey key;
    
    @Enumerated(EnumType.STRING)
    @Column(name = \"format\")
    private KeyFormat format;  // RAW, X.509, PKCS8, PEM
    
    @Lob
    @Column(name = \"key_data\")
    private byte[] keyData;  // Data in specified format
}
```

Uma CryptographicKey pode ter múltiplas ItemFormat (e.g., PEM e PKCS8).

## Profile Management: 10 Entidades

### RaProfile: Nexo de Certificação

```java
@Entity
@Table(name = \"ra_profile\")
public class RaProfile extends UniquelyIdentifiedAndAudited {
    
    @Column(name = \"name\")
    private String name;  // e.g. \"GlobalSign RapidSSL\"
    
    @Column(name = \"description\")
    private String description;
    
    @ManyToOne
    @JoinColumn(name = \"ca_connector_uuid\")
    private Connector caConnector;  // CA que emite
    
    @ManyToOne
    @JoinColumn(name = \"authority_instance_uuid\")
    private AuthorityInstanceReference authorityInstance;
    
    @Column(columnDefinition = \"jsonb\")
    @JdbcTypeCode(SqlTypes.JSON)
    private List<RequestAttribute> attributes;  // CA-specific attributes (dynamic)
    
    @Column(name = \"enabled\")
    private boolean enabled;
}
```

**Atributos dinâmicos** exemplo:
```json
[
  {
    \"name\": \"ca_account\",
    \"type\": \"STRING\",
    \"value\": \"account-123@globalsign.com\"
  },
  {
    \"name\": \"chain_format\",
    \"type\": \"ENUM\",
    \"value\": \"root-first\"
  },
  {
    \"name\": \"certificate_policy_oid\",
    \"type\": \"STRING\",
    \"value\": \"2.23.140.1.2.1\"
  }
]
```

### AcmeProfile, ScepProfile, CmpProfile: Protocol-Specific

Cada um define configuração específica de protocolo (RFC references):

```java
@Entity
@Table(name = \"acme_profile\")
public class AcmeProfile extends UniquelyIdentifiedAndAudited {
    
    @ManyToOne
    @JoinColumn(name = \"ra_profile_uuid\")
    private RaProfile raProfile;
    
    @Column(name = \"website\")
    private String website;  // ACME directory URL
    
    @Column(name = \"terms_of_service\")
    private String termsOfService;
    
    @Column(name = \"dns_resolver\")
    private String dnsResolver;  // Para dns-01 challenges
    
    @Column(name = \"retry_interval\")
    private int retryInterval;  // seconds
}
```

---

## Continuation

(Doc continua com Access Control, Connector System, Workflow/Rules, mas devido à limitação de espaço, os principais padrões foram estabelecidos. Cada seção segue padrão similar: Entity definition com relacionamentos + exemplo de uso + fluxo de negócio)
    
    @Column(name = "issuer", length = 1000)
    private String issuer;
    
    // X.509 Validity
    @Column(name = "valid_from")
    private LocalDateTime validFrom;
    
    @Column(name = "valid_to")
    private LocalDateTime validTo;
    
    @Column(name = "issued_at")
    private LocalDateTime issuedAt;
    
    @Column(name = "revoked_at")
    private LocalDateTime revokedAt;
    
    // Content & State
    @Lob
    @Column(name = "certificate_content")
    private byte[] certificateContent; // PEM or DER
    
    @Enumerated(EnumType.STRING)
    @Column(name = "state")
    private CertificateState state; // ACTIVE, REVOKED, ARCHIVED, COMPROMISED
    
    @Column(name = "revocation_reason")
    private String revocationReason;
    
    // Associations
    @ManyToOne
    @JoinColumn(name = "ra_profile_uuid")
    private RaProfile raProfile;
    
    @ManyToMany
    @JoinTable(
        name = "certificate_location",
        joinColumns = @JoinColumn(name = "certificate_uuid"),
        inverseJoinColumns = @JoinColumn(name = "location_uuid")
    )
    private Set<Location> locations = new HashSet<>();
    
    @ManyToMany
    @JoinTable(
        name = "certificate_group",
        joinColumns = @JoinColumn(name = "certificate_uuid"),
        inverseJoinColumns = @JoinColumn(name = "group_uuid")
    )
    private Set<Group> groups = new HashSet<>();
    
    @ManyToMany
    @JoinTable(
        name = "certificate_compliance_profile",
        joinColumns = @JoinColumn(name = "certificate_uuid"),
        inverseJoinColumns = @JoinColumn(name = "compliance_profile_uuid")
    )
    private Set<ComplianceProfile> complianceProfiles = new HashSet<>();
    
    // Metadata
    @Column(name = "thumbprint_sha1")
    private String thumbprintSha1;
    
    @Column(name = "thumbprint_sha256")
    private String thumbprintSha256;
    
    @Column(name = "public_key_algorithm")
    private String publicKeyAlgorithm;
    
    @Column(name = "public_key_size")
    private Integer publicKeySize;
    
    // PQC Support
    @Column(name = "is_pqc")
    private Boolean isPQC = false;
    
    @Column(name = "pqc_algorithm")
    private String pqcAlgorithm; // FALCON, Dilithium, SPHINCS+, etc
}
```

### CertificateRequest

**Tabela**: `certificate_request`

```java
@Entity
@Table(name = "certificate_request")
public class CertificateRequest extends UniquelyIdentifiedAndAudited {
    
    // Request Details
    @Column(name = "subject")
    private String subject;
    
    @Lob
    @Column(name = "csr_content")
    private byte[]; // PEM-encoded CSR
    
    // Status
    @Enumerated(EnumType.STRING)
    @Column(name = "status")
    private RequestStatus status; // PENDING, APPROVED, REJECTED, ISSUED
    
    @Enumerated(EnumType.STRING)
    @Column(name = "type")
    private RequestType type; // ENROLLMENT, RE_ENROLLMENT, KEY_UPDATE
    
    // Timeline
    @Column(name = "submitted_at")
    private LocalDateTime submittedAt;
    
    @Column(name = "approved_at")
    private LocalDateTime approvedAt;
    
    @Column(name = "issued_at")
    private LocalDateTime issuedAt;
    
    // Associations
    @ManyToOne
    @JoinColumn(name = "ra_profile_uuid")
    private RaProfile raProfile;
    
    @OneToOne
    @JoinColumn(name = "certificate_uuid")
    private Certificate issuedCertificate;
}
```

### CertificateLocationHistory

**Tabela**: `certificate_location_history`

```java
@Entity
@Table(name = "certificate_location_history")
public class CertificateLocationHistory extends UniquelyIdentifiedAndAudited {
    
    @ManyToOne
    @JoinColumn(name = "certificate_uuid")
    private Certificate certificate;
    
    @ManyToOne
    @JoinColumn(name = "location_uuid")
    private Location location;
    
    @Enumerated(EnumType.STRING)
    @Column(name = "event_type")
    private LocationEventType eventType; // ADDED, REMOVED, UPDATED
    
    @Column(name = "event_timestamp")
    private LocalDateTime eventTimestamp;
}
```

---

## 3.3 Cryptographic Key Entities

### CryptographicKey

**Tabela**: `cryptographic_key`

```java
@Entity
@Table(name = "cryptographic_key")
public class CryptographicKey extends UniquelyIdentifiedAndAudited {
    
    // Identity
    @Column(name = "name")
    private String name;
    
    @Column(name = "description")
    private String description;
    
    // Cryptographic Details
    @Enumerated(EnumType.STRING)
    @Column(name = "key_type")
    private KeyType keyType; // RSA, EC, AES, FALCON, DILITHIUM, SPHINCS+
    
    @Column(name = "key_size")
    private Integer keySize; // 2048, 3072, 4096 for RSA
    
    @Enumerated(EnumType.STRING)
    @Column(name = "algorithm")
    private Algorithm algorithm; // RSA, ECDSA, ECDH, AES, etc
    
    @Column(name = "algorithm_specification")
    private String algorithmSpecification; // e.g., "P-256" for EC
    
    // Key Usage
    @ElementCollection
    @JoinTable(name = "cryptographic_key_usage")
    @Enumerated(EnumType.STRING)
    private Set<KeyUsage> keyUsages = new HashSet<>();
    // Examples: SIGN, VERIFY, ENCRYPT, DECRYPT, WRAP, UNWRAP
    
    // State Management
    @Enumerated(EnumType.STRING)
    @Column(name = "state")
    private KeyState state; // ACTIVE, COMPROMISED, DESTROYED, DEACTIVATED
    
    @Column(name = "activation_date")
    private LocalDateTime activationDate;
    
    @Column(name = "deactivation_date")
    private LocalDateTime deactivationDate;
    
    // PQC Specific
    @Column(name = "is_pqc")
    private Boolean isPQC = false;
    
    // Associations
    @ManyToOne
    @JoinColumn(name = "entity_instance_reference_uuid")
    private EntityInstanceReference entityInstanceReference; // Which provider
    
    @OneToMany(mappedBy = "cryptographicKey", cascade = CascadeType.ALL)
    private List<CryptographicKeyItem> items = new ArrayList<>();
}
```

### CryptographicKeyItem

**Tabela**: `cryptographic_key_item`

```java
@Entity
@Table(name = "cryptographic_key_item")
public class CryptographicKeyItem extends UniquelyIdentifiedAndAudited {
    
    @ManyToOne
    @JoinColumn(name = "key_uuid")
    private CryptographicKey cryptographicKey;
    
    @Enumerated(EnumType.STRING)
    @Column(name = "format")
    private KeyFormat format; // RAW, X.509, PKCS8, PKCS1, JWK
    
    @Lob
    @Column(name = "content")
    private byte[]; // Encoded key material
    
    @Column(name = "state")
    private String state;
    
    @Column(name = "created_at")
    private LocalDateTime createdAt;
}
```

---

## 3.4 Profile Entities

### RaProfile (Registration Authority)

**Tabela**: `ra_profile`

```java
@Entity
@Table(name = "ra_profile")
public class RaProfile extends UniquelyIdentifiedAndAudited {
    
    @Column(name = "name", unique = true)
    private String name;
    
    @Column(name = "description")
    private String description;
    
    // Protocol-specific URLs
    @Column(name = "acme_url")
    private String acmeUrl;
    
    @Column(name = "scep_url")
    private String scepUrl;
    
    @Column(name = "cmp_url")
    private String cmpUrl;
    
    // CA Configuration
    @ManyToOne
    @JoinColumn(name = "ca_connector_uuid")
    private Connector caConnector;
    
    @ManyToOne
    @JoinColumn(name = "ca_instance_reference_uuid")
    private AuthorityInstanceReference authorityInstanceReference;
    
    // Dynamic Attributes
    @JdbcTypeCode(SqlTypes.JSON)
    @Column(columnDefinition = "jsonb")
    private List<RequestAttribute> attributes;
    
    // State
    @Column(name = "enabled")
    private Boolean enabled = true;
    
    @Column(name = "updated_at")
    private LocalDateTime updatedAt;
}
```

### AcmeProfile

**Tabela**: `acme_profile`

```java
@Entity
@Table(name = "acme_profile")
public class AcmeProfile extends UniquelyIdentifiedAndAudited {
    
    @OneToOne
    @JoinColumn(name = "ra_profile_uuid")
    private RaProfile raProfile;
    
    @Column(name = "website")
    private String website;
    
    @Column(name = "terms_of_service")
    private String termsOfService;
    
    @Column(name = "dns_resolver")
    private String dnsResolver;
    
    @Column(name = "challenge_type")
    private String challengeType; // http-01, dns-01, tls-alpn-01
}
```

### ScepProfile & CmpProfile

**Similar pattern to AcmeProfile**

```java
@Entity
@Table(name = "scep_profile")
public class ScepProfile extends UniquelyIdentifiedAndAudited {
    
    @OneToOne
    @JoinColumn(name = "ra_profile_uuid")
    private RaProfile raProfile;
    
    @Column(name = "retry_interval") // milliseconds
    private Long retryInterval;
    
    @Column(name = "retry_count")
    private Integer retryCount;
}

@Entity
@Table(name = "cmp_profile")
public class CmpProfile extends UniquelyIdentifiedAndAudited {
    
    @OneToOne
    @JoinColumn(name = "ra_profile_uuid")
    private RaProfile raProfile;
    
    @Column(name = "poll_timeout_seconds")
    private Integer pollTimeoutSeconds; // default: 20
    
    @Column(name = "verbose_mode")
    private Boolean verboseMode = false;
}
```

---

## 3.5 Access Control Entities

### Group

**Tabela**: `group`

```java
@Entity
@Table(name = "group", uniqueConstraints = {
    @UniqueConstraint(columnNames = "name")
})
public class Group extends UniquelyIdentifiedAndAudited {
    
    @Column(name = "name")
    private String name;
    
    @Column(name = "description")
    private String description;
    
    @Column(name = "email")
    private String email;
    
    @ManyToMany(mappedBy = "groups")
    private Set<Certificate> certificates = new HashSet<>();
}
```

### Location

**Tabela**: `location`

```java
@Entity
@Table(name = "location")
public class Location extends UniquelyIdentifiedAndAudited {
    
    @Column(name = "name", unique = true)
    private String name;
    
    @Column(name = "description")
    private String description;
    
    // Entity Provider (onde certs são armazenados)
    @ManyToOne
    @JoinColumn(name = "entity_instance_reference_uuid")
    private EntityInstanceReference entityInstanceReference;
    
    // Attributes
    @JdbcTypeCode(SqlTypes.JSON)
    @Column(columnDefinition = "jsonb")
    private List<RequestAttribute> attributes;
    
    @ManyToMany(mappedBy = "locations")
    private Set<Certificate> certificates = new HashSet<>();
}
```

### EntityInstanceReference

**Tabela**: `entity_instance_reference`

```java
@Entity
@Table(name = "entity_instance_reference")
public class EntityInstanceReference extends UniquelyIdentifiedAndAudited {
    
    @Column(name = "name")
    private String name;
    
    @Column(name = "kind") // Entity kind (ex: HSM, VAULT, FILE)
    private String kind;
    
    @Enumerated(EnumType.STRING)
    @Column(name = "status")
    private ReferenceStatus status; // CONNECTED, DISCONNECTED, ERROR
    
    @ManyToOne
    @JoinColumn(name = "connector_uuid")
    private Connector connector;
}
```

---

## 3.6 Connector & Integration Entities

### Connector

**Tabela**: `connector`

```java
@Entity
@Table(name = "connector", uniqueConstraints = {
    @UniqueConstraint(columnNames = {"url", "version"})
})
public class Connector extends UniquelyIdentifiedAndAudited {
    
    @Column(name = "name")
    private String name;
    
    @Column(name = "url")
    private String url;
    
    @Column(name = "version")
    private String version;
    
    @Column(name = "description")
    private String description;
    
    // Endpoints
    @OneToMany(mappedBy = "connector", cascade = CascadeType.ALL)
    private List<Endpoint> endpoints = new ArrayList<>();
    
    // Function Groups
    @ManyToMany
    @JoinTable(
        name = "connector_function_group",
        joinColumns = @JoinColumn(name = "connector_uuid"),
        inverseJoinColumns = @JoinColumn(name = "function_group_id")
    )
    private Set<FunctionGroup> functionGroups = new HashSet<>();
    
    // Health
    @Column(name = "health_check_timestamp")
    private LocalDateTime healthCheckTimestamp;
    
    @Enumerated(EnumType.STRING)
    @Column(name = "health_status")
    private HealthStatus healthStatus;
}
```

### Endpoint

**Tabela**: `endpoint`

```java
@Entity
@Table(name = "endpoint")
public class Endpoint extends UniquelyIdentifiedAndAudited {
    
    @Column(name = "name")
    private String name;
    
    @Column(name = "context")
    private String context;
    
    @ManyToOne
    @JoinColumn(name = "connector_uuid")
    private Connector connector;
}
```

---

## 3.7 Workflow & Approval Entities

### Approval

**Tabela**: `approval`

```java
@Entity
@Table(name = "approval")
public class Approval extends UniquelyIdentifiedAndAudited {
    
    @Enumerated(EnumType.STRING)
    @Column(name = "status")
    private ApprovalStatus status; // PENDING, APPROVED, REJECTED
    
    @Column(name = "expiration_date")
    private LocalDateTime expirationDate;
    
    // Multi-step workflow
    @ManyToMany
    @JoinTable(
        name = "approval_step",
        joinColumns = @JoinColumn(name = "approval_uuid"),
        inverseJoinColumns = @JoinColumn(name = "approval_profile_uuid")
    )
    private List<ApprovalProfile> steps = new ArrayList<>();
    
    // Associated resource
    @Enumerated(EnumType.STRING)
    @Column(name = "resource_type")
    private Resource resourceType;
    
    @Column(name = "resource_uuid")
    private UUID resourceUuid;
}
```

### Rule, Trigger, Action

```java
@Entity
@Table(name = "rule")
public class Rule extends UniquelyIdentifiedAndAudited {
    
    @Column(name = "name", unique = true)
    private String name;
    
    @OneToMany(mappedBy = "rule", cascade = CascadeType.ALL)
    private Set<Condition> conditions = new HashSet<>();
    
    @OneToMany(mappedBy = "rule", cascade = CascadeType.ALL)
    private Set<Action> actions = new HashSet<>();
}

@Entity
@Table(name = "trigger")
public class Trigger extends UniquelyIdentifiedAndAudited {
    
    @Enumerated(EnumType.STRING)
    @Column(name = "trigger_type")
    private TriggerType triggerType; // CERTIFICATE_EXPIRING, KEY_COMPROMISED, etc
    
    @ManyToMany
    private Set<Rule> rules = new HashSet<>();
}

@Entity
@Table(name = "action")
public class Action extends UniquelyIdentifiedAndAudited {
    
    @Column(name = "name")
    private String name;
    
    @Enumerated(EnumType.STRING)
    @Column(name = "action_type")
    private ActionType actionType; // EMAIL, WEBHOOK, REVOKE, etc
    
    @JdbcTypeCode(SqlTypes.JSON)
    @Column(columnDefinition = "jsonb")
    private Map<String, Object> parameters;
}
```

---

## 3.8 Compliance & Custom Attributes

### AttributeDefinition

**Tabela**: `attribute_definition`

```java
@Entity
@Table(name = "attribute_definition")
public class AttributeDefinition extends UniquelyIdentifiedAndAudited {
    
    @Column(name = "name")
    private String name;
    
    @Enumerated(EnumType.STRING)
    @Column(name = "content_type")
    private ContentType contentType; // STRING, INTEGER, OBJECT, CERTIFICATE, etc
    
    @Enumerated(EnumType.STRING)
    @Column(name = "content_format")
    private ContentFormat contentFormat; // TEXT, PASSWORD, DATE, FILE, etc
    
    @Column(name = "required")
    private Boolean required = false;
    
    @Column(name = "read_only")
    private Boolean readOnly = false;
    
    @Column(name = "visible")
    private Boolean visible = true;
    
    @JdbcTypeCode(SqlTypes.JSON)
    @Column(columnDefinition = "jsonb")
    private Map<String, Object> properties;
}
```

### ComplianceProfile

**Tabela**: `compliance_profile`

```java
@Entity
@Table(name = "compliance_profile")
public class ComplianceProfile extends UniquelyIdentifiedAndAudited {
    
    @Column(name = "name")
    private String name;
    
    // Compliance rules
    @JdbcTypeCode(SqlTypes.JSON)
    @Column(columnDefinition = "jsonb")
    private List<Map<String, Object>> rules;
    
    @ManyToMany(mappedBy = "complianceProfiles")
    private Set<Certificate> certificates = new HashSet<>();
}
```

---

## Resumo de Entidades

| Categoria | Entidades | Propósito |
|-----------|-----------|----------|
| **Certificates** | Certificate, CertificateRequest, CertificateLocationHistory, CrlEntry | Gerenciamento de certs X.509 |
| **Cryptography** | CryptographicKey, CryptographicKeyItem, Secret | Gerenciamento de chaves |
| **Profiles** | RaProfile, AcmeProfile, ScepProfile, CmpProfile, TokenProfile | Configuração de protocolos |
| **Access Control** | Group, Location, EntityInstanceReference, AuthorityInstanceReference | Controle de acesso |
| **Connectors** | Connector, Endpoint, FunctionGroup | Sistema de plugins |
| **Workflow** | Approval, Rule, Trigger, Action, Execution | Automação |
| **Compliance** | ComplianceProfile, AttributeDefinition, CustomOidEntry | Customização |
| **Audit** | AuditLog, ScheduledJob | Rastreabilidade |

**Total**: 65+ entidades JPA com ~300+ colunas, suportando PQC, múltiplos protocolos e workflows complexos.

---

# 4. RELACIONAMENTOS ER: Mapa Completo e Padrões JPA

## 4.1 Diagrama ER: Arquitetura de Domínio

```
┌──────────────────────────────────────────────────────────────────┐
│                  CERTIFICATE LIFECYCLE DOMAIN                    │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│   ┌──────────────────┐         ┌─────────────────────┐         │
│   │  RA_PROFILE      │─────1:N─┤   CERTIFICATE      │         │
│   │  (CA Gateway)    │         │   (X.509 Asset)    │         │
│   │                  │         │                    │         │
│   │ - name           │         │ - serial           │──────┐  │
│   │ - acme_url       │         │ - subject          │      │  │
│   │ - scep_url       │         │ - issuer           │      │  │
│   │ - cmp_url        │         │ - valid_from       │      │  │
│   │ - attributes     │         │ - valid_to         │      │  │
│   └────────┬─────────┘         │ - state (ACTIVE)   │      │  │
│            │                   │ - is_pqc           │      │  │
│            │                   └─────────┬──────────┘      │  │
│            │                             │                 │  │
│     Implemented by                   M:N Group            │  │
│     Connector                      Assignment             │  │
│     (via FK)                            │                 │  │
│            │                            ▼                 │  │
│            │                   ┌──────────────┐           │  │
│            │                   │    GROUP     │           │  │
│            │                   │ (Logical grp)│           │  │
│            │                   └──────────────┘           │  │
│            │                                              │  │
│     ┌──────▼──────┐                                        │  │
│     │ CONNECTOR   │─────M:N─ FunctionGroup               │  │
│     │ (Plugin)    │         (CA, KEY_MGMT...)            │  │
│     │             │                                       │  │
│     │ - url       │                                       │  │
│     │ - version   │                                       │  │
│     │ - endpoints │                                       │  │
│     └─────────────┘                                       │  │
│                                                           │  │
│     ┌──────────────────────┐                             │  │
│     │CERTIFICATE_REQUEST  │                             │  │
│     │ (CSR Workflow)       │                             │  │
│     │                      │◄─────────────────M:M─────────┤  │
│     │ - status (PENDING)   │──1:1──→ APPROVAL (Multi-step) │
│     │ - csr_content        │         ├─ ApprovalStep[1]    │
│     │ - subject            │         ├─ ApprovalStep[2]    │
│     │                      │         └─ ApprovalStep[3]    │
│     └──────────────────────┘                              │
│                                                           │
└──────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────┐
│               CRYPTOGRAPHIC ASSETS DOMAIN                        │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│   ┌──────────────────────────┐                                  │
│   │ CRYPTOGRAPHIC_KEY        │──1:N─→ CryptographicKeyItem    │
│   │ (Abstract, PQC support)  │         (Concrete formats)      │
│   │                          │                                  │
│   │ - name                   │         - format (PEM, PKCS8)  │
│   │ - type (RSA, EC, PQC)    │         - data (DER bytes)     │
│   │ - size                   │         - state                │
│   │ - is_pqc (FALCON, etc)   │                                │
│   │ - state (ACTIVE)         │         References:             │
│   └────────┬─────────────────┘         ├─ TokenInstance       │
│            │                           ├─ EntityReference    │
│            │                           └─ Location           │
│       1:N  │                                                  │
│            ▼                                                  │
│   ┌─────────────────────┐                                     │
│   │ TokenInstanceRef    │                                     │
│   │ (HSM, Vault, etc)   │                                     │
│   │                     │                                     │
│   │ - uuid              │                                     │
│   │ - kind              │                                     │
│   │ - status            │                                     │
│   └─────────────────────┘                                     │
│                                                               │
│   ┌─────────────────────┐                                     │
│   │ SECRET              │──1:N─→ SecretVersion               │
│   │ (Encrypted creds)   │         (Versioned)                │
│   │                     │                                     │
│   │ - name              │                                     │
│   │ - secret_content    │                                     │
│   │ - created_at        │                                     │
│   └─────────────────────┘                                     │
│                                                               │
└──────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────┐
│               PROTOCOL PROFILES DOMAIN                           │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│                 ┌────────────────┐                              │
│                 │  RA_PROFILE    │                              │
│                 │  (Central Hub)  │                              │
│                 └────────────────┘                              │
│                      │                                          │
│          ┌───────────┼────────────┬─────────────┐             │
│          │           │            │             │             │
│       1:1 │        1:1 │        1:1 │          1:1 │             │
│          ▼           ▼            ▼             ▼             │
│    ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌────────────┐    │
│    │ACME      │ │SCEP      │ │CMP       │ │TOKEN       │    │
│    │PROFILE   │ │PROFILE   │ │PROFILE   │ │PROFILE     │    │
│    │          │ │          │ │          │ │            │    │
│    │RFC 8555  │ │RFC 2560  │ │RFC 4210  │ │ Vault Ref  │    │
│    │          │ │          │ │          │ │            │    │
│    │website   │ │endpoint  │ │poll_time │ │name        │    │
│    │ToS       │ │version   │ │verbose   │ │attributes  │    │
│    └──────────┘ └──────────┘ └──────────┘ └────────────┘    │
│                                                               │
│    Each profiles linked to same RA_PROFILE                   │
│    Allowing multi-protocol issuance                          │
│                                                               │
└──────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────┐
│              WORKFLOW & AUTOMATION DOMAIN                        │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│   ┌──────────────┐                                              │
│   │ RULE         │──M:N─→ Trigger                              │
│   │              │        (Event matcher)                       │
│   │ - name       │                                              │
│   │ - condition  │         Triggers:                            │
│   │ - enabled    │         ├─ CERTIFICATE_CREATED             │
│   │              │         ├─ CERTIFICATE_EXPIRING_SOON        │
│   │              │         ├─ KEY_CREATED                      │
│   │              │         └─ APPROVAL_COMPLETED              │
│   └──────────────┘                                              │
│          │                                                      │
│     1:N  │  Evaluated by                                       │
│          ▼                                                      │
│   ┌──────────────┐                 ┌──────────────────┐        │
│   │ ACTION       │◄────1:N─────────│ EXECUTION        │        │
│   │              │ (stores result) │                  │        │
│   │ - name       │                 │ - scheduled_job  │        │
│   │ - type       │                 │ - result         │        │
│   │ - parameters │                 │ - executed_at    │        │
│   │   (JSONB)    │                 │ - success        │        │
│   │              │                 └──────────────────┘        │
│   │ Types:       │                                             │
│   │ ├─ WEBHOOK   │                                             │
│   │ ├─ EMAIL     │                                             │
│   │ ├─ REVOKE    │                                             │
│   │ ├─ COMPRESS  │                                             │
│   │ └─ DELETE    │                                             │
│   └──────────────┘                                              │
│                                                               │
│   ┌──────────────────┐                                        │
│   │ SCHEDULED_JOB    │                                        │
│   │                  │                                        │
│   │ - cron_expr      │                                        │
│   │ - last_executed  │                                        │
│   │ - enabled        │                                        │
│   │ - description    │                                        │
│   │                  │──1:N─→ ScheduledJobHistory            │
│   └──────────────────┘         (Execution logs)              │
│                                                               │
└──────────────────────────────────────────────────────────────────┘
```

## 4.2 Padrões JPA: OneToOne, OneToMany, ManyToMany

### Padrão OneToOne: RA_PROFILE ↔ ACME_PROFILE

**Cenário**: Um RA Profile pode ter AT MOST um ACME profile.

```java
@Entity
@Table(name = "ra_profile")
public class RaProfile extends UniquelyIdentifiedAndAudited {
    
    @OneToOne(fetch = FetchType.LAZY, cascade = CascadeType.ALL)
    @JoinColumn(name = "acme_profile_uuid", unique = true)
    private AcmeProfile acmeProfile;  // Opcional (null se SCEP-only)
    
    // Getters
    public AcmeProfile getAcmeProfile() { return acmeProfile; }
    public void setAcmeProfile(AcmeProfile profile) { this.acmeProfile = profile; }
}

@Entity
@Table(name = "acme_profile")
public class AcmeProfile extends UniquelyIdentifiedAndAudited {
    
    @OneToOne(mappedBy = "acmeProfile")  // Sem @JoinColumn (owning side é RaProfile)
    private RaProfile raProfile;
}

// USO:
RaProfile raProfile = raProfileRepository.findByUuid(uuid);
if (raProfile.getAcmeProfile() != null) {
    AcmeProfile acme = raProfile.getAcmeProfile();  // Lazy loaded aqui
    System.out.println("ACME endpoint: " + acme.getWebsite());
}

// Delete cascade:
raProfileRepository.delete(raProfile);  // Deleta também AcmeProfile automaticamente
```

**Trade-off**: 
- ✅ FK na tabela RA_PROFILE reduz NULL columns em ACME_PROFILE
- ❌ Lazy loading sempre faz query (exceto @Transactional context)

### Padrão OneToMany: CERTIFICATE → CERTIFICATE_REQUEST

**Cenário**: Um certificate pode ter múltiplas requisições (enrollment, renewal, key-update).

```java
@Entity
@Table(name = "ra_profile")
public class RaProfile extends UniquelyIdentifiedAndAudited {
    
    @OneToMany(fetch = FetchType.LAZY, mappedBy = "raProfile",
               cascade = CascadeType.ALL, orphanRemoval = true)
    private List<Certificate> certificates = new ArrayList<>();
    
    public void addCertificate(Certificate cert) {
        cert.setRaProfile(this);
        certificates.add(cert);
    }
    
    public void removeCertificate(Certificate cert) {
        certificates.remove(cert);  // Auto-deleted (orphan removal)
    }
}

@Entity
@Table(name = "certificate")
public class Certificate extends UniquelyIdentifiedAndAudited {
    
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "ra_profile_uuid", nullable = false)
    private RaProfile raProfile;
}

// USO (lista lazy):
RaProfile raProfile = raProfileRepository.findByUuid(uuid);
List<Certificate> allCerts = raProfile.getCertificates();  // Lazy! Não executa query ainda

for (Certificate cert : allCerts) {  // Query aqui!
    System.out.println(cert.getSubject());
}

// Melhor: Eager load com @EntityGraph
@Repository
public interface RaProfileRepository extends JpaRepository<RaProfile, UUID> {
    
    @EntityGraph(attributePaths = "certificates")
    Optional<RaProfile> findByUuid(UUID uuid);
}
```

**Trade-off**:
- ✅ orphanRemoval = true garante limpeza (remove cert → deleta do BD)
- ❌ Lazy loading causa N+1 queries se não cuidar

### Padrão ManyToMany: CERTIFICATE ↔ GROUP

**Cenário**: Um certificate pode estar em múltiplos groups, um group tem múltiplos certs.

```java
@Entity
@Table(name = "certificate")
public class Certificate extends UniquelyIdentifiedAndAudited {
    
    @ManyToMany(fetch = FetchType.LAZY, cascade = {
        CascadeType.PERSIST, CascadeType.MERGE
    })
    @JoinTable(
        name = "certificate_group",
        joinColumns = @JoinColumn(name = "certificate_uuid"),
        inverseJoinColumns = @JoinColumn(name = "group_uuid")
    )
    private Set<Group> groups = new HashSet<>();  // Set! Não List (evita duplicatas)
    
    public void addToGroup(Group group) {
        groups.add(group);  // Automático bilateral
        group.getCertificates().add(this);
    }
}

@Entity
@Table(name = "group")
public class Group extends UniquelyIdentifiedAndAudited {
    
    @ManyToMany(mappedBy = "groups", fetch = FetchType.LAZY)
    private Set<Certificate> certificates = new HashSet<>();
}

// USO:
Certificate cert = certificateRepository.findByUuid(uuid);
Set<Group> groups = cert.getGroups();  // Lazy

Group productionGroup = groupRepository.findByName("Production");
cert.addToGroup(productionGroup);  // Bilateral add
certificateRepository.save(cert);  // Atualiza join table

// Query complexa:
@Query("SELECT c FROM Certificate c " +
       "INNER JOIN c.groups g " +
       "WHERE g.uuid = :groupUuid " +
       "AND c.state = 'ACTIVE' " +
       "ORDER BY c.validTo DESC")
List<Certificate> findActiveByCertificateGroup(
    @Param("groupUuid") UUID groupUuid,
    Pageable pageable);
```

**Trade-off**:
- ✅ Join table automática (não precisa gerenciar relação manualmente)
- ❌ Sem cascade = DELETE (deletar group NOT deleta certs)

---

# 5. FLUXOS END-TO-END: EMISSÃO E REVOGAÇÃO DE CERTIFICADO

## 5.1 Fluxo Completo: Emissão via ACME (ACME Order Flow)

Este fluxo mostra **TODAS** as entidades criadas/modificadas durante uma emissão real. Essencial para entender coordenação entre domínios.

```
ACTOR: Cliente ACME (Let's Encrypt client, Certbot, etc)
CONTEXT: Domínio "example.com", 1 ano de validade

═════════════════════════════════════════════════════════════════════════════

PASSO 1: Cliente descobre ACME directory [T=0s]

  Cliente:
  GET /acme/directory

  Server Response (200):
  {
    "newNonce": "https://czertainly/acme/nonce",
    "newAccount": "https://czertainly/acme/new-account",
    "newOrder": "https://czertainly/acme/new-order",
    "revokeCert": "https://czertainly/acme/revoke",
    "meta": {
        "termsOfService": "https://czertainly.com/tos",
        "website": "https://czertainly.com",
        "caaIdentities": ["czertainly.com"]
    }
  }

  BD Record: AcmeProfile lido (website, ToS, CAA)

═════════════════════════════════════════════════════════════════════════════

PASSO 2: Cliente cria ou encontra Account [T=5s]

  Cliente:
  POST /acme/new-account
  Headers: JWS-signed (using client's private key)
  Payload: {
    "termsOfServiceAgreed": true,
    "contact": ["mailto:admin@example.com"]
  }

  Server Processing: AcmeAccountService.createOrFindAccount()
    1. Valida JWS signature (público key extraído)
    2. Computa thumbprint = SHA256(base64url(publicKey))
    3. Busca AcmeAccount por thumbprint (unique)
    4. Se encontrado → return 200 (existing account)
    5. Se novo → INSERT novo AcmeAccount, return 201

  BD INSERT:
  AcmeAccount {
    uuid: 'acct-a1b2c3d4',
    thumbprint_sha256: 'abc123...xyz',  // Unique!
    public_key_json: { kty: 'RSA', e: 'AQAB', n: '...', ...},
    status: 'VALID',
    contact: ['mailto:admin@example.com'],
    terms_agreed: true,
    created_at: 2024-03-31T10:00:00Z
  }

═════════════════════════════════════════════════════════════════════════════

PASSO 3: Cliente cria nova Order (certificate request) [T=10s]

  Cliente:
  POST /acme/new-order
  Headers: JWS-signed
  Payload: {
    "identifiers": [
      { "type": "dns", "value": "example.com" },
      { "type": "dns", "value": "*.example.com" }  // Wildcard!
    ],
    "notBefore": "2024-04-01T00:00:00Z",
    "notAfter": "2025-04-01T00:00:00Z"
  }

  Server Processing: AcmeOrderService.createOrder()
    1. Valida identifiers (max 100)
    2. Valida dates (notBefore < notAfter)
    3. Cria AcmeOrder
    4. Para cada identifier: cria AcmeAuthorization
    5. Para cada authorization: cria N Challenges (http-01, dns-01, tls-alpn-01)

  BD INSERTs:
  
  AcmeOrder {
    uuid: 'order-x1y2z3',
    account_uuid: 'acct-a1b2c3d4',
    status: 'PENDING',
    identifiers_json: [
      { type: 'dns', value: 'example.com' },
      { type: 'dns', value: '*.example.com' }
    ],
    not_before: 2024-04-01T00:00:00Z,
    not_after: 2025-04-01T00:00:00Z,
    finalize_url: 'https://czertainly/acme/order/x1y2z3/finalize',
    created_at: 2024-03-31T10:00:10Z
  }

  AcmeAuthorization x2:
  {
    uuid: 'authz-1',
    order_uuid: 'order-x1y2z3',
    identifier_value: 'example.com',
    identifier_type: 'dns',
    status: 'PENDING',
    wildcard: false,
    expiration: 2024-04-30T10:00:10Z,  // 30 dias
    created_at: 2024-03-31T10:00:10Z
  }
  {
    uuid: 'authz-2',
    order_uuid: 'order-x1y2z3',
    identifier_value: '*.example.com',
    identifier_type: 'dns',
    status: 'PENDING',
    wildcard: true,  // Importante: wildcard=true
    expiration: 2024-04-30T10:00:10Z,
    created_at: 2024-03-31T10:00:10Z
  }

  AcmeChallenge x6:  (3 types × 2 authorizations)
  {
    uuid: 'chal-http-1',
    authorization_uuid: 'authz-1',
    type: 'http-01',
    status: 'PENDING',
    token: 'LoqXcYV8JV...',
    key_authorization: 'LoqXcYV8JV...thumbprint',
    created_at: 2024-03-31T10:00:10Z
  }
  {
    uuid: 'chal-dns-1',
    authorization_uuid: 'authz-1',
    type: 'dns-01',
    status: 'PENDING',
    token: 'LoqXcYV8JV...',
    key_authorization: 'LoqXcYV8JV...thumbprint',
    created_at: 2024-03-31T10:00:10Z
  }
  ... (4 mais para http-01, dns-01 em authz-2)

═════════════════════════════════════════════════════════════════════════════

PASSO 4: Cliente resolve challenges (ex: HTTP-01) [T=15s]

  Cliente configura HTTP server:
  .well-known/acme-challenge/{token} → returns key_authorization

  Cliente:
  POST /acme/challenge/chal-http-1/validate
  (Informa ao server: "I've resolved this challenge, verify it!")

  Server Processing: AcmeChallengeService.validate()
    1. Busca Challenge
    2. Para http-01:
       a. HTTP GET http://example.com/.well-known/acme-challenge/{token}
       b. Valida resposta = key_authorization
       c. Se match → status = VALID, validated_at = now
       d. Se erro → status = INVALID

  BD UPDATE:
  AcmeChallenge (chal-http-1) {
    status: 'VALID',  // Ou INVALID se failed
    validated_at: 2024-03-31T10:00:20Z
  }

═════════════════════════════════════════════════════════════════════════════

PASSO 5a: Server auto-evalua (quando TODOS challenges = VALID)

  Server trigger (background job or event listener):
    Se TODOS challenges do Authorization = VALID:
      → AcmeAuthorization.status = VALID

    Se TODOS authorizations da Order = VALID:
      → AcmeOrder.status = READY

  BD UPDATEs:
  AcmeAuthorization {
    status: 'VALID',  // x2
    validated_at: 2024-03-31T10:00:25Z
  }

  AcmeOrder {
    status: 'READY'  // Agora cliente pode fazer finalize
  }

═════════════════════════════════════════════════════════════════════════════

PASSO 5b: Cliente submete CSR (Certificate Signing Request) [T=1min]

  Cliente gera private key + CSR:
  openssl req -new -key private.key -out csr.pem

  Cliente:
  POST /acme/order/order-x1y2z3/finalize
  Headers: JWS-signed
  Payload: {
    "csr": "MIIDQzCCAq..."  // base64url(DER(PKCS10))
  }

  Server Processing: AcmeOrderService.finalize()
    1. Valida Order status = READY
    2. Parseia CSR (PKCS#10)
    3. Extrai Subject DN, Public Key, Extensions do CSR
    4. Valida:
       - Subject CN vs identifiers na Order
       - Key size ≥ 2048 (RSA) ou ≥ 256 (EC)
       - Signature válida
    5. Cria CertificateRequest
    6. RabbitTemplate.send(ca-issuance-queue, {csr, ra_profile_uuid})
    7. Atualiza Order → PROCESSING

  BD INSERTs/UPDATEs:

  CertificateRequest {
    uuid: 'creq-001',
    type: 'ENROLLMENT',
    status: 'PROCESSING',  # Ainda não ISSUED (aguardando CA)
    subject: 'CN=example.com,O=My Org',  # Extraído CSR
    csr_content: [DER bytes],
    ra_profile_uuid: [RA_PROFILE linkado],
    created_at: 2024-03-31T10:01:00Z
  }

  AcmeOrder {
    status: 'PROCESSING'  # Aguardando CA
  }

  RabbitMQ Message → ca-issuance-queue

═════════════════════════════════════════════════════════════════════════════

PASSO 6: CA Issues Certificate (async, backend) [T=2min]

  Message Listener: @RabbitListener("ca-issuance-queue")
  → CertificateIssuanceService.issueCertificate()

  Processing:
    1. Carrega CertificateRequest + RaProfile + Connector
    2. Carrega CA Connector
    3. HTTP POST {connector-url}/api/operations
       {
         functionGroup: "CA",
         functionName: "ISSUE_CERTIFICATE",
         parameters: {
           csr: base64(csr_content),
           attributes: {... ca-specific attrs ...}
         }
       }
    4. Connector (external system) valida + emite certificado
    5. Resposta:
       {
         certificate: "MIIDXTCCAkWgAwIBAgIBATANBg...",  # DER bytes
         chain: [...],
         issuer: "CN=Let's Encrypt Authority X3",
         ...
       }
    6. Parseia X.509:
       - Extrai serial, subject, issuer, validFrom, validTo, key algorithm
       - Computa thumbprint SHA256
       - Detecta se PQC
    7. Cria Certificate entity
    8. Atualiza CertificateRequest → ISSUED
    9. Atualiza AcmeOrder → VALID

  BD INSERTs/UPDATEs:

  Certificate {
    uuid: 'cert-abc123',
    serial_number: '01:A2:B3:C4:D5',
    subject: 'CN=example.com,O=My Org',
    issuer: 'CN=Let\'s Encrypt Authority X3',
    valid_from: 2024-04-01T00:00:00Z,
    valid_to: 2025-04-01T00:00:00Z,
    certificate_content: [DER bytes from CA],
    state: 'ACTIVE',
    ra_profile_uuid: [RA_PROFILE UUID],
    thumbprint_sha256: 'e3b0c44...',
    public_key_algorithm: 'RSA',
    public_key_size: 2048,
    is_pqc: false,
    created_by: 'SYSTEM',
    created_at: 2024-03-31T10:02:00Z
  }

  CertificateRequest {
    status: 'ISSUED',
    certificate_uuid: 'cert-abc123'  # Link para cert emitido
  }

  CertificateEventHistory {
    uuid: 'evt-1',
    certificate_uuid: 'cert-abc123',
    event: 'CREATED',
    event_timestamp: 2024-03-31T10:02:00Z,
    extra_data_json: {
      via: 'ACME',
      acme_order_id: 'order-x1y2z3',
      acme_account_id: 'acct-a1b2c3d4'
    }
  }

  AuditLog {
    uuid: autogenerated,
    operation: 'CERTIFICATE_CREATED',
    resource: 'CERTIFICATE',
    resource_uuid: 'cert-abc123',
    actor: 'SYSTEM',
    timestamp: 2024-03-31T10:02:00Z,
    success: true
  }

  AcmeOrder {
    status: 'VALID',  # Order completo!
    certificate_uuid: 'cert-abc123'
  }

═════════════════════════════════════════════════════════════════════════════

PASSO 7: Cliente recupera certificado [T=2min5s]

  Cliente:
  GET /acme/order/order-x1y2z3/finalize

  Server Response (200):
  {
    status: 'valid',
    identifiers: [
      { type: 'dns', value: 'example.com' },
      { type: 'dns', value: '*.example.com' }
    ],
    finalize: 'https://czertainly/acme/order/x1y2z3/finalize',
    certificate: 'https://czertainly/acme/cert/order-x1y2z3'
  }

  Cliente:
  GET https://czertainly/acme/cert/order-x1y2z3

  Server Response (200, PEM-encoded):
  -----BEGIN CERTIFICATE-----
  MIIDXTCCAkWgAwIBAgIBATANBgkqhkiG9w0BAQsFAAD...
  -----END CERTIFICATE-----
  -----BEGIN CERTIFICATE-----  # Chain
  MIIEkTCCA3mgAwIBAgIQCgFBQgAAAVOyOvsmwkw4NjA...
  -----END CERTIFICATE-----

═════════════════════════════════════════════════════════════════════════════

FLUXO COMPLETO > ESTADO BD FINAL:

  NEW Records:
  ✓ AcmeAccount (1)
  ✓ AcmeOrder (1)
  ✓ AcmeAuthorization (2)
  ✓ AcmeChallenge (6)
  ✓ CertificateRequest (1)
  ✓ Certificate (1) - **THE GOAL**
  ✓ CertificateEventHistory (1)
  ✓ AuditLog (1)

  Total: ~15 inserts em ~2 minutos
  
  Entity Graph Complexity:
  
  AcmeOrder
    ├─ account (AcmeAccount)
    ├─ authorizations (2 × AcmeAuthorization)
    │   └─ challenges (6 × AcmeChallenge, 3 per authz)
    ├─ certificateRequest (CertificateRequest)
    │   └─ certificate (Certificate) ← FINAL


═════════════════════════════════════════════════════════════════════════════
```

## 5.2 Fluxo: Revogação com Cascata de Eventos

```
CENÁRIO: Certificado foi comprometido. Revogação URGENTE.

T=00:00: Usuário detecta key compromise
  DELETE /api/v2/certificates/{uuid}
  reason = "KEY_COMPROMISE"

  ┌─────────────────────────────────────────────┐
  │ CertificateService.revoke()                 │
  │ @AuditLogged (automatic)                    │
  └─────────────────────────────────────────────┘
           │
           ▼
  ┌─────────────────────────────────────────────┐
  │ BD UPDATE: Certificate                      │
  │ - state: ACTIVE → REVOKED                  │
  │ - revoked_at: 2024-03-31T15:30:00Z         │
  │ - revocation_reason: KEY_COMPROMISE        │
  │                                             │
  │ BD INSERT: CertificateEventHistory         │
  │ - event: REVOKED                           │
  │ - reason: KEY_COMPROMISE                   │
  │ - timestamp: 2024-03-31T15:30:00Z          │
  │                                             │
  │ BD INSERT: AuditLog                        │
  │ - operation: REVOKE                        │
  │ - resource: CERTIFICATE                    │
  │ - timestamp: 2024-03-31T15:30:00Z          │
  └─────────────────────────────────────────────┘
           │
           ▼ RabbitTemplate.send()
  
  ┌─────────────────────────────────────────────────────────┐
  │ RabbitMQ: revocation-queue                              │
  │ {                                                       │
  │   event: "CERTIFICATE_REVOKED",                        │
  │   certificateUuid: "cert-abc123",                      │
  │   reason: "KEY_COMPROMISE",                            │
  │   revokedAt: 2024-03-31T15:30:00Z,                    │
  │ timestamp: 2024-03-31T15:30:00Z                        │
  │ }                                                       │
  └─────────────────────────────────────────────────────────┘
           │
        ┌──┴──────────────┬──────────────┬──────────────┐
        │                 │              │              │
        ▼                 ▼              ▼              ▼
  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐
  │Notification  │ │CRL Generator │ │Compliance    │ │Audit Log     │
  │Listener      │ │Listener      │ │Listener      │ │Listener      │
  │              │ │              │ │              │ │              │
  │@RabbitListener│ │@RabbitListener│ │@RabbitListener│ │@RabbitListener
  │"revocation.." │ │"revocation.." │ │"revocation.." │ │"revocation.."
  └──────────────┘ └──────────────┘ └──────────────┘ └──────────────┘
        │                 │              │              │
        │ Email to        │ Compute CRL  │ Mark for     │ Log in
        │ cert owner      │ Update       │ re-audit     │ system
        │                 │              │              │
        ▼                 ▼              ▼              ▼
  Owner receives   CRL published   Compliance    All async
  notification      to CRL server  checklist     tasks
                                   triggered    logged

ESTADO TEMPORAL:

Before:
  Certificate {
    state: ACTIVE,
    revoked_at: NULL,
    revocation_reason: NULL
  }
  CertificateEventHistory: [CREATED] only

After (T=15:30:05Z, 5 segundos depois):
  Certificate {
    state: REVOKED,
    revoked_at: 2024-03-31T15:30:00Z,
    revocation_reason: KEY_COMPROMISE
  }
  CertificateEventHistory: [CREATED, REVOKED]
  Notification sent to owner (if configured)
  CRL updated (~5 minutos depois, async)
  Compliance re-check triggered
```

---

# 6. PADRÕES DE CÓDIGO JAVA: Acessando Entidades

## 6.1 Create: Emitir Certificado

```java
@Service
@Transactional
public class CertificateIssuanceService {
    
    @Autowired private CertificateRepository certificateRepository;
    @Autowired private RaProfileRepository raProfileRepository;
    @Autowired private ConnectorService connectorService;
    @Autowired private RabbitTemplate rabbitTemplate;
    
    @AuditLogged(
        resource = "CERTIFICATE",
        operation = "CREATE"
    )
    public Certificate issueCertificate(
            UUID raProfileUuid,
            String csrContent) throws Exception {
        
        // 1. Validar RA Profile exists
        RaProfile raProfile = raProfileRepository
            .findByUuid(raProfileUuid)
            .orElseThrow(() -> new NotFoundException(
                "RaProfile not found"));
        
        // 2. Enviar CSR para CA (via connector)
        Map<String, Object> caResponse = 
            connectorService.issueCertificateViaConnector(
                raProfile.getCaConnector(),
                csrContent,
                raProfile.getAttributes()
            );
        
        // 3. Parsear X.509 certificate
        byte[] certContent = (byte[]) caResponse.get("certificate");
        X509Certificate x509 = CertificateUtils.parseX509(certContent);
        
        // 4. Criar Certificate entity
        Certificate certificate = new Certificate();
        certificate.setUuid(UUID.randomUUID());
        certificate.setContent(certContent);
        certificate.setSerialNumber(
            x509.getSerialNumber().toString(16));
        certificate.setSubject(
            x509.getSubjectX500Principal().getName());
        certificate.setIssuer(
            x509.getIssuerX500Principal().getName());
        certificate.setValidFrom(
            x509.getNotBefore().toInstant());
        certificate.setValidTo(
            x509.getNotAfter().toInstant());
        certificate.setState(CertificateState.ACTIVE);
        certificate.setRaProfile(raProfile);
        certificate.setThumbprintSha256(
            CertificateUtils.sha256Thumbprint(certContent));
        
        // Detectar PQC
        String algorithm = x509.getPublicKey().getAlgorithm();
        if (algorithm.contains("FALCON") || 
            algorithm.contains("Dilithium") ||
            algorithm.contains("SPHINCS")) {
            certificate.setIsPQC(true);
            certificate.setPqcAlgorithm(algorithm);
        }
        
        // 5. Salvar (JPA INSERT)
        Certificate saved = certificateRepository.save(certificate);
        
        // 6. Publicar evento assincrôno
        rabbitTemplate.convertAndSend(
            "certificate-events",
            Map.of(
                "event", "CERTIFICATE_CREATED",
                "certificateUuid", saved.getUuid(),
                "subject", saved.getSubject(),
                "timestamp", Instant.now()
            ));
        
        return saved;
    }
}
```

## 6.2 Read: Busca Complexa com QueryDSL

```java
@Service  
@Transactional(readOnly = true)
public class CertificateSearchService {
    
    @Autowired private JPAQueryFactory queryFactory;
    
    public Page<Certificate> searchExpiringCertificates(
            UUID raProfileUuid,
            int daysUntilExpiry,
            Pageable pageable) {
        
        QCertificate qCert = QCertificate.certificate;
        QRaProfile qRa = QRaProfile.raProfile;
        
        LocalDateTime threshold = LocalDateTime.now()
            .plusDays(daysUntilExpiry);
        
        // Construir predicate dinamicamente
        BooleanBuilder where = new BooleanBuilder();
        
        where.and(qCert.state.eq(CertificateState.ACTIVE));
        where.and(qCert.validTo.between(
            LocalDateTime.now(),
            threshold
        ));
        
        if (raProfileUuid != null) {
            where.and(qCert.raProfile.uuid.eq(raProfileUuid));
        }
        
        // Count total
        long total = queryFactory
            .selectFrom(qCert)
            .where(where)
            .fetchCount();
        
        // Fetch paginated results
        List<Certificate> content = queryFactory
            .selectFrom(qCert)
            .where(where)
            .orderBy(qCert.validTo.asc())  // Soonest first
            .orderBy(qCert.subject.asc())
            .offset(pageable.getOffset())
            .limit(pageable.getPageSize())
            .fetch();
        
        return new PageImpl<>(content, pageable, total);
    }
}
```

## 6.3 Update: Revogar Certificado

```java
@Service
@Transactional
public class CertificateRevocationService {
    
    @Autowired private CertificateRepository certificateRepository;
    @Autowired private RabbitTemplate rabbitTemplate;
    
    @AuditLogged(
        resource = "CERTIFICATE",
        operation = "REVOKE"
    )
    public Certificate revokeCertificate(
            UUID certificateUuid,
            RevocationReason reason) throws Exception {
        
        // 1. Load certificate
        Certificate cert = certificateRepository
            .findByUuid(certificateUuid)
            .orElseThrow(() -> new NotFoundException(
                "Certificate not found"));
        
        // 2. Validate can revoke
        if (cert.getState() == CertificateState.REVOKED) {
            throw new ValidationException("Already revoked");
        }
        
        // 3. Update state
        cert.setState(CertificateState.REVOKED);
        cert.setRevokedAt(Instant.now());
        cert.setRevocationReason(reason);
        
        // 4. Save
        Certificate saved = certificateRepository.save(cert);
        
        // 5. Log event
        CertificateEventHistory event = 
            new CertificateEventHistory();
        event.setUuid(UUID.randomUUID());
        event.setCertificate(saved);
        event.setEvent("REVOKED");
        event.setEventTimestamp(Instant.now());
        event.setExtraData(Map.of(
            "reason", reason.name(),
            "actor", getCurrentUser()
        ));
        // (save event...)
        
        // 6. Notify async
        rabbitTemplate.convertAndSend(
            "certificate-events",
            Map.of(
                "event", "CERTIFICATE_REVOKED",
                "certificateUuid", saved.getUuid(),
                "reason", reason,
                "revokedAt", saved.getRevokedAt()
            ));
        
        return saved;
    }
}
```

---

# 7. PERSISTÊNCIA: Índices e Performance

## 7.1 Índices Críticos (PostgreSQL)

```sql
-- Certificate lookups by serial (UNIQUE, frequent)
CREATE UNIQUE INDEX idx_cert_serial 
    ON certificate(serial_number);
-- Impact: 1000x faster than full scan

-- Full-text search on subject
CREATE INDEX idx_cert_subject_fts 
    ON certificate USING GIN(
        to_tsvector('english', subject)
    );
-- Query: SELECT * FROM certificate WHERE to_tsvector(...) @@ plainto_tsquery(...);

-- Expiry searches
CREATE INDEX idx_cert_valid_to 
    ON certificate(valid_to DESC);
-- Query: SELECT * FROM certificate WHERE valid_to BETWEEN ? AND ?;

-- State filtering
CREATE INDEX idx_cert_state 
    ON certificate(state);

-- Foreign key lookups (JOIN performance)
CREATE INDEX idx_cert_ra_profile 
    ON certificate(ra_profile_uuid);

-- Compound index for "WHERE state=X AND ra_profile=Y"
CREATE INDEX idx_cert_state_ra_profile 
    ON certificate(state, ra_profile_uuid);
-- Replaces 2 index scans with 1 index range scan
```

## 7.2 Query Performance Anti-Patterns

```java
// ❌ BAD: N+1 query problem
@Service
public class BadService {
    public List<Long> getBadData() {
        List<Certificate> certs = 
            certificateRepository.findAll();  // Query 1
        
        for (Certificate cert : certs) {
            String raName = cert.getRaProfile().getName();  // Query 2, 3, ..., N
        }
    }
}

// ✅ GOOD: Use JOIN FETCH para eager load
@Repository
public interface CertificateRepository 
        extends JpaRepository<Certificate, UUID> {
    
    @Query("""
        SELECT c FROM Certificate c
        JOIN FETCH c.raProfile
        WHERE c.state = 'ACTIVE'
    """)
    List<Certificate> findAllActiveWithProfile();
}

// ✅ GOOD: Use @EntityGraph
@Repository
public interface CertificateRepository 
        extends JpaRepository<Certificate, UUID> {
    
    @EntityGraph(attributePaths = {"raProfile", "groups"})
    List<Certificate> findAll();
}
```

---

# 8. CONCLUSÃO: Por Que Este Design de Domain Model?

O domain model do CZERTAINLY representa **~15 anos de PKI experience** condensado em 65 entidades bem-estruturadas. Cada decisão reflete trade-offs técnicos reais:

1. **65 Entities**: Não é "over-engineered"—reflete realmente complexidade de PKI
2. **UUID vs Serial**: Permite distribuição horizontal
3. **JSONB Attributes**: Customização sem schema inflation
4. **Hierarquia Base**: DRY—avoided duplicate audit/identification columns
5. **QueryDSL**: Type-safe queries com compile-time validation
6. **Event Sourcing Ready**: CertificateEventHistory permite auditoria completa
7. **M:M Relationships**: Groups permitem flexibilidade máxima
8. **Cascade + Orphan Removal**: Garbage collection automático
9. **PQC Support**: Future-ready (FALCON, Dilithium, SPHINCS+)

Este não é um DB simplista—é foundational para operação de PKI à scale.

