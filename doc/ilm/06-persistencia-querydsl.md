# 6. PERSISTÊNCIA: 59 Repositórios + QueryDSL Type-Safe

## 6.1 Arquitetura de Persistência - Visão Estratégica

### Camadas de Persistência

```
┌─────────────────────────────────────────┐
│ JPA Entities (65 classes)               │
│ @Entity: Certificate, Key, Profile...   │
│ • Lifecycle callbacks (@PrePersist)     │
│ • Lazy/Eager loading strategies         │
│ • JSONB columns para dados dinâmicos     │
└─────────────────┬───────────────────────┘
                  │
        ORM Layer (Hibernate)
                  │
┌─────────────────▼───────────────────────┐
│ Spring Data JPA Repositories (59)       │
│ • CrudRepository (CRUD ops)             │
│ • QueryDslPredicateExecutor (dynamic)   │
│ • Custom @Query methods                 │
└─────────────────┬───────────────────────┘
                  │
        QueryDSL Type-Safe Queries
                  │
┌─────────────────▼───────────────────────┐
│ QueryDSL API (generated Q* classes)     │
│ • QCertificate, QKey, QRaProfile        │
│ • Predicate building (BooleanBuilder)   │
│ • No string-based SQL injection risk     │
└─────────────────┬───────────────────────┘
                  │
        JDBC + Connection Pool
                  │
┌─────────────────▼───────────────────────┐
│ PostgreSQL 14+ Database                 │
│ • 65 Tables with constraints             │
│ • Indexes for performance               │
│ • JSONB support                         │
└─────────────────────────────────────────┘
```

### Trade-offs: ORM vs Raw SQL

| Aspecto | Hibernate ORM | QueryDSL | Raw SQL |
|---------|---|---|---|
| **Type Safety** | ✅ @ compile-time | ✅ Via Q* classes | ❌ Runtime |
| **Performance** | ⚠️ Lazy loading overhead | ✅ Optimized | ✅ Full control |
| **Complex Joins** | ❌ N+1 problem | ✅ Single query | ✅ Explicit |
| **Flexibility** | ⚠️ Limited | ✅ Full SQL | ✅ Full |

**CZERTAINLY Decision**: Hibernate + QueryDSL (melhor balanço)

---

## 6.2 Hibernate Configuration - Production-Ready

### application.yml

```yaml
spring:
  jpa:
    hibernate:
      # Não usar ddl-auto: create/update em produção!
      # Usar Flyway para migrations
      ddl-auto: none
      
    open-in-view: false  # ❌ NÃO abrir session para views
    show-sql: false      # ❌ Log SQL só em debug
    
    properties:
      hibernate:
        # Database dialect
        dialect: org.hibernate.dialect.PostgreSQL14Dialect
        
        # Performance tuning
        jdbc:
          batch_size: 20        # Insert/update batches
          fetch_size: 50        # Select fetch size
          use_get_generated_keys: true
          use_streams_for_binary: true
          
        # DDL generation
        use_sql_comments: true  # Legibilidade
        format_sql: true
        
        # Connection pool
        generate_statistics: false  # Overhead!
        
  datasource:
    hikari:
      maximum-pool-size: 20     # Conexões máximas (prod: 10-20)
      minimum-idle: 5           # Warm connections
      connection-timeout: 30000  # 30s timeout (network issues)
      idle-timeout: 600000      # 10min idle before close
      max-lifetime: 1800000     # 30min max connection lifetime
      auto-commit: false
```

###EntityManager Configuration

```java
@Configuration
public class HibernateConfiguration {
    
    /**
     * LocalContainerEntityManagerFactoryBean = Proprietary do Spring
     * Configuração fine-grained do Hibernate
     */
    @Bean
    public LocalContainerEntityManagerFactoryBean entityManagerFactory(
            DataSource dataSource,
            Environment environment) {
        
        LocalContainerEntityManagerFactoryBean factory = 
            new LocalContainerEntityManagerFactoryBean();
        
        factory.setDataSource(dataSource);
        factory.setPackagesToScan("com.czertainly.core.dao.entity");
        factory.setJpaVendorAdapter(new HibernateJpaVendorAdapter());
        
        Properties jpaProperties = new Properties();
        jpaProperties.put("hibernate.dialect", "org.hibernate.dialect.PostgreSQL14Dialect");
        jpaProperties.put("hibernate.jdbc.batch_size", "20");
        jpaProperties.put("hibernate.order_inserts", "true");
        jpaProperties.put("hibernate.order_updates", "true");
        
        factory.setJpaProperties(jpaProperties);
        
        return factory;
    }
}
```

---

## 6.3 JPA Entities - JSONB & Complex Mappings

### Base Entity Classes

```java
@MappedSuperclass
@EntityListeners(AuditingEntityListener.class)
public abstract class Audited implements Serializable {
    
    @CreatedBy
    @Column(name = "created_by", updatable = false, length = 255)
    private String createdBy;
    
    @CreatedDate
    @Column(name = "created_at", updatable = false)
    private LocalDateTime createdAt;
    
    @LastModifiedBy
    @Column(name = "updated_by", length = 255)
    private String updatedBy;
    
    @LastModifiedDate
    @Column(name = "updated_at")
    private LocalDateTime updatedAt;
}

@MappedSuperclass
public abstract class UniquelyIdentifiedAndAudited extends Audited {
    
    @Id
    @GeneratedValue(generator = "UUID")
    @GenericGenerator(name = "UUID", strategy = "uuid2")
    @Column(name = "uuid", nullable = false, updatable = false)
    private UUID uuid;
    
    @Version
    private Long version;  // Optimistic locking
}
```

### Certificate Entity - Real World Example

```java
@Entity
@Table(name = "certificate", indexes = {
    @Index(name = "idx_cert_subject", columnList = "subject"),
    @Index(name = "idx_cert_serial", columnList = "serial_number", unique = true),
    @Index(name = "idx_cert_state", columnList = "state"),
    @Index(name = "idx_cert_valid_to", columnList = "valid_to")
})
@DynamicInsert
@DynamicUpdate
public class Certificate extends UniquelyIdentifiedAndAudited {
    
    // =============== X.509 Metadata ===============
    
    @Column(name = "subject", length = 500, nullable = false)
    private String subject;  // CN=example.com,O=Organization
    
    @Column(name = "issuer", length = 500, nullable = false)
    private String issuer;
    
    @Column(name = "serial_number", unique = true, nullable = false)
    private String serialNumber;
    
    @Column(name = "fingerprint_sha256", length = 64)
    private String fingerprintSha256;
    
    // =============== Validity ===============
    
    @Column(name = "valid_from")
    private Instant validFrom;
    
    @Column(name = "valid_to")
    private Instant validTo;
    
    // =============== State Machine ===============
    
    @Enumerated(EnumType.STRING)
    @Column(name = "state", nullable = false, length = 50)
    private CertificateState state;  // VALID, REVOKED, EXPIRED
    
    @Column(name = "revocation_reason")
    private String revocationReason;
    
    @Column(name = "revocation_timestamp")
    private Instant revocationTimestamp;
    
    // =============== Binary Content ===============
    
    @Column(name = "certificate_content", columnDefinition = "bytea")
    private byte[] certificateContent;
    
    // =============== JSONB Attributes ===============
    
    /**
     * JSONB storage para dados dinâmicos
     * 
     * Vantagens:
     * - Sem migration para novos atributos
     * - Indexável: CREATE INDEX idx_attr ON certificate USING GIN(attributes)
     * - Queryável: SELECT * FROM certificate WHERE attributes @> '{"key":"value"}'
     */
    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "attributes", columnDefinition = "jsonb")
    private Map<String, Object> attributes = new HashMap<>();
    
    // =============== Relationships ===============
    
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "source_location_uuid")
    private Location sourceLocation;
    
    @OneToMany(mappedBy = "certificate", cascade = CascadeType.ALL)
    private Set<CertificateChain> certificateChains = new HashSet<>();
    
    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(
        name = "certificate_ra_profile",
        joinColumns = @JoinColumn(name = "certificate_uuid"),
        inverseJoinColumns = @JoinColumn(name = "ra_profile_uuid")
    )
    private Set<RaProfile> usedInProfiles = new HashSet<>();
}
```

---

## 6.4 QueryDSL - Type-Safe Dynamic Queries

### Q* Classes - Auto-generated

**Maven Plugin** (`pom.xml`):

```xml
<plugin>
    <groupId>com.mysema.maven</groupId>
    <artifactId>apt-maven-plugin</artifactId>
    <version>1.1.3</version>
    <configuration>
        <processor>com.querydsl.apt.jpa.JPAAnnotationProcessor</processor>
        <outputDirectory>target/generated-sources/java</outputDirectory>
    </configuration>
    <executions>
        <execution>
            <phase>generate-sources</phase>
            <goals>
                <goal>process</goal>
            </goals>
        </execution>
    </executions>
</plugin>
```

**Output**: Gera `target/generated-sources/java/com/czertainly/core/dao/entity/QCertificate.java`

```java
public class QCertificate extends EntityPathBase<Certificate> {
    
    public static final QCertificate certificate = new QCertificate("certificate");
    
    public final StringPath subject = createString("subject");
    public final StringPath issuer = createString("issuer");
    public final StringPath serialNumber = createString("serialNumber");
    public final DateTimePath<Instant> validFrom = createDateTime("validFrom", Instant.class);
    public final DateTimePath<Instant> validTo = createDateTime("validTo", Instant.class);
    public final EnumPath<CertificateState> state = createEnum("state", CertificateState.class);
}
```

### Dynamic Query Building

```java
@Service
@Transactional(readOnly = true)
public class CertificateService {
    
    @Autowired
    private CertificateRepository certificateRepository;
    
    /**
     * Busca dinâmica sem string-based SQL
     */
    public Page<CertificateDto> search(
            CertificateSearchCriteria criteria, 
            Pageable pageable) {
        
        QCertificate qCert = QCertificate.certificate;
        BooleanBuilder predicate = new BooleanBuilder();
        
        // Filtro 1: Subject (case-insensitive)
        if (StringUtils.hasText(criteria.getSubject())) {
            predicate.and(
                qCert.subject.containsIgnoreCase(criteria.getSubject())
            );
        }
        
        // Filtro 2: Estado
        if (criteria.getState() != null) {
            predicate.and(qCert.state.eq(criteria.getState()));
        }
        
        // Filtro 3: Data range
        if (criteria.getValidFromStart() != null) {
            predicate.and(qCert.validFrom.goe(criteria.getValidFromStart()));
        }
        if (criteria.getValidFromEnd() != null) {
            predicate.and(qCert.validFrom.loe(criteria.getValidFromEnd()));
        }
        
        // Filtro 4: Expiração em X dias
        if (criteria.getExpiringInDays() != null) {
            Instant expiryDate = Instant.now().plus(
                Duration.ofDays(criteria.getExpiringInDays())
            );
            predicate.and(qCert.validTo.between(Instant.now(), expiryDate));
        }
        
        return certificateRepository.findAll(
            predicate,
            pageable.withSort(Sort.by("validTo").ascending())
        ).map(this::toDto);
    }
}
```

---

## 6.5 Repository Layer - 59 Implementations
  <configuration>
    <processor>com.querydsl.apt.jpa.JPAAnnotationProcessor</processor>
  </configuration>
  <executions>
    <execution>
      <goals>
        <goal>process</goal>
      </goals>
    </execution>
  </executions>
</plugin>
```

**Gera**: QEntity classes (QCertificate, QCryptographicKey, QRaProfile, etc) em target/generated-sources

---

## 6.2 Security-Aware Repository Base

### SecurityFilterRepository

```java
public interface SecurityFilterRepository<T, ID> extends 
        CrudRepository<T, ID>,
        QuerydslPredicateExecutor<T>,
        QuerydslBinderCustomizer<QEntity> {
    
    /**
     * Fornece row-level security via @SQLRestriction
     * Exemplo: WHERE owned_by = current_user
     */
}

@Entity
@Table(name = "certificate")
@SQLRestriction("owner_uuid = CAST(? AS UUID)")  // Placeholder
public class Certificate extends UniquelyIdentifiedAndAudited {
    // ...
}
```

---

## 6.3 Certificate Repositories (5 Classes)

### CertificateRepository

```java
@Repository
public interface CertificateRepository extends 
        SecurityFilterRepository<Certificate, UUID> {
    
    /**
     * Find by serial number
     * Used during import/discovery
     */
    Optional<Certificate> findBySerialNumber(String serialNumber);
    
    /**
     * Find by subject DN
     * Used for certificate lookup by subject
     */
    List<Certificate> findBySubjectContainingIgnoreCase(String subject);
    
    /**
     * Find by issuer DN
     */
    List<Certificate> findByIssuerContainingIgnoreCase(String issuer);
    
    /**
     * Find expired certificates
     * (validity period check)
     */
    @Query("SELECT c FROM Certificate c WHERE c.validTo < CURRENT_TIMESTAMP AND c.state = 'ACTIVE'")
    List<Certificate> findExpiredCertificates();
    
    /**
     * Find expiring certificates (within N days)
     */
    @Query("SELECT c FROM Certificate c WHERE c.validTo BETWEEN CURRENT_DATE AND CURRENT_DATE + :days")
    Page<Certificate> findExpiringCertificates(int days, Pageable pageable);
    
    /**
     * Find certificates by RA profile
     */
    Page<Certificate> findByRaProfileUuid(UUID raProfileUuid, Pageable pageable);
    
    /**
     * Find revoked certificates
     */
    @Query("SELECT c FROM Certificate c WHERE c.state = 'REVOKED' AND c.raProfile.uuid = :raUuid")
    List<Certificate> findRevokedCertificatesByRaProfile(@Param("raUuid") UUID raUuid);
    
    /**
     * Find by validity date range
     */
    List<Certificate> findByValidFromBetween(LocalDateTime from, LocalDateTime to);
    
    /**
     * Find archived certificates (for cleanup)
     */
    @Query("SELECT c FROM Certificate c WHERE c.state = 'ARCHIVED' AND c.updatedAt < :date")
    List<Certificate> findArchivedCertificates(LocalDateTime date);
    
    /**
     * Find by state
     */
    Page<Certificate> findByStateOrderByValidToDesc(
            CertificateState state, 
            Pageable pageable);
}
```

### CertificateRequestRepository

```java
@Repository
public interface CertificateRequestRepository extends 
        SecurityFilterRepository<CertificateRequest, UUID> {
    
    /**
     * Find pending requests
     */
    Page<CertificateRequest> findByStatusOrderBySubmittedAtDesc(
            RequestStatus status,
            Pageable pageable);
    
    /**
     * Find requests by RA profile
     */
    Page<CertificateRequest> findByRaProfileUuid(
            UUID raProfileUuid,
            Pageable pageable);
    
    /**
     * Find requests older than date
     * (for cleanup/archival)
     */
    @Query("SELECT cr FROM CertificateRequest cr WHERE cr.submittedAt < :date AND cr.status IN ('APPROVED', 'REJECTED')")
    List<CertificateRequest> findProcessedRequestsBefore(@Param("date") LocalDateTime date);
}
```

### CertificateLocationRepository

```java
@Repository
public interface CertificateLocationRepository extends 
        CrudRepository<CertificateLocation, UUID> {
    
    /**
     * Find locations containing specific certificate
     */
    List<CertificateLocation> findByCertificateUuid(UUID certificateUuid);
    
    /**
     * Find certificates in location
     */
    List<CertificateLocation> findByLocationUuid(UUID locationUuid);
}
```

### CertificateEventHistoryRepository

```java
@Repository
public interface CertificateEventHistoryRepository extends 
        CrudRepository<CertificateEventHistory, UUID> {
    
    /**
     * Find events for certificate
     */
    List<CertificateEventHistory> findByCertificateUuidOrderByEventTimestampDesc(
            UUID certificateUuid);
    
    /**
     * Count events by type
     */
    Map<EventType, Long> countByEventType();
}
```

---

## 6.4 Cryptographic Key Repositories (4 Classes)

### CryptographicKeyRepository

```java
@Repository
public interface CryptographicKeyRepository extends 
        SecurityFilterRepository<CryptographicKey, UUID> {
    
    /**
     * Find keys by name
     */
    List<CryptographicKey> findByNameContainingIgnoreCaseOrderByCreatedDateDesc(
            String name);
    
    /**
     * Find keys by type (RSA, EC, AES, FALCON, etc)
     */
    Page<CryptographicKey> findByKeyType(
            KeyType keyType,
            Pageable pageable);
    
    /**
     * Find keys by state (ACTIVE, COMPROMISED, DESTROYED)
     */
    Page<CryptographicKey> findByState(
            KeyState state,
            Pageable pageable);
    
    /**
     * Find keys by algorithm
     */
    List<CryptographicKey> findByAlgorithm(Algorithm algorithm);
    
    /**
     * Find PQC keys (for CZERTAINLY's PQC support)
     */
    @Query("SELECT k FROM CryptographicKey k WHERE k.isPQC = true")
    List<CryptographicKey> findPQCKeys();
    
    /**
     * Find keys by entity provider
     * (for HSM-backed keys)
     */
    List<CryptographicKey> findByEntityInstanceReferenceUuid(
            UUID entityInstanceReferenceUuid);
    
    /**
     * Find compromised keys
     * (security alert use-case)
     */
    @Query("SELECT k FROM CryptographicKey k WHERE k.state = 'COMPROMISED' AND k.deactivationDate IS NULL")
    List<CryptographicKey> findCompromisedKeysNotDeactivated();
}
```

### CryptographicKeyItemRepository

```java
@Repository
public interface CryptographicKeyItemRepository extends 
        CrudRepository<CryptographicKeyItem, UUID> {
    
    /**
     * Find all formats of a key
     */
    List<CryptographicKeyItem> findByCryptographicKeyUuid(UUID keyUuid);
    
    /**
     * Find specific format
     */
    Optional<CryptographicKeyItem> findByCryptographicKeyUuidAndFormat(
            UUID keyUuid,
            KeyFormat format);
}
```

### CryptographicKeyEventHistoryRepository

```java
@Repository
public interface CryptographicKeyEventHistoryRepository extends 
        CrudRepository<CryptographicKeyEventHistory, UUID> {
    
    /**
     * Find audit trail for key
     */
    List<CryptographicKeyEventHistory> findByCryptographicKeyUuidOrderByEventTimestampDesc(
            UUID keyUuid);
}
```

### SecretRepository

```java
@Repository
public interface SecretRepository extends 
        SecurityFilterRepository<Secret, UUID> {
    
    /**
     * Find secrets by vault profile
     */
    List<Secret> findByVaultProfileUuid(UUID vaultProfileUuid);
}
```

---

## 6.5 Profile Repositories (8 Classes)

### RaProfileRepository

```java
@Repository
public interface RaProfileRepository extends 
        SecurityFilterRepository<RaProfile, UUID> {
    
    /**
     * Find by name (unique)
     */
    Optional<RaProfile> findByName(String name);
    
    /**
     * Find by connector
     * (show all profiles for a CA connector)
     */
    List<RaProfile> findByConnectorUuid(UUID connectorUuid);
    
    /**
     * Find enabled profiles
     */
    List<RaProfile> findByEnabled(boolean enabled);
    
    /**
     * Find profiles with ACME protocol configured
     */
    @Query("SELECT r FROM RaProfile r WHERE r.acmeUrl IS NOT NULL")
    List<RaProfile> findWithAcmeEnabled();
    
    /**
     * Find profiles with SCEP protocol configured
     */
    @Query("SELECT r FROM RaProfile r WHERE r.scepUrl IS NOT NULL")
    List<RaProfile> findWithScepEnabled();
    
    /**
     * Find profiles with CMP protocol configured
     */
    @Query("SELECT r FROM RaProfile r WHERE r.cmpUrl IS NOT NULL")
    List<RaProfile> findWithCmpEnabled();
}
```

### AcmeProfileRepository, ScepProfileRepository, CmpProfileRepository

```java
@Repository
public interface AcmeProfileRepository extends 
        CrudRepository<AcmeProfile, UUID> {
    
    Optional<AcmeProfile> findByRaProfileUuid(UUID raProfileUuid);
}

@Repository
public interface ScepProfileRepository extends 
        CrudRepository<ScepProfile, UUID> {
    
    Optional<ScepProfile> findByRaProfileUuid(UUID raProfileUuid);
}

@Repository
public interface CmpProfileRepository extends 
        CrudRepository<CmpProfile, UUID> {
    
    Optional<CmpProfile> findByRaProfileUuid(UUID raProfileUuid);
}
```

### TokenProfileRepository, VaultProfileRepository, ApprovalProfileRepository

```java
@Repository
public interface TokenProfileRepository extends 
        SecurityFilterRepository<TokenProfile, UUID> {
    
    List<TokenProfile> findByTokenInstanceReferenceUuid(
            UUID tokenInstanceReferenceUuid);
}

@Repository
public interface VaultProfileRepository extends 
        SecurityFilterRepository<VaultProfile, UUID> {
    
    Optional<VaultProfile> findByName(String name);
}

@Repository
public interface ApprovalProfileRepository extends 
        SecurityFilterRepository<ApprovalProfile, UUID> {
    
    Optional<ApprovalProfile> findByName(String name);
}
```

---

## 6.6 Access Control Repositories (6 Classes)

### GroupRepository

```java
@Repository
public interface GroupRepository extends 
        SecurityFilterRepository<Group, UUID> {
    
    /**
     * Find by name (unique)
     */
    Optional<Group> findByName(String name);
    
    /**
     * Find groups containing certificate
     */
    @Query("SELECT g FROM Group g JOIN g.certificates c WHERE c.uuid = :certificateUuid")
    List<Group> findByCertificateUuid(@Param("certificateUuid") UUID certificateUuid);
}
```

### LocationRepository

```java
@Repository
public interface LocationRepository extends 
        SecurityFilterRepository<Location, UUID> {
    
    /**
     * Find by name
     */
    Optional<Location> findByName(String name);
    
    /**
     * Find by entity provider
     */
    List<Location> findByEntityInstanceReferenceUuid(
            UUID entityInstanceReferenceUuid);
    
    /**
     * Find locations containing certificate
     */
    @Query("SELECT l FROM Location l JOIN l.certificates c WHERE c.uuid = :certificateUuid")
    List<Location> findByCertificateUuid(@Param("certificateUuid") UUID certificateUuid);
}
```

### EntityInstanceReferenceRepository

```java
@Repository
public interface EntityInstanceReferenceRepository extends 
        SecurityFilterRepository<EntityInstanceReference, UUID> {
    
    /**
     * Find by connector
     */
    List<EntityInstanceReference> findByConnectorUuid(UUID connectorUuid);
    
    /**
     * Find by kind (HSM, VAULT, FILE, etc)
     */
    List<EntityInstanceReference> findByKind(String kind);
}
```

### AuthorityInstanceReferenceRepository, ConnectorRepository, CredentialRepository

```java
@Repository
public interface AuthorityInstanceReferenceRepository extends 
        SecurityFilterRepository<AuthorityInstanceReference, UUID> {
    
    List<AuthorityInstanceReference> findByConnectorUuid(UUID connectorUuid);
}

@Repository
public interface ConnectorRepository extends 
        SecurityFilterRepository<Connector, UUID> {
    
    Optional<Connector> findByUrlAndVersion(String url, String version);
    
    List<Connector> findAll();
}

@Repository
public interface CredentialRepository extends 
        SecurityFilterRepository<Credential, UUID> {
    
    List<Credential> findByConnectorUuid(UUID connectorUuid);
}
```

---

## 6.7 Workflow & Rules Repositories (10 Classes)

### RuleRepository

```java
@Repository
public interface RuleRepository extends 
        SecurityFilterRepository<Rule, UUID> {
    
    Optional<Rule> findByName(String name);
    
    /**
     * Find rules by trigger
     */
    @Query("SELECT r FROM Rule r JOIN r.triggers t WHERE t.uuid = :triggerUuid")
    List<Rule> findByTriggerUuid(@Param("triggerUuid") UUID triggerUuid);
}
```

### ConditionRepository, ActionRepository, ExecutionRepository, TriggerRepository, TriggerAssociationRepository

```java
@Repository
public interface ConditionRepository extends 
        CrudRepository<Condition, UUID> {
    
    List<Condition> findByRuleUuid(UUID ruleUuid);
}

@Repository
public interface ActionRepository extends 
        SecurityFilterRepository<Action, UUID> {
    
    List<Action> findByRuleUuid(UUID ruleUuid);
    
    @Query("SELECT a FROM Action a WHERE a.actionType = :actionType")
    List<Action> findByActionType(@Param("actionType") ActionType actionType);
}

@Repository
public interface ExecutionRepository extends 
        CrudRepository<Execution, UUID> {
    
    /**
     * Find executions of an action
     */
    Page<Execution> findByActionUuid(UUID actionUuid, Pageable pageable);
    
    /**
     * Find failed executions
     */
    @Query("SELECT e FROM Execution e WHERE e.status = 'FAILED'")
    Page<Execution> findFailedExecutions(Pageable pageable);
}

@Repository
public interface TriggerRepository extends 
        SecurityFilterRepository<Trigger, UUID> {
    
    /**
     * Find triggers by type
     */
    List<Trigger> findByTriggerType(TriggerType triggerType);
}

@Repository
public interface TriggerAssociationRepository extends 
        CrudRepository<TriggerAssociation, UUID> {
    
    List<TriggerAssociation> findByTriggerUuid(UUID triggerUuid);
}
```

### ApprovalRepository, ApprovalStepRepository

```java
@Repository
public interface ApprovalRepository extends 
        SecurityFilterRepository<Approval, UUID> {
    
    /**
     * Find pending approvals
     */
    Page<Approval> findByStatus(ApprovalStatus status, Pageable pageable);
    
    /**
     * Find pending approvals for current user
     */
    @Query("SELECT a FROM Approval a WHERE a.status = 'PENDING' AND a.assignee = :userId")
    Page<Approval> findPendingForUser(@Param("userId") String userId, Pageable pageable);
    
    /**
     * Find expired approvals
     */
    @Query("SELECT a FROM Approval a WHERE a.expirationDate < CURRENT_TIMESTAMP AND a.status = 'PENDING'")
    List<Approval> findExpiredApprovals();
}

@Repository
public interface ApprovalStepRepository extends 
        CrudRepository<ApprovalStep, UUID> {
    
    List<ApprovalStep> findByApprovalUuid(UUID approvalUuid);
}
```

---

## 6.8 Compliance & Notification Repositories (8 Classes)

### ComplianceProfileRepository

```java
@Repository
public interface ComplianceProfileRepository extends 
        SecurityFilterRepository<ComplianceProfile, UUID> {
    
    Optional<ComplianceProfile> findByName(String name);
    
    /**
     * Find compliance profiles for certificate
     */
    @Query("SELECT cp FROM ComplianceProfile cp JOIN cp.certificates c WHERE c.uuid = :certificateUuid")
    List<ComplianceProfile> findByCertificateUuid(@Param("certificateUuid") UUID certificateUuid);
}
```

### ComplianceInternalRuleRepository

```java
@Repository
public interface ComplianceInternalRuleRepository extends 
        CrudRepository<ComplianceInternalRule, UUID> {
    
    List<ComplianceInternalRule> findByComplianceProfileUuid(
            UUID complianceProfileUuid);
}
```

### NotificationInstanceReferenceRepository, NotificationInstanceMappedAttributesRepository

```java
@Repository
public interface NotificationInstanceReferenceRepository extends 
        SecurityFilterRepository<NotificationInstanceReference, UUID> {
    
    List<NotificationInstanceReference> findByConnectorUuid(UUID connectorUuid);
}

@Repository
public interface NotificationInstanceMappedAttributesRepository extends 
        CrudRepository<NotificationInstanceMappedAttributes, UUID> {
    
    List<NotificationInstanceMappedAttributes> findByNotificationInstanceReferenceUuid(
            UUID notificationInstanceReferenceUuid);
}
```

### AuditLogRepository

```java
@Repository
public interface AuditLogRepository extends 
        CrudRepository<AuditLog, Long> {
    
    /**
     * Find logs by module
     */
    Page<AuditLog> findByModule(
            Module module,
            Pageable pageable);
    
    /**
     * Find logs by operation
     */
    Page<AuditLog> findByOperation(
            Operation operation,
            Pageable pageable);
    
    /**
     * Find logs by actor
     */
    Page<AuditLog> findByActorName(
            String actorName,
            Pageable pageable);
    
    /**
     * Find logs by timestamp range
     */
    Page<AuditLog> findByTimestampBetweenOrderByTimestampDesc(
            Instant start,
            Instant end,
            Pageable pageable);
    
    /**
     * Find logs by result
     */
    Page<AuditLog> findByOperationResult(
            OperationResult result,
            Pageable pageable);
}
```

### SettingRepository, AttributeDefinitionRepository, CustomOidEntryRepository

```java
@Repository
public interface SettingRepository extends 
        CrudRepository<Setting, UUID> {
    
    Optional<Setting> findByKey(String key);
}

@Repository
public interface AttributeDefinitionRepository extends 
        CrudRepository<AttributeDefinition, UUID> {
    
    List<AttributeDefinition> findByContentType(ContentType contentType);
}

@Repository
public interface CustomOidEntryRepository extends 
        CrudRepository<CustomOidEntry, UUID> {
    
    Optional<CustomOidEntry> findByOid(String oid);
}
```

---

## 6.9 QueryDSL Usage Examples

### Complex Query with Predicates

```java
// Service using CertificateRepository
@Transactional(readOnly = true)
public Page<Certificate> advancedSearch(
        String subject,
        String issuer,
        CertificateState state,
        LocalDateTime validFromStart,
        LocalDateTime validFromEnd,
        Pageable pageable) {
    
    QCertificate qCert = QCertificate.certificate;
    BooleanBuilder predicate = new BooleanBuilder();
    
    // Build WHERE clause dynamically
    if (subject != null && !subject.isEmpty()) {
        predicate.and(qCert.subject.containsIgnoreCase(subject));
    }
    
    if (issuer != null && !issuer.isEmpty()) {
        predicate.and(qCert.issuer.containsIgnoreCase(issuer));
    }
    
    if (state != null) {
        predicate.and(qCert.state.eq(state));
    }
    
    if (validFromStart != null && validFromEnd != null) {
        predicate.and(qCert.validFrom.between(validFromStart, validFromEnd));
    }
    
    // Execute query
    return certificateRepository.findAll(predicate, pageable);
}
```

### Aggregation Query

```java
@Transactional(readOnly = true)
public DashboardStatistics getDashboardStats() {
    
    QCertificate qCert = QCertificate.certificate;
    QCryptographicKey qKey = QCryptographicKey.cryptographicKey;
    
    long totalCertificates = queryFactory
        .selectFrom(qCert)
        .fetchCount();
    
    long activeCertificates = queryFactory
        .selectFrom(qCert)
        .where(qCert.state.eq(CertificateState.ACTIVE))
        .fetchCount();
    
    long expiringCertificates = queryFactory
        .selectFrom(qCert)
        .where(qCert.validTo.between(
            LocalDateTime.now(),
            LocalDateTime.now().plusDays(30)
        ))
        .fetchCount();
    
    // Group by algorithm
    Map<String, Long> byAlgorithm = queryFactory
        .selectFrom(qKey)
        .groupBy(qKey.algorithm)
        .transform(
            GroupBy.groupBy(qKey.algorithm).as(qKey.count())
        );
    
    return DashboardStatistics.builder()
        .totalCertificates(totalCertificates)
        .activeCertificates(activeCertificates)
        .expiringCertificates(expiringCertificates)
        .keysByAlgorithm(byAlgorithm)
        .build();
}
```

---

## 6.10 Database Optimization

### Indexes Created by Flyway

```sql
-- Certificate indexes
CREATE INDEX idx_certificate_subject ON certificate(subject);
CREATE INDEX idx_certificate_issuer ON certificate(issuer);
CREATE INDEX idx_certificate_serial ON certificate(serial_number);
CREATE INDEX idx_certificate_state ON certificate(state);
CREATE INDEX idx_certificate_valid_to ON certificate(valid_to DESC);
CREATE INDEX idx_certificate_ra_profile ON certificate(ra_profile_uuid);
CREATE INDEX idx_certificate_created_at ON certificate(created_at DESC);

-- Key indexes
CREATE INDEX idx_key_type ON cryptographic_key(key_type);
CREATE INDEX idx_key_state ON cryptographic_key(state);
CREATE INDEX idx_key_name ON cryptographic_key(name);

-- Foreign key indexes (auto-created by PostgreSQL)
-- Audit log indexes
CREATE INDEX idx_audit_log_timestamp ON audit_log(timestamp DESC);
CREATE INDEX idx_audit_log_module ON audit_log(module);
CREATE INDEX idx_audit_log_actor ON audit_log(actor_name);
CREATE INDEX idx_audit_log_operation ON audit_log(operation);

-- JSONB indexes (for attribute queries)
CREATE INDEX idx_ra_profile_attributes ON ra_profile USING GIN(attributes);
```

### Connection Pooling

**HikariCP Configuration** (via application.yml):
```yaml
datasource:
  hikari:
    maximum-pool-size: 20
    minimum-idle: 5
    connection-timeout: 30000 ms
    idle-timeout: 600000 ms
    max-lifetime: 1800000 ms
    auto-commit: true
```

---

## Resumo de Repositórios

| Categoria | Repos | Total |
|-----------|-------|-------|
| **Certificate** | CertificateRepository, CertificateRequestRepository, CertificateLocationRepository, CertificateEventHistoryRepository, CrlRepository | 5 |
| **Cryptographic** | CryptographicKeyRepository, CryptographicKeyItemRepository, CryptographicKeyEventHistoryRepository, SecretRepository | 4 |
| **Profiles** | RaProfileRepository, AcmeProfileRepository, ScepProfileRepository, CmpProfileRepository, TokenProfileRepository, VaultProfileRepository, ApprovalProfileRepository, NotificationProfileRepository | 8 |
| **Access Control** | GroupRepository, LocationRepository, EntityInstanceReferenceRepository, AuthorityInstanceReferenceRepository, ConnectorRepository, CredentialRepository | 6 |
| **Workflow** | RuleRepository, ConditionRepository, ActionRepository, ExecutionRepository, TriggerRepository, TriggerAssociationRepository, ApprovalRepository, ApprovalStepRepository | 8 |
| **Compliance** | ComplianceProfileRepository, ComplianceInternalRuleRepository, NotificationInstanceReferenceRepository, NotificationInstanceMappedAttributesRepository | 4 |
| **Audit & Config** | AuditLogRepository, SettingRepository, AttributeDefinitionRepository, CustomOidEntryRepository, ScheduledJobRepository | 5 |

**Total**: 59 Repositories com suporte completo a QueryDSL, paginação, sorting e custom queries

