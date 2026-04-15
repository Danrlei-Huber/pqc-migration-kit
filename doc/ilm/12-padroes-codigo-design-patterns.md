# 12. DESIGN PATTERNS & BEST PRACTICES

## 12.1 Repository Pattern

### Definition
Abstrata access to data sources, allowing services to query without knowing persistence details.

### Implementation in CZERTAINLY

```java
// Base interface with Row-Level Security (RLS)
@RepositoryRestResource(exported = false)
public interface SecurityFilterRepository<T, ID> extends 
        CrudRepository<T, ID>,
        QuerydslPredicateExecutor<T> {
    
    // Provides parameterized queries + full-text search
}

// Concrete implementation
@Repository
public interface CertificateRepository extends 
        SecurityFilterRepository<Certificate, UUID> {
    
    // Query methods (Spring auto-implements)
    Certificate findBySerialNumber(String serialNumber);
    
    Page<Certificate> findByState(CertificateState state, Pageable pageable);
    
    // QueryDSL support
    @Query("SELECT c FROM Certificate c WHERE " +
           "c.subject ILIKE %:subject% AND " +
           "c.validTo > CURRENT_TIMESTAMP")
    List<Certificate> findActiveBySubject(@Param("subject") String subject);
    
    // Native SQL
    @Query(value = "SELECT * FROM certificate WHERE " +
           "extract(year from valid_to) = :year", 
           nativeQuery = true)
    List<Certificate> findExpiringInYear(@Param("year") int year);
}

// Usage in Service
@Service
public class CertificateService {
    
    @Autowired
    private CertificateRepository certificateRepository;
    
    public Certificate getCertificateBySerial(String serial) {
        // Repository handles SQL + caching
        return certificateRepository.findBySerialNumber(serial);
    }
    
    public Page<Certificate> searchCertificates(
            CertificateSearchCriteria criteria,
            Pageable pageable) {
        
        // QueryDSL dynamic query builder
        BooleanBuilder predicate = new BooleanBuilder();
        
        if (criteria.getSubject() != null) {
            predicate.and(QCertificate.certificate.subject
                .containsIgnoreCase(criteria.getSubject()));
        }
        
        if (criteria.getState() != null) {
            predicate.and(QCertificate.certificate.state
                .eq(criteria.getState()));
        }
        
        if (criteria.getValidBefore() != null) {
            predicate.and(QCertificate.certificate.validTo
                .before(criteria.getValidBefore()));
        }
        
        return certificateRepository.findAll(predicate, pageable);
    }
}
```

### Benefits
- **Decoupling**: Services don't know about JPA/SQL
- **Testability**: Easy to mock repositories
- **Performance**: Pagination, lazy loading, indexes
- **Security**: Row-level filtering via @SQLRestriction

---

## 12.2 Service Locator & Dependency Injection

### Service Layer Organization

```java
// Base service interface
public interface CryptoOperationService {
    SignatureResponse sign(SignRequest request);
    VerifyResponse verify(VerifyRequest request);
}

// Local signing implementation
@Service
@Transactional
public class LocalCryptoOperationService 
        implements CryptoOperationService {
    
    private final CryptographicKeyRepository keyRepository;
    private final CryptographicOperationAuditService auditService;
    
    @Autowired
    public LocalCryptoOperationService(
            CryptographicKeyRepository keyRepository,
            CryptographicOperationAuditService auditService) {
        this.keyRepository = keyRepository;
        this.auditService = auditService;
    }
    
    @Override
    public SignatureResponse sign(SignRequest request) {
        CryptographicKey key = keyRepository
            .findByUuid(request.getKeyUuid())
            .orElseThrow(() -> new NotFoundException("Key not found"));
        
        byte[] signature = localJceProvider.sign(
            key,
            request.getDataToSign()
        );
        
        auditService.logSigningOperation(key, signature.length);
        
        return new SignatureResponse(signature, "LOCAL");
    }
    
    @Override
    public VerifyResponse verify(VerifyRequest request) {
        // Implementation
    }
}

// HSM signing implementation (pluggable)
@Service
@ConditionalOnProperty(name = "hsm.enabled", havingValue = "true")
public class HsmCryptoOperationService 
        implements CryptoOperationService {
    
    private final HsmConnectorClient hsmClient;
    
    @Override
    public SignatureResponse sign(SignRequest request) {
        // Delegates to HSM connector
        byte[] signature = hsmClient.sign(
            request.getKeyUuid(),
            request.getDataToSign()
        );
        
        return new SignatureResponse(signature, "HSM");
    }
    
    @Override
    public VerifyResponse verify(VerifyRequest request) {
        // HSM verification
    }
}

// Factory/Router service
@Service
public class CryptoOperationDispatcher {
    
    @Autowired
    private LocalCryptoOperationService localService;
    
    @Autowired(required = false)
    private HsmCryptoOperationService hsmService;
    
    public SignatureResponse sign(SignRequest request) {
        
        CryptographicKey key = getKey(request.getKeyUuid());
        
        // Route to appropriate implementation
        if (key.getStorageLocation() == StorageLocation.HSM && hsmService != null) {
            return hsmService.sign(request);
        } else {
            return localService.sign(request);
        }
    }
}

// Usage in Controller
@RestController
@RequestMapping("/api/v2/sign")
public class SignatureController {
    
    @Autowired
    private CryptoOperationDispatcher dispatcher;
    
    @PostMapping
    public SignatureResponse sign(@RequestBody SignRequest request) {
        return dispatcher.sign(request);
    }
}
```

### Benefits
- **Modularity**: Service implementations are pluggable
- **Configuration-driven**: Enable/disable via properties
- **Easy testing**: Mock each implementation separately
- **Extensibility**: Add new implementations without modifying dispatcher

---

## 12.3 Observer Pattern: Event Publishing

### Implementation with Spring Events

```java
// Domain Event (immutable)
@Data
public class CertificateIssuedEvent extends ApplicationEvent {
    
    private final UUID certificateUuid;
    private final String serialNumber;
    private final String subject;
    private final LocalDateTime issuedAt;
    private final LocalDateTime expiresAt;
    private final UUID raProfileUuid;
    
    public CertificateIssuedEvent(
            Object source,
            Certificate certificate) {
        
        super(source);
        this.certificateUuid = certificate.getUuid();
        this.serialNumber = certificate.getSerialNumber();
        this.subject = certificate.getSubject();
        this.issuedAt = certificate.getCreatedAt();
        this.expiresAt = certificate.getValidTo();
        this.raProfileUuid = certificate.getRaProfile().getUuid();
    }
}

// Publisher
@Service
@Transactional
public class CertificateService {
    
    @Autowired
    private ApplicationEventPublisher eventPublisher;
    
    public Certificate issueCertificate(CertificateRequest request) {
        
        Certificate cert = new Certificate();
        // ... populate certificate
        
        Certificate saved = certificateRepository.save(cert);
        
        // Publish event
        CertificateIssuedEvent event = new CertificateIssuedEvent(this, saved);
        eventPublisher.publishEvent(event);
        
        return saved;
    }
}

// Synchronous Listeners
@Component
public class CertificateIssuedEventListener {
    
    @EventListener
    @Transactional
    public void onCertificateIssued(CertificateIssuedEvent event) {
        
        // Update statistics
        CertificateStatistics stats = new CertificateStatistics();
        stats.setCertificateCount(stats.getCertificateCount() + 1);
        // ... save stats
        
        logger.info("Certificate issued: {}", event.getSerialNumber());
    }
}

// Asynchronous Listeners (RabbitMQ)
@Component
public class CertificateIssuedEventAsyncListener {
    
    @Autowired
    private NotificationService notificationService;
    
    @EventListener
    @Async("taskExecutor")
    public void onCertificateIssuedAsync(CertificateIssuedEvent event) 
            throws Exception {
        
        // Long-running operations
        notificationService.notifyAdminOfIssuance(event);
        // ... other async work
    }
}

// RabbitMQ Producer (triggered by event listener)
@Component
public class CertificateEventProducer {
    
    @Autowired
    private RabbitTemplate rabbitTemplate;
    
    @EventListener(CertificateIssuedEvent.class)
    public void publishCertificateIssuedEvent(CertificateIssuedEvent event) {
        
        rabbitTemplate.convertAndSend(
            "certificate-exchange",
            "certificate.issued",
            new CertificateIssuedMessage(
                event.getCertificateUuid(),
                event.getSerialNumber(),
                event.getIssuedAt()
            ),
            m -> {
                m.getMessageProperties().setCorrelationId(
                    UUID.randomUUID().toString()
                );
                m.getMessageProperties().setTimestamp(System.currentTimeMillis());
                return m;
            }
        );
    }
}

// Consumer (in listener container)
@Component
public class CertificateEventConsumer {
    
    @RabbitListener(queues = "certificate-issuance-queue")
    public void handleCertificateIssuedMessage(
            CertificateIssuedMessage message,
            Channel channel,
            @Header(AmqpHeaders.DELIVERY_TAG) long deliveryTag) 
            throws IOException {
        
        try {
            // Process message (indexing, compliance, archival)
            processIssuedCertificate(message);
            
            // Acknowledge to RabbitMQ
            channel.basicAck(deliveryTag, false);
            
        } catch (Exception e) {
            logger.error("Error processing certificate issuance", e);
            
            // Negative acknowledge (retry)
            channel.basicNack(deliveryTag, false, true);
        }
    }
}
```

### Benefits
- **Decoupling**: Publishers don't know about listeners
- **Flexibility**: Add new listeners without changing publisher
- **Async workflows**: Long operations don't block main thread
- **Audit trail**: All events can be logged/archived

---

## 12.4 Factory Pattern: Object Creation

### Abstract Factory for Cryptographic Operations

```java
// Interface
public interface CryptographicAlgorithmFactory {
    KeyPairGenerator createKeyGenerator(KeyType keyType, int keySize);
    Signature createSigner(KeyType keyType, String algorithm);
    Cipher createCipher(String algorithm);
}

// Concrete implementations
@Component
public class RsaAlgorithmFactory implements CryptographicAlgorithmFactory {
    
    @Override
    public KeyPairGenerator createKeyGenerator(KeyType keyType, int keySize) {
        
        if (keyType != KeyType.RSA) {
            throw new IllegalArgumentException("Expected RSA key type");
        }
        
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");
            kpg.initialize(keySize);
            return kpg;
        } catch (Exception e) {
            throw new CryptographyException("Failed to create RSA generator", e);
        }
    }
    
    @Override
    public Signature createSigner(KeyType keyType, String algorithm) {
        try {
            // algorithm: "SHA256withRSA", "SHA512withRSA", etc.
            return Signature.getInstance(algorithm, "BC");
        } catch (Exception e) {
            throw new CryptographyException("Failed to create signer", e);
        }
    }
    
    @Override
    public Cipher createCipher(String algorithm) {
        try {
            return Cipher.getInstance(algorithm, "BC");
        } catch (Exception e) {
            throw new CryptographyException("Failed to create cipher", e);
        }
    }
}

// PQC factory
@Component
@ConditionalOnProperty(name = "pqc.enabled", havingValue = "true")
public class PqcAlgorithmFactory implements CryptographicAlgorithmFactory {
    
    @Override
    public KeyPairGenerator createKeyGenerator(KeyType keyType, int keySize) {
        
        try {
            String algorithm = switch(keyType) {
                case FALCON -> "Falcon";
                case DILITHIUM -> "Dilithium";
                case SPHINCS_PLUS -> "SPHINCS+";
                default -> throw new IllegalArgumentException("Not PQC: " + keyType);
            };
            
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(algorithm, "BC");
            kpg.initialize(keySize);
            return kpg;
            
        } catch (Exception e) {
            throw new CryptographyException(
                "Failed to create PQC generator for " + keyType, e);
        }
    }
    
    // ... other implementations
}

// Factory locator
@Service
public class CryptographicAlgorithmFactoryLocator {
    
    @Autowired
    private Map<String, CryptographicAlgorithmFactory> factories;
    
    public CryptographicAlgorithmFactory getFactory(KeyType keyType) {
        
        // Route to appropriate factory based on key type
        if (keyType.isPqc()) {
            return factories.get("pqcAlgorithmFactory");
        } else if (keyType == KeyType.RSA) {
            return factories.get("rsaAlgorithmFactory");
        } else if (keyType == KeyType.EC) {
            return factories.get("ecAlgorithmFactory");
        } else {
            throw new UnsupportedOperationException("Key type: " + keyType);
        }
    }
    
    public KeyPair generateKeyPair(KeyType keyType, int keySize) {
        
        CryptographicAlgorithmFactory factory = getFactory(keyType);
        KeyPairGenerator kpg = factory.createKeyGenerator(keyType, keySize);
        return kpg.generateKeyPair();
    }
}

// Usage in Service
@Service
public class CryptographicKeyGenerationService {
    
    @Autowired
    private CryptographicAlgorithmFactoryLocator factoryLocator;
    
    public CryptographicKey generateKey(KeyGenerationRequest request) {
        
        KeyPair keyPair = factoryLocator.generateKeyPair(
            request.getKeyType(),
            request.getKeySize()
        );
        
        CryptographicKey key = new CryptographicKey();
        key.setKeyType(request.getKeyType());
        key.setPublicKey(keyPair.getPublic().getEncoded());
        key.setPrivateKey(keyPair.getPrivate().getEncoded());
        
        return keyRepository.save(key);
    }
}
```

### Benefits
- **Encapsulation**: Factory hides complexity of object creation
- **Configurability**: Add/remove implementations via @Bean
- **Type safety**: Factory ensures correct algorithm combination
- **Extensibility**: New key types don't break existing code

---

## 12.5 Transaction Management Best Practices

### Transactional Boundaries

```java
@Service
@Slf4j
public class CertificateIssuanceService {
    
    @Autowired
    private CertificateRepository certificateRepository;
    
    @Autowired
    private RaProfileService raProfileService;
    
    @Autowired
    private ApplicationEventPublisher eventPublisher;
    
    /**
     * Public API - outer transaction boundary
     */
    @Transactional(rollbackFor = Exception.class)
    public Certificate issueCertificateWithApproval(UUID approvalUuid) {
        
        Approval approval = getAndValidateApproval(approvalUuid);
        
        try {
            
            // 1. Fetch CA connector
            CaConnector connector = approval.getRaProfile()
                .getCaConnector();
            
            // 2. Call connector (external call - outside transaction)
            CertResponse certResponse = issueViaConnector(connector);
            
            // 3. Save certificate
            Certificate cert = new Certificate();
            cert.setSerialNumber(certResponse.getSerialNumber());
            cert.setSubject(certResponse.getSubject());
            cert.setValidFrom(certResponse.getValidFrom());
            cert.setValidTo(certResponse.getValidTo());
            
            Certificate saved = certificateRepository.save(cert);
            
            // 4. Update approval status
            updateApprovalStatus(approval, ApprovalStatus.APPROVED);
            
            // 5. Publish event (will trigger async listeners)
            eventPublisher.publishEvent(
                new CertificateIssuedEvent(this, saved)
            );
            
            logger.info("Certificate issued: {}", saved.getSerialNumber());
            
            return saved;
            
        } catch (ConnectorException e) {
            logger.error("Failed to issue certificate via connector", e);
            throw new OperationFailedException("Connector error", e);
            
        } catch (Exception e) {
            logger.error("Unexpected error during issuance", e);
            throw new RuntimeException("Issuance failed", e);  // Triggers rollback
        }
    }
    
    /**
     * Internal method - separate transaction
     * (needed because connector call is not transactional)
     */
    @Transactional(readOnly = true)
    private Approval getAndValidateApproval(UUID approvalUuid) {
        
        Approval approval = approvalRepository
            .findByUuid(approvalUuid)
            .orElseThrow(() -> new NotFoundException("Approval not found"));
        
        if (approval.getStatus() != ApprovalStatus.PENDING) {
            throw new ValidationException(
                "Approval is not pending: " + approval.getStatus());
        }
        
        return approval;
    }
    
    /**
     * External call - NO transactional boundary
     * (REST call should not be inside transaction)
     */
    private CertResponse issueViaConnector(CaConnector connector) 
            throws Exception {
        
        // Connector call (could fail, could timeout)
        // No transaction active to prevent locks
        return connector.issueCertificate(...);
    }
    
    /**
     * Internal update - separate transaction
     */
    @Transactional
    private void updateApprovalStatus(
            Approval approval,
            ApprovalStatus newStatus) {
        
        approval.setStatus(newStatus);
        approval.setApprovedAt(LocalDateTime.now());
        
        approvalRepository.save(approval);
    }
}

/**
 * Configuration for transaction attributes
 */
@Configuration
public class TransactionConfiguration implements TransactionManagementConfigurer {
    
    @Bean
    public PlatformTransactionManager transactionManager(
            EntityManagerFactory emf) {
        return new JpaTransactionManager(emf);
    }
    
    @Override
    public TransactionAttributeSource transactionAttributeSource() {
        
        // Custom transaction interceptor
        NameMatchTransactionAttributeSource source = 
            new NameMatchTransactionAttributeSource();
        
        source.addTransactionalMethod("*", 
            new DefaultTransactionAttribute(
                TransactionDefinition.PROPAGATION_REQUIRED
            )
        );
        
        source.addTransactionalMethod("*Query*",
            new DefaultTransactionAttribute(
                TransactionDefinition.PROPAGATION_REQUIRED,
                TransactionDefinition.ISOLATION_READ_COMMITTED
            ) {
                {
                    setReadOnly(true);
                }
            }
        );
        
        return source;
    }
}
```

### Best Practices
- Keep transactions short (don't include I/O)
- Separate read-only transactions
- Use appropriate isolation levels
- Avoid nested transactions when possible
- Log transaction boundaries
- Handle rollback scenarios explicitly

---

## 12.6 Anti-Patterns to Avoid

### 1. N+1 Query Problem

```java
// ❌ BAD: Triggers 1 query for list + N queries for lazy-loaded associations
@Service
public class BadCertificateService {
    
    public List<CertificateDto> listCertificatesWithProfiles() {
        List<Certificate> certs = certificateRepository.findAll();
        
        return certs.stream()
            .map(cert -> new CertificateDto(
                cert.getUuid(),
                cert.getSerialNumber(),
                cert.getRaProfile().getName()  // ← LAZY LOAD QUERY per cert!
            ))
            .collect(Collectors.toList());
    }
}

// ✅ GOOD: Single query with JOIN FETCH
@Repository
public interface CertificateRepository extends SecurityFilterRepository<Certificate, UUID> {
    
    @Query("SELECT c FROM Certificate c " +
           "JOIN FETCH c.raProfile rp " +
           "WHERE c.enabled = true")
    List<Certificate> findAllWithProfiles();
}

@Service
public class GoodCertificateService {
    
    public List<CertificateDto> listCertificatesWithProfiles() {
        return certificateRepository.findAllWithProfiles()
            .stream()
            .map(CertificateDto::from)
            .collect(Collectors.toList());
    }
}
```

### 2. Lazy Loading Outside Transaction

```java
// ❌ BAD: LazyInitializationException - entity detached from session
@Service
public class BadApprovalService {
    
    @Transactional
    public Approval getApproval(UUID uuid) {
        return approvalRepository.findByUuid(uuid).orElse(null);
    }
    
    // Later, in controller or another layer
    public void processApproval(Approval approval) {
        approval.getApprovalSteps().forEach(step -> {  // ← Exception!
            // step.getName();
        });
    }
}

// ✅ GOOD: Trigger loading inside transaction
@Service
public class GoodApprovalService {
    
    @Transactional(readOnly = true)
    public ApprovalDetailedDto getApprovalWithDetails(UUID uuid) {
        
        Approval approval = approvalRepository
            .findByUuid(uuid)
            .orElse(null);
        
        if (approval == null) {
            return null;
        }
        
        // Access lazy collections while still in transaction
        return new ApprovalDetailedDto(
            approval.getUuid(),
            approval.getApprovalProfile().getName(),
            approval.getApprovalSteps()  // ← Already loaded
        );
    }
}
```

### 3. Synchronous External Calls in Transaction

```java
// ❌ BAD: Holds DB connection while waiting for HTTP response
@Service
@Transactional
public class BadConnectorCallService {
    
    public Certificate issueCertificate(String csr) {
        
        Certificate cert = new Certificate();
        // ... populate
        
        Certificate saved = certificateRepository.save(cert);
        
        // 30s HTTP call while holding DB connection!
        ConnectorResponse response = connectorClient.sign(csr);
        
        cert.setSignature(response.getSignature());
        
        return certificateRepository.save(cert);
    }
}

// ✅ GOOD: Separate transaction boundaries
@Service
public class GoodConnectorCallService {
    
    @Transactional
    public Certificate issueCertificate(String csr) {
        
        Certificate cert = new Certificate();
        Certificate saved = certificateRepository.save(cert);
        
        // Release transaction before HTTP call
        return saved;
    }
    
    @Async
    public CompletableFuture<CertificateSignedEvent> signCertificateAsync(
            UUID certUuid,
            String csr) {
        
        try {
            // HTTP call OUTSIDE transaction
            ConnectorResponse response = connectorClient.sign(csr);
            
            // Update in separate transaction
            updateCertificateSignature(certUuid, response.getSignature());
            
            return CompletableFuture.completedFuture(
                new CertificateSignedEvent(certUuid)
            );
            
        } catch (Exception e) {
            return CompletableFuture.failedFuture(e);
        }
    }
    
    @Transactional
    private void updateCertificateSignature(UUID certUuid, byte[] signature) {
        
        Certificate cert = certificateRepository
            .findByUuid(certUuid)
            .orElseThrow();
        
        cert.setSignature(signature);
        certificateRepository.save(cert);
    }
}
```

### 4. Exception Swallowing

```java
// ❌ BAD: Silently ignores errors
@Service
public class BadErrorHandlingService {
    
    public void processConnector(Connector connector) {
        try {
            connectorClient.healthCheck(connector.getUrl());
        } catch (Exception e) {
            logger.debug("Error ignored");  // ← Problem hidden!
        }
    }
}

// ✅ GOOD: Explicit error handling
@Service
public class GoodErrorHandlingService {
    
    public void processConnector(Connector connector) {
        try {
            connectorClient.healthCheck(connector.getUrl());
            
        } catch (TimeoutException e) {
            logger.warn("Connector health check timed out: {}", connector.getName());
            updateConnectorStatus(connector, HealthStatus.TIMEOUT);
            
        } catch (ConnectionException e) {
            logger.error("Connector unreachable: {}", connector.getName(), e);
            updateConnectorStatus(connector, HealthStatus.DOWN);
            publishConnectorDownEvent(connector);
            
        } catch (Exception e) {
            logger.error("Unexpected error during health check", e);
            throw new SystemException("Health check failed", e);
        }
    }
}
```

---

## Resumo de Padrões

| Padrão | Propósito | Uso no CZERTAINLY |
|--------|----------|---|
| **Repository** | Data access abstraction | All repositories extend SecurityFilterRepository |
| **Observer** | Decoupled event handling | Domain events + RabbitMQ publishers |
| **Factory** | Object creation encapsulation | Crypto algorithm factories |
| **Service Locator** | Dynamic service selection | Local vs HSM crypto dispatcher |
| **Transactional Boundaries** | Data consistency | Read-only, separate transactions for I/O |
| **Strategy** | Pluggable algorithms | PQC, RSA, EC signing |
| **Decorator** | Cross-cutting concerns | @Transactional, @Async, @Cacheable |
| **Builder** | Complex object creation | DTOs, search criteria |

**Anti-patterns avoided**:
❌ N+1 queries → JOIN FETCH
❌ Lazy loading outside transaction → Eager load or separate transaction
❌ Sync calls in transaction → Async @Transactional boundaries
❌ Exception swallowing → Explicit error handling

