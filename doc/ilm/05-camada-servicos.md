# 5. CAMADA DE SERVIÇOS: 55+ Implementações & Padrões Transacionais

## 5.1 Visão Estratégica da Camada de Serviços

### Responsabilidades (Separation of Concerns)

```
┌──────────────────────────────────────────────────────────┐
│ API LAYER (Controllers)                                 │
│ • HTTP request/response                                 │
│ • Exception mapping to HTTP status                       │
│ • DTO conversion                                         │
└────────────────────┬─────────────────────────────────────┘
                     │
        Calls Services (Transactional)
                     │
┌────────────────────▼─────────────────────────────────────┐
│ SERVICE LAYER                                           │
├──────────────────────────────────────────────────────────┤
│ • Business logic (Certificate lifecycle)                │
│ • Transactional boundaries (@Transactional)              │
│ • Cross-service coordination (CACall A then B)          │
│ • Data validation & enrichment                          │
│ • Event publishing (Kafka, RabbitMQ)                    │
└────────────────────┬─────────────────────────────────────┘
                     │
        Delegates to Repositories (Data Access)
                     │
┌────────────────────▼─────────────────────────────────────┐
│ PERSISTENCE LAYER                                       │
│ • Repository interfaces (JPA)                           │
│ • QueryDSL predicates                                   │
│ • Caching strategy                                      │
└────────────────────┬─────────────────────────────────────┘
                     │
        JDBC
                     │
┌────────────────────▼─────────────────────────────────────┐
│ DATABASE                                                │
│ • Tables, indexes, constraints                          │
└──────────────────────────────────────────────────────────┘
```

### 55 Services - Categorização

**Certificate Management (8 services)**:
- CertificateService, CertificateChainService, CertificateContent, CertificateProfileService, etc

**Connector & Plugin System (6 services)**:
- ConnectorService, EndpointService, FunctionGroupService, AttributeService, etc

**Cryptographic Operations (7 services)**:
- KeyService, KeyManagementService, CryptoOperationService, PqcKeyService, etc

**RA Profiles & Authorities (5 services)**:
- RaProfileService, AuthorityInstanceService, AuthorityInstanceReferenceService, etc

**Compliance & Audit (4 services)**:
- AuditLogService, ComplianceProfileService, ComplianceCheckService, etc

**Security & Authentication (3 services)**:
- SecurityService, CredentialService, AccessControlService

**Messaging & Integration (4 services)**:
- NotificationService, DiscoveryService, WebhookService, EventPublisher

**Protocol Handlers (5 services)**:
- AcmeService, ScepService, CmpService, CertificateIssuanceService, etc

**Infrastructure (3 services)**:
- HealthCheckService, MetricsService, TimerService

---

## 5.2 Padrões Transacionais Profundos

### Padrão 1: Simple Transaction (Read-Only)

**Caso de uso**: Buscar certificado

```java
@Service
@Transactional  // READ_WRITE por default
@Slf4j
public class CertificateService {
    
    @Autowired
    private CertificateRepository certificateRepository;
    
    /**
     * @Transactional(readOnly = true) ativa otimizações:
     * - Hibernate não rastreia mudanças
     * - DB usa isolation level READ_COMMITTED (vs REPEATABLE_READ)
     * - Sem flush para DB (apenas SELECT)
     * 
     * Performance: ~5-10ms de overhead por transação
     */
    @Transactional(readOnly = true)
    public CertificateDto getCertificateById(UUID uuid) {
        log.info("Fetching certificate: {}", uuid);
        
        Certificate cert = certificateRepository.findById(uuid)
            .orElseThrow(() -> new ResourceNotFoundException(
                "Certificate not found: " + uuid
            ));
        
        return mapper.toDto(cert);
    }
}
```

### Padrão 2: Write Transaction with Atomicity

**Caso de uso**: Revogar certificado (muda estado + cria audit log)

```java
@Service
@Transactional  // Atomicity: tudo ou nada
@Slf4j
public class CertificateService {
    
    @Autowired
    private CertificateRepository certificateRepository;
    
    @Autowired
    private AuditLogService auditLogService;
    
    /**
     * Fluxo atomic (tudo em 1 transação):
     * 1. Busca certificado
     * 2. Valida estado (pode revogar?)
     * 3. Muda estado para REVOKED
     * 4. Cria audit log
     * 5. Salva tudo no BD
     * 
     * Se qualquer passo falhar: ROLLBACK automático!
     * 
     * Isolation: REPEATABLE_READ (default PostgreSQL)
     * - Garante que lê dados consistent durante transação
     */
    @Transactional
    public void revokeCertificate(UUID uuid, String reason) {
        
        // 1. Fetch (locks row: FOR UPDATE)
        Certificate cert = certificateRepository.findById(uuid)
            .orElseThrow();
        
        // 2. Validate
        if (cert.getState() == CertificateState.REVOKED) {
            throw new IllegalStateException("Already revoked");
        }
        
        // 3. Update state
        cert.setState(CertificateState.REVOKED);
        cert.setRevocationReason(reason);
        cert.setRevocationTimestamp(Instant.now());
        
        // 4. Save (Hibernate tracks dirty writes)
        certificateRepository.save(cert);
        
        // 5. Audit (on same transaction!)
        auditLogService.log(AuditEvent.builder()
            .module(Module.CERTIFICATE)
            .operation(Operation.REVOKE)
            .resourceId(uuid)
            .operationResult(OperationResult.SUCCESS)
            .additionalData("reason",reason)
            .build());
        
        // Transaction ends here: COMMIT
        log.info("Certificate {} revoked", uuid);
    }
}
```

**Garantias ACID**:
- **A** (Atomicity): Ambos updates ou nenhum
- **C** (Consistency): BD em estado válido antes/depois
- **I** (Isolation): Outras transações não veem estado intermediário
- **D** (Durability): Committed data não se perde em crash

### Padrão 3: Nested Transactions (Delegação entre Services)

**Caso de uso**: Emitir certificado (chamada a múltiplos services)

```java
@Service
@Transactional
@Slf4j
public class CertificateIssuanceService {
    
    @Autowired
    private CertificateService certificateService;
    
    @Autowired
    private KeyService keyService;
    
    @Autowired
    private RaProfileService raProfileService;
    
    @Autowired
    private NotificationService notificationService;
    
    /**
     * Fluxo de emissão (TRANSACTIONAL):
     * 
     * 1. RaProfile.issueCertificate()
     *    └─ Transaction BEGIN
     * 2. KeyService.generateKey()
     *    └─ (same transaction, não novo COMMIT)
     * 3. CertificateService.createCertificate()
     *    └─ (same transaction)
     * 4. NotificationService.notifyIssued()
     *    └─ (same transaction)
     * 5. Transaction END (COMMIT se tudo OK, ROLLBACK se erro)
     * 
     * PROBLEMA: Se NotificationService falha, tudo reverte!
     * SOLUÇÃO: Use @Transactional(propagation=REQUIRES_NEW)
     */
    @Transactional
    public CertificateDto issueCertificate(IssueCertificateRequest request) {
        
        log.info("Starting certificate issuance");
        
        // 1. Busca RA Profile
        RaProfile profile = raProfileService.findById(request.getProfileId());
        
        // 2. Gera chave privada
        KeyPair keyPair = keyService.generateKeyPair(
            request.getKeyAlgorithm(), 
            request.getKeyLength()
        );  // Mesmo BD: insert em cryptographic_key table
        
        // 3. Emite certificado
        Certificate certificate = certificateService.createCertificate(
            request, 
            Profile, 
            keyPair.getPublicKey()
        );  // Mesmo BD: insert em certificate table
        
        // 4. Notifica (ISOLADO - não interfere com rollback)
        notifyUserAsync(request, certificate);
        
        log.info("Certificate issued: {}", certificate.getId());
        
        // Transaction COMMIT aqui
        return mapper.toDto(certificate);
    }
    
    /**
     * Enviar email/SMS FORA da transação principal
     * Se email falha: não cancela certificado!
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void notifyUserAsync(IssueCertificateRequest request, Certificate cert) {
        try {
            notificationService.sendIssueNotification(request.getEmail(), cert);
        } catch (Exception e) {
            log.warn("Failed to notify user, but cert was issued", e);
            // Não relança: transação anterior já fez COMMIT
        }
    }
}
```

### Padrão 4: Propagation Strategy Trade-offs

| Tipo | Comportamento | Use Case|
|------|---|---|
| **REQUIRED** (default) | Participar da transação existente ou criar nova | 99% dos casos |
| **REQUIRES_NEW** | SEMPRE nova transação (suspend anterior) | Notifications, logging que não devem falhar |
| **SUPPORTS** | Participar se existir, senão executa sem transação | Operações que podem ser read-only |
| **NOT_SUPPORTED** | NUNCA em transação | Operações que não precisam atomicity |
| **NEVER** | Falha se em transação | Validações que devem ser stateless |

```java
@Service
public class NotificationService {
    
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void sendEmail(String recipient, String message) {
        // Esta transação é NOVA e INDEPENDENTE
        // Falha aqui NÃO afeta transaction anterior
    }
}

@Service
public class AuditService  {
    
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public void logEvent(AuditEvent event) {
        // Executa SEM transação (melhor performance p/ logging)
    }
}
```

### Padrão 5: Deadlock Prevention & Optimistic Locking

**Cenário**: 2 threads atualizam mesmo certificado simultaneamente

```java
@Entity
@Table(name = "certificate")
public class Certificate {
    
    /**
     * @Version alterna Optimistic Locking
     * PostgreSQL: increments version on UPDATE
     * 
     * Hibernate: lê version=1
     * UPDATE certificate SET state='REVOKED', version=2 
     *   WHERE id=abc AND version=1
     * 
     * Se alguém atualizou: versão!=1, UPDATE falha
     * Hibernate lança: ObjectOptimisticLockingFailureException
     */
    @Version
    private Long version;
}

@Service
public class CertificateService {
    
    @Transactional
    public void updateCertificate(UUID uuid, CertificateUpdateDto dto) {
        Certificate cert = repository.findById(uuid).orElseThrow();
        cert.setState(dto.getState());
        
        try {
            repository.save(cert);  // Pode lançar StaleObjectStateException
        } catch (OptimisticLockingFailureException e) {
            // Alguém modificou entre leitura e escrita
            // Retry ou notify user
            log.warn("Concurrent modification detected", e);
            throw new ConflictException("Certificate was modified by another user");
        }
    }
}
```

---

## 5.3 Certificate Management Services - Implementação Real

### CertificateService - Core Operations

**Arquivo**: `src/main/java/com/czertainly/core/service/CertificateService.java`

```java
@Service
@Transactional
@Slf4j
public class CertificateService {
    
    @Autowired
    private CertificateRepository certificateRepository;
    
    @Autowired
    private CertificateChainService certificateChainService;
    
    @Autowired
    private LocationService locationService;
    
    @Autowired
    private RaProfileService raProfileService;
    
    /**
     * LISTAR certificados com filtros dinâmicos e paginação
     * 
     * Query: GET /api/v2/certificates?subject=example&state=VALID&page=0&size=10
     * 
     * Implementação com QueryDSL (type-safe):
     * - Sem risco de SQL injection
     * - Autocomplete em IDE
     * - Predicados compostos
     */
    @Transactional(readOnly = true)
    public Page<CertificateDto> list(CertificateSearchCriteria criteria) {
        
        log.debug("Searching certificates: {}", criteria);
        
        QCertificate qCert = QCertificate.certificate;
        BooleanBuilder predicate = new BooleanBuilder();
        
        // Filtro 1: Subject (ignorar case)
        if (StringUtils.hasText(criteria.getSubject())) {
            predicate.and(qCert.subject.containsIgnoreCase(criteria.getSubject()));
        }
        
        // Filtro 2: Estado
        if (criteria.getState() != null) {
            predicate.and(qCert.state.eq(criteria.getState()));
        }
        
        // Filtro 3: Range de datas de validade
        if (criteria.getValidFromStart() != null && criteria.getValidFromEnd() != null) {
            predicate.and(
                qCert.validFrom.between(criteria.getValidFromStart(), criteria.getValidFromEnd())
            );
        }
        
        // Filtro 4: Owner (row-level security)
        String currentUser = extractCurrentUser();
        predicate.and(qCert.owner.eq(currentUser));
        
        Pageable pageable = PageRequest.of(
            criteria.getPageNumber(),
            criteria.getPageSize(),
            Sort.by("validFrom").descending()
        );
        
        return certificateRepository.findAll(predicate, pageable)
            .map(this::toDto);
    }
    
    /**
     * CRIAR novo certificado
     * 
     * Fluxo completo:
     * 1. Valida input (não pode estar vazio)
     * 2. Parseia X.509 certificate
     * 3. Extrai metadados (subject, issuer, validity)
     * 4. Busca location ou cria nova
     * 5. Salva no BD com audit log
     */
    @Transactional
    public CertificateDto create(CreateCertificateRequest request) {
        
        log.info("Creating certificate from base64 content");
        
        try {
            // 1. Decode base64
            byte[] certBytes = Base64.getDecoder().decode(request.getCertificateContent());
            
            // 2. Parse X.509
            X509Certificate x509 = parseX509(certBytes);
            
            // 3. Extract metadata
            String subject = x509.getSubjectX500Principal().getName();
            String issuer = x509.getIssuerX500Principal().getName();
            Date notBefore = x509.getNotBefore();
            Date notAfter = x509.getNotAfter();
            String serialNumber = x509.getSerialNumber().toString();
            
            // 4. Check if already exists
            Optional<Certificate> existing = certificateRepository.findBySerialNumber(serialNumber);
            if (existing.isPresent()) {
                throw new EntityAlreadyExistsException("Certificate already exists");
            }
            
            // 5. Create entity
            Certificate cert = new Certificate();
            cert.setSubject(subject);
            cert.setIssuer(issuer);
            cert.setValidFrom(notBefore.toInstant());
            cert.setValidTo(notAfter.toInstant());
            cert.setSerialNumber(serialNumber);
            cert.setState(CertificateState.VALID);
            cert.setRawContent(certBytes);
        return certificateRepository.findBySerialAndRaProfileUuid(
            serial, raProfileUuid
        );
    }
    
    /**
     * Revogar certificado
     */
    @Transactional(rollbackFor = Exception.class)
    @AuditLogged(module = Module.CERTIFICATE_MANAGEMENT, operation = Operation.REVOKE)
    public void revokeCertificate(
            UUID certificateUuid,
            RevocationReason reason,
            LocalDateTime revokedAt) {
        
        Certificate cert = certificateRepository
            .findById(certificateUuid)
            .orElseThrow(() -> new NotFoundException("Certificate not found"));
        
        cert.setState(CertificateState.REVOKED);
        cert.setRevocationReason(reason.toString());
        cert.setRevokedAt(revokedAt);
        
        certificateRepository.save(cert);
        
        // Publish event
        eventPublisher.publishEvent(new CertificateRevokedEvent(
            cert.getUuid(), reason
        ));
    }
    
    /**
     * Descobrir certificados (de location/entity provider)
     */
    @Transactional
    public void discoverCertificates(UUID locationUuid) {
        Location location = locationRepository
            .findById(locationUuid)
            .orElseThrow(() -> new NotFoundException("Location not found"));
        
        EntityInstanceReference entity = location.getEntityInstanceReference();
        
        // Call connector
        List<CertificateDiscoveryResult> discovered = 
            locationApiClient.discoverCertificates(entity, location.getAttributes());
        
        // Import discovered certificates
        discovered.forEach(result -> {
            Certificate cert = convertToCertificate(result);
            cert.getLocations().add(location);
            certificateRepository.save(cert);
        });
    }
    
    /**
     * Export certificado em múltiplos formatos
     */
    @Transactional(readOnly = true)
    public byte[] exportCertificate(UUID certificateUuid, ExportFormat format) {
        Certificate cert = certificateRepository
            .findById(certificateUuid)
            .orElseThrow(() -> new NotFoundException("Certificate not found"));
        
        if (format == ExportFormat.PEM) {
            return cert.getCertificateContent();  // Already PEM
        } else if (format == ExportFormat.DER) {
            return convertPemToDer(cert.getCertificateContent());
        } else if (format == ExportFormat.PKCS12) {
            return createPkcs12(cert);  // With private key if available
        }
        
        throw new IllegalArgumentException("Unsupported format: " + format);
    }
}
```

### CrlService (Certificate Revocation List)

```java
@Service
@Transactional
public class CrlService {
    
    /**
     * Gerar CRL para um RA Profile
     * (inclui certificados revogados)
     */
    @Transactional(readOnly = true)
    public byte[] generateCRL(UUID raProfileUuid) {
        
        RaProfile raProfile = raProfileRepository
            .findById(raProfileUuid)
            .orElseThrow(() -> new NotFoundException("RA Profile not found"));
        
        // Buscar certificados revogados para este RA
        List<Certificate> revokedCerts = certificateRepository
            .findRevokedCertificatesByRaProfile(raProfileUuid);
        
        // Build X.509 CRL
        X509CRLBuilder builder = buildCRL(raProfile);
        revokedCerts.forEach(cert -> {
            builder.addRevokedCertificate(
                new BigInteger(cert.getSerialNumber()),
                new Date(Timestamp.valueOf(cert.getRevokedAt()).getTime()),
                CRLReason.unspecified  // or extract from cert
            );
        });
        
        // Sign with CA
        X509CRL crl = builder.build(caPrivateKey, "SHA256withRSA");
        
        return crl.getEncoded();
    }
    
    /**
     * Validar status de certificado via CRL
     */
    @Transactional(readOnly = true)
    public CertificateStatus checkRevocationStatus(String serial) {
        
        Optional<Certificate> cert = certificateRepository
            .findBySerialNumber(serial);
        
        if (!cert.isPresent()) {
            return CertificateStatus.UNKNOWN;
        }
        
        if (cert.get().getState() == CertificateState.REVOKED) {
            return CertificateStatus.REVOKED;
        }
        
        return CertificateStatus.VALID;
    }
}
```

---

## 5.3 Cryptographic Key Services

### CryptographicKeyService

```java
@Service
@Transactional
public class CryptographicKeyService {
    
    @Autowired
    private CryptographicKeyRepository keyRepository;
    
    @Autowired
    private ConnectorService connectorService;
    
    /**
     * Gerar nova chave criptográfica
     * Pode ser local (JCE) ou delegado ao conector (HSM)
     */
    @Transactional
    public CryptographicKey generateKey(GenerateKeyRequest request) {
        
        CryptographicKey key = new CryptographicKey();
        key.setName(request.getName());
        key.setKeyType(request.getKeyType());  // RSA, EC, AES, FALCON, etc
        key.setKeySize(request.getKeySize());
        key.setAlgorithm(request.getAlgorithm());
        key.setState(KeyState.ACTIVE);
        
        if (request.isDelegateToConnector()) {
            // Delega ao conector (HSM)
            EntityInstanceReference entity = entityInstanceRepository
                .findById(request.getEntityInstanceReferenceUuid())
                .orElseThrow();
            
            key.setEntityInstanceReference(entity);
            
            // Call connector POST /operation
            GenerateKeyResponse response = connectorApiClient
                .generateKey(entity, request);
            
            // Armazenar public key
            CryptographicKeyItem publicKeyItem = new CryptographicKeyItem();
            publicKeyItem.setFormat(KeyFormat.X509);
            publicKeyItem.setContent(response.getPublicKeyContent());
            
            key.getItems().add(publicKeyItem);
            
        } else {
            // Gerar localmente
            KeyPair keyPair = generateKeyPairLocally(
                request.getKeyType(),
                request.getKeySize()
            );
            
            // Armazenar both public e private keys
            storeKeyItems(key, keyPair);
        }
        
        return keyRepository.save(key);
    }
    
    /**
     * Listar chaves com filtros
     */
    @Transactional(readOnly = true)
    public Page<CryptographicKey> listKeys(
            KeyType keyType,
            KeyState state,
            String name,
            Pageable pageable) {
        
        QCryptographicKey qKey = QCryptographicKey.cryptographicKey;
        BooleanBuilder predicate = new BooleanBuilder();
        
        if (keyType != null) {
            predicate.and(qKey.keyType.eq(keyType));
        }
        if (state != null) {
            predicate.and(qKey.state.eq(state));
        }
        if (name != null) {
            predicate.and(qKey.name.containsIgnoreCase(name));
        }
        
        return keyRepository.findAll(predicate, pageable);
    }
    
    /**
     * Buscar itens de uma chave (diferentes formatos)
     */
    @Transactional(readOnly = true)
    public List<CryptographicKeyItem> getKeyItems(UUID keyUuid) {
        return keyRepository.findById(keyUuid)
            .map(CryptographicKey::getItems)
            .orElseThrow(() -> new NotFoundException("Key not found"));
    }
}
```

### CryptographicOperationService (Sign/Verify)

```java
@Service
@Transactional
public class CryptographicOperationService {
    
    /**
     * Assinar dados com chave privada
     */
    @Transactional
    @AuditLogged(module = Module.CRYPTOGRAPHIC_OPERATIONS, operation = Operation.SIGN)
    public SignatureResponse sign(UUID keyUuid, SignatureRequest request) {
        
        CryptographicKey key = keyRepository.findById(keyUuid)
            .orElseThrow(() -> new NotFoundException("Key not found"));
        
        byte[] dataToSign = Base64.getDecoder().decode(request.getData());
        String hashAlgorithm = request.getHashAlgorithm();  // SHA-256, etc
        
        if (key.getEntityInstanceReference() != null) {
            // Delegate to HSM connector
            return connectorApiClient.sign(
                key.getEntityInstanceReference(),
                keyUuid,
                dataToSign,
                hashAlgorithm
            );
        } else {
            // Local signing
            PrivateKey privateKey = extractPrivateKey(key);
            
            Signature signature = Signature.getInstance(
                getSignatureAlgorithm(key.getAlgorithm(), hashAlgorithm)
            );
            signature.initSign(privateKey);
            signature.update(dataToSign);
            
            byte[] signedData = signature.sign();
            
            return new SignatureResponse(
                Base64.getEncoder().encodeToString(signedData)
            );
        }
    }
    
    /**
     * Verificar assinatura com chave pública
     */
    @Transactional(readOnly = true)
    public VerificationResponse verify(UUID keyUuid, VerificationRequest request) {
        
        CryptographicKey key = keyRepository.findById(keyUuid)
            .orElseThrow(() -> new NotFoundException("Key not found"));
        
        byte[] dataToVerify = Base64.getDecoder().decode(request.getData());
        byte[] signatureBytes = Base64.getDecoder().decode(request.getSignature());
        String hashAlgorithm = request.getHashAlgorithm();
        
        PublicKey publicKey = extractPublicKey(key);
        
        Signature signature = Signature.getInstance(
            getSignatureAlgorithm(key.getAlgorithm(), hashAlgorithm)
        );
        signature.initVerify(publicKey);
        signature.update(dataToVerify);
        
        boolean isValid = signature.verify(signatureBytes);
        
        return new VerificationResponse(isValid);
    }
    
    /**
     * Suport para PQC algorithms (FALCON, Dilithium, SPHINCS+)
     */
    @Transactional
    public SignatureResponse signWithPQC(UUID keyUuid, SignatureRequest request) {
        
        CryptographicKey key = keyRepository.findById(keyUuid)
            .orElseThrow(() -> new NotFoundException("Key not found"));
        
        if (!key.getIsPQC()) {
            throw new IllegalArgumentException("Key is not PQC");
        }
        
        byte[] dataToSign = Base64.getDecoder().decode(request.getData());
        
        // Use BouncyCastle PQC providers
        Signature signature = Signature.getInstance(
            getPQCSignatureAlgorithm(key.getPqcAlgorithm()),
            "BC"  // BouncyCastle
        );
        
        PrivateKey privateKey = extractPrivateKeyPQC(key);
        signature.initSign(privateKey);
        signature.update(dataToSign);
        
        byte[] signedData = signature.sign();
        
        return new SignatureResponse(
            Base64.getEncoder().encodeToString(signedData)
        );
    }
}
```

---

## 5.4 Profile Services

### RaProfileService

```java
@Service
@Transactional
public class RaProfileService {
    
    @Autowired
    private RaProfileRepository raProfileRepository;
    
    @Autowired
    private ConnectorService connectorService;
    
    @Autowired
    private AttributeEngine attributeEngine;
    
    /**
     * Criar RA Profile
     * Associa CA Connector + attributes
     */
    @Transactional
    public RaProfile createRaProfile(RaProfileRequest request) {
        
        RaProfile profile = new RaProfile();
        profile.setName(request.getName());
        profile.setDescription(request.getDescription());
        
        // Associate CA Connector
        Connector caConnector = connectorService.getConnector(
            request.getCaConnectorUuid()
        );
        profile.setCaConnector(caConnector);
        
        // Associate CA Instance
        AuthorityInstanceReference authority = 
            authorityInstanceService.getAuthorityInstance(
                request.getCaInstanceUuid()
            );
        profile.setAuthorityInstanceReference(authority);
        
        // Validate & Store Attributes
        List<RequestAttribute> attributes = 
            attributeEngine.validateAttributes(
                request.getAttributes(),
                caConnector.getUuid(),
                "CA"  // Function group
            );
        profile.setAttributes(attributes);
        
        return raProfileRepository.save(profile);
    }
    
    /**
     * Construir URLs dos protocolos (ACME, SCEP, CMP)
     */
    @Transactional(readOnly = true)
    public RaProfileUrls buildProfileUrls(UUID raProfileUuid) {
        
        RaProfile profile = raProfileRepository.findById(raProfileUuid)
            .orElseThrow();
        
        String baseUrl = "https://czertainly-core:8080/api";
        
        return RaProfileUrls.builder()
            .acmeUrl(baseUrl + "/acme/" + profile.getUuid())
            .scepUrl(baseUrl + "/scep/" + profile.getUuid())
            .cmpUrl(baseUrl + "/cmp/" + profile.getUuid())
            .build();
    }
}
```

### ComplianceProfileService

```java
@Service
@Transactional
public class ComplianceProfileService {
    
    /**
     * Validar certificado contra compliance profile
     */
    @Transactional(readOnly = true)
    public ComplianceStatus checkCompliance(
            UUID certificateUuid,
            UUID complianceProfileUuid) {
        
        Certificate cert = certificateRepository.findById(certificateUuid)
            .orElseThrow();
        
        ComplianceProfile profile = complianceProfileRepository
            .findById(complianceProfileUuid)
            .orElseThrow();
        
        List<ComplianceCheckResult> results = new ArrayList<>();
        
        // Check each rule in the profile
        for (Map<String, Object> rule : profile.getRules()) {
            ComplianceCheckResult result = evaluateRule(cert, rule);
            results.add(result);
        }
        
        // Aggregate results
        boolean allPassed = results.stream()
            .allMatch(r -> r.getStatus() == CheckStatus.PASS);
        
        return ComplianceStatus.builder()
            .overall(allPassed ? CheckStatus.PASS : CheckStatus.FAIL)
            .results(results)
            .build();
    }
    
    /**
     * Trigger compliance check via messaging
     */
    @Transactional
    public void triggerComplianceCheck(UUID certificateUuid) {
        
        // Publish event to RabbitMQ
        complianceProducer.publishComplianceCheckEvent(
            ComplianceCheckEvent.builder()
                .certificateUuid(certificateUuid)
                .timestamp(Instant.now())
                .build()
        );
    }
}
```

---

## 5.5 Integration & Connector Services

### ConnectorService

```java
@Service
@Transactional
public class ConnectorService {
    
    @Autowired
    private ConnectorRepository connectorRepository;
    
    @Autowired
    private ConnectorApiClient connectorApiClient;
    
    /**
     * Registrar novo conector (auto-registration via callback)
     */
    @Transactional
    public Connector registerConnector(ConnectorRegistrationRequest request) {
        
        Connector connector = new Connector();
        connector.setUrl(request.getUrl());
        connector.setVersion(request.getVersion());
        connector.setName(request.getName());
        
        // Test connectivity
        ConnectorInfoResponse info = connectorApiClient
            .getConnectorInfo(request.getUrl());
        
        connector.setDescription(info.getDescription());
        
        // Discover endpoints
        List<Endpoint> endpoints = discoverEndpoints(request.getUrl());
        connector.setEndpoints(endpoints);
        
        // Discover function groups
        Set<FunctionGroup> functionGroups = discoverFunctionGroups(request.getUrl());
        connector.setFunctionGroups(functionGroups);
        
        connector.setHealthStatus(HealthStatus.UP);
        connector.setHealthCheckTimestamp(LocalDateTime.now());
        
        return connectorRepository.save(connector);
    }
    
    /**
     * Verificar saúde do conector periodicamente
     */
    @Scheduled(fixedDelay = 300000)  // 5 minutos
    public void healthCheck() {
        
        List<Connector> connectors = connectorRepository.findAll();
        
        for (Connector connector : connectors) {
            try {
                boolean isHealthy = connectorApiClient
                    .isHealthy(connector.getUrl());
                
                connector.setHealthStatus(
                    isHealthy ? HealthStatus.UP : HealthStatus.DOWN
                );
                
            } catch (Exception e) {
                connector.setHealthStatus(HealthStatus.ERROR);
                logger.error("Connector health check failed", e);
            }
            
            connector.setHealthCheckTimestamp(LocalDateTime.now());
            connectorRepository.save(connector);
        }
    }
}
```

### CallbackService

```java
@Service
@Transactional
public class CallbackService {
    
    /**
     * Processar callbacks do conector
     * (Conector solicita validação de attributes, etc)
     */
    @Transactional
    public void handleConnectorCallback(ConnectorCallbackRequest request) {
        
        Connector connector = connectorRepository
            .findByUrl(request.getConnectorUrl())
            .orElseThrow();
        
        String callbackType = request.getCallbackType();
        
        if ("CONNECTOR_DISCOVERY_STATE".equals(callbackType)) {
            updateConnectorDiscoveryState(connector, request);
        } else if ("ATTRIBUTE_UPDATE".equals(callbackType)) {
            updateConnectorAttributes(connector, request);
        }
    }
}
```

---

## 5.6 Workflow & Automation Services

### RuleService

```java
@Service
@Transactional
public class RuleService {
    
    /**
     * Avaliar rule contra certificado
     * (usado para compliance, automation)
     */
    @Transactional(readOnly = true)
    public RuleEvaluationResult evaluateRule(
            UUID ruleUuid,
            Certificate certificate) {
        
        Rule rule = ruleRepository.findById(ruleUuid)
            .orElseThrow();
        
        // Evaluate all conditions
        boolean allConditionsMet = rule.getConditions().stream()
            .allMatch(cond -> evaluateCondition(cond, certificate));
        
        // If all conditions met, collect actions
        List<Action> triggeredActions = allConditionsMet ?
            new ArrayList<>(rule.getActions()) :
            new ArrayList<>();
        
        return RuleEvaluationResult.builder()
            .ruleUuid(ruleUuid)
            .conditionsMet(allConditionsMet)
            .triggeredActions(triggeredActions)
            .evaluatedAt(Instant.now())
            .build();
    }
}
```

### ApprovalService

```java
@Service
@Transactional
public class ApprovalService {
    
    /**
     * Iniciar workflow de aprovação multi-step
     */
    @Transactional
    public Approval initiateApproval(
            Resource resource,
            UUID resourceUuid,
            UUID approvalProfileUuid) {
        
        Approval approval = new Approval();
        approval.setResourceType(resource);
        approval.setResourceUuid(resourceUuid);
        approval.setStatus(ApprovalStatus.PENDING);
        approval.setExpirationDate(LocalDateTime.now().plusDays(7));
        
        ApprovalProfile profile = approvalProfileRepository
            .findById(approvalProfileUuid)
            .orElseThrow();
        
        // Setup multi-step workflow
        approval.setSteps(profile.getSteps());
        
        return approvalRepository.save(approval);
    }
    
    /**
     * Aprovar etapa
     */
    @Transactional
    @AuditLogged(module = Module.APPROVAL_MANAGEMENT, operation = Operation.APPROVE)
    public Approval approveStep(UUID approvalUuid, ApprovalDecision decision) {
        
        Approval approval = approvalRepository.findById(approvalUuid)
            .orElseThrow();
        
        // Mark current step as APPROVED
        ApprovalProfile currentStep = approval.getCurrentStep();
        currentStep.setApprovedAt(LocalDateTime.now());
        currentStep.setApprovedBy(getCurrentUser());
        
        // Check if all steps completed
        if (approval.allStepsApproved()) {
            approval.setStatus(ApprovalStatus.APPROVED);
            
            // Trigger actual operation
            executeApprovedAction(approval);
        }
        
        return approvalRepository.save(approval);
    }
}
```

---

## 5.7 Utility & Infrastructure Services

### AuditLogService

```java
@Service
@Transactional
public class AuditLogService {
    
    /**
     * Log operação
     * (com event publishing para async processing)
     */
    @Transactional
    public void log(AuditEvent event) {
        
        AuditLog auditLog = new AuditLog();
        auditLog.setModule(event.getModule());
        auditLog.setOperation(event.getOperation());
        auditLog.setOperationResult(event.getOperationResult());
        auditLog.setActorType(event.getActorType());
        auditLog.setActorName(extractCurrentUser());
        auditLog.setSourceIp(extractClientIp());
        auditLog.setTimestamp(Instant.now());
        
        // Store log record (JSONB)
        auditLog.setLogRecord(buildLogRecord(event));
        
        auditLogRepository.save(auditLog);
        
        // Publish para RabbitMQ (async)
        auditEventProducer.publishAuditEvent(auditLog);
    }
    
    /**
     * Exportar logs de auditoria
     */
    @Transactional(readOnly = true)
    public byte[] exportLogs(AuditLogExportFormat format) {
        
        List<AuditLog> logs = auditLogRepository.findAll();
        
        if (format == AuditLogExportFormat.CSV) {
            return exportAsCSV(logs);
        } else if (format == AuditLogExportFormat.JSON) {
            return exportAsJSON(logs);
        } else if (format == AuditLogExportFormat.XML) {
            return exportAsXML(logs);
        }
        
        throw new IllegalArgumentException("Unsupported format: " + format);
    }
}
```

### SettingService

```java
@Service
@Transactional
public class SettingService {
    
    @Autowired
    private SettingRepository settingRepository;
    
    @Autowired
    private CacheManager cacheManager;
    
    /**
     * Get configuração global
     * (com cache Redis)
     */
    @Transactional(readOnly = true)
    @Cacheable(value = "settings", key = "#key")
    public String getSetting(String key) {
        
        Setting setting = settingRepository.findByKey(key)
            .orElseThrow(() -> new NotFoundException("Setting not found: " + key));
        
        return setting.getValue();
    }
    
    /**
     * Atualizar configuração
     * (invalida cache)
     */
    @Transactional
    @CacheEvict(value = "settings", key = "#key")
    public void updateSetting(String key, String value) {
        
        Optional<Setting> existing = settingRepository.findByKey(key);
        
        Setting setting = existing.orElseGet(Setting::new);
        setting.setKey(key);
        setting.setValue(value);
        setting.setUpdatedAt(LocalDateTime.now());
        
        settingRepository.save(setting);
    }
}
```

---

## Resumo de Serviços

| Categoria | Serviços | Quantidade |
|-----------|----------|-----------|
| **Certificate** | CertificateService, CertificateEventHistoryService, CrlService | 3 |
| **Cryptography** | CryptographicKeyService, CryptographicOperationService, CryptographicKeyEventHistoryService | 3 |
| **Credentials** | CredentialService, SecretService | 2 |
| **Profiles** | RaProfileService, AcmeProfileService, ScepProfileService, CmpProfileService, TokenProfileService, VaultProfileService | 6 |
| **Compliance** | ComplianceProfileService, ComplianceService | 2 |
| **Rules/Actions** | RuleService, TriggerService, ActionService | 3 |
| **Approval/Notifications** | ApprovalService, NotificationService, NotificationProfileService | 3 |
| **Access Control** | GroupService, LocationService, EntityInstanceService, AuthorityInstanceService | 4 |
| **Connectors** | ConnectorService, CallbackService, CoreCallbackService | 3 |
| **Protocols** | AcmeAccountService, ScepServiceImpl, CmpServiceImpl | 3 |
| **Utilities** | AuditLogService, SettingService, EnumService, StatisticsService, ResourceService, DiscoveryService | 6 |
| **Scheduler** | SchedulerService, ScheduledJobService | 2 |

**Total**: 55+ serviços implementando lógica de negócio, transações, autorização e auditoria

