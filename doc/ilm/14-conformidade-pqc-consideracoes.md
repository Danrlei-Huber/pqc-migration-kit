# 14. CONFORMIDADE & CONSIDERAÇÕES PQC

## 14.1 Compliance Framework Implementation

### ComplianceProfile Entity

```java
@Entity
@Table(name = "compliance_profile")
public class ComplianceProfile extends UniquelyIdentifiedAndAudited {
    
    @Column(name = "name")
    private String name;  // e.g. "HIPAA", "PCI-DSS", "ISO27001"
    
    @Column(name = "description")
    private String description;
    
    @Column(name = "enabled")
    private boolean enabled;
    
    // Store rules as JSONB for flexibility
    @Column(name = "rules", columnDefinition = "jsonb")
    @JdbcTypeCode(SqlTypes.JSON)
    private List<ComplianceRule> rules;
    
    @Column(name = "check_interval_days")
    private Integer checkIntervalDays;  // e.g., 30
}

@Data
public class ComplianceRule {
    
    private UUID ruleId;
    private String ruleName;  // e.g. "key_size_requirement"
    private String description;
    
    // Rule type
    @JsonProperty("rule_type")
    private RuleType ruleType;  // MIN_KEY_SIZE, MAX_VALIDITY, ALGORITHM_WHITELIST, etc
    
    // Condition evaluation
    @JsonProperty("condition")
    private Map<String, Object> condition;  // JSON condition (flexible)
    
    // Action on violation
    @JsonProperty("violation_action")
    private ViolationAction violationAction;  // WARN, BLOCK, AUDIT
    
    @JsonProperty("last_check")
    private LocalDateTime lastCheck;
    
    @JsonProperty("last_check_result")
    private CheckResult lastCheckResult;  // PASSED, FAILED, INCONCLUSIVE
}
```

### Compliance Rule Examples

```json
// Rule: All keys must be >= 2048 bits
{
  "ruleName": "key_size_requirement",
  "ruleType": "MIN_KEY_SIZE",
  "description": "Enforce minimum key size of 2048 bits",
  "condition": {
    "keyType": ["RSA", "EC"],
    "minKeySize": 2048
  },
  "violationAction": "BLOCK"
}

// Rule: Certificates must expire within 1 year
{
  "ruleName": "certificate_validity",
  "ruleType": "MAX_VALIDITY",
  "description": "Certificate validity period must be <= 365 days",
  "condition": {
    "maxValidityDays": 365
  },
  "violationAction": "WARN"
}

// Rule: Only approved algorithms allowed
{
  "ruleName": "algorithm_whitelist",
  "ruleType": "ALGORITHM_WHITELIST",
  "description": "Only approved algorithms: RSA, EC, FALCON, DILITHIUM",
  "condition": {
    "allowedAlgorithms": [
      "RSA",
      "EC",
      "FALCON",
      "DILITHIUM"
    ],
    "blacklistedAlgorithms": [
      "DSA",
      "MD5"
    ]
  },
  "violationAction": "BLOCK"
}

// Rule: Regular certificate discovery required
{
  "ruleName": "discovery_requirement",
  "ruleType": "DISCOVERY_REQUIRED",
  "description": "Certificates must be discovered/scanned at least monthly",
  "condition": {
    "maxDaysSinceLastDiscovery": 30
  },
  "violationAction": "WARN"
}

// Rule: Audit logging required
{
  "ruleName": "audit_logging",
  "ruleType": "AUDIT_REQUIRED",
  "description": "All operations must be logged with timestamps",
  "condition": {
    "requireAuditLog": true,
    "retentionDays": 10950,  // 30 years for HIPAA
    "includeModules": ["CERTIFICATE", "KEY", "CONNECTOR"]
  },
  "violationAction": "BLOCK"
}
```

---

## 14.2 Compliance Checking Service

### Compliance Evaluation

```java
@Service
@Transactional
@Slf4j
public class ComplianceCheckService {
    
    @Autowired
    private ComplianceProfileRepository profileRepository;
    
    @Autowired
    private CertificateRepository certificateRepository;
    
    @Autowired
    private CryptographicKeyRepository keyRepository;
    
    @Autowired
    private RabbitTemplate rabbitTemplate;
    
    /**
     * Execute compliance check against all profiles
     */
    @Scheduled(fixedDelay = 86400000)  // Daily
    public void executeComplianceChecks() {
        
        List<ComplianceProfile> profiles = profileRepository
            .findByEnabled(true);
        
        for (ComplianceProfile profile : profiles) {
            
            try {
                ComplianceCheckResult result = 
                    checkComplianceProfile(profile);
                
                // Publish result event
                publishComplianceCheckResult(result);
                
                // Update last check timestamp
                profile.setLastCheckTimestamp(LocalDateTime.now());
                profileRepository.save(profile);
                
            } catch (Exception e) {
                logger.error(
                    "Error checking compliance profile: {}", 
                    profile.getName(), e
                );
            }
        }
    }
    
    /**
     * Check single compliance profile
     */
    public ComplianceCheckResult checkComplianceProfile(
            ComplianceProfile profile) {
        
        ComplianceCheckResult result = new ComplianceCheckResult();
        result.setProfileUuid(profile.getUuid());
        result.setProfileName(profile.getName());
        result.setCheckTimestamp(LocalDateTime.now());
        
        List<RuleViolation> violations = new ArrayList<>();
        
        // Evaluate each rule
        for (ComplianceRule rule : profile.getRules()) {
            
            List<RuleViolation> ruleViolations = 
                evaluateRule(rule);
            
            violations.addAll(ruleViolations);
            
            // Update rule check history
            rule.setLastCheck(LocalDateTime.now());
            rule.setLastCheckResult(
                ruleViolations.isEmpty() ? 
                    CheckResult.PASSED : CheckResult.FAILED
            );
        }
        
        result.setViolations(violations);
        result.setStatus(violations.isEmpty() ? 
            ComplianceStatus.COMPLIANT : ComplianceStatus.NON_COMPLIANT);
        
        return result;
    }
    
    /**
     * Evaluate single rule (dispatch to type-specific evaluators)
     */
    private List<RuleViolation> evaluateRule(ComplianceRule rule) {
        
        return switch(rule.getRuleType()) {
            
            case MIN_KEY_SIZE -> 
                evaluateKeySize(rule);
            
            case MAX_VALIDITY -> 
                evaluateCertificateValidity(rule);
            
            case ALGORITHM_WHITELIST -> 
                evaluateAlgorithmWhitelist(rule);
            
            case DISCOVERY_REQUIRED -> 
                evaluateDiscoveryRequirement(rule);
            
            case AUDIT_REQUIRED -> 
                evaluateAuditRequirement(rule);
            
            default -> Collections.emptyList();
        };
    }
    
    /**
     * MIN_KEY_SIZE rule evaluation
     */
    private List<RuleViolation> evaluateKeySize(ComplianceRule rule) {
        
        List<RuleViolation> violations = new ArrayList<>();
        
        Integer minKeySize = (Integer) rule.getCondition()
            .get("minKeySize");
        
        @SuppressWarnings("unchecked")
        List<String> keyTypes = (List<String>) rule.getCondition()
            .get("keyType");
        
        // Find all keys with size < minimum
        List<CryptographicKey> nonCompliantKeys = keyRepository
            .findAll((root, query, cb) -> {
                
                Predicate keySizePredicate = cb.lt(
                    root.get("size"),
                    minKeySize
                );
                
                if (keyTypes != null && !keyTypes.isEmpty()) {
                    Predicate keyTypePredicate = root.get("keyType")
                        .in(keyTypes);
                    return cb.and(keySizePredicate, keyTypePredicate);
                }
                
                return keySizePredicate;
            });
        
        // Create violation for each non-compliant key
        for (CryptographicKey key : nonCompliantKeys) {
            
            RuleViolation violation = new RuleViolation();
            violation.setRuleId(rule.getRuleId());
            violation.setRuleName(rule.getRuleName());
            violation.setResourceType("CRYPTOGRAPHIC_KEY");
            violation.setResourceUuid(key.getUuid());
            violation.setResourceName(key.getName());
            violation.setSeverity("HIGH");  // Key too small
            violation.setDescription(
                String.format(
                    "Key %s has size %d bits, minimum required is %d",
                    key.getName(),
                    key.getSize(),
                    minKeySize
                )
            );
            
            violations.add(violation);
        }
        
        return violations;
    }
    
    /**
     * MAX_VALIDITY rule evaluation
     */
    private List<RuleViolation> evaluateCertificateValidity(
            ComplianceRule rule) {
        
        List<RuleViolation> violations = new ArrayList<>();
        
        Integer maxValidityDays = (Integer) rule.getCondition()
            .get("maxValidityDays");
        
        // Find all certificates with validity > maximum
        LocalDateTime maxValidToDate = LocalDateTime.now()
            .plusDays(maxValidityDays);
        
        List<Certificate> nonCompliantCerts = certificateRepository
            .findAll((root, query, cb) -> 
                cb.greaterThan(
                    root.get("validTo"),
                    maxValidToDate.toInstant(ZoneOffset.UTC)
                )
            );
        
        for (Certificate cert : nonCompliantCerts) {
            
            long actualValidityDays = 
                ChronoUnit.DAYS.between(
                    cert.getValidFrom(),
                    cert.getValidTo()
                );
            
            RuleViolation violation = new RuleViolation();
            violation.setRuleId(rule.getRuleId());
            violation.setRuleName(rule.getRuleName());
            violation.setResourceType("CERTIFICATE");
            violation.setResourceUuid(cert.getUuid());
            violation.setResourceName(cert.getSubject());
            violation.setSeverity("MEDIUM");
            violation.setDescription(
                String.format(
                    "Certificate %s valid for %d days, max is %d",
                    cert.getSerialNumber(),
                    actualValidityDays,
                    maxValidityDays
                )
            );
            
            violations.add(violation);
        }
        
        return violations;
    }
    
    /**
     * Publish compliance check results to RabbitMQ
     */
    private void publishComplianceCheckResult(
            ComplianceCheckResult result) {
        
        String routingKey = String.format(
            "compliance.%s.%s",
            result.getProfileName(),
            result.getStatus().name()
        );
        
        rabbitTemplate.convertAndSend(
            "compliance-exchange",
            routingKey,
            result,
            message -> {
                message.getMessageProperties()
                    .setCorrelationId(result.getProfileUuid().toString());
                return message;
            }
        );
    }
}

@Data
public class ComplianceCheckResult {
    
    private UUID profileUuid;
    private String profileName;
    private LocalDateTime checkTimestamp;
    private ComplianceStatus status;  // COMPLIANT | NON_COMPLIANT | INCONCLUSIVE
    private List<RuleViolation> violations;
    private int violationCount;
    private String summary;
    
    public void setSummary() {
        this.violationCount = violations.size();
        this.summary = String.format(
            "Profile %s: %d violations found",
            profileName,
            violationCount
        );
    }
}
```

---

## 14.3 Post-Quantum Cryptography Roadmap & Considerations

### Current PQC Status

```
CZERTAINLY-Core PQC Support:
Status: EXPERIMENTAL (v2.16.4)
Algorithms: FALCON, Dilithium, SPHINCS+ (NIST standardized)

Supported Operations:
✅ PQC key generation
✅ PQC signing/verification
✅ Storage (PKCS#8 format)
✅ Hybrid certificates (RSA + PQC)
⚠️  Endpoint discovery still in testing
❌ Ecosystem tooling (limited third-party support)
❌ Full migration readiness (performance considerations)
```

### PQC Migration Phases

#### Phase 1: Parallel Operation (Current - 2024)

```java
@Component
public class PqcMigrationPhase1 {
    
    /**
     * Generate keys in BOTH classical and PQC
     * (For backward compatibility evaluation)
     */
    @Service
    public class HybridKeyGenerationService {
        
        public HybridKeyPair generateHybridKeyPair(
                String keyName,
                Integer rsaKeySize) {
            
            // 1. Generate RSA key (classical)
            KeyPair rsaKeyPair = generateRsaKeyPair(rsaKeySize);
            
            // 2. Generate Dilithium key (PQC)
            KeyPair dilithiumKeyPair = generateDilithiumKeyPair();
            
            // 3. Store BOTH (separate entities)
            CryptographicKey rsaKey = new CryptographicKey();
            rsaKey.setName(keyName + "_RSA");
            rsaKey.setKeyType(KeyType.RSA);
            rsaKey.setPublicKey(rsaKeyPair.getPublic().getEncoded());
            rsaKey.setPrivateKey(rsaKeyPair.getPrivate().getEncoded());
            rsaKey.setPqc(false);
            keyRepository.save(rsaKey);
            
            CryptographicKey dilithiumKey = new CryptographicKey();
            dilithiumKey.setName(keyName + "_DILITHIUM");
            dilithiumKey.setKeyType(KeyType.DILITHIUM);
            dilithiumKey.setPublicKey(dilithiumKeyPair.getPublic().getEncoded());
            dilithiumKey.setPrivateKey(dilithiumKeyPair.getPrivate().getEncoded());
            dilithiumKey.setPqc(true);
            dilithiumKey.setPqcAlgorithm("Dilithium5");  // NIST Level 5
            keyRepository.save(dilithiumKey);
            
            return new HybridKeyPair(rsaKey, dilithiumKey);
        }
        
        /**
         * Metrics to track adoption
         */
        @Scheduled(fixedDelay = 86400000)  // Daily
        public void trackPqcAdoption() {
            
            long totalKeys = keyRepository.count();
            long pqcKeys = keyRepository.countByPqc(true);
            
            double adoptionPercentage = (pqcKeys / (double) totalKeys) * 100;
            
            logger.info(
                "PQC Adoption Metrics: {} PQC keys / {} total ({:.2f}%)",
                pqcKeys, totalKeys, adoptionPercentage
            );
            
            // Publish metric event for monitoring
            publishPqcMetricEvent(new PqcAdoptionMetric(
                adoptionPercentage,
                pqcKeys,
                totalKeys
            ));
        }
    }
}

// Configuration via properties
application.yml:
pqc:
  phase: PHASE_1_PARALLEL
  algorithms:
    - FALCON       # NIST Level 5
    - DILITHIUM    # NIST Level 5
    - SPHINCS_PLUS # Conservative (hash-based)
  key-generation-mode: HYBRID  # Generate both classical + PQC
  certificate-signing: CLASSICAL_ONLY  # Still issue RSA certs
```

#### Phase 2: Monitoring & Validation (2024-2025)

```java
@Component
public class PqcMigrationPhase2 {
    
    /**
     * Comprehensive PQC Performance Testing
     */
    @Component
    @Slf4j
    public class PqcPerformanceMonitor {
        
        @Scheduled(fixedDelay = 604800000)  // Weekly
        public void benchmarkPqcOperations() {
            
            logger.info("Starting PQC performance benchmarking...");
            
            // Test RSA signing performance
            long rsaStartTime = System.nanoTime();
            for (int i = 0; i < 100; i++) {
                cryptoService.signWithRsa(testData);
            }
            long rsaDuration = System.nanoTime() - rsaStartTime;
            
            // Test FALCON signing performance
            long falconStartTime = System.nanoTime();
            for (int i = 0; i < 100; i++) {
                cryptoService.signWithFalcon(testData);
            }
            long falconDuration = System.nanoTime() - falconStartTime;
            
            // Test Dilithium signing performance
            long dilithiumStartTime = System.nanoTime();
            for (int i = 0; i < 100; i++) {
                cryptoService.signWithDilithium(testData);
            }
            long dilithiumDuration = System.nanoTime() - dilithiumStartTime;
            
            // Test SPHINCS+ signing performance (slow)
            long sphincsStartTime = System.nanoTime();
            for (int i = 0; i < 10; i++) {  // Only 10 iterations (slow)
                cryptoService.signWithSphincs(testData);
            }
            long sphincsDuration = System.nanoTime() - sphincsStartTime;
            
            // Report findings
            logger.info("""
                PQC Performance Benchmarks:
                RSA (100 ops):       {} ms
                FALCON (100 ops):    {} ms ({:.1f}x RSA)
                Dilithium (100 ops): {} ms ({:.1f}x RSA)
                SPHINCS+ (10 ops):   {} ms ({:.1f}x RSA per op)
                """,
                rsaDuration / 1_000_000,
                falconDuration / 1_000_000,
                (double) falconDuration / rsaDuration,
                dilithiumDuration / 1_000_000,
                (double) dilithiumDuration / rsaDuration,
                sphincsDuration / 1_000_000,
                (double) (sphincsDuration / 10) / rsaDuration
            );
            
            // Store metrics for trending
            storePqcBenchmarkMetrics(new PqcBenchmarkResult(
                LocalDateTime.now(),
                rsaDuration,
                falconDuration,
                dilithiumDuration,
                sphincsDuration
            ));
        }
        
        /**
         * Monitor ecosystem support (e.g., for CRL, OCSP...)
         */
        @Scheduled(fixedDelay = 604800000)  // Weekly
        public void checkEcosystemSupport() {
            
            logger.info("Checking PQC ecosystem support...");
            
            List<EcosystemComponent> components = Arrays.asList(
                new EcosystemComponent("OpenSSL", checkOpenSslPqcSupport()),
                new EcosystemComponent("libcurl", checkCurlPqcSupport()),
                new EcosystemComponent("Java JCE", checkJavaPqcSupport()),
                new EcosystemComponent("Web browsers", checkBrowserPqcSupport())
            );
            
            for (EcosystemComponent comp : components) {
                
                boolean supported = comp.isPqcSupported();
                logger.info(
                    "{}: {} {}",
                    comp.getName(),
                    supported ? "✓" : "✗",
                    comp.getVersion()
                );
                
                publishEcosystemSupportEvent(comp);
            }
        }
    }
}

// Phase 2 Configuration
application.yml:
pqc:
  phase: PHASE_2_MONITORING
  pilot-rollout-percentage: 5%  # Only 5% new certs use PQC
  performance-monitoring: true
  ecosystem-compatibility-check: true
  telemetry:
    enabled: true
    collection-interval: PT1H
```

#### Phase 3: Full Migration (2025-2026)

```java
@Component
public class PqcMigrationPhase3 {
    
    /**
     * Migrate all new certificates to PQC-first
     */
    @Configuration
    public class PqcFirstConfiguration {
        
        /**
         * Default algorithm selection (at issuance)
         */
        @Bean
        public CertificateIssuancePolicy certificateIssuancePolicy() {
            
            return new CertificateIssuancePolicy() {
                
                @Override
                public AlgorithmSelection selectAlgorithm(
                        CertificateRequest request) {
                    
                    // New policy: PQC-first with hybrid fallback
                    
                    if (request.requiresPqc() || 
                        !request.requiresBackwardCompatibility()) {
                        
                        // Use Dilithium5 (NIST Level 5, ECDSA-like perf)
                        return new AlgorithmSelection(
                            KeyType.DILITHIUM,
                            "Dilithium5",
                            true,  // isPqc
                            "Phase3_PqcFirst"
                        );
                        
                    } else if (request.allowsHybrid()) {
                        
                        // Hybrid: RSA + Dilithium signature
                        return new AlgorithmSelection(
                            KeyType.RSA,  // Primary
                            "RSA-4096_with_Dilithium5",
                            true,  // isPqc
                            "Phase3_Hybrid"
                        );
                        
                    } else {
                        
                        // Legacy fallback (for compatibility)
                        return new AlgorithmSelection(
                            KeyType.RSA,
                            "RSA-4096",
                            false,
                            "Phase3_LegacyFallback"
                        );
                    }
                }
                
                @Override
                public boolean shouldDeprecateAlgorithm(KeyType keyType) {
                    
                    // Deprecation timeline
                    return switch(keyType) {
                        
                        // Immediately deprecated
                        case RSA_2048, EC_P256 -> true;
                        
                        // Deprecated in 2 years
                        case RSA_3072 -> LocalDate.now().isAfter(
                            LocalDate.of(2027, 1, 1)
                        );
                        
                        // Still supported
                        case RSA_4096, EC_P384, EC_P521 -> false;
                        
                        // PQC always new
                        case FALCON, DILITHIUM, SPHINCS_PLUS -> false;
                        
                        default -> false;
                    };
                }
            };
        }
    }
}

// Phase 3 Configuration
application.yml:
pqc:
  phase: PHASE_3_FULL_MIGRATION
  pqc-first-enabled: true
  primary-algorithm: DILITHIUM  # All new certs use Dilithium5
  hybrid-signing-enabled: false  # Pure PQC, no hybrid
  deprecated-algorithms: [RSA_2048, EC_P256]  # Reject these
  migration-deadline: "2026-01-01"
  backward-compatibility:
    enable: false  # No classic RSA support
    sunset-date: "2026-12-31"
```

---

## 14.4 Crypto-Agility Requirements

### Agile Algorithm Support

```java
/**
 * Support algorithm changes without code recompilation
 */
@Configuration
public class CryptoAgileConfiguration {
    
    @Bean
    public AlgorithmSupport algorithmSupport(
            @Value("${crypto.supported-algorithms}") String algList) {
        
        return new AlgorithmSupport(
            Arrays.asList(algList.split(","))
        );
    }
    
    /**
     * Example properties:
     * 
     * crypto.supported-algorithms: RSA_2048,RSA_4096,EC_P256,EC_P384,DILITHIUM5,FALCON1024
     * crypto.default-algorithm: DILITHIUM5
     * crypto.algorithm-deprecation-date.RSA_2048: 2024-12-31
     * crypto.algorithm-deprecation-date.EC_P256: 2025-12-31
     * crypto.algorithm-end-of-support.RSA_2048: 2026-12-31
     */
}

// Runtime algorithm preference updates
@Service
public class AlgorithmCryptoAgilityService {
    
    @Autowired
    private ApplicationContext context;
    
    /**
     * Update preferred algorithms at runtime (no restart)
     */
    public void updateAlgorithmPreference(String algorithmName) {
        
        // Event published to all instances (via event bus)
        context.publishEvent(
            new AlgorithmPreferenceChangedEvent(algorithmName)
        );
        
        logger.info("Algorithm preference updated to: {}", algorithmName);
    }
    
    @EventListener
    public void onAlgorithmPreferenceChanged(
            AlgorithmPreferenceChangedEvent event) {
        
        // Update in-memory caches
        cryptoOperationService.updateDefaultAlgorithm(
            event.getAlgorithmName()
        );
        
        // New certificates use updated algorithm
        // Existing certificates remain unchanged
    }
}
```

---

## 14.5 Compliance Audit Reports

### Automated Compliance Reporting

```java
@Service
@Slf4j
public class ComplianceReportingService {
    
    /**
     * Generate compliance report (daily, weekly, yearly)
     */
    @Scheduled(cron = "0 0 2 * * ?")  // 2 AM daily
    public void generateDailyComplianceReport() {
        
        LocalDate reportDate = LocalDate.now();
        
        // Collect compliance data
        ComplianceReportData reportData = new ComplianceReportData();
        reportData.setReportDate(reportDate);
        reportData.setReportType("DAILY");
        
        // 1. Certificate health
        reportData.setCertificateMetrics(
            calculateCertificateMetrics()
        );
        
        // 2. Key management health
        reportData.setKeyMetrics(
            calculateKeyMetrics()
        );
        
        // 3. Recent violations
        reportData.setRecentViolations(
            findRecentComplianceViolations(1)  // Last 1 day
        );
        
        // 4. Audit activity
        reportData.setAuditActivitySummary(
            summarizeAuditActivity(1)  // Last 1 day
        );
        
        // 5. PQC metrics
        reportData.setPqcAdoptionMetrics(
            calculatePqcMetrics()
        );
        
        // Store report
        complianceReportRepository.save(reportData);
        
        // Send to compliance team (email, SIEM, etc)
        publishComplianceReport(reportData);
    }
    
    private ComplianceReportMetrics calculateCertificateMetrics() {
        
        long totalCerts = certificateRepository.count();
        long activeCerts = certificateRepository
            .countByState(CertificateState.ACTIVE);
        long expiringIn30Days = certificateRepository
            .countExpiringBefore(LocalDateTime.now().plusDays(30));
        
        return new ComplianceReportMetrics(
            totalCerts,
            activeCerts,
            expiringIn30Days
        );
    }
    
    private PqcAdoptionMetrics calculatePqcMetrics() {
        
        long totalKeys = keyRepository.count();
        long pqcKeys = keyRepository.countByPqc(true);
        long pqcCerts = certificateRepository
            .countByIsPqc(true);
        
        return new PqcAdoptionMetrics(
            pqcKeys,
            totalKeys,
            pqcCerts,
            (pqcKeys * 100.0) / totalKeys,
            (pqcCerts * 100.0) / certificateRepository.count()
        );
    }
}
```

---

## Resumo de Conformidade & PQC

| Aspecto | Status | Ação |
|--------|--------|------|
| **Compliance Checking** | ✅ Implemented | Profiles define rules, automated checking |
| **Audit Logging** | ✅ Implemented | JSONB audit trails, 30-year retention |
| **PQC Support** | ⚠️ Experimental | Phase 1 (parallel), Phase 2-3 planned |
| **Algorithm Agility** | ✅ Supported | Runtime preference updates |
| **Migration Path** | 📋 Documented | 3-phase roadmap (2024-2026) |
| **Performance** | 📊 Monitoring | Weekly benchmarking for PQC ops |
| **Ecosystem** | ⚠️ Limited | Check compatibility weekly |

