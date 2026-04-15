# 10. SISTEMA DE CONECTORES: Plugin Architecture

## 10.1 Connector Pattern Overview

CZERTAINLY implementa um **plugin system** baseado em REST callbacks, permitindo que conectores externos (em containers Docker) estenda a funcionalidade do Core sem modificação de código.

### Architecture

```
┌─────────────────────────────────────────────────┐
│  CZERTAINLY Core (Java/Spring Boot)             │
│  ┌───────────────────────────────────────────┐  │
│  │ API Controllers                           │  │
│  │ (Connectors, Certificates, Keys, etc)    │  │
│  └───────────────────────────────────────────┘  │
│           ↑                           ↓           │
│           │                           │          │
│  ┌────────┴───────────────────────────┴────┐   │
│  │ Connector Service Layer                  │   │
│  │ - Discovery                              │   │
│  │ - Health Check                           │   │
│  │ - Attribute Management                   │   │
│  │ - Operation Dispatch                     │   │
│  └──────────────────────────────────────────┘   │
└────────────────┬─────────────────┬──────────────┘
                 │                 │
         ┌───────▼─────────┐  ┌────▼────────────┐
         │ HTTPS + mTLS    │  │ REST API        │
         │ Callbacks       │  │ 9000+ endpoints │
         └───────┬─────────┘  └────┬────────────┘
                 │                 │
    ┌────────────▼──────────┐  ┌───▼──────────────┐
    │ Connector 1 Container │  │ Connector 2      │
    │ (CA Provider)         │  │ (HSM)            │
    │ Port 8080             │  │ Port 8080        │
    └───────────────────────┘  └──────────────────┘
```

---

## 10.2 Connector Entity & Registration

### Connector Entity

```java
@Entity
@Table(name = "connector", uniqueConstraints = {
    @UniqueConstraint(columnNames = {"url", "version"})
})
public class Connector extends UniquelyIdentifiedAndAudited {
    
    // Identity
    @Column(name = "name")
    private String name;
    
    @Column(name = "url")
    private String url;  // e.g., https://ca-connector:8080
    
    @Column(name = "version")
    private String version;  // e.g., v2.15.0
    
    @Column(name = "description")
    private String description;
    
    // Endpoints (REST paths)
    @OneToMany(mappedBy = "connector", cascade = CascadeType.ALL, fetch = FetchType.EAGER)
    private List<Endpoint> endpoints = new ArrayList<>();
    
    // Supported Functions
    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(
        name = "connector_function_group",
        joinColumns = @JoinColumn(name = "connector_uuid"),
        inverseJoinColumns = @JoinColumn(name = "function_group_id")
    )
    private Set<FunctionGroup> functionGroups = new HashSet<>();
    
    // Health Status
    @Enumerated(EnumType.STRING)
    @Column(name = "health_status")
    private HealthStatus healthStatus;  // UP, DOWN, ERROR
    
    @Column(name = "health_check_timestamp")
    private LocalDateTime healthCheckTimestamp;
}
```

### Endpoint Entity

```java
@Entity
@Table(name = "endpoint")
public class Endpoint extends UniquelyIdentifiedAndAudited {
    
    @Column(name = "name")
    private String name;  // e.g., "CA_OPERATIONS"
    
    @Column(name = "context")
    private String context;  // e.g., "/ca/operations"
    
    @ManyToOne
    @JoinColumn(name = "connector_uuid")
    private Connector connector;
}
```

### Connector Registration (Auto)

```java
@Service
@Transactional
public class ConnectorService {
    
    /**
     * Register connector (geralmente via POST /connectors)
     */
    public Connector registerConnector(ConnectorRegistrationRequest request) {
        
        Connector connector = new Connector();
        connector.setUrl(request.getUrl());
        connector.setVersion(request.getVersion());
        connector.setName(request.getName());
        connector.setDescription(request.getDescription());
        
        try {
            // 1. Test connectivity
            ConnectorInfoResponse info = connectorApiClient
                .getConnectorInfo(request.getUrl());
            
            // 2. Discover endpoints
            List<Endpoint> endpoints = discoverEndpoints(request.getUrl());
            connector.setEndpoints(endpoints);
            
            // 3. Discover function groups
            Set<FunctionGroup> functionGroups = discoverFunctionGroups(
                request.getUrl()
            );
            connector.setFunctionGroups(functionGroups);
            
            connector.setHealthStatus(HealthStatus.UP);
            connector.setHealthCheckTimestamp(LocalDateTime.now());
            
            connectorRepository.save(connector);
            
            logger.info("Connector registered: {} v{}", connector.getName(), 
                connector.getVersion());
            
            return connector;
            
        } catch (Exception e) {
            logger.error("Failed to register connector", e);
            connector.setHealthStatus(HealthStatus.ERROR);
            throw e;
        }
    }
}
```

---

## 10.3 Function Groups & Capabilities

### Function Group Enum

```java
public enum FunctionGroupCode {
    
    CA("CA"),  // Certificate Authority operations
    CRYPTOGRAPHY_KEY_MANAGEMENT("CRYPTOGRAPHY_KEY_MANAGEMENT"),
    TOKEN_MANAGEMENT("TOKEN_MANAGEMENT"),
    ENTITY("ENTITY"),  // Entity/Storage provider
    LOCATION("LOCATION"),
    NOTIFICATION("NOTIFICATION"),
    COMPLIANCE("COMPLIANCE"),
    CUSTOM("CUSTOM");
    
    private final String value;
    
    FunctionGroupCode(String value) {
        this.value = value;
    }
}
```

### Available Functions per Group

| Function Group | Functions | Examples |
|---|---|---|
| **CA** | Issue, Revoke, Renew | Issue certificate, Get CRL |
| **CRYPTO_KEY** | Generate, Sign, Verify | Generate key, Sign data |
| **TOKEN** | Register, List, Manage | HSM registration, key storage |
| **ENTITY** | List, Push, Discover | Upload cert to storage |
| **LOCATION** | Manage, Push | Certificate storage location |
| **NOTIFICATION** | Send, Configure | Email, Webhook notification |

---

## 10.4 Connector REST API

### Core Endpoints (Called by Connector)

```java
@RestController
@RequestMapping("/v1/connector")
@Slf4j
public class ConnectorApiController {
    
    /**
     * GET /v1/connector/info
     * 返回 connector info (health check)
     */
    @GetMapping("/info")
    public ConnectorInfoDto getConnectorInfo() {
        return new ConnectorInfoDto(
            "CA-Connector",
            "2.15.0",
            "Certificate Authority connector",
            LocalDateTime.now()
        );
    }
    
    /**
     * GET /v1/connector/health
     * Health check endpoint
     */
    @GetMapping("/health")
    public ResponseEntity<HealthStatus> getHealth() {
        return ResponseEntity.ok(HealthStatus.UP);
    }
    
    /**
     * GET /v1/connector/functions
     * List supported functions/operations
     */
    @GetMapping("/functions")
    public FunctionsDto getSupportedFunctions() {
        return new FunctionsDto(
            Arrays.asList(
                new FunctionDto("CA", "ISSUE_CERTIFICATE", 
                    "Issue certificate from CSR"),
                new FunctionDto("CA", "REVOKE_CERTIFICATE",
                    "Revoke issued certificate"),
                new FunctionDto("CRYPTO_KEY", "GENERATE_KEY",
                    "Generate cryptographic key"),
                new FunctionDto("CRYPTO_KEY", "SIGN_DATA",
                    "Sign data with key")
            )
        );
    }
}
```

### Callback Endpoints (Conector Calls Core)

```java
@RestController
@RequestMapping("/v1/connector/callback")
@Slf4j
public class CallbackController {
    
    @Autowired
    private CallbackService callbackService;
    
    /**
     * POST /v1/connector/callback/get-attributes
     * Connector pede definição de attributes pra interface
     */
    @PostMapping("/get-attributes")
    public List<AttributeDefinition> getAttributes(
            @RequestBody AttributeRequest request) {
        
        String functionGroup = request.getFunctionGroup();  // e.g., "CA"
        String functionName = request.getFunctionName();    // e.g., "ISSUE_CERTIFICATE"
        
        // Busca attributes schema específicas pra função
        return callbackService.getAttributeDefinitions(
            request.getConnectorUuid(),
            functionGroup,
            functionName
        );
    }
    
    /**
     * POST /v1/connector/callback/validate-attributes
     * Connector pede validação de attribute values
     */
    @PostMapping("/validate-attributes")
    public AttributeValidationResponse validateAttributes(
            @RequestBody AttributeValidationRequest request) {
        
        // Valida valores contra schema
        List<AttributeValidationError> errors = callbackService
            .validateAttributes(request.getAttributes());
        
        return new AttributeValidationResponse(
            errors.isEmpty(),
            errors
        );
    }
    
    /**
     * POST /v1/connector/callback/connector-discovery-state
     * Connector publica atualização de state
     * (descoberta de CAs, recursos, etc)
     */
    @PostMapping("/connector-discovery-state")
    @AuditLogged(module = Module.DISCOVERY, operation = Operation.UPDATE)
    public void updateConnectorDiscoveryState(
            @RequestBody DiscoveryStateUpdateRequest request) {
        
        callbackService.updateDiscoveryState(
            request.getConnectorUuid(),
            request.getDiscoveryData()
        );
    }
}
```

---

## 10.5 Connector Operations Dispatch

### Operation Executor

```java
@Service
@Transactional
@Slf4j
public class ConnectorOperationExecutor {
    
    @Autowired
    private RestTemplate restTemplate;
    
    /**
     * Executa operação no conector
     * (ex: Certificate issuance, key generation)
     */
    public ConnectorOperationResult executeOperation(
            String connectorUrl,
            ConnectorOperation operation) throws Exception {
        
        String operationUrl = connectorUrl + "/operation";
        
        long startTime = System.currentTimeMillis();
        
        try {
            // Call connector
            ResponseEntity<ConnectorOperationResponse> response = 
                restTemplate.postForEntity(
                    operationUrl,
                    operation,
                    ConnectorOperationResponse.class
                );
            
            long executionTime = System.currentTimeMillis() - startTime;
            
            if (response.getStatusCode() != HttpStatus.OK) {
                throw new ConnectorException(
                    "Operation failed: " + response.getStatusCode(),
                    response.getStatusCode().value()
                );
            }
            
            ConnectorOperationResponse result = response.getBody();
            
            logger.info("Operation executed in {}ms", executionTime);
            
            return new ConnectorOperationResult(
                true,
                result.getOutput(),
                null,
                executionTime
            );
            
        } catch (HttpClientErrorException e) {
            logger.error("Client error during operation: {}", e.getMessage());
            throw new ConnectorException(e.getMessage(), e.getRawStatusCode());
            
        } catch (HttpServerErrorException e) {
            logger.error("Server error during operation: {}", e.getMessage());
            throw new ConnectorException(
                "Connector service error: " + e.getMessage(),
                e.getRawStatusCode()
            );
            
        } catch (ResourceAccessException e) {
            logger.error("Connection error with connector: {}", e.getMessage());
            throw new ConnectorException("Connection timeout", 503);
        }
    }
}

@Data
public class ConnectorOperation {
    private String functionGroup;  // CA, CRYPTOGRAPHY_KEY_MANAGEMENT, etc
    private String functionName;   // ISSUE_CERTIFICATE, GENERATE_KEY, etc
    private UUID connectorUuid;
    private List<RequestAttribute> parameters;  // Dynamic attributes
    private Map<String, Object> operationData;  // Operation-specific data
}
```

---

## 10.6 Health Check & Monitoring

### Periodic Health Check

```java
@Component
@Slf4j
public class ConnectorHealthCheckScheduler {
    
    @Autowired
    private ConnectorRepository connectorRepository;
    
    @Autowired
    private RestTemplate restTemplate;
    
    /**
     * Verificar saúde de todos conectores
     * (agendado: cada 5 minutos)
     */
    @Scheduled(fixedDelay = 300000)  // 5 minutes
    public void performHealthCheck() {
        
        List<Connector> connectors = connectorRepository.findAll();
        
        for (Connector connector : connectors) {
            
            boolean isHealthy = checkConnectorHealth(connector);
            
            HealthStatus newStatus = isHealthy ? 
                HealthStatus.UP : HealthStatus.DOWN;
            
            // Update only if status changed
            if (connector.getHealthStatus() != newStatus) {
                connector.setHealthStatus(newStatus);
                connector.setHealthCheckTimestamp(LocalDateTime.now());
                connector.setUpdatedAt(LocalDateTime.now());
                
                connectorRepository.save(connector);
                
                logger.warn("Connector {} health status changed to: {}", 
                    connector.getName(), newStatus);
                
                // Notify if DOWN
                if (newStatus == HealthStatus.DOWN) {
                    publishHealthChangeEvent(connector);
                }
            }
        }
    }
    
    private boolean checkConnectorHealth(Connector connector) {
        try {
            String healthUrl = connector.getUrl() + "/health";
            
            ResponseEntity<String> response = restTemplate.getForEntity(
                healthUrl,
                String.class
            );
            
            return response.getStatusCode() == HttpStatus.OK;
            
        } catch (Exception e) {
            logger.error("Health check failed for connector: {}", 
                connector.getName(), e);
            return false;
        }
    }
}
```

---

## 10.7 mTLS Setup for Connector Communication

### Client Certificate Configuration

```java
@Configuration
public class ConnectorMtlsConfiguration {
    
    @Bean
    public RestTemplate mtlsRestTemplate(
            SSLContext sslContext) {
        
        HttpClient httpClient = HttpClientBuilder.create()
            .setSSLContext(sslContext)
            .setSSLHostVerifier(new DefaultHostnameVerifier())
            .build();
        
        HttpComponentsClientHttpRequestFactory factory = 
            new HttpComponentsClientHttpRequestFactory(httpClient);
        
        return new RestTemplate(factory);
    }
    
    @Bean
    public SSLContext sslContext() throws Exception {
        
        // Load client certificate
        KeyStore keyStore = loadKeyStore(
            "/etc/czertainly-backend/client-keystore.jks",
            "password"
        );
        
        // Load trusted CA cert
        KeyStore trustStore = loadTrustStore(
            "/etc/czertainly-backend/trust-keystore.jks",
            "password"
        );
        
        KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
        kmf.init(keyStore, "keypass".toCharArray());
        
        TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
        tmf.init(trustStore);
        
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
        
        return sslContext;
    }
}
```

---

## 10.8 Attribute Management & Dynamic Configuration

### Attribute Definition Flow

```
1. Connector registers mit attributes schema
2. Core stores em AttributeDefinition tabela
3. UI/API queries /api/v2/connectors/{uuid}/attributes
4. User fornece valores
5. Core valida via connector callback
6. Values armazenados em Request attribute
7. Connector recebe valores ao processar operation
```

### Example: CA Connector Attributes

```json
{
  "functionGroup": "CA",
  "functionName": "ISSUE_CERTIFICATE",
  "attributes": [
    {
      "name": "ca_id",
      "contentType": "STRING",
      "contentFormat": "TEXT",
      "required": true,
      "description": "Certificate Authority ID"
    },
    {
      "name": "profile",
      "contentType": "STRING",
      "contentFormat": "DROPDOWN",
      "required": true,
      "options": ["Production", "Testing", "Development"],
      "description": "CA Profile"
    },
    {
      "name": "validity_period_days",
      "contentType": "INTEGER",
      "required": false,
      "defaultValue": 365,
      "description": "Certificate validity period"
    }
  ]
}
```

---

## 10.9 Error Handling & Resilience

### Retry Logic

```java
@Component
@Slf4j
public class ConnectorRetryHandler {
    
    @Bean
    public RestTemplate retryableRestTemplate() {
        SimpleClientHttpRequestFactory factory = 
            new SimpleClientHttpRequestFactory();
        factory.setConnectTimeout(10000);  // 10s
        factory.setReadTimeout(30000);     // 30s
        
        return new RestTemplate(factory);
    }
    
    public <T> T executeWithRetry(
            String connectorUrl,
            String operation,
            Class<T> responseType,
            int maxRetries) throws Exception {
        
        int retries = 0;
        long backoff = 1000;  // Start with 1 second
        
        while (retries < maxRetries) {
            try {
                return executeOperation(connectorUrl, operation, responseType);
                
            } catch (ConnectorException e) {
                retries++;
                
                if (retries >= maxRetries) {
                    logger.error("Max retries exceeded for operation: {}", operation);
                    throw e;
                }
                
                logger.warn("Retrying operation {} (attempt {}/{})", 
                    operation, retries, maxRetries);
                
                Thread.sleep(backoff);
                backoff *= 2;  // Exponential backoff
            }
        }
        
        throw new ConnectorException("Operation failed after retries");
    }
}
```

---

## Resumo de Conectores

| Aspecto | Implementação |
|---------|---|
| **Registration** | Auto-discovery via REST API |
| **Communication** | HTTPS + mTLS |
| **Endpoints** | REST callbacks |
| **Attributes** | Dynamic schema + validation |
| **Health** | Periodic checks (5 min) |
| **Operations** | Function dispatch pattern |
| **Error** | Retry + exponential backoff |
| **Monitoring** | Status tracking + events |

**Extensível**: Conectores novos podem ser adicionados sem modificar Core

