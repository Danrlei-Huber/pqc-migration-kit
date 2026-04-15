# APIs REST & Controllers: Análise de 30+ Endpoints

## Visão Estratégica de Design de API

O CZERTAINLY-Core expõe 30+ controllers REST que implementam RESTful principles com extensões domain-specific para PKI. A arquitetura segue padrão de versioning (v1 legacy, v2 current) e discovery endpoints para client auto-configuration.

**Princípios de design**:
1. **Resource-oriented**: HTTP methods (GET, POST, PUT, DELETE) mapeiam operações em recursos
2. **Stateless**: Cada request é independente, token JWT contém contexto
3. **Versioned**: v1 legacy, v2 current, permite evolução sem breaking clients
4. **Discoverable**: Endpoints anunciam capabilities via OpenAPI/Swagger
5. **Secure**: `@AuthEndpoint` + `@PreAuthorize` + OPA checks

## API Versioning Strategy

### Versioning Approach: URI Versioning

CZERTAINLY escolheu **URI versioning** em vez de alternatives:

```
/api/v1/certificates         → v1 endpoints (legacy)
/api/v2/certificates         → v2 endpoints (current)
/discover/v2/certificates    → discovery responses
```

**Por quê URI versioning?**

Alternativas:
- **Header versioning**: `Accept: application/vnd.czertainly.v2+json`
  - Vantagem: URL limpa
  - Desvantagem: Browsers não suportam; APIs de testing (curl, Postman) precisam header extra
  - Usado por: GitHub, Twitter

- **Query parameter versioning**: `/certificates?api-version=2`
  - Vantagem: Simples
  - Desvantagem: Confunde versioning com filtering; query params para buscas reais fica messy
  - Usado por: Microsoft Azure

- **URI versioning** ✓ (escolhido)
  - Vantagem: Explícito, URL é self-documenting
  - Desvantagem: Copia código entre /api/v1 e /api/v2
  - Usado por: REST API design guides

CZERTAINLY escolheu URI por ser mais explicit e browser-friendly (URL é copied/pasted em tickets, logs, etc).

### Lifecycle: v1 → v2

v1 é deprecated mas mantida por backward compatibility:
- Novos clients deve usar v2
- v1 será removida em major version (e.g., v3.0.0)
- Deprecation warnings em HTTP headers
- Logging de uso de v1 para monitorar migration progress

```
GET /api/v1/certificates
HTTP/1.1 200 OK
Deprecation: true
Sunset: Sun, 31 Dec 2025 23:59:59 GMT  // Quando v1 será removida
Link: </api/v2/certificates>; rel="successor-version"
```

## Certificate Management: REST API

### CertificateManagementController

**BaseURL**: `/api/v2/certificates`

### GET /api/v2/certificates (List Certificates)

```rest
GET /api/v2/certificates?page=0&size=50&subject=example.com&state=ACTIVE
Authorization: Bearer {jwt}
```

Request params:
- `page`: Número da página (0-indexed)
- `size`: Items por página (max 500, default 50)
- `subject`: Filtro por subject DN (partial match)
- `issuer`: Filtro por issuer DN
- `state`: ACTIVE, REVOKED, ARCHIVED
- `raProfile`: Filtro por profile UUID

Response (HTTP 200):
```json
{
  \"content\": [
    {
      \"uuid\": \"550e8400-e29b-41d4-a716-446655440000\",
      \"commonName\": \"www.example.com\",
      \"subject\": \"CN=www.example.com,O=Example Inc\",
      \"issuer\": \"CN=Let's Encrypt Authority X3\",
      \"validFrom\": \"2024-01-01T00:00:00Z\",
      \"validTo\": \"2025-01-01T00:00:00Z\",
      \"serialNumber\": \"01:02:03:04\",
      \"state\": \"ACTIVE\",
      \"fingerprint\": \"sha256:abc123...\"
    }
  ],
  \"pageable\": {
    \"pageNumber\": 0,
    \"pageSize\": 50,
    \"totalElements\": 1234,
    \"totalPages\": 25
  }
}
```

**Backend flow**:
1. Request param parsing + validation
2. `@AuthEndpoint` verifica user tem CERTIFICATE:READ permission
3. ServiceImpl aplica filters via QueryDSL
4. JPA pagina resultados
5. DTOization (Certificate entity → CertificateDto)
6. Response JSON serialization

### GET /api/v2/certificates/{uuid} (Get Certificate Detail)

```rest
GET /api/v2/certificates/550e8400-e29b-41d4-a716-446655440000
Authorization: Bearer {jwt}
```

Response (HTTP 200):
```json
{
  \"uuid\": \"550e8400-e29b-41d4-a716-446655440000\",
  \"commonName\": \"www.example.com\",
  \"subject\": \"CN=www.example.com,O=Example Inc\",
  \"issuer\": \"CN=Let's Encrypt Authority X3\",
  \"validFrom\": \"2024-01-01T00:00:00Z\",
  \"validTo\": \"2025-01-01T00:00:00Z\",
  \"content\": \"-----BEGIN CERTIFICATE-----\\nMIIDXTC...\",  // PEM
  \"chain\": [
    \"-----BEGIN CERTIFICATE-----\\nMIIFxzCC...\",  // Root CA
    \"-----BEGIN CERTIFICATE-----\\nMIIFkjCC...\"   // Intermediate CA
  ],
  \"complianceProfiles\": [\"SOC2_AUDITED\", \"FIPS_APPROVED\"],
  \"owner\": \"user-uuid-123\",
  \"groups\": [\"Production\", \"Web Services\"],
  \"revokedAt\": null,
  \"revocationReason\": null
}
```

Response Error (HTTP 404):
```json
{
  \"code\": \"CERTIFICATE_NOT_FOUND\",
  \"message\": \"Certificate with UUID 550e8400... not found\"
}
```

### POST /api/v2/certificates (Import Certificate)

```rest
POST /api/v2/certificates
Content-Type: application/json
Authorization: Bearer {jwt}

{
  \"certificate\": \"-----BEGIN CERTIFICATE-----\\nMIIDXTC...\",
  \"raProfile\": \"550e8400-e29b-41d4-a716-446655440000\",
  \"groups\": [\"Production\"],
  \"complianceProfiles\": [\"SOC2_AUDITED\"]
}
```

Response (HTTP 201):
```json
{
  \"uuid\": \"550e8400-e29b-41d4-a716-446655440000\",
  \"commonName\": \"www.example.com\",
  \"validTo\": \"2025-01-01T00:00:00Z\"
}
```

Backend logic:
1. Deserializar certificado (PEM ou DER)
2. X.509 parsing via BouncyCastle
3. Validar date (notBefore ≤ now ≤ notAfter)
4. Check duplicate (serial + issuer combination)
5. OPA authorize user pode import para este raProfile
6. Persistir com created_by = current user

### DELETE /api/v2/certificates/{uuid} (Delete Certificate)

```rest
DELETE /api/v2/certificates/550e8400-e29b-41d4-a716-446655440000
Authorization: Bearer {jwt}
```

Response (HTTP 204 No Content)

Flow:
1. Check certificate existe
2. OPA authorize DELETE
3. Soft-delete: certificatedeleted_at = now (não remove fisicamente)
4. Audit log: {module: CERTIFICATE, operation: DELETE, result: SUCCESS}

### POST /api/v2/certificates/{uuid}/revoke (Revoke Certificate)

```rest
POST /api/v2/certificates/550e8400-e29b-41d4-a716-446655440000/revoke
Content-Type: application/json
Authorization: Bearer {jwt}

{
  \"reason\": \"KEY_COMPROMISE\",
  \"comment\": \"Key exposed in GitHub commit\"
}
```

Reason enums (CRL RFC 5280):
- `UNSPECIFIED`
- `KEY_COMPROMISE`
- `CA_COMPROMISE`
- `AFFILIATION_CHANGED`
- `SUPERSEDED`
- `CESSATION_OF_OPERATION`
- `CERTIFICATE_HOLD`
- `REMOVE_FROM_CRL`
- `PRIVILEGE_WITHDRAWN`
- `AA_COMPROMISE`

Response (HTTP 200):
```json
{
  \"uuid\": \"550e8400-e29b-41d4-a716-446655440000\",
  \"revokedAt\": \"2024-03-31T10:30:45Z\",
  \"revocationReason\": \"KEY_COMPROMISE\"
}
```

Backend flow:
1. Check certificate exists
2. Check not already revoked (idempotent—safe to revoke twice)
3. OPA authorize revoke (pode ter policies complexas)
4. certificate.revokedAt = now
5. certificate.revocationReason = reason
6. DB save
7. CRL regenerado (async via RabbitMQ)
8. AuditLog entry com reason
9. Notifications enviadas (subscribers notificados de revogação)

## Protocol-Specific APIs

### ACME Controller (RFC 8555)

**BaseURL**: `/acme`

Endpoints (RFC 8555 standard):
- `GET /acme/directory`: Discovery
- `POST /acme/nonce`: Get single-use nonce
- `POST /acme/new-account`: Account registration/lookup
- `POST /acme/new-order`: Issue new order
- `POST /acme/order/{id}`: Get order status
- `POST /acme/authz/{id}`: Get authorization details
- `POST /acme/challenge/{id}`: Get challenge details
- `POST /acme/challenge/{id}/validate`: Client challenges
- `POST /acme/finalize`: Finalize order com CSR
- `POST /acme/cert/{id}`: Download certificate
- `POST /acme/revoke`: Revoke certificate
- `POST /acme/key-change`: Key rotation

Example: ACME order flow
```
1. POST /acme/new-order {identifiers: [\"example.com\", \"*.example.com\"]}
   → {status: pending, finalize: \"/acme/finalize/...\"}

2. POST /acme/authz/{authz-id}
   → {status: pending, challenges: [{type: \"http-01\", token: \"abc123\"}]}

3. PUT challenge validation file to .well-known/acme-challenge/abc123

4. POST /acme/challenge/abc-id/validate
   → {status: processing}

5. Poll /acme/order/{order-id} until status: ready

6. POST /acme/finalize with CSR
   → {status: processing}

7. GET /acme/cert/{cert-id}
   → PEM certificate
```

### SCEP Controller (RFC 2560)

**BaseURL**: `/scep/{profile}`

Endpoints:
- `GET /scep/{profile}/pkicsrsetup`: Operation discovery
- `GET /scep/{profile}/?operation=GetCACaps`: CA capabilities
- `GET /scep/{profile}/?operation=GetCACert`: CA cert download
- `POST /scep/{profile}/?operation=PKIOperation`: Request/response

### CMP Controller (RFC 4210)

**BaseURL**: `/cmp/{profile}`

Endpoints:
- `POST /cmp/{profile}`: CMP request
- `GET /cmp/{profile}/revocation`: Revocation status

## Common Patterns: Error Handling

### Exception Mapping via @RestControllerAdvice

```java
@RestControllerAdvice
public class ExceptionHandlingAdvice {
    
    @ExceptionHandler(NotFoundException.class)
    public ResponseEntity<ErrorResponse> handleNotFound(
            NotFoundException ex) {
        return ResponseEntity
            .status(HttpStatus.NOT_FOUND)
            .body(new ErrorResponse(\"NOT_FOUND\", ex.getMessage()));
    }
    
    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ErrorResponse> handleAccessDenied(
            AccessDeniedException ex) {
        return ResponseEntity
            .status(HttpStatus.FORBIDDEN)
            .body(new ErrorResponse(\"ACCESS_DENIED\", ex.getMessage()));
    }
    
    @ExceptionHandler(ValidationException.class)
    public ResponseEntity<ErrorResponse> handleValidation(
            ValidationException ex) {
        return ResponseEntity
            .status(HttpStatus.BAD_REQUEST)
            .body(new ErrorResponse(\"VALIDATION_ERROR\", ex.getMessage()));
    }
    
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleGeneric(
            Exception ex) {
        logger.error(\"Unhandled exception\", ex);
        return ResponseEntity
            .status(HttpStatus.INTERNAL_SERVER_ERROR)
            .body(new ErrorResponse(\"INTERNAL_ERROR\", 
                    \"Internal server error\"));
    }
}
```

Error Response format:
```json
{
  \"code\": \"NOT_FOUND\",
  \"message\": \"Certificate not found\",
  \"timestamp\": \"2024-03-31T10:30:45Z\",
  \"path\": \"/api/v2/certificates/\invalid-uuid\",
  \"trace\": \"com.czertainly.core.exception.NotFoundException: ...\",
  \"details\": {
    \"resourceId\": \"invalid-uuid\",
    \"resourceType\": \"Certificate\"
  }
}
```

## OpenAPI/Swagger Documentation

Todos controllers são auto-documentados via Spring Doc OpenAPI:

```java
@Operation(summary = \"Revoke certificate\",
           description = \"Revoke a certificate and add to CRL\")
@ApiResponses({
    @ApiResponse(responseCode = \"200\",
                 description = \"Certificate revoked\"),
    @ApiResponse(responseCode = \"404\",
                 description = \"Certificate not found\"),
    @ApiResponse(responseCode = \"403\",
                 description = \"User lacks revocation permission\")
})
@PostMapping(\"/{uuid}/revoke\")
public CertificateDto revokeCertificate(
    @PathVariable
    @Parameter(description = \"Certificate UUID\")
    UUID uuid,
    
    @RequestBody
    @io.swagger.v3.oas.annotations.parameters.RequestBody(
        description = \"Revocation request with reason\"
    )
    RevokeRequestDto request
) { ... }
```

Swagger UI available at: `/swagger-ui.html`
OpenAPI 3.0 JSON at: `/v3/api-docs`

---

## 4.2 Web API Controllers

### CertificateManagementController

**Path**: `com.czertainly.core.api.web.CertificateManagementControllerImpl`  
**Base URL**: `/api/v2/certificates`

**Endpoints**:

```java
/**
 * GET /api/v2/certificates
 * Lista certificados com paginação e filtros
 */
@GetMapping
@AuthEndpoint(resourceName = "CERTIFICATE", permissions = {"READ"})
public Page<CertificateDto> listCertificates(
    @RequestParam(defaultValue = "0") int page,
    @RequestParam(defaultValue = "50") int size,
    @RequestParam(required = false) String subject,
    @RequestParam(required = false) String issuer,
    @RequestParam(required = false) CertificateState state
) {
    // Retorna Page com CertificateDto
}

/**
 * GET /api/v2/certificates/{uuid}
 * Detalha um certificado específico
 */
@GetMapping("/{uuid}")
@AuthEndpoint(resourceName = "CERTIFICATE", permissions = {"READ"})
public CertificateDetailDto getCertificate(@PathVariable UUID uuid) {
    // Retorna CertificateDetailDto com content, chain, etc
}

/**
 * DELETE /api/v2/certificates/{uuid}
 * Remove certificado
 */
@DeleteMapping("/{uuid}")
@AuthEndpoint(resourceName = "CERTIFICATE", permissions = {"DELETE"})
@AuditLogged(module = Module.CERTIFICATE_MANAGEMENT, operation = Operation.DELETE)
public void deleteCertificate(@PathVariable UUID uuid) {
    // Delete logic
}

/**
 * POST /api/v2/certificates/{uuid}/revoke
 * Revoga certificado (com especificação de motivo)
 */
@PostMapping("/{uuid}/revoke")
@AuthEndpoint(resourceName = "CERTIFICATE", permissions = {"DELETE"})
@AuditLogged(module = Module.CERTIFICATE_MANAGEMENT, operation = Operation.REVOKE)
public CertificateDto revokeCertificate(
    @PathVariable UUID uuid,
    @RequestBody RevokeRequestDto request
) {
    // RevocationReason handling
}

/**
 * POST /api/v2/certificates/search
 * Busca avançada com múltiplos critérios
 */
@PostMapping("/search")
public Page<CertificateDto> searchCertificates(
    @RequestBody SearchRequestDto searchRequest,
    Pageable pageable
) {
    // QueryDSL-based search
}

/**
 * GET /api/v2/certificates/{uuid}/export
 * Exporta certificado em diferentes formatos
 */
@GetMapping("/{uuid}/export")
public ResponseEntity<byte[]> exportCertificate(
    @PathVariable UUID uuid,
    @RequestParam(defaultValue = "PEM") ExportFormat format
) {
    // Exporta em PEM, DER, PKCS12, etc
}
```

### CryptographicKeyManagementController

**Path**: `com.czertainly.core.api.web.CryptographicKeyManagementControllerImpl`  
**Base URL**: `/api/v2/cryptographic-keys`

**Endpoints**:

```java
/**
 * GET /api/v2/cryptographic-keys
 * Lista todas as chaves criptográficas
 */
@GetMapping
@AuthEndpoint(resourceName = "CRYPTOGRAPHIC_KEY", permissions = {"READ"})
public Page<CryptographicKeyDto> listKeys(Pageable pageable) {
    // Keys listing with filtering
}

/**
 * POST /api/v2/cryptographic-keys
 * Cria nova chave criptográfica (local ou delegada ao conector)
 */
@PostMapping
@AuthEndpoint(resourceName = "CRYPTOGRAPHIC_KEY", permissions = {"CREATE"})
@AuditLogged(module = Module.KEY_MANAGEMENT, operation = Operation.CREATE)
public CryptographicKeyDetailDto createKey(
    @RequestBody CryptographicKeyRequestDto request
) {
    // Delegate to connector if external provider
}

/**
 * GET /api/v2/cryptographic-keys/{uuid}/items
 * Lista itens (diferentes formatos) da mesma chave
 */
@GetMapping("/{uuid}/items")
@AuthEndpoint(resourceName = "CRYPTOGRAPHIC_KEY", permissions = {"READ"})
public List<CryptographicKeyItemDto> getKeyItems(
    @PathVariable UUID uuid
) {
    // Returns key variants: RAW, X.509, PKCS#8, etc
}

/**
 * POST /api/v2/cryptographic-keys/{uuid}/sign
 * Assina dados com a chave privada
 */
@PostMapping("/{uuid}/sign")
@AuthEndpoint(resourceName = "CRYPTOGRAPHIC_KEY", permissions = {"SIGN"})
@AuditLogged(module = Module.CRYPTOGRAPHIC_OPERATIONS, operation = Operation.SIGN)
public SignatureResponseDto sign(
    @PathVariable UUID uuid,
    @RequestBody SignRequestDto request
) {
    // Signature operation (local or delegate to HSM)
}

/**
 * POST /api/v2/cryptographic-keys/{uuid}/verify
 * Verifica assinatura com chave pública
 */
@PostMapping("/{uuid}/verify")
@AuthEndpoint(resourceName = "CRYPTOGRAPHIC_KEY", permissions = {"VERIFY"})
public VerificationResponseDto verify(
    @PathVariable UUID uuid,
    @RequestBody VerificationRequestDto request
) {
    // Verification: true/false
}
```

### ConnectorController

**Path**: `com.czertainly.core.api.web.v2.ConnectorControllerImpl`  
**Base URL**: `/api/v2/connectors`

**Endpoints**:

```java
/**
 * GET /api/v2/connectors
 * Lista todos os conectores registrados
 */
@GetMapping
@AuthEndpoint(resourceName = "CONNECTOR", permissions = {"READ"})
public List<ConnectorDto> listConnectors() {
    // List with health status
}

/**
 * POST /api/v2/connectors
 * Registra novo conector (geralmente auto-registration)
 */
@PostMapping
@AuthEndpoint(resourceName = "CONNECTOR", permissions = {"CREATE"})
@AuditLogged(module = Module.CONNECTOR_MANAGEMENT, operation = Operation.CREATE)
public ConnectorDetailDto createConnector(
    @RequestBody ConnectorRequestDto request
) {
    // Setup connector
}

/**
 * GET /api/v2/connectors/{uuid}
 * Detalha conector (endpoints, função groups, etc)
 */
@GetMapping("/{uuid}")
@AuthEndpoint(resourceName = "CONNECTOR", permissions = {"READ"})
public ConnectorDetailDto getConnector(@PathVariable UUID uuid) {
    // Full details
}

/**
 * POST /api/v2/connectors/{uuid}/connect
 * Testa conectividade com conector
 */
@PostMapping("/{uuid}/connect")
@AuthEndpoint(resourceName = "CONNECTOR", permissions = {"CONNECT"})
@AuditLogged(module = Module.CONNECTOR_MANAGEMENT, operation = Operation.CONNECT)
public ConnectivityStatusDto testConnection(
    @PathVariable UUID uuid
) {
    // HTTP GET conector:/health
}

/**
 * GET /api/v2/connectors/{uuid}/function-groups
 * Descobre function groups suportadas
 */
@GetMapping("/{uuid}/function-groups")
@AuthEndpoint(resourceName = "CONNECTOR", permissions = {"READ"})
public List<FunctionGroupDto> getFunctionGroups(
    @PathVariable UUID uuid
) {
    // CA, CRYPTOGRAPHY_KEY_MANAGEMENT, etc
}

/**
 * DELETE /api/v2/connectors/{uuid}
 * Remove conector
 */
@DeleteMapping("/{uuid}")
@AuthEndpoint(resourceName = "CONNECTOR", permissions = {"DELETE"})
@AuditLogged(module = Module.CONNECTOR_MANAGEMENT, operation = Operation.DELETE)
public void deleteConnector(@PathVariable UUID uuid) {
    // Unregister connector
}
```

### RaProfileManagementController

**Path**: `com.czertainly.core.api.web.RaProfileManagementControllerImpl`  
**Base URL**: `/api/v2/ra-profiles`

**Endpoints**:

```java
/**
 * POST /api/v2/ra-profiles
 * Cria novo RA Profile (associa CA, protocolos, etc)
 */
@PostMapping
@AuthEndpoint(resourceName = "RA_PROFILE", permissions = {"CREATE"})
@AuditLogged(module = Module.PROFILE_MANAGEMENT, operation = Operation.CREATE)
public RaProfileDetailDto createRaProfile(
    @RequestBody RaProfileRequestDto request
) {
    // Create with associated CA connector + attributes
}

/**
 * GET /api/v2/ra-profiles/{uuid}/attributes
 * Carrega atributos dinâmicos do perfil (dependentes da CA)
 */
@GetMapping("/{uuid}/attributes")
public List<RequestAttribute> getRaProfileAttributes(
    @PathVariable UUID uuid
) {
    // CA-specific attributes schema
}

/**
 * PUT /api/v2/ra-profiles/{uuid}/attributes
 * Atualiza valores de atributos
 */
@PutMapping("/{uuid}/attributes")
@AuditLogged(module = Module.PROFILE_MANAGEMENT, operation = Operation.UPDATE)
public RaProfileDetailDto updateRaProfileAttributes(
    @PathVariable UUID uuid,
    @RequestBody List<RequestAttribute> attributes
) {
    // Callback ao conector para validação se necessário
}
```

### LocationManagementController

**Path**: `com.czertainly.core.api.web.LocationManagementControllerImpl`  
**Base URL**: `/api/v2/locations`

**Endpoints**:

```java
/**
 * POST /api/v2/locations
 * Cria localização (referência ao entity provider)
 */
@PostMapping
@AuthEndpoint(resourceName = "LOCATION", permissions = {"CREATE"})
@AuditLogged(module = Module.LOCATION_MANAGEMENT, operation = Operation.CREATE)
public LocationDetailDto createLocation(
    @RequestBody LocationRequestDto request
) {
    // Associate with EntityInstanceReference + attributes
}

/**
 * POST /api/v2/locations/{uuid}/push/{certificateUuid}
 * Empurra certificado para localização
 * (envia cert para física storage via entity provider)
 */
@PostMapping("/{uuid}/push/{certificateUuid}")
@AuthEndpoint(resourceName = "LOCATION", permissions = {"WRITE"})
@AuditLogged(module = Module.LOCATION_MANAGEMENT, operation = Operation.PUSH)
public OperationResultDto pushCertificateToLocation(
    @PathVariable UUID uuid,
    @PathVariable UUID certificateUuid
) {
    // Entity provider callback
}
```

### GroupController

**Path**: `com.czertainly.core.api.web.GroupControllerImpl`  
**Base URL**: `/api/v2/groups`

**Endpoints**:

```java
/**
 * POST /api/v2/groups
 * Cria novo grupo de certificados
 */
@PostMapping
@AuthEndpoint(resourceName = "GROUP", permissions = {"CREATE"})
@AuditLogged(module = Module.GROUP_MANAGEMENT, operation = Operation.CREATE)
public GroupDetailDto createGroup(
    @RequestBody GroupRequestDto request
) {
    // Create group
}

/**
 * POST /api/v2/groups/{uuid}/certificates/{certificateUuid}
 * Adiciona certificado ao grupo
 */
@PostMapping("/{uuid}/certificates/{certificateUuid}")
@AuthEndpoint(resourceName = "GROUP", permissions = {"UPDATE"})
public GroupDetailDto addCertificateToGroup(
    @PathVariable UUID uuid,
    @PathVariable UUID certificateUuid
) {
    // ManyToMany association
}

/**
 * DELETE /api/v2/groups/{uuid}/certificates/{certificateUuid}
 * Remove certificado do grupo
 */
@DeleteMapping("/{uuid}/certificates/{certificateUuid}")
@AuthEndpoint(resourceName = "GROUP", permissions = {"UPDATE"})
public GroupDetailDto removeCertificateFromGroup(
    @PathVariable UUID uuid,
    @PathVariable UUID certificateUuid
) {
    // Remove association
}
```

### ApprovalController

**Path**: `com.czertainly.core.api.web.ApprovalControllerImpl`  
**Base URL**: `/api/v2/approvals`

**Endpoints**:

```java
/**
 * GET /api/v2/approvals?status=PENDING
 * Lista aprovações pendentes (para o usuário atual)
 */
@GetMapping
@AuthEndpoint(resourceName = "APPROVAL", permissions = {"READ"})
public List<ApprovalDto> getPendingApprovalsForUser() {
    // Multi-step approval workflow
}

/**
 * PUT /api/v2/approvals/{uuid}/approve
 * Aprova uma etapa
 */
@PutMapping("/{uuid}/approve")
@AuthEndpoint(resourceName = "APPROVAL", permissions = {"APPROVE"})
@AuditLogged(module = Module.APPROVAL_MANAGEMENT, operation = Operation.APPROVE)
public ApprovalDetailDto approveStep(
    @PathVariable UUID uuid,
    @RequestBody ApprovalRequestDto request
) {
    // Mark step APPROVED
}

/**
 * PUT /api/v2/approvals/{uuid}/reject
 * Rejeita uma etapa
 */
@PutMapping("/{uuid}/reject")
@AuthEndpoint(resourceName = "APPROVAL", permissions = {"APPROVE"})
@AuditLogged(module = Module.APPROVAL_MANAGEMENT, operation = Operation.REJECT)
public ApprovalDetailDto rejectStep(
    @PathVariable UUID uuid,
    @RequestBody RejectionRequestDto request
) {
    // Mark step REJECTED
}
```

### NotificationController

**Path**: `com.czertainly.core.api.web.NotificationControllerImpl`  
**Base URL**: `/api/v2/notifications`

**Endpoints**:

```java
/**
 * GET /api/v2/notifications
 * Lista notificações do usuário
 */
@GetMapping
public Page<NotificationDto> getNotifications(Pageable pageable) {
    // In-app notifications
}

/**
 * PUT /api/v2/notifications/{uuid}/read
 * Marca notificação como lida
 */
@PutMapping("/{uuid}/read")
public NotificationDto markAsRead(@PathVariable UUID uuid) {
    // Update read status
}
```

### StatisticsController

**Path**: `com.czertainly.core.api.web.StatisticsControllerImpl`  
**Base URL**: `/api/v2/statistics`

**Endpoints**:

```java
/**
 * GET /api/v2/statistics/dashboard
 * Retorna métricas para dashboard
 */
@GetMapping("/dashboard")
public DashboardStatisticsDto getDashboardStatistics() {
    // Total certs, expiring, revoked, by algorithm, etc
}

/**
 * GET /api/v2/statistics/certificate-trends
 * Tendências de certificados por período
 */
@GetMapping("/trends")
public CertificateTrendsDto getCertificateTrends(
    @RequestParam(defaultValue = "30") int days
) {
    // Time-series data
}
```

---

## 4.3 Protocol APIs

### ACME Controller

**Path**: `com.czertainly.core.api.acme.AcmeControllerImpl`  
**Base URL**: `/acme` (RFC 8555)

**Endpoints**:

```java
/**
 * GET /acme/directory
 * ACME Directory discovery
 * (RFC 8555 Section 7.1.1)
 */
@GetMapping("/directory")
public AcmeDirectoryDto getDirectory() {
    // newNonce, newAccount, newOrder, revokeCert endpoints
}

/**
 * HEAD /acme/nonce
 * Gera nonce (anti-replay)
 */
@HeadMapping("/nonce")
public void getNonce(HttpServletResponse response) {
    // Set Replay-Nonce header
}

/**
 * POST /acme/new-account
 * Cria ou busca account ACME
 */
@PostMapping("/new-account")
public AcmeAccountDto newAccount(
    @RequestBody AcmeAccountRequest request
) {
    // Account creation with contact info
}

/**
 * POST /acme/new-order
 * Cria nova order de certificado
 */
@PostMapping("/new-order")
public AcmeOrderDto newOrder(
    @RequestBody AcmeOrderRequest request
) {
    // Identifiers, notBefore, notAfter
}

/**
 * POST /acme/authz/{authzId}
 * Retorna status de autorização + challenges
 */
@PostMapping("/authz/{authzId}")
public AcmeAuthorizationDto getAuthorization(
    @PathVariable String authzId
) {
    // Pending challenges
}

/**
 * POST /acme/challenge/{challengeId}/validate
 * Valida challenge (http-01, dns-01, etc)
 */
@PostMapping("/challenge/{challengeId}/validate")
public void validateChallenge(
    @PathVariable String challengeId
) {
    // Server-side challenge validation
}

/**
 * POST /acme/finalize/{orderId}
 * Finaliza order com CSR
 */
@PostMapping("/finalize/{orderId}")
public AcmeOrderDto finalizeOrder(
    @PathVariable String orderId,
    @RequestBody AcmeFinalizeRequest request
) {
    // CSR submission → certificate issuance
}

/**
 * POST /acme/cert/{certId}
 * Download certificado emitido
 */
@PostMapping("/cert/{certId}")
public ResponseEntity<byte[]> downloadCertificate(
    @PathVariable String certId
) {
    // PEM-encoded certificate
}
```

### SCEP Controller

**Path**: `com.czertainly.core.api.scep.ScepControllerImpl`  
**Base URL**: `/scep/{profileName}` (RFC 2560)

**Endpoints**:

```java
/**
 * GET /scep/{profileName}/pkicsrsetup
 * Capabilities discovery
 * (SCEP proprietary endpoint)
 */
@GetMapping("/pkicsrsetup")
public ScepCapabilitiesDto getPkicsrSetup() {
    // Supported algorithms, key formats, etc
}

/**
 * POST /scep/{profileName}?operation=PKIOperation
 * Main SCEP request/response
 * (RFC 2560 Section 3.2.1)
 */
@PostMapping
@RequestParam(name = "operation", defaultValue = "PKIOperation")
public byte[] handleScepOperation(
    @PathVariable String profileName,
    @RequestBody byte[] scepRequest
) {
    // PKCSReq → PKCSRep processing
}
```

### CMP Controller

**Path**: `com.czertainly.core.api.cmp.CmpControllerImpl`  
**Base URL**: `/cmp` (RFC 4210)

**Endpoints**:

```java
/**
 * POST /cmp
 * CMP PDU processing
 * (RFC 4210 Section 5.1.3)
 */
@PostMapping
@RequestParam(name = "operation")
public ResponseEntity<byte[]> handleCmpOperation(
    @RequestBody byte[] cmpRequest
) {
    // PKIData → PKIResponse processing
}
```

---

## 4.4 Connector Callbacks

### CallbackController

**Path**: `com.czertainly.core.api.connector.CallbackControllerImpl`  
**Base URL**: `/v1/connector/callback`

**Endpoints**:

```java
/**
 * POST /v1/connector/callback/get-attributes
 * Conector solicita definição de atributos
 */
@PostMapping("/get-attributes")
public List<AttributeDefinition> getAttributes(
    @RequestBody AttributeRequest request
) {
    // Connector-specific attribute schema
}

/**
 * POST /v1/connector/callback/validate-attributes
 */
@PostMapping("/validate-attributes")
public AttributeValidationResponse validateAttributes(
    @RequestBody AttributeValidationRequest request
) {
    // Server-side validation callback
}

/**
 * POST /v1/connector/callback/connector-discovery-state
 */
@PostMapping("/connector-discovery-state")
@AuditLogged(module = Module.DISCOVERY, operation = Operation.DISCOVERY_STATE_UPDATE)
public void updateDiscoveryState(
    @RequestBody DiscoveryStateUpdateRequest request
) {
    // Update connector's discovery state
}
```

---

## 4.5 DTO Patterns

### Request DTOs

```java
@Data
public class CertificateRequestDto {
    private String commonName;
    private String subjectDN;
    private String issuerDN;
    private LocalDateTime validFrom;
    private LocalDateTime validTo;
    private List<RequestAttribute> attributes;
}

@Data
public class SearchRequestDto {
    private String keyword;  // Multi-field search
    private Map<String, Object> filters;  // +10 filtros customizáveis
    private int page = 0;
    private int size = 50;
    private String sort;  // field + direction
    private String sortDirection;  // ASC or DESC
}
```

### Response DTOs

```java
@Data
public class CertificateDto {
    private UUID uuid;
    private String commonName;
    private String subject;
    private String issuer;
    private LocalDateTime validFrom;
    private LocalDateTime validTo;
    private CertificateState state;
}

@Data
public class CertificateDetailDto extends CertificateDto {
    private byte[] certificateContent;  // PEM/DER
    private List<CertificateDto> chain;  // CA chain
    private CryptographicKeyDto key;
    private List<LocationDto> locations;
    private List<GroupDto> groups;
    private List<ComplianceProfileDto> complianceProfiles;
}

@Data
public class PaginationResponseDto<T> {
    private List<T> content;
    private int page;
    private int size;
    private long total;
    private int totalPages;
}
```

---

## 4.6 Exception Handling

**Classe**: `com.czertainly.core.api.ExceptionHandlingAdvice`

```java
@RestControllerAdvice
public class ExceptionHandlingAdvice {
    
    @ExceptionHandler(NotFoundException.class)
    public ResponseEntity<ErrorMessageDto> handleNotFound(
            NotFoundException ex) {
        return ResponseEntity
            .status(HttpStatus.NOT_FOUND)
            .body(new ErrorMessageDto("Resource not found", ex.getMessage()));
    }
    
    @ExceptionHandler(ValidationException.class)
    public ResponseEntity<ErrorMessageDto> handleValidation(
            ValidationException ex) {
        return ResponseEntity
            .status(HttpStatus.BAD_REQUEST)
            .body(new ErrorMessageDto("Validation error", ex.getMessage()));
    }
    
    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ErrorMessageDto> handleAccessDenied(
            AccessDeniedException ex) {
        return ResponseEntity
            .status(HttpStatus.FORBIDDEN)
            .body(new ErrorMessageDto("Access denied", ex.getMessage()));
    }
    
    @ExceptionHandler(AttributeException.class)
    public ResponseEntity<ErrorMessageDto> handleAttribute(
            AttributeException ex) {
        return ResponseEntity
            .status(HttpStatus.UNPROCESSABLE_ENTITY)
            .body(new ErrorMessageDto("Attribute error", ex.getMessage()));
    }
    
    @ExceptionHandler(ConnectorException.class)
    public ResponseEntity<ErrorMessageDto> handleConnector(
            ConnectorException ex) {
        return ResponseEntity
            .status(HttpStatus.SERVICE_UNAVAILABLE)
            .body(new ErrorMessageDto("Connector error", ex.getMessage()));
    }
}
```

---

## 4.7 API Documentation

**Framework**: Spring Doc OpenAPI 3.0 (Swagger)

**Endpoints**:
- `/v3/api-docs`: OpenAPI raw JSON
- `/swagger-ui.html`: Interactive UI

**Auto-generated via**:
- `@Operation`: Endpoint summary/description
- `@Parameter`: Path/query parameter docs
- `@Schema`: DTO field documentation
- `@ApiResponse`: Possible responses

---

## Resumo de Controllers

| Endpoint | Métodos | Resources |
|----------|---------|-----------|
| `/api/v2/certificates` | 12+ | Certificate CRUD, revocation, export |
| `/api/v2/cryptographic-keys` | 10+ | Key CRUD, sign, verify |
| `/api/v2/connectors` | 8+ | Connector management + discovery |
| `/api/v2/ra-profiles` | 6+ | RA Profile configuration |
| `/api/v2/locations` | 6+ | Location management + push |
| `/api/v2/groups` | 5+ | Group management |
| `/api/v2/approvals` | 5+ | Approval workflow |
| `/api/v2/notifications` | 3+ | User notifications |
| `/api/v2/statistics` | 4+ | Dashboard metrics |
| `/acme/**` | 8+ | ACME protocol (RFC 8555) |
| `/scep/**` | 3+ | SCEP protocol (RFC 2560) |
| `/cmp` | 2+ | CMP protocol (RFC 4210) |

**Total**: 30+ controllers, 75+ endpoints, 100% RESTful

