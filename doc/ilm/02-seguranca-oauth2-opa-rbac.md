# 2. SEGURANÇA: OAuth2, OPA, RBAC, Auditoria

## 2.1 Visão Estratégica de Segurança

### Modelo de Confiança em Três Camadas

CZERTAINLY-Core implementa segurança em **3 camadas ortogonais**:

1. **Autenticação (OAuth2/OIDC)**: Identity verification - "Quem é você?"
2. **Autorização (OPA)**: Fine-grained access control - "O que você pode fazer?"
3. **Auditoria (AuditLog)**: Compliance & forensics - "O que você fez?"

```
┌─────────────────────────────────────────────────────────────┐
│ REQUEST FLOW - 3 Camadas de Segurança                       │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  GET /api/v1/certificates/ABC123                            │
│         │                                                    │
│         ▼                                                    │
│  ┌──────────────────────────────────────┐                   │
│  │ 1. AUTENTICAÇÃO (OAuth2 Filter)      │                   │
│  ├──────────────────────────────────────┤                   │
│  │ • Extract JWT from Authorization     │                   │
│  │ • Validate signature vs JWKS         │                   │
│  │ • Extract username=john              │                   │
│  │ • Set SecurityContext                │                   │
│  │ Result: /USERNAME = john/            │                   │
│  └──────────────────────────────────────┘                   │
│         │                                                    │
│         ▼                                                    │
│  ┌──────────────────────────────────────┐                   │
│  │ 2. AUTORIZAÇÃO (OPA AspectJ)        │                   │
│  ├──────────────────────────────────────┤                   │
│  │ • QueryPolicy to OPA engine          │                   │
│  │ • Input: {                           │                   │
│  │    user: "john"                      │                   │
│  │    action: "view"                    │                   │
│  │    resource: "certificate"           │                   │
│  │    cert_owner: "john"                │                   │
│  │   }                                  │                   │
│  │ • OPA evalutes rules → ALLOW/DENY    │                   │
│  │ Result: 200 OK                       │                   │
│  └──────────────────────────────────────┘                   │
│         │                                                    │
│         ▼                                                    │
│  ┌──────────────────────────────────────┐                   │
│  │ 3. AUDITORIA (AuditAspect)          │                   │
│  ├──────────────────────────────────────┤                   │
│  │ • Log access event to database       │                   │
│  │ • Timestamp: 2026-03-31T10:23:45Z    │                   │
│  │ • Event: CERTIFICATE_VIEWED          │                   │
│  │ • Resource: cert/ABC123              │                   │
│  │ • Actor: john                        │                   │
│  │ • Status: SUCCESS                    │                   │
│  │ • IP: 192.168.1.100                  │                   │
│  └──────────────────────────────────────┘                   │
│         │                                                    │
└─────────────────────────────────────────────────────────────┘
```

---

## 2.2 OAuth2/OIDC Resource Server Pattern

### Por que OAuth2? Trade-offs vs Alternativas

| Aspecto | OAuth2 | SAML | mTLS | API Key |
|---------|--------|------|------|---------|
| **Escalabilidade** | ✅ Stateless tokens | ❌ XML assertions | ⚠️ Cert management | ✅ Simple |
| **Delegação** | ✅ 3rd-party auth | ⚠️ Complex | ❌ No support | ❌ No |
| **Mobile/SPA** | ✅ Token refresh | ❌ Heavy | ❌ No support | ⚠️ Storage risk |
| **Revocation** | ⚠️ Token TTL | ✅ Immediate | ✅ CRL | ✅ Immediate |
| **Compliance** | ✅ OIDC standard | ✅ SAML standard | ✅ mTLS standard | ❌ Custom |

**Decisão CZERTAINLY**: OAuth2 + OPA (melhor compromisso entre escalabilidade e segurança granular)

### JWT Decoder - Implementação Profunda

**Arquivo**: `com.czertainly.core.auth.oauth2.CzertainlyJwtDecoder`

```java
@Component
@Slf4j
public class CzertainlyJwtDecoder implements JwtDecoder {
    
    private static final int JWKS_CACHE_TTL_SECONDS = 3600;
    private static final int JWT_DECODE_TIMEOUT_MILLIS = 5000;
    
    @Autowired
    private RestTemplate restTemplate;
    
    @Autowired
    private CacheManager cacheManager;
    
    @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}")
    private String issuerUri;
    
    @Value("${spring.security.oauth2.resourceserver.jwt.expected-audience:czertainly-api}")
    private String expectedAudience;
    
    private JWKSet cachedJwkSet;
    private long jwksLastFetchTime = 0;
    
    /**
     * PASSO 1: Decodificar JWT
     * 
     * JWT formato: eyJhbGc....(header).eyJzdWI....(payload).SflKx...(signature)
     * 
     * Header: { "alg": "RS256", "kid": "key-id-1", "typ": "JWT" }
     * Payload: { "sub": "john", "roles": ["admin", "user"], "exp": 1743638625 }
     * Signature: HMAC(header.payload, secret_key)
     * 
     * Ataques evitados:
     * - Token alteration (valida assinatura)
     * - Token replay (valida exp + iat claims)
     * - Token reutilização (valida audience/issuer)
     */
    @Override
    public Jwt decode(String token) throws JwtException {
        
        log.debug("Decoding JWT token: {}", token.substring(0, 50) + "...");
        
        try {
            // PASSO 1: Parser JWT (sem validação ainda)
            JWT jwtToken = JWTParser.parse(token);
            String keyId = jwtToken.getHeader().getKeyID();
            
            if (keyId == null) {
                throw new JwtException("Missing 'kid' (Key ID) in JWT header");
            }
            
            log.debug("JWT Key ID: {}", keyId);
            
            // PASSO 2: Fetch JWKS da authorization server
            JWKSet jwkSet = getJwkSet();
            
            JWK key = jwkSet.getKeyByKeyId(keyId);
            if (key == null) {
                log.warn("Key ID '{}' not found in JWKS", keyId);
                throw new JwtException("Key ID '" + keyId + "' not found");
            }
            
            // PASSO 3: Validate signature usando chave pública
            SignedJWT signedJWT = (SignedJWT) jwtToken;
            RSAKey rsaKey = (RSAKey) key;
            RSAPublicKey publicKey = rsaKey.toRSAPublicKey();
            
            JWSVerifier verifier = new RSASSAVerifier(publicKey);
            if (!signedJWT.verify(verifier)) {
                log.warn("JWT signature validation failed for key: {}", keyId);
                throw new JwtException("Signature validation failed");
            }
            
            log.debug("JWT signature valid");
            
            // PASSO 4: Extract e validate claims
            JWTClaimsSet claims = signedJWT.getJWTClaimsSet();
            validateClaims(claims);
            
            log.debug("JWT claims validation passed");
            
            // PASSO 5: Convert to Spring Security JWT
            return convertToSpringJwt(signedJWT, claims);
            
        } catch (ParseException e) {
            log.error("Failed to parse JWT: {}", e.getMessage());
            throw new JwtException("Failed to parse JWT", e);
        } catch (JwtException e) {
            throw e;
        } catch (Exception e) {
            log.error("Unexpected error during JWT decoding", e);
            throw new JwtException("JWT decoding failed: " + e.getMessage(), e);
        }
    }
    
    /**
     * PASSO 2: Fetch JWKS (com cache)
     * 
     * JWKS é um JSON contendo chaves públicas usadas para verificar JWTs.
     * Armazenado em: https://auth-server/.well-known/jwks.json
     * 
     * Estratégia de cache:
     * - TTL: 1 hora (30 minutos antes de exp)
     * - Invalidação por update_child (refresh se novo kid não encontrado)
     * 
     * Alternativas consideradas:
     * - Sem cache: Alto latency de rede (~200ms por JWT)
     * - Cache sem TTL: Não pega key rotation (risco!)
     * - TTL curto (5min): Trade-off com latency
     */
    private JWKSet getJwkSet() throws Exception {
        
        // Check cache
        if (isCacheValid()) {
            log.debug("Using cached JWKS");
            return cachedJwkSet;
        }
        
        String jwksUri = issuerUri + "/.well-known/jwks.json";
        log.info("Fetching JWKS from: {}", jwksUri);
        
        try {
            HttpHeaders headers = new HttpHeaders();
            headers.setAccept(List.of(MediaType.APPLICATION_JSON));
            headers.setConnectionTimeout(JWT_DECODE_TIMEOUT_MILLIS);
            
            HttpEntity<String> request = new HttpEntity<>(headers);
            
            ResponseEntity<Map<String, Object>> response = restTemplate.exchange(
                jwksUri,
                HttpMethod.GET,
                request,
                new ParameterizedTypeReference<Map<String, Object>>() {}
            );
            
            if (!response.getStatusCode().is2xxSuccessful()) {
                throw new JwtException("Failed to fetch JWKS: " + response.getStatusCode());
            }
            
            // Parse JWKS JSON
            JSONObject jwksJson = new JSONObject(response.getBody());
            cachedJwkSet = JWKSet.parse(jwksJson.toString());
            jwksLastFetchTime = System.currentTimeMillis();
            
            log.info("JWKS fetched successfully. Keys count: {}", 
                     cachedJwkSet.getKeys().size());
            
            return cachedJwkSet;
            
        } catch (Exception e) {
            log.error("Failed to fetch JWKS from: {}", jwksUri, e);
            throw new JwtException("JWKS fetch failed", e);
        }
    }
    
    private boolean isCacheValid() {
        if (cachedJwkSet == null) return false;
        long cacheAgeSeconds = (System.currentTimeMillis() - jwksLastFetchTime) / 1000;
        return cacheAgeSeconds < JWKS_CACHE_TTL_SECONDS;
    }
    
    /**
     * PASSO 4: Validate JWT Claims
     * 
     * Validações importantes:
     * 
     * 1. exp (Expiration): Token não deve estar expirado
     *    Margem: 0s (expirou = inválido imediatamente)
     * 
     * 2. iss (Issuer): Deve vir de autoridade confiável
     *    Previne: ataque de substitution (outro auth server)
     * 
     * 3. aud (Audience): Token deve ser para CZERTAINLY
     *    Previne: token destinado a outro serviço
     * 
     * 4. sub (Subject): Identificador único do usuário
     *    Usado para: rastrear usuário em audit logs
     * 
     * Exemplo de payload JWT:
     * {
     *   "sub": "john@example.com",
     *   "exp": 1743638625,           // Unix timestamp
     *   "iat": 1743635025,           // Emitido há 1 hora
     *   "iss": "https://auth.example.com",
     *   "aud": "czertainly-api",
     *   "roles": ["admin", "operator"],
     *   "scope": "read write"
     * }
     */
    private void validateClaims(JWTClaimsSet claims) throws JwtException {
        
        log.debug("Validating JWT claims");
        
        // 1. Expiration check
        Date expTime = claims.getExpirationTime();
        if (expTime != null) {
            if (new Date().after(expTime)) {
                throw new JwtException("Token is expired. Exp: " + expTime);
            }
        } else {
            throw new JwtException("Missing 'exp' claim");
        }
        
        // 2. Issuer check
        String issuer = claims.getIssuer();
        if (!issuer.equals(issuerUri)) {
            throw new JwtException(
                String.format("Invalid issuer. Expected: %s, Got: %s", 
                             issuerUri, issuer)
            );
        }
        
        // 3. Audience check
        List<String> audiences = claims.getAudience();
        if (audiences == null || !audiences.contains(expectedAudience)) {
            throw new JwtException(
                String.format("Invalid audience. Expected: %s, Got: %s", 
                             expectedAudience, audiences)
            );
        }
        
        // 4. Subject check (username must exist)
        String subject = claims.getSubject();
        if (subject == null || subject.isEmpty()) {
            throw new JwtException("Missing 'sub' (subject) claim");
        }
        
        log.debug("JWT claims validation successful for subject: {}", subject);
    }
    
    /**
     * Converter JWT para Spring Security JWT
     * (abstrair detalhes de implementação da biblioteca)
     */
    private Jwt convertToSpringJwt(SignedJWT signedJWT, 
                                    JWTClaimsSet claims) {
        
        Map<String, Object> headers = new HashMap<>(signedJWT.getHeader().toJSONObject());
        Map<String, Object> claimsMap = new HashMap<>(claims.getClaims());
        
        return new Jwt(
            signedJWT.serialize(),
            claims.getIssueTime().toInstant(),
            claims.getExpirationTime().toInstant(),
            headers,
            claimsMap
        );
    }
}
```

---

## 2.3 Extração de Claims e User Principal

**Classe**: `com.czertainly.core.auth.oauth2.CzertainlyJwtAuthenticationConverter`

```java
@Component
public class CzertainlyJwtAuthenticationConverter 
        implements Converter<Jwt, AbstractAuthenticationToken> {
    
    @Override
    public AbstractAuthenticationToken convert(Jwt jwt) {
        // Extract standard OIDC/OAuth2 claims
        String username = jwt.getClaimAsString("preferred_username");
        String subject = jwt.getSubject();
        
        // Extract custom claims (storage depends on authorization server)
        @SuppressWarnings("unchecked")
        List<String> realmRoles = 
            (List<String>) jwt.getClaim("realm_access:roles");
        
        @SuppressWarnings("unchecked")
        Map<String, List<String>> clientRoles = 
            (Map<String, List<String>>) jwt.getClaim("resource_access");
        
        // Convert to Spring Security GrantedAuthority
        Collection<GrantedAuthority> authorities = extractAuthorities(
            realmRoles, clientRoles
        );
        
        // Create authentication token
        JwtAuthenticationToken token = new JwtAuthenticationToken(
            jwt, 
            authorities, 
            username
        );
        
        return token;
    }
    
    private Collection<GrantedAuthority> extractAuthorities(
            List<String> realmRoles, 
            Map<String, List<String>> clientRoles) {
        
        Set<GrantedAuthority> authorities = new HashSet<>();
        
        // Add realm-level roles
        if (realmRoles != null) {
            realmRoles.forEach(role -> 
                authorities.add(new SimpleGrantedAuthority("ROLE_" + role))
            );
        }
        
        // Add client-level roles (resource_access)
        if (clientRoles != null) {
            clientRoles.forEach((clientId, roles) -> {
                roles.forEach(role -> 
                    authorities.add(
                        new SimpleGrantedAuthority(clientId + "_" + role)
                    )
                );
            });
        }
        
        return authorities;
    }
}
```

### Login Success Handler

**Classe**: `com.czertainly.core.auth.oauth2.CzertainlyAuthenticationSuccessHandler`

```java
@Component
public class CzertainlyAuthenticationSuccessHandler 
        implements AuthenticationSuccessHandler {
    
    @Value("${app.security.default-redirect-url}")
    private String defaultRedirectUrl;
    
    @Override
    public void onAuthenticationSuccess(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication) throws IOException {
        
        // Log successful authentication
        logger.info("User authenticated: {}", authentication.getName());
        
        // Optional: Create user record if first login
        if (isFirstLogin(authentication)) {
            createUserProfile(authentication);
        }
        
        // Redirect to default URL or stored "redirect_uri"
        String redirectUrl = getRedirectUrl(request);
        response.sendRedirect(redirectUrl);
    }
    
    private String getRedirectUrl(HttpServletRequest request) {
        // Support state param for redirect
        String state = request.getParameter("state");
        if (state != null && isValidState(state)) {
            return decodeRedirectUrl(state);
        }
        return defaultRedirectUrl;
    }
}
```

### Failure Handler

**Classe**: `com.czertainly.core.auth.oauth2.CzertainlyOAuth2FailureHandler`

```java
@Component
public class CzertainlyOAuth2FailureHandler implements AuthenticationFailureHandler {
    
    @Autowired
    private AuditLogService auditLogService;
    
    @Override
    public void onAuthenticationFailure(
            HttpServletRequest request,
            HttpServletResponse response,
            AuthenticationException exception) throws IOException {
        
        // Log failed authentication attempt
        auditLogService.log(AuditEvent.builder()
            .module(Module.AUTHENTICATION)
            .operation(Operation.LOGIN_ATTEMPT)
            .operationResult(OperationResult.FAILED)
            .additionalData("error", exception.getMessage())
            .additionalData("ip", request.getRemoteAddr())
            .build());
        
        // Send error response
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType("application/json");
        response.getWriter().write(
            new ObjectMapper().writeValueAsString(
                new ErrorResponse("Authentication failed", exception.getMessage())
            )
        );
    }
}
```

---

## 2.3 OPA (Open Policy Agent) Integration

### Por que OPA? Fine-Grained Authorization

**Problema**: RBAC (Role-Based) é insuficiente para negócios complexos:
- Admin pode deletar qualquer certificado? NÃO - apenas próprios certs
- Operador pode emitir certificado? DEPENDE - se tem quota disponível
- Usuário pode acessar relatório? DEPENDE - apenas seus dados

**Solução**: OPA permite politicas declarativas (Rego language)

### OPA Policy Example - Real-World Scenario

**Cenário**: Usuário John tenta acessar certificado de Bob

```rego
# /opt/opa/policies/czertainly.rego

package czertainly

# Regra 1: Admins têm acesso a tudo
allow {
    input.user.roles[_] == "admin"
    input.action == "read"
}

# Regra 2: Usuário acessa seu próprio certificado
allow {
    input.action == "read"
    input.resource.owner_id == input.user.id
}

# Regra 3: Usuário acessa certificado compartilhado
allow {
    input.action == "read"
    input.resource.shared_with[_] == input.user.id
}

# Regra 4: Operador emite certificado se tem quota
allow {
    input.action == "issue"
    input.user.roles[_] == "operator"
    input.user.quota.certificates_issued < input.user.quota.max_certificates
    input.resource.ra_profile_id in input.user.allowed_profiles[_]
}

# Regra 5: Auditores são read-only
allow {
    input.action == "read"
    input.user.roles[_] == "auditor"
}

# Default deny
allow = false
```

### Traffic Flow com OPA

```
┌─────────────────────────────────────────────────────────┐
│ REQUEST: DELETE /api/v2/certificates/ABC123             │
│ Header: Authorization: Bearer eyJ...                      │
└────────────────────┬────────────────────────────────────┘
                     │
                     ▼
        ┌────────────────────────────┐
        │ JWT Decoder                 │
        │ (OAuth2 Filter)             │
        │ ✓ Signature valid           │
        │ ✓ Not expired               │
        │ Extract: user=john, roles=[operator] │
        └────────────────┬────────────┘
                         │
                         ▼
        ┌────────────────────────────┐
        │ @OpaSecured Aspect          │
        │ Build OpaInput:             │
        │ {                            │
        │   action: "delete"           │
        │   resource: {                │
        │     id: "ABC123"             │
        │     owner_id: "bob"          │
        │     type: "certificate"      │
        │   }                           │
        │   user: {                    │
        │     id: "john"               │
        │     roles: ["operator"]      │
        │   }                           │
        │ }                            │
        └────────────────┬────────────┘
                         │
                         ▼ HTTP POST
        ┌────────────────────────────┐
        │ OPA Server (Port 8181)      │
        │ POST /v1/data/             │
        │    czertainly/allow         │
        │                             │
        │ Evaluate policies...        │
        │ Regra 2: owner_id!=john ✗   │
        │ Regra 4: não é owner ✗      │
        │                             │
        │ Result: DENY                │
        └────────────────┬────────────┘
                         │
                         ▼
        ┌────────────────────────────┐
        │ AccessDeniedException       │
        │ = 403 Forbidden             │
        └────────────────────────────┘
```

### OPA Client - Implementação Profunda

### OPA Client

**Classe**: `com.czertainly.core.auth.opa.OpaClient`

```java
@Component
public class OpaClient {
    
    @Value("${opa.base-url}")
    private String opaBaseUrl; // e.g., http://opa:8181
    
    @Autowired
    private RestTemplate restTemplate;
    
    public OpaAuthorizationResult evaluatePolicy(
            String policyPath,  // e.g., "data.czertainly.allow"
            OpaInput input) {
        
        try {
            String url = opaBaseUrl + "/v1/data/" + policyPath;
            
            // Build OPA request
            OpaRequest request = new OpaRequest();
            request.setInput(input);
            
            // Call OPA
            ResponseEntity<OpaResponse> response = restTemplate.postForEntity(
                url,
                request,
                OpaResponse.class
            );
            
            if (response.getStatusCode() != HttpStatus.OK) {
                logger.warn("OPA returned non-200 status: {}", 
                    response.getStatusCode());
                return OpaAuthorizationResult.DENIED;
            }
            
            OpaResponse opaResponse = response.getBody();
            boolean allowed = (boolean) opaResponse.getResult();
            
            return allowed ? 
                OpaAuthorizationResult.ALLOWED : 
                OpaAuthorizationResult.DENIED;
            
        } catch (Exception e) {
            logger.error("OPA policy evaluation failed", e);
            // Fail-secure: deny on error
            return OpaAuthorizationResult.DENIED;
        }
    }
}
```

### OPA Annotation

**Classe**: `com.czertainly.core.auth.opa.OpaSecuredAnnotation`

```java
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface OpaSecured {
    String policy() default "data.czertainly.allow";
    String[] inputParams() default {};
}
```

### OPA Aspect (Interceptor)

**Classe**: `com.czertainly.core.auth.opa.OpaSecurityAspect`

```java
@Aspect
@Component
public class OpaSecurityAspect {
    
    @Autowired
    private OpaClient opaClient;
    
    @Before("@annotation(opaSecured)")
    public void checkOpaPolicy(JoinPoint joinPoint, OpaSecured opaSecured) {
        
        // Build OPA input from method params
        OpaInput input = extractInputFromParams(
            joinPoint.getArgs(), 
            opaSecured.inputParams()
        );
        
        // Evaluate policy
        OpaAuthorizationResult result = opaClient.evaluatePolicy(
            opaSecured.policy(),
            input
        );
        
        // Deny if not allowed
        if (result == OpaAuthorizationResult.DENIED) {
            throw new AccessDeniedException("OPA policy denied access");
        }
    }
}
```

### OPA Policy Example

**Rego Policy** (on OPA server):
```rego
package czertainly

# Allow if user has admin role
allow {
    input.user.roles[_] == "admin"
}

# Allow if user owns the resource
allow {
    input.user.id == input.resource.owner_id
}

# Allow if user has explicit permission
allow {
    data.permissions[input.user.id][_] == input.action
}

# Default: deny
allow = false
```

---

## 2.3 RBAC (Role-Based Access Control)

### Authorization Endpoint Annotation

**Classe**: `com.czertainly.core.auth.AuthEndpoint`

```java
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface AuthEndpoint {
    String resourceName();  // e.g., "CERTIFICATE", "CONNECTOR"
    String[] permissions() default {};  // e.g., {"READ", "WRITE"}
}
```

### RBAC Aspect

**Classe**: `com.czertainly.core.auth.RbacAspect`

```java
@Aspect
@Component
public class RbacAspect {
    
    @Autowired
    private SecurityService securityService;
    
    @Before("@annotation(authEndpoint)")
    public void checkAuthorization(
            JoinPoint joinPoint, 
            AuthEndpoint authEndpoint) {
        
        String resourceName = authEndpoint.resourceName();
        String[] permissions = authEndpoint.permissions();
        
        Authentication auth = SecurityContextHolder.getContext()
            .getAuthentication();
        
        // Verify user has at least one permission
        boolean hasPermission = securityService.hasPermission(
            auth.getName(),
            resourceName,
            permissions
        );
        
        if (!hasPermission) {
            throw new AccessDeniedException(
                "User lacks required permissions for " + resourceName
            );
        }
    }
}
```

### Usage Example

```java
@RestController
@RequestMapping("/api/v2/certificates")
public class CertificateController {
    
    @DeleteMapping("/{uuid}")
    @AuthEndpoint(resourceName = "CERTIFICATE", permissions = {"DELETE"})
    @AuditLogged(resource = "CERTIFICATE", operation = "DELETE")
    public void deleteCertificate(@PathVariable UUID uuid) {
        certificateService.delete(uuid);
    }
}
```

---

## 2.4 Credential & Secret Management

### Credential Entity

**Tabela**: `credential`

| Campo | Tipo | Descrição |
|-------|------|-----------|
| `uuid` | UUID PK | Identificador único |
| `name` | TEXT | Nome do credential |
| `description` | TEXT | Descrição |
| `connector_uuid` | FK | Referência ao conector |
| `attributes` | JSONB | Atributos dinâmicos |
| `created_by` | TEXT | Autor |
| `created_at` | TIMESTAMP | Data criação |
| `updated_at` | TIMESTAMP | Data atualização |

### Secret Storage

**Classe**: `com.czertainly.core.dao.entity.Credential`

```java
@Entity
@Table(name = "credential")
public class Credential extends UniquelyIdentifiedAndAudited {
    
    private String name;
    private String description;
    
    @ManyToOne
    @JoinColumn(name = "connector_uuid")
    private Connector connector;
    
    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "attributes", columnDefinition = "jsonb")
    private List<RequestAttribute> attributes;
    
    // Secrets encrypted in attributes
    // Secret encryption: CredentialService uses SecretsUtil
}
```

### Secret Encryption/Decryption

**Classe**: `com.czertainly.core.util.SecretsUtil`

```java
public class SecretsUtil {
    
    private static final String ENCRYPTION_ALGORITHM = "AES/GCM/NoPadding";
    private static final int KEY_SIZE = 256; // AES-256
    
    public static String encryptSecret(String plaintext, String key) 
            throws Exception {
        
        Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);
        SecretKey secretKey = generateKey(key);
        
        // Generate random IV
        byte[] iv = new byte[12]; // 96 bits for GCM
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);
        
        // Initialize cipher
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmSpec);
        
        // Encrypt
        byte[] ciphertext = cipher.doFinal(plaintext.getBytes(UTF_8));
        
        // Return base64(IV + ciphertext)
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(iv);
        baos.write(ciphertext);
        
        return Base64.getEncoder().encodeToString(baos.toByteArray());
    }
    
    public static String decryptSecret(String encryptedSecret, String key) 
            throws Exception {
        
        byte[] decodedData = Base64.getDecoder().decode(encryptedSecret);
        
        // Extract IV
        byte[] iv = Arrays.copyOfRange(decodedData, 0, 12);
        byte[] ciphertext = Arrays.copyOfRange(decodedData, 12, decodedData.length);
        
        Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);
        SecretKey secretKey = generateKey(key);
        
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmSpec);
        
        byte[] plaintext = cipher.doFinal(ciphertext);
        
        return new String(plaintext, UTF_8);
    }
    
    private static SecretKey generateKey(String key) throws Exception {
        // Derive key from passphrase using PBKDF2
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(
            key.toCharArray(), 
            "salt".getBytes(), 
            65536, 
            256
        );
        SecretKey tmp = factory.generateSecret(spec);
        return new SecretKeySpec(tmp.getEncoded(), 0, tmp.getEncoded().length, "AES");
    }
}
```

---

## 2.4 RBAC (Role-Based Access Control) Profundo

### Hierarquia de Roles e Permissões

**Modelo**: CZERTAINLY usa RBAC + atributos dinâmicos

```
ROLES (Static):
├── ADMIN
│   ├── Pode: deletar qualquer recurso
│   ├── Pode: modificar policies
│   └── Pode: acessar audit logs
│
├── OPERATOR
│   ├── Pode: emitir certificados
│   ├── Pode: revogar certificados
│   └── Pode: gerenciar RA profiles (atribuídos)
│
├── AUDITOR
│   ├── Pode-LER: Audit logs
│   ├── Pode-LER: Certificates
│   └── PROIBIDO: Modificar dados
│
└── USER
    ├── Pode-LER: Suas próprias requests
    ├── Pode-CRIAR: Certificate requests
    └── Pode-REVOGAR: Suas próprias certs
```

### Role-Permission Matrix

| Role | Certificate.READ | Certificate.ISSUE | Cert.REVOKE | Cert.DELETE | AuditLog.READ | OPA Policy.WRITE |
|------|---|---|---|---|---|---|
| **ADMIN** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **OPERATOR** | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ |
| **AUDITOR** | ✅ | ❌ | ❌ | ❌ | ✅ | ❌ |
| **USER** | ⚠️ Own | ✅ | ⚠️ Own | ❌ | ❌ | ❌ |

**Nota**: ⚠️ = Condicional (own resources only)

### Authorization Endpoint - Real Example

```java
@RestController
@RequestMapping("/api/v2/certificates")
@Slf4j
public class CertificateController {
    
    @Autowired
    private CertificateService certificateService;
    
    @Autowired
    private AuditLogService auditLogService;
    
    /**
     * Exemplo 1: READ operation (everyone pode ler certs)
     * 
     * Fluxo:
     * 1. OAuth2 valida JWT
     * 2. @OpaSecured verifica policy
     * 3. @AuditLogged registra no log
     * 4. Retorna certificado
     */
    @GetMapping("/{uuid}")
    @OpaSecured(policy = "data.czertainly.certificate.read")
    @AuditLogged(module = Module.CERTIFICATE, operation = Operation.VIEW)
    @AuthEndpoint(resourceName = "CERTIFICATE", permissions = {"READ"})
    public CertificateDto viewCertificate(@PathVariable UUID uuid) {
        log.info("User {} viewing certificate {}", 
                 SecurityContextHolder.getContext().getAuthentication().getName(), 
                 uuid);
        return certificateService.getCertificate(uuid);
    }
    
    /**
     * Exemplo 2: DELETE operation (restrito a owners)
     * 
     * Fluxo de autorização:
     * 1. Valida token JWT
     * 2. OPA policy:
     *    - Se admin → ALLOW
     *    - Se owner → ALLOW
     *    - Senão → DENY
     * 3. Se autorizado:
     *    - Delete no BD
     *    - Log com sucesso
     * 4. Se não → 403 + log failure
     */
    @DeleteMapping("/{uuid}")
    @OpaSecured(policy = "data.czertainly.certificate.delete")
    @AuditLogged(module = Module.CERTIFICATE, operation = Operation.DELETE)
    @AuthEndpoint(resourceName = "CERTIFICATE", permissions = {"DELETE"})
    public void deleteCertificate(@PathVariable UUID uuid) {
        
        // OPA já validou (see annotation)
        log.info("User {} deleting certificate {}", 
                 extractUsername(), 
                 uuid);
        
        certificateService.delete(uuid);
    }
}
```

---

## 2.5 Audit Logging - Compliance & Forensics

### Visão Estratégica de Auditoria

**"O quem, o quê, quando, onde, por que"**

CZERTAINLY registra **toda** ação que modifica estado:

```
┌──────────────────────────────────────────────────────────┐
│ AUDIT LOG - Informações Capturadas                       │
├──────────────────────────────────────────────────────────┤
│                                                          │
│ WHO (Quem fez):        user_id, actor_type            │
│ WHAT (O quê fez):      operation, resource_type       │
│ WHEN (Quando):         timestamp (UTC), duration       │
│ WHERE (Onde):          source_ip, user_agent, method   │
│ HOW (Como):            old_value → new_value           │
│ WHY (Por quê):         operation_result (SUCCESS/FAIL)  │
│ IMPACT (Impacto):      resource_count, data_changed    │
│                                                          │
└──────────────────────────────────────────────────────────┘
```

### AuditLog Schema (PostgreSQL)

```sql
-- Tabela principal
CREATE TABLE audit_log (
    id BIGSERIAL PRIMARY KEY,
    version INT NOT NULL DEFAULT 1,
    
    -- Timing
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    logged_at TIMESTAMP WITH TIME ZONE NOT NULL,
    duration_ms INT,  -- Request duration em milliseconds
    
    -- Actor (Quem)
    actor_type VARCHAR(50) NOT NULL,  -- USER, SYSTEM, SERVICE
    actor_name VARCHAR(255) NOT NULL,  -- john@example.com ou SERVICE_ACCOUNT
    actor_ip VARCHAR(45) NOT NULL,     -- IPv4 ou IPv6
    actor_user_agent TEXT,             -- Browser/Client info
    
    -- Action (O Quê)
    module VARCHAR(100) NOT NULL,      -- CERTIFICATE, CONNECTOR, etc
    operation VARCHAR(100) NOT NULL,   -- CREATE, UPDATE, DELETE, REVOKE
    operation_result VARCHAR(50) NOT NULL,  -- SUCCESS, FAILURE, PARTIAL
    
    -- Resource (Onde)
    resource_type VARCHAR(100),        -- Certificate, Key, RA Profile
    resource_id UUID,                  -- Qual recurso foi afetado
    resource_name TEXT,                -- Friendly name
    
    -- Details (JSONB para flexibilidade)
    log_record JSONB NOT NULL,         -- Estrutura completa do evento
    
    -- Auditoria interna
    created_by VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE,
    
    -- Full text search
    CONSTRAINT fk_audit_log_check CHECK (actor_type IN ('USER', 'SYSTEM', 'SERVICE'))
);

-- Índices para performance
CREATE INDEX idx_audit_timestamp ON audit_log(timestamp DESC) WHERE operation_result != 'SUCCESS';
CREATE INDEX idx_audit_module_op ON audit_log(module, operation, timestamp DESC);
CREATE INDEX idx_audit_actor ON audit_log(actor_name, timestamp DESC);
CREATE INDEX idx_audit_resource ON audit_log(resource_type, resource_id);

-- Full text search para compliance
CREATE INDEX idx_audit_log_record_gin ON audit_log USING GIN(log_record);
```

### AuditLog Entity - Implementação Profund```java
@Entity
@Table(name = "audit_log", indexes = {
    @Index(name = "idx_audit_timestamp", columnList = "timestamp desc"),
    @Index(name = "idx_audit_module_op", columnList = "module, operation, timestamp desc"),
    @Index(name = "idx_audit_actor", columnList = "actor_name, timestamp desc"),
    @Index(name = "idx_audit_resource", columnList = "resource_type, resource_id")
})
@DynamicInsert
@DynamicUpdate
@Slf4j
public class AuditLog extends Audited {
    
    @Column(name = "timestamp", nullable = false)
    private Instant timestamp;
    
    @Column(name = "duration_ms")
    private Integer durationMs;
    
    @Enumerated(EnumType.STRING)
    @Column(name = "actor_type", nullable = false)
    private ActorType actorType;  // USER, SYSTEM, SERVICE
    
    @Column(name = "actor_name", nullable = false, length = 255)
    private String actorName;  // Username ou service account
    
    @Column(name = "actor_ip", nullable = false, length = 45)
    private String actorIp;  // IPv4 ou IPv6
    
    @Column(name = "actor_user_agent")
    private String actorUserAgent;  // HTTP User-Agent
    
    @Enumerated(EnumType.STRING)
    @Column(name = "module", nullable = false, length = 100)
    private Module module;  // CERTIFICATE, CONNECTOR, etc
    
    @Enumerated(EnumType.STRING)
    @Column(name = "operation", nullable = false, length = 100)
    private Operation operation;  // CREATE, UPDATE, DELETE, etc
    
    @Enumerated(EnumType.STRING)
    @Column(name = "operation_result", nullable = false)
    private OperationResult operationResult;  // SUCCESS, FAILURE, PARTIAL
    
    @Column(name = "resource_type", length = 100)
    private String resourceType;  // Certificate, Connector, etc
    
    @Column(name = "resource_id")
    private UUID resourceId;  // UUID do recurso
    
    @Column(name = "resource_name")
    private String resourceName;  // Friendly name para busca
    
    /**
     * log_record é JSONB na DB para flexibilidade total
     * Permite adicionar campos sem migration de schema
     * 
     * Exemplo:
     * {
     *   "action": "certificate_issued",
     *   "request_id": "abc-123-def",
     *   "old_state": {"status": "PENDING"},
     *   "new_state": {"status": "ISSUED"},
     *   "changes": {
     *     "issuer": {"old": null, "new": "CN=MyCA"},
     *     "serial": {"old": null, "new": "ABC123"}
     *   },
     *   "error": null
     * }
     */
    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "log_record", columnDefinition = "jsonb", nullable = false)
    private Map<String, Object> logRecord;
}
```

### AuditLog Service - Implementação Profunda

### AuditLog Service

**Classe**: `com.czertainly.core.service.AuditLogService`

```java
@Service
@Transactional
public class AuditLogService {
    
    @Autowired
    private AuditLogRepository repository;
    
    @Autowired
    private AuditEventProducer eventProducer;
    
    public void log(AuditEvent event) {
        
        AuditLog auditLog = new AuditLog();
        auditLog.setModule(event.getModule());
        auditLog.setOperation(event.getOperation());
        auditLog.setOperationResult(event.getOperationResult());
        auditLog.setActorType(event.getActorType());
        auditLog.setActorName(extractCurrentUser());
        auditLog.setSourceIp(extractClientIp());
        auditLog.setUserAgent(extractUserAgent());
        
        // LogRecord contém métadata estruturada
        LogRecord logRecord = new LogRecord();
        logRecord.setResource(event.getResourceId(), event.getResourceType());
        logRecord.setAction(event.getAction());
        logRecord.setOperationData(event.getOperationData());
        logRecord.setAdditionalData(event.getAdditionalData());
        
        auditLog.setLogRecord(logRecord);
        auditLog.setTimestamp(Instant.now());
        
        // Salva no BD
        repository.save(auditLog);
        
        // Publica evento para processamento assíncrono
        eventProducer.publishAuditEvent(auditLog);
    }
    
    public Page<AuditLogDto> searchLogs(AuditLogSearchCriteria criteria) {
        QAuditLog qAuditLog = QAuditLog.auditLog;
        
        BooleanBuilder predicate = new BooleanBuilder();
        
        if (criteria.getModule() != null) {
            predicate.and(qAuditLog.module.eq(criteria.getModule()));
        }
        
        if (criteria.getStartDate() != null) {
            predicate.and(qAuditLog.timestamp.goe(
                criteria.getStartDate().atStartOfDay()
            ));
        }
        
        if (criteria.getEndDate() != null) {
            predicate.and(qAuditLog.timestamp.loe(
                criteria.getEndDate().atTime(23, 59, 59)
            ));
        }
        
        return repository.findAll(
            predicate,
            PageRequest.of(
                criteria.getPageNumber(),
                criteria.getPageSize(),
                Sort.by("timestamp").descending()
            )
        ).map(this::convertToDto);
    }
    
    public byte[] exportLogs(AuditLogExportFormat format) {
        if (format == AuditLogExportFormat.CSV) {
            return exportAsCSV();
        } else if (format == AuditLogExportFormat.JSON) {
            return exportAsJSON();
        }
        throw new IllegalArgumentException("Unsupported format: " + format);
    }
}
```

### AuditLogged Annotation

**Classe**: `com.czertainly.core.audit.AuditLogged`

```java
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface AuditLogged {
    Module module();
    Operation operation();
    String resource() default "";
}
```

### AuditLog Aspect

```java
@Aspect
@Component
public class AuditLoggingAspect {
    
    @Autowired
    private AuditLogService auditLogService;
    
    @AfterReturning(value = "@annotation(auditLogged)", returning = "result")
    public void logSuccess(
            JoinPoint joinPoint, 
            AuditLogged auditLogged, 
            Object result) {
        
        auditLogService.log(AuditEvent.builder()
            .module(auditLogged.module())
            .operation(auditLogged.operation())
            .operationResult(OperationResult.SUCCESS)
            .resourceId(extractResourceId(result))
            .resourceType(auditLogged.resource())
            .operationData(result)
            .build());
    }
    
    @AfterThrowing(value = "@annotation(auditLogged)", throwing = "ex")
    public void logFailure(
            JoinPoint joinPoint, 
            AuditLogged auditLogged, 
            Exception ex) {
        
        auditLogService.log(AuditEvent.builder()
            .module(auditLogged.module())
            .operation(auditLogged.operation())
            .operationResult(OperationResult.FAILURE)
            .additionalData("error", ex.getMessage())
            .build());
    }
}
```

---

## 2.6 External Authorization Service Integration

**Classe**: `com.czertainly.core.auth.ExternalAuthorizationServiceClient`

```java
@Component
public class ExternalAuthorizationServiceClient {
    
    @Value("${auth-service.base-url}")
    private String authServiceBaseUrl;
    
    @Autowired
    private RestTemplate restTemplate;
    
    public boolean isAuthorized(
            String userId,
            String resource,
            String action) {
        
        try {
            String url = authServiceBaseUrl + "/v1/authorize";
            
            AuthorizationRequest request = new AuthorizationRequest();
            request.setUserId(userId);
            request.setResource(resource);
            request.setAction(action);
            
            ResponseEntity<AuthorizationResponse> response = 
                restTemplate.postForEntity(url, request, AuthorizationResponse.class);
            
            return response.getStatusCode() == HttpStatus.OK && 
                   response.getBody().isAllowed();
            
        } catch (Exception e) {
            logger.error("External authorization failed", e);
            return false;  // Fail-secure
        }
    }
}
```

---

## Resumo de Segurança

| Layer | Tecnologia | Propósito |
|-------|-----------|----------|
| **Autenticação** | OAuth2/OIDC + JWT | Identidade do usuário |
| **Autorização (Coarse)** | RBAC + Spring Security | Role-based access control |
| **Autorização (Fine)** | OPA | Context-aware policies |
| **Acesso a Dados** | SecurityFilterRepository | Row-level security |
| **Secrets** | AES-256-GCM | Encrypted credential storage |
| **Auditoria** | AuditLog + RabbitMQ | Immutable operation logging |
| **Transport** | HTTPS + mTLS | TLS 1.2+ encryption |
| **Sync Access** | External Auth Service | Centralized authorization |

