# 8. PROTOCOLOS: ACME (RFC 8555), SCEP, CMP (RFC 4210)

## 8.1 ACME Protocol (RFC 8555) - Automatic Certificate Management

### Visão Estratégica

ACME é o protocolo usado por **Let's Encrypt**. CZERTAINLY-Core o implementa como **ACME Server** (não cliente).

```
ACME Client (Let's Encrypt CLI)     CZERTAINLY-Core (ACME Server)
        │                                    │
        ├──→ GET /acme/directory ────────────→ List endpoints
        │                                    │
        ├──→ POST /acme/new-account ────────→ Create/find account
        │                                    │
        ├──→ POST /acme/new-order ─────────→ Create order
        │                                    │ (e.g., DNS names)
        │                                    │
        ├──→ GET /acme/authz/xxxx ────────→ Get challenges
        │                                    │
        ├──→ (client proves ownership)       │
        │    (HTTP-01, DNS-01)               │
        │                                    │
        ├──→ POST /acme/challenge/yyyy ────→ Notify challenge done
        │                                    │
        ├──→ POST /acme/finalize ──────────→ Send CSR
        │                                    │
        ├──→ GET /acme/cert/zzzz ────────→ Download certificate
        │                                    │
        └──→ POST /acme/revoke-cert ──────→ Revoke if needed
```

### ACME Endpoints Implementation

**Arquivo**: `com.czertainly.core.api.acme.AcmeControllerImpl`

```java
@RestController
@RequestMapping("/acme")
@Slf4j
public class AcmeControllerImpl {
    
    @Autowired
    private AcmeService acmeService;
    
    @Autowired
    private AcmeAccountService acmeAccountService;
    
    /**
     * ACME Directory (RFC 8555 Section 7.1.1)
     * 
     * Retorna URLs de endpoints disponíveis
     * Essencial para discovery do cliente
     */
    @GetMapping("/directory")
    public ResponseEntity<AcmeDirectoryResponse> getDirectory(
            HttpServletRequest request) {
        
        String baseUrl = extractBaseUrl(request);  // https://czertainly.com/acme
        
        AcmeDirectoryResponse response = AcmeDirectoryResponse.builder()
            .newNonce(baseUrl + "/new-nonce")
            .newAccount(baseUrl + "/new-account")
            .newOrder(baseUrl + "/new-order")
            .revokeCert(baseUrl + "/revoke-cert")
            .keyChange(baseUrl + "/key-change")
            .meta(AcmeDirectoryMeta.builder()
                .termsOfService("https://czertainly.com/tos")
                .website("https://czertainly.com")
                .type("CZERTAINLY")
                .build())
            .build();
        
        return ResponseEntity.ok(response);
    }
    
    /**
     * GET /acme/new-nonce (RFC 8555 Section 7.2)
     * 
     * Cada request JWS deve conter:
     * - "nonce": valor único anti-replay
     * - "jwk"/  "kid": chave ou ID da chave
     * - "alg": RS256, ES256, etc
     * 
     * Servidor deve verificar:
     * 1. Nonce não foi usado antes
     * 2. Nonce não está expirado
     * 3. Assinatura é válida
     */
    @GetMapping("/new-nonce")
    public ResponseEntity<Void> getNewNonce(HttpServletResponse response,
                                            HttpServletRequest request) {
        
        // Generate nonce
        String nonce = acmeService.generateNonce();
        
        // Must return in header (HEAD or GET)
        response.addHeader("Replay-Nonce", nonce);
        response.addHeader("Cache-Control", "no-store");
        response.addHeader("Pragma", "no-cache");
        
        return ResponseEntity.noContent().build();
    }
    
    /**
     * POST /acme/new-account (RFC 8555 Section 7.3)
     * 
     * Request:
     * {
     *   "protected": "eyJhbGc...",
     *   "payload": "eyJ0ZXJtc...",
     *   "signature": "RSA signature"
     * }
     * 
     * Payload:
     * {
     *   "termsOfServiceAgreed": true,
     *   "contact": ["mailto:admin@example.com"],
     *   "externalAccountBinding": {...}  // Optional
     * }
     */
    @PostMapping("/new-account")
    public ResponseEntity<AcmeAccountResponse> newAccount(
            @RequestBody AcmeJwsRequest request,
            HttpServletResponse response,
            HttpServletRequest servletRequest) {
        
        try {
            // 1. Verify JWS signature & claims
            JwsVerification verification = acmeService.verifyJws(request);
            if (!verification.isValid()) {
                return ResponseEntity.badRequest().build();
            }
            
            // 2. Parse payload
            AcmeAccountRequest payload = acmeService.parsePayload(
                request.getPayload(),
                AcmeAccountRequest.class
            );
            
            // 3. Validate terms agreed
            if (!payload.isTermsOfServiceAgreed()) {
                return ResponseEntity.status(400).build();
            }
            
            // 4. Find or create account
            AcmeAccount account = acmeAccountService.findOrCreateAccount(
                verification.getJwk(),
                payload.getContact(),
                accountId -> {
                    // New account created
                    log.info("New ACME account created: {}", accountId);
                }
            );
            
            // 5. Return account with Location header
            String accountUrl = extractBaseUrl(servletRequest) + 
                                "/account/" + account.getId();
            
            response.addHeader("Location", accountUrl);
            response.addHeader("Replay-Nonce", acmeService.generateNonce());
            response.addHeader("Link", 
                "<" + extractBaseUrl(servletRequest) + "/directory>; rel=\"index\"");
            
            return ResponseEntity.status(201).body(
                mapToResponse(account)
            );
            
        } catch (Exception e) {
            log.error("Failed to create account", e);
            return ResponseEntity.status(400).build();
        }
    }
    
    /**
     * POST /acme/new-order (RFC 8555 Section 7.4)
     * 
     * Fluxo de emissão de certificado:
     * 1. Cliente cria order (identifiers = DNS names)
     * 2. Servidor retorna challenges para provar ownership
     * 3. Cliente completa challenges
     * 4. Cliente envia CSR (Certificate Signing Request)
     * 5. Servidor emite certificado
     */
    @PostMapping("/new-order")
    public ResponseEntity<AcmeOrderResponse> newOrder(
            @RequestBody AcmeJwsRequest request,
            HttpServletRequest servletRequest,
            HttpServletResponse response) {
        
        try {
            // 1. Verify JWS
            AcmeAccountRequest orderRequest = acmeService.verifyAndParse(request);
            
            // 2. Create order
            List<AcmeIdentifier> identifiers = orderRequest.getIdentifiers();
            
            AcmeOrder order = acmeService.createOrder(
                identifiers,
                orderRequest.getNotBefore(),
                orderRequest.getNotAfter()
            );
            
            // 3. Create authorization for each identifier
            List<String> authzUrls = new ArrayList<>();
            for (AcmeIdentifier id : identifiers) {
                AcmeAuthorization authz = acmeService.createAuthorization(order, id);
                authzUrls.add(extractBaseUrl(servletRequest) + 
                             "/authz/" + authz.getId());
            }
            
            // 4. Response
            String orderUrl = extractBaseUrl(servletRequest) + 
                             "/order/" + order.getId();
            
            response.addHeader("Location", orderUrl);
            response.addHeader("Replay-Nonce", acmeService.generateNonce());
            
            return ResponseEntity.status(201).body(
                AcmeOrderResponse.builder()
                    .status(order.getStatus())  // PENDING
                    .expires(order.getExpires())
                    .identifiers(identifiers)
                    .authorizations(authzUrls)
                    .finalize(orderUrl + "/finalize")
                    .build()
            );
            
        } catch (Exception e) {
            log.error("Failed to create order", e);
            return ResponseEntity.badRequest().build();
        }
    }
    
    /**
     * GET /acme/authz/xxxx (RFC 8555 Section 7.4.1)
     * 
     * Retorna challenges para o cliente provar ownership
     * 
     * Tipos de challenges:
     * - http-01: Coloca arquivo em .well-known/acme-challenge/token
     * - dns-01: Cria DNS TXT record
     * - tls-alpn-01: TLS ALPN challenge
     */
    @GetMapping("/authz/{authzId}")
    public ResponseEntity<AcmeAuthorizationResponse> getAuthorization(
            @PathVariable String authzId) {
        
        AcmeAuthorization authz = acmeService.getAuthorization(authzId);
        if (authz == null) {
            return ResponseEntity.notFound().build();
        }
        
        // Generate challenges
        List<AcmeChallenge> challenges = new ArrayList<>();
        
        // http-01 challenge
        String token = acmeService.generateChallengeToken();
        String keyAuthorization = calculateKeyAuthorization(token);  // token + JWK thumbprint
        
        challenges.add(AcmeChallenge.builder()
            .type("http-01")
            .url(baseUrl + "/challenge/" + token)
            .status("pending")
            .token(token)
            .build());
        
        // dns-01 challenge
        String dnsValue = Base64.getUrlEncoder().encodeToString(
            DigestUtils.sha256(keyAuthorization)
        );
        
        challenges.add(AcmeChallenge.builder()
            .type("dns-01")
            .url(baseUrl + "/challenge/" + token)
            .status("pending")
            .token(token)
            // Client must create: _acme-challenge.example.com TXT "dnsValue"
            .build());
        
        return ResponseEntity.ok(
            AcmeAuthorizationResponse.builder()
                .identifier(authz.getIdentifier())
                .status(authz.getStatus())
                .challenges(challenges)
                .build()
        );
    }
    
    /**
     * POST /acme/finalize (RFC 8555 Section 7.4.4)
     * 
     * Cliente envia CSR (Certificate Signing Request)
     * Servidor valida:
     * 1. Todas as challenges foram completadas
     * 2. CSR contém identifiers corretos
     * 3. CSR é válido (signature, format)
     * 
     * Retorna: order status muda para VALID
     */
    @PostMapping("/order/{orderId}/finalize")
    public ResponseEntity<AcmeOrderResponse> finalizeOrder(
            @PathVariable String orderId,
            @RequestBody FinalizeOrderRequest request) {
        
        try {
            // 1. Get order & validate
            AcmeOrder order = acmeService.getOrder(orderId);
            if (order.getStatus() != AcmeOrderStatus.READY) {
                return ResponseEntity.status(422).build();  // Unprocessable
            }
            
            // 2. Validate all challenges completed
            boolean allChallengesComplete = acmeService.validateChallenges(order);
            if (!allChallengesComplete) {
                return ResponseEntity.status(400).build();
            }
            
            // 3. Parse & validate CSR
            byte[] csrBytes = Base64.getUrlDecoder().decode(request.getCsr());
            PKCS10CertificationRequest csr = new PKCS10CertificationRequest(csrBytes);
            
            // Validate CSR signature
            if (!csr.isSignatureValid(
                    new JcaContentVerifierProviderBuilder()
                        .build(csr.getPublicKey()))) {
                return ResponseEntity.badRequest().build();
            }
            
            // 4. Issue certificate
            X509Certificate certificate = acmeService.issueCertificate(
                order,
                csr
            );
            
            // 5. Update order
            order.setStatus(AcmeOrderStatus.VALID);
            order.setCertificateUrl(baseUrl + "/cert/" + certificate.getSerialNumber());
            
            return ResponseEntity.ok(mapToResponse(order));
            
        } catch (Exception e) {
            log.error("Finalize order failed", e);
            return ResponseEntity.badRequest().build();
        }
    }
}
```

### Performance & Constraints

**Rate Limiting** (Anti-DDoS):
```yaml
acme:
  rate-limit:
    certificates-per-domain: 50       # Per 24h
    duplicate-cert: 5                 # Same cert in 24h
    new-orders-per-ip: 100           # Per hour
    invalid-nonce-grace: 60           # Seconds
```

---

## 8.2 SCEP Protocol (RFC 2560 + Intune Integration)

###Overview

SCEP = Simple Certificate Enrollment Protocol (legacy, mas ainda usado)

```
Client (Windows/macOS)              CZERTAINLY-Core (SCEP Server)
        │                                    │
        ├──→ GET /scep?operation=GetCACert ──→ Return CA cert chain
        │                                    │
        ├──→ POST /scep (PKCS#7 request) ───→ Enroll new certificate
        │                                    │ (password-based or existing)
        │                                    │
        ├──← PKCS#7 response (cert+chain) ───→ Return issued cert
        │                                    │
        └──→ Periodically renew              │ (if near expiry)
```

### SCEP Endpoints

```java
@RestController
@RequestMapping("/scep")
@Slf4j
public class ScepControllerImpl {
    
    @Autowired
    private ScepService scepService;
    
    /**
     * GET /scep?operation=GetCACert
     * 
     * Retorna certificado da CA (chain)
     * Formato: PKCS#7 (DER-encoded)
     */
    @GetMapping
    public ResponseEntity<byte[]> scepGet(
            @RequestParam(value = "operation", required = false) String operation,
            @RequestParam(value = "message", required = false) String message) {
        
        if ("GetCACert".equalsIgnoreCase(operation)) {
            byte[] caCertChain = scepService.getCACertChain();
            
            return ResponseEntity.ok()
                .contentType(MediaType.valueOf("application/x-x509-ca-cert"))
                .body(caCertChain);
        }
        
        return ResponseEntity.badRequest().build();
    }
    
    /**
     * POST /scep
     * 
     * Enrollment request:
     * 1. Client envia PKCS#7 (sginado + criptografado)
     * 2. Contém CSR + senha (ou existing cert para renewal)
     * 3. Server valida + emite novo cert
     * 4. Retorna PKCS#7 response
     * 
     * Intune Integration:
     * - Suporte para MDM enrollment
     * - Password-based ou certificate-based
     * - Renewal automático antes de expiry
     */
    @PostMapping
    public ResponseEntity<byte[]> scepPost(@RequestBody byte[] request) {
        
        try {
            // 1. Parse PKCS#7
            CMSSignedData signedData = new CMSSignedData(request);
            
            // 2. Extract message (criptografada)
            CMSEnvelopedData envelopedData = new CMSEnvelopedData(
                signedData.getSignedContent().getContent()
            );
            
            // 3. Decrypt usando private key do server
            byte[]decryptedMessage = scepService.decryptMessage(envelopedData);
            
            // 4. Parse CSR + attributes
            PkiData pkiData = parsePkiData(decryptedMessage);
            
            // 5. Validate password (se enrollment)
            if (!validateEnrollmentPassword(pkiData, request)) {
                return ResponseEntity.status(403).build();
            }
            
            // 6. Issue certificate
            X509Certificate certificate = scepService.issueCertificate(
                pkiData.getCsr(),
                pkiData.getAttributes()
            );
            
            // 7. Build response (PKCS#7 signed + encrypted)
            byte[] response = scepService.buildPkiResponse(
                certificate,
                pkiData
            );
            
            return ResponseEntity.ok()
                .contentType(MediaType.valueOf("application/pkcs7-mime"))
                .body(response);
            
        } catch (Exception e) {
            log.error("SCEP enrollment failed", e);
            return ResponseEntity.status(400).build();
        }
    }
}
```

---

## 8.3 CMP Protocol (RFC 4210)

### Overview

CMP = Certificate Management Protocol (mas complex, menos comum)

```java
@RestController
@RequestMapping("/cmp")
@Slf4j
public class CmpControllerImpl {
    
    @Autowired
    private CmpService cmpService;
    
    /**
     * POST /cmp
     * 
     * Suporta múltiplas operações:
     * - PKIData (certificate request)
     * - CertRepMessage (response)
     * - Revocation requests
     * - Key update
     * 
     * Mensagens: ASN.1 DER-encoded
     */
    @PostMapping
    public ResponseEntity<byte[]> handleCmp(@RequestBody byte[] request) {
        
        try {
            // Parse PKIMessage
            PKIMessage pKIMessage = PKIMessage.getInstance(request);
            
            // Determine message type & route
            String typeOid = pKIMessage.getMessageType().getId();
            
            if ("ir".equals(typeOid)) {
                // Initialization Request
                return handleInitializationRequest(pKIMessage);
            } else if ("cr".equals(typeOid)) {
                // Certificate Request
                return handleCertificateRequest(pKIMessage);
            } else if ("rr".equals(typeOid)) {
                // Revocation Request
                return handleRevocationRequest(pKIMessage);
            }
            
            return ResponseEntity.badRequest().build();
            
        } catch (Exception e) {
            log.error("CMP request failed", e);
            return ResponseEntity.status(400).build();
        }
    }
}
```

---

## 8.4 Protocol Selection & Trade-offs

| Protocolo | Vantagens | Desvantagens | Quando Usar |
|-----------|-----------|--------------|-------------|
| **ACME** | RESTful, moderno, HTTP | Requer DNS/HTTP challenge | Public CAs, Let's Encrypt |
| **SCEP** | Simples, Windows suporta | Antigo, fraco crypto | MDM/Intune, legacy |
| **CMP** | Robusto, crypto-heavy | Complexo, ASN.1 | Enterprise PKI |

---

## 8.5 Fluxo de Certificação Comparado

```
ACME:        directory → new-account → new-order → challenge → finalize → download
SCEP:        GetCACert → POST (PKCS7) → [response with cert]
CMP:         PKIMessage → [process] → PKIResponse
```
        order.setAccount(account);
        
        // Create authorizations
        List<AcmeAuthorization> authorizations = createAuthorizations(
            request.getIdentifiers(),
            order
        );
        order.setAuthorizations(authorizations);
        
        acmeOrderRepository.save(order);
        
        return ResponseEntity.status(201).body(
            convertToOrderResponse(order)
        );
    }
    
    /**
     * POST /acme/authz/{authzId}
     * RFC 8555 Section 7.5: Authorization Objects
     * 
     * Retorna detalhes de autorização + challenges disponíveis
     */
    @PostMapping("/authz/{authzId}")
    public ResponseEntity<AcmeAuthorizationResponse> getAuthorization(
            @PathVariable String authzId,
            @RequestBody JwsRequest request) {
        
        AcmeAuthorization authz = acmeAuthzRepository
            .findById(authzId)
            .orElseThrow(() -> new AcmeException("Invalid authorization ID", 404));
        
        // Return challenges
        List<AcmeChallengeResponse> challenges = authz.getChallenges()
            .stream()
            .map(c -> convertToChallengeResponse(c))
            .collect(toList());
        
        return ResponseEntity.ok(
            new AcmeAuthorizationResponse(
                authz.getIdentifier(),
                authz.getStatus(),
                authz.getExpires(),
                challenges
            )
        );
    }
    
    /**
     * POST /acme/challenge/{challengeId}/validate
     * RFC 8555 Section 7.5.1: Challenge Objects
     * 
     * Cliente notifica para validar challenge
     * (exemplo: http-01, dns-01, tls-alpn-01)
     */
    @PostMapping("/challenge/{challengeId}/validate")
    public ResponseEntity<AcmeChallengeResponse> validateChallenge(
            @PathVariable String challengeId) {
        
        AcmeChallenge challenge = acmeChallengeRepository
            .findById(challengeId)
            .orElseThrow(() -> new AcmeException("Invalid challenge ID", 404));
        
        // Validate challenge based on type
        boolean isValid = false;
        
        if (ChallengeType.HTTP_01.equals(challenge.getType())) {
            isValid = validateHttp01Challenge(challenge);
        } else if (ChallengeType.DNS_01.equals(challenge.getType())) {
            isValid = validateDns01Challenge(challenge);
        } else if (ChallengeType.TLS_ALPN_01.equals(challenge.getType())) {
            isValid = validateTlsAlpn01Challenge(challenge);
        }
        
        if (isValid) {
            challenge.setStatus(ChallengeStatus.VALID);
            
            // Check if all challenges for authz are valid
            AcmeAuthorization authz = challenge.getAuthorization();
            if (authz.allChallengesValid()) {
                authz.setStatus(AuthorizationStatus.VALID);
            }
        } else {
            challenge.setStatus(ChallengeStatus.INVALID);
            challenge.setError(new AcmeError(
                "challenge-failed",
                "Challenge validation failed"
            ));
        }
        
        acmeChallengeRepository.save(challenge);
        
        return ResponseEntity.ok(convertToChallengeResponse(challenge));
    }
    
    /**
     * POST /acme/finalize/{orderId}
     * RFC 8555 Section 7.4: Finalize Order
     * 
     * Cliente submete CSR para finalizar order
     */
    @PostMapping("/finalize/{orderId}")
    public ResponseEntity<AcmeOrderResponse> finalizeOrder(
            @PathVariable String orderId,
            @RequestBody AcmeFinalizeRequest request) {
        
        AcmeOrder order = acmeOrderRepository
            .findById(orderId)
            .orElseThrow(() -> new AcmeException("Invalid order ID", 404));
        
        // Validate all authorizations are valid
        if (!order.allAuthorizationsValid()) {
            throw new AcmeException("Authorizations not valid", 403);
        }
        
        // Parse CSR
        PKCS10CertificationRequest csr = parseCsr(request.getCsr());
        
        // Trigger certificate issuance
        Certificate certificate = issueCertificate(
            order.getAccount().getRaProfile(),
            csr
        );
        
        order.setStatus(OrderStatus.VALID);
        order.setCertificate(certificate);
        order.setFinalizedAt(LocalDateTime.now());
        
        acmeOrderRepository.save(order);
        
        return ResponseEntity.ok(convertToOrderResponse(order));
    }
    
    /**
     * POST /acme/cert/{certId}
     * RFC 8555 Section 7.4: Download Certificate
     * 
     * Download certificado emitido (em cadeia PEM)
     */
    @GetMapping("/cert/{certId}")
    public ResponseEntity<String> downloadCertificate(
            @PathVariable String certId) {
        
        Certificate certificate = certificateRepository
            .findById(UUID.fromString(certId))
            .orElseThrow(() -> new AcmeException("Certificate not found", 404));
        
        // Return certificate chain in PEM format
        String certificateChain = buildCertificateChain(certificate);
        
        return ResponseEntity.ok()
            .contentType(MediaType.valueOf("application/pem-certificate-chain"))
            .body(certificateChain);
    }
    
    /**
     * POST /acme/revoke-cert
     * RFC 8555 Section 7.6: Revocation
     * 
     * Cliente solicita revogação de certificado
     */
    @PostMapping("/revoke-cert")
    public ResponseEntity<Void> revokeCertificate(
            @RequestBody AcmeRevocationRequest request) {
        
        // Parse certificate from request
        X509Certificate cert = parseCertificate(request.getCertificate());
        
        // Find in database
        Certificate dbCert = certificateRepository
            .findBySerialNumber(cert.getSerialNumber().toString())
            .orElseThrow(() -> new AcmeException("Certificate not found", 404));
        
        // Revoke
        dbCert.setState(CertificateState.REVOKED);
        dbCert.setRevocationReason(request.getReason() != null ? 
            request.getReason() : "unspecified");
        dbCert.setRevokedAt(LocalDateTime.now());
        
        certificateRepository.save(dbCert);
        
        // Publish event
        eventPublisher.publishEvent(new CertificateRevokedEvent(
            dbCert.getUuid(),
            dbCert.getRevocationReason(),
            dbCert.getRevokedAt(),
            "ACME"
        ));
        
        return ResponseEntity.ok().build();
    }
}
```

### Challenge Validators

```java
@Component
@Slf4j
public class Acme01ChallengeValidator {
    
    /**
     * Validar http-01 challenge
     * RFC 8555 Section 8.3
     */
    public boolean validateHttp01(AcmeChallenge challenge) {
        
        /*
         * Challenge: http-01
         * Client must make HTTP GET to:
         *   http://{domain}/.well-known/acme-challenge/{token}
         * Response deve ser: {token}.{keyAuthorization}
         */
        
        String token = challenge.getToken();
        String keyAuthorization = challenge.getKeyAuthorization();
        String domain = challenge.getIdentifier();
        
        try {
            String url = "http://" + domain + "/.well-known/acme-challenge/" + token;
            String response = httpClient.get(url, 10000);  // 10 second timeout
            
            String expected = token + "." + keyAuthorization;
            
            return response.equals(expected);
            
        } catch (Exception e) {
            log.error("HTTP-01 challenge validation failed", e);
            return false;
        }
    }
    
    /**
     * Validar dns-01 challenge
     * RFC 8555 Section 8.4
     */
    public boolean validateDns01(AcmeChallenge challenge) {
        
        /*
         * Challenge: dns-01
         * Client must create TXT record:
         *   _acme-challenge.{domain} IN TXT "{digest}"
         * onde digest = base64url(sha256(keyAuthorization))
         */
        
        String domain = challenge.getIdentifier();
        String expectedDigest = challenge.getValidationValue();
        
        try {
            // Query DNS TXT records
            List<String> txtRecords = dnsResolver.resolveTxt(
                "_acme-challenge." + domain
            );
            
            return txtRecords.contains(expectedDigest);
            
        } catch (Exception e) {
            log.error("DNS-01 challenge validation failed", e);
            return false;
        }
    }
}
```

---

## 8.2 SCEP Protocol (RFC 2560)

### Overview
Simple Certificate Enrollment Protocol - protocolo cliente-servidor para requisição e entrega de certificados.

### SCEP Endpoints

```java
@RestController
@RequestMapping("/scep/{profileName}")
@Slf4j
public class ScepControllerImpl {
    
    @Autowired
    private ScepServiceImpl scepService;
    
    /**
     * GET /scep/{profileName}/pkicsrsetup
     * SCEP Proprietary: Capabilities Discovery (GetCACaps)
     */
    @GetMapping("/pkicsrsetup")
    public String getPkicsrSetup(@PathVariable String profileName) {
        
        ScepProfile profile = scepProfileService.findByName(profileName)
            .orElseThrow(() -> new NotFoundException("SCEP profile not found"));
        
        /*
         * Response: capabilities in application/x-www-form-urlencoded
         * Exemplo:
         *   GetNextCACert
         *   PostSigningCert
         *   Renewal
         *   SHA-256
         */
        
        StringBuilder capabilities = new StringBuilder();
        capabilities.append("GetNextCACert\n");
        capabilities.append("PostSigningCert\n");
        capabilities.append("Renewal\n");
        capabilities.append("SHA-256\n");
        capabilities.append("SHA-384\n");
        capabilities.append("SHA-512\n");
        
        return capabilities.toString();
    }
    
    /**
     * GET /scep/{profileName}/?operation=GetCACert
     * SCEP Operation: Get CA Certificate
     * 
     * Retorna certificado da CA (DER-encoded)
     */
    @GetMapping
    @RequestParam(name = "operation", required = true)
    public ResponseEntity<byte[]> handleScepOperation(
            @PathVariable String profileName,
            @RequestParam String operation) {
        
        ScepProfile profile = scepProfileService.findByName(profileName)
            .orElseThrow();
        
        if ("GetCACert".equals(operation)) {
            
            // Return CA cert chain
            byte[] caCertChain = getCACertificateChain(profile.getRaProfile());
            
            return ResponseEntity.ok()
                .contentType(MediaType.APPLICATION_OCTET_STREAM)
                .body(caCertChain);
        }
        
        throw new AcmeException("Unsupported operation: " + operation, 400);
    }
    
    /**
     * POST /scep/{profileName}/?operation=PKIOperation
     * SCEP Operation: Main protocol message exchange
     * 
     * Processa mensagens SCEP (PKCSReq, CertRep, etc)
     * RFC 2560 Section 3.2.1
     */
    @PostMapping
    @RequestParam(name = "operation", defaultValue = "PKIOperation")
    public ResponseEntity<byte[]> handlePkiOperation(
            @PathVariable String profileName,
            @RequestBody byte[] requestData) {
        
        log.info("SCEP PKIOperation request for profile: {}", profileName);
        
        try {
            ScepProfile profile = scepProfileService.findByName(profileName)
                .orElseThrow();
            
            // Parse SCEP request
            ScepMessage scepRequest = parseScepMessage(requestData);
            
            // Process based on message type
            ScepMessage scepResponse = null;
            
            if (MessageType.PKCSReq.equals(scepRequest.getMessageType())) {
                // Certificate Request
                scepResponse = processCertificateRequest(scepRequest, profile);
                
            } else if (MessageType.GetCert.equals(scepRequest.getMessageType())) {
                // Get existing certificate
                scepResponse = getCertificate(scepRequest, profile);
                
            } else if (MessageType.GetCRL.equals(scepRequest.getMessageType())) {
                // Get CRL
                scepResponse = getCRL(scepRequest, profile);
                
            } else if (MessageType.RenewalReq.equals(scepRequest.getMessageType())) {
                // Renewal request
                scepResponse = processRenewalRequest(scepRequest, profile);
            }
            
            // Sign and encrypt response
            byte[] encryptedResponse = encryptAndSignScepResponse(
                scepResponse,
                profile
            );
            
            return ResponseEntity.ok()
                .contentType(MediaType.APPLICATION_OCTET_STREAM)
                .body(encryptedResponse);
            
        } catch (Exception e) {
            log.error("Error processing SCEP request", e);
            
            // Return error response
            byte[] errorResponse = createErrorResponse(e.getMessage());
            return ResponseEntity.ok()
                .contentType(MediaType.APPLICATION_OCTET_STREAM)
                .body(errorResponse);
        }
    }
}
```

### SCEP Message Processing

```java
@Service
@Slf4j
public class ScepServiceImpl {
    
    /**
     * Processa certificate request (PKCSReq)
     */
    public ScepMessage processCertificateRequest(
            ScepMessage request,
            ScepProfile profile) {
        
        // Extract CSR from request
        PKCS10CertificationRequest csr = extractCsr(request);
        
        // Issue certificate
        Certificate certificate = certificateService.issueCertificate(
            profile.getRaProfile(),
            csr
        );
        
        // Create response
        ScepMessage response = new ScepMessage();
        response.setMessageType(MessageType.CertRep);
        response.setTransactionId(request.getTransactionId());
        response.setStatus(TransactionStatus.SUCCESS);
        response.setCertificate(certificate.getCertificateContent());
        
        return response;
    }
    
    /**
     * Processa renewal request
     */
    public ScepMessage processRenewalRequest(
            ScepMessage request,
            ScepProfile profile) {
        
        // Extract old certificate
        X509Certificate oldCert = extractCertificate(request);
        
        // Extract new CSR
        PKCS10CertificationRequest newCsr = extractCsr(request);
        
        // Validate old certificate is still valid
        if (isCertificateExpiredOrRevoked(oldCert)) {
            throw new ScepException("Old certificate is expired or revoked");
        }
        
        // Issue new certificate
        Certificate newCertificate = certificateService.issueCertificate(
            profile.getRaProfile(),
            newCsr
        );
        
        return createResponseMessage(TransactionStatus.SUCCESS, newCertificate);
    }
    
    /**
     * Encriptar e assinar resposta SCEP
     * (usando certificado de encriptação do cliente)
     */
    private byte[] encryptAndSignScepResponse(
            ScepMessage message,
            ScepProfile profile) throws Exception {
        
        // 1. Serializar mensagem (DER)
        byte[] messageDer = serializeScepMessage(message);
        
        // 2. Assinar com chave privada da CA
        byte[] signedMessage = signData(messageDer, caPrivateKey);
        
        // 3. Encriptar com certificado do cliente (do request)
        byte[] encryptedMessage = encryptData(signedMessage, clientCertificate);
        
        return encryptedMessage;
    }
}
```

---

## 8.3 CMP Protocol (RFC 4210)

### Overview
Certificate Management Protocol - protocolo para gerenciamento de certificados (requisição, entrega, renewal, revogação).

### CMP Service

```java
@Service
@Slf4j
@Transactional
public class CmpServiceImpl {
    
    @Autowired
    private CmpProfileRepository cmpProfileRepository;
    
    @Autowired
    private CertificateService certificateService;
    
    /**
     * Processa CMP PDU (Protocol Data Unit)
     * RFC 4210 Section 5.1.3
     */
    public byte[] processCmpPdu(
            byte[] cmpRequest,
            UUID cmpProfileUuid) throws Exception {
        
        // Parse CMP PDU
        PKIMessage pkiMessage = parsePkiMessage(cmpRequest);
        
        log.info("Processing CMP message type: {}", pkiMessage.getBody().getType());
        
        PKIMessage responseMessage = null;
        
        // Handle different message types
        switch (pkiMessage.getBody().getType()) {
            case PKIBody.TYPE_INIT_REQ:
                // RFC 4210: ir - Initialization Request
                responseMessage = handleInitializationRequest(
                    pkiMessage, cmpProfileUuid
                );
                break;
                
            case PKIBody.TYPE_CERT_REQ:
                // RFC 4210: cr - Certification Request
                responseMessage = handleCertificationRequest(
                    pkiMessage, cmpProfileUuid
                );
                break;
                
            case PKIBody.TYPE_KEY_UPDATE_REQ:
                // RFC 4210: kur - Key Update Request
                responseMessage = handleKeyUpdateRequest(
                    pkiMessage, cmpProfileUuid
                );
                break;
                
            case PKIBody.TYPE_REV_REQ:
                // RFC 4210: rr - Revocation Request
                responseMessage = handleRevocationRequest(
                    pkiMessage, cmpProfileUuid
                );
                break;
                
            case PKIBody.TYPE_GENM:
                // RFC 4210: genm - General Message
                responseMessage = handleGeneralMessage(
                    pkiMessage, cmpProfileUuid
                );
                break;
        }
        
        // Build response
        return encodePkiMessage(responseMessage);
    }
    
    /**
     * RFC 4210: Initialization Request
     * Client requests initial credential
     */
    private PKIMessage handleInitializationRequest(
            PKIMessage request,
            UUID cmpProfileUuid) throws Exception {
        
        CertReqMessages certReqs = (CertReqMessages) request.getBody();
        
        PKIMessage response = new PKIMessage(
            new PKIHeader(request.getHeader()),
            new PKIBody(PKIBody.TYPE_INIT_REP, null)
        );
        
        // Process certificate request(s)
        CertRepMessage certReps = new CertRepMessage();
        
        for (CertReqMsg certReq : certReqs.getToCertReqMsgArray()) {
            
            CertResponse certResponse = new CertResponse();
            
            try {
                // Extract CSR and issue certificate
                Certificate certificate = certificateService.issueCertificate(
                    cmpProfileUuid,
                    certReq.getCertRequest()
                );
                
                certResponse.setStatus(new PKIStatusInfo(PKIStatus.granted));
                certResponse.setCertifiedKeyPair(
                    new CertifiedKeyPair(
                        new CMPCertId(certificate.getSerialNumber()),
                        certificate.getCertificateContent()
                    )
                );
                
            } catch (Exception e) {
                certResponse.setStatus(new PKIStatusInfo(
                    PKIStatus.rejection,
                    new PKIFreeText("Certificate issuance failed"),
                    new PKIFailureInfo(PKIFailureInfo.badCertTemplate)
                ));
            }
            
            certReps.addCertResponse(certResponse);
        }
        
        return response;
    }
    
    /**
     * RFC 4210: Polling Mode
     * Cliente periodicamente inquire status de pedido
     */
    @Scheduled(cron = "0 */5 * * * *")  // Every 5 minutes
    public void handlePollRequests() {
        
        List<CmpProfile> profiles = cmpProfileRepository.findAll();
        
        for (CmpProfile profile : profiles) {
            
            // Find pending transactions
            List<CmpTransaction> pendingTxs = cmpTransactionRepository
                .findByStatusAndProfileUuid(
                    TransactionStatus.PENDING,
                    profile.getUuid()
                );
            
            pendingTxs.forEach(tx -> {
                long elapsedSeconds = getElapsedSeconds(
                    tx.getCreatedAt(),
                    LocalDateTime.now()
                );
                
                // Check if timeout exceeded
                if (elapsedSeconds > profile.getPollTimeoutSeconds()) {
                    tx.setStatus(TransactionStatus.TIMEOUT);
                    tx.setUpdatedAt(LocalDateTime.now());
                    
                    logger.warn("CMP transaction timed out: {}", tx.getId());
                }
                
                cmpTransactionRepository.save(tx);
            });
        }
    }
}
```

---

## 8.4 Common Protocol Features

### Error Handling

```java
public class ProtocolErrorHandler {
    
    public static AcmeError createAcmeError(String type, String detail) {
        return new AcmeError(type, detail);
    }
    
    public static ScepError createScepError(String message) {
        return new ScepError(message);
    }
    
    public static PKIStatusInfo createCmpError(String message) {
        return new PKIStatusInfo(
            PKIStatus.rejection,
            new PKIFreeText(message)
        );
    }
}
```

### Nonce & Replay Protection

```java
@Component
public class NonceGenerator {
    
    @Autowired
    private RedisTemplate<String, String> redisTemplate;
    
    /**
     * Generate nonce (anti-replay)
     * Armazenar no Redis com TTL
     */
    public String generateNonce() {
        String nonce = UUID.randomUUID().toString();
        
        // Store with 1 hour TTL
        redisTemplate.opsForValue().set(
            "nonce:" + nonce,
            "used",
            1, TimeUnit.HOURS
        );
        
        return nonce;
    }
    
    /**
     * Validate nonce (one-time use)
     */
    public boolean validateAndConsumeNonce(String nonce) {
        String key = "nonce:" + nonce;
        
        Boolean exists = redisTemplate.hasKey(key);
        if (Boolean.TRUE.equals(exists)) {
            redisTemplate.delete(key);
            return true;
        }
        
        return false;
    }
}
```

---

## Resumo de Protocolos

| Protocolo | RFC | Endpoints | Features |
|-----------|-----|-----------|----------|
| **ACME** | 8555 | 7+ | Challenge types (http-01, dns-01, tls-alpn-01), nonce, account, order |
| **SCEP** | 2560 | 3+ | GetCACaps, PKIOperation, renewal, encryption |
| **CMP** | 4210 | 5+ | Initialization, certification, key update, revocation, polling |

**Common**: Nonce/replay protection, error handling, message signing, encryption

