# Interface Definitions - CZERTAINLY-Interfaces Repository

## 1. Visão Geral

O repositório **CZERTAINLY-Interfaces** centraliza toda a **comunicação interprocessos** entre:

- **Core** ↔ **Conectores**
- **Core** ↔ **Clientes REST**
- **Core** ↔ **Autenticadores** (OAuth2)

Define:
- DTOs (Data Transfer Objects) para requisições/respostas
- Enumerações (Enums) de domínio
- Exceções customizadas
- Schemas de atributos dinâmicos
- Callbacks e mecanismos de integração

**Propósito principal**: Contrato imutável entre componentes em evolução independente.

---

## 2. Estrutura de Diretórios

```
CZERTAINLY-Interfaces/src/main/java/com/czertainly/api/

├── clients/                    # HTTP Clients para comunicação
│   ├── CertificateApiClient
│   ├── ConnectorApiClient
│   ├── AuthorityApiClient
│   └── ...
│
├── config/serializer/          # Serialização/desserialização
│   ├── AttributeContentSerializer
│   ├── ResponseAttributeDeserializer
│   ├── RequestAttributeDeserializer
│   └── ...
│
├── exception/                  # Exceções da plataforma
│   ├── ValidationException
│   ├── NotFoundException
│   ├── ConnectorException
│   ├── ConnectorCommunicationException
│   ├── ConnectorServerException
│   ├── AttributeException
│   └── CertificateException
│
├── interfaces/
│   ├── connector/              # APIs para conectores
│   │   ├── AttributesController.java
│   │   ├── CertificateController.java
│   │   ├── AuthorityInstanceController.java
│   │   ├── ComplianceController.java
│   │   ├── DiscoveryController.java
│   │   ├── KeyManagementController.java
│   │   ├── EntityController.java
│   │   ├── NotificationController.java
│   │   ├── TokenInstanceController.java
│   │   ├── VaultInstanceController.java
│   │   └── CustomAttributeController.java
│   │
│   └── core/                   # APIs centrais do Core
│       ├── web/                # Protocolos
│       │   ├── AcmeRestController.java
│       │   ├── ScepRestController.java
│       │   ├── CmpRestController.java
│       │   └── ...
│       │
│       ├── client/v2/          # Operations de certificados
│       │   ├── CertificateController.java
│       │   ├── ClientCertificateController.java
│       │   ├── RaProfileController.java
│       │   ├── ConnectorController.java
│       │   ├── ApprovalController.java
│       │   ├── DiscoveryController.java
│       │   └── ...
│       │
│       └── ...
│
└── model/                      # DTOs e modelos
    ├── common/                 # Atributos, callbacks, enums compartilhados
    │   ├── RequestAttribute.java
    │   ├── ResponseAttribute.java
    │   ├── AttributeContent.java
    │   ├── Attribute.java
    │   ├── AttributeCallback.java
    │   ├── AttributeCallback1Param.java
    │   ├── MetadataResponseDto.java
    │   ├── enums/
    │   │   ├── AttributeType.java       (STRING, INTEGER, BOOLEAN, etc)
    │   │   ├── AttributeTypeEnum.java
    │   │   ├── ContentType.java
    │   │   ├── ValidationError.java
    │   │   └── ...
    │   └── ...
    │
    ├── client/                 # DTOs de cliente HTTP
    │   ├── ClientCertificateSignRequestDto
    │   ├── ClientCertificateRenewRequestDto
    │   ├── ClientCertificateRevocationDto
    │   ├── ClientCertificateDataResponseDto
    │   ├── SearchRequestDto
    │   └── ...
    │
    ├── connector/              # DTOs de conectores
    │   ├── ConnectorRequestDto
    │   ├── ConnectorResponseDto
    │   ├── ConnectorStatusDto
    │   ├── FunctionGroupCode.java
    │   └── ...
    │
    └── core/                   # DTOs principais
        ├── certificate/        # 26 arquivos
        │   ├── CertificateDto
        │   ├── CertificateDetailDto
        │   ├── CertificateSimpleDto
        │   ├── CertificateRequestDto
        │   ├── CertificateListDto
        │   ├── DiscoveryCertificateDto
        │   ├── CertificateState.java           (ENUM)
        │   ├── CertificateValidationStatus.java (ENUM)
        │   ├── CertificateProtocol.java         (ENUM)
        │   ├── CertificateFormat.java           (ENUM)
        │   ├── CertificateContentType.java      (ENUM)
        │   ├── CertificateEventHistory.java
        │   ├── CertificateEventStatus.java      (ENUM)
        │   ├── CertificateEvent.java            (ENUM)
        │   └── ...
        │
        ├── authority/          # DTOs de Autoridade Certificadora
        │   ├── CertificateSignRequestDto
        │   ├── CertificateSignResponseDto
        │   ├── CertificateRevokeRequestDto
        │   ├── CertRevocationDto
        │   ├── AuthorityInstanceDto
        │   └── ...
        │
        ├── cryptography/       # DTOs de chaves/criptografia
        │   ├── CryptographicKeyDto
        │   ├── CryptographicKeyDetailDto
        │   ├── CryptographicKeyRequestDto
        │   ├── CryptographicOperationDto
        │   ├── TokenProfileDto
        │   ├── TokenInstanceDto
        │   └── ...
        │
        ├── v2/                 # Client operations (v2 API)
        │   ├── ClientCertificateSignRequestDto
        │   ├── ClientCertificateRenewRequestDto
        │   ├── ClientCertificateRekeyRequestDto
        │   ├── ClientCertificateRevocationDto
        │   ├── ClientCertificateDataResponseDto
        │   └── ...
        │
        ├── acme/               # ACME protocol DTOs
        │   ├── AcmeProfileDto
        │   ├── AcmeAccountDto
        │   ├── AcmeOrderDto
        │   ├── AcmeChallengeDto
        │   └── ...
        │
        ├── scep/               # SCEP protocol DTOs
        │   ├── ScepProfileDto
        │   ├── ScepRequestDto
        │   ├── ScepResponseDto
        │   └── ...
        │
        ├── cmp/                # CMP protocol DTOs
        │   ├── CmpProfileDto
        │   ├── CmpRequestDto
        │   ├── CmpResponseDto
        │   └── ...
        │
        └── enums/              # Enumerações
            ├── CertificateEvent.java
            ├── CertificateEventStatus.java
            ├── CertificateProtocol.java
            ├── CertificateState.java
            ├── CertificateValidationStatus.java
            ├── CertificateFormat.java
            ├── CertificateContentType.java
            ├── ComplianceStatus.java
            ├── ApprovalStatus.java
            ├── ResourceAction.java
            ├── Resource.java
            └── ...
```

---

## 3. DTOs Principais - Certificados

### 3.1. CertificateDto (Básico)

```java
public class CertificateDto {
    // Identidade
    UUID uuid;
    String fingerprint;
    String commonName;
    String subjectDn;
    String issuerDn;
    String serialNumber;
    
    // Validade
    LocalDateTime notBefore;
    LocalDateTime notAfter;
    
    // Estado
    CertificateState state;                 // ACTIVE, REVOKED, EXPIRED
    CertificateValidationStatus validationStatus;  // VALID, INVALID, UNKNOWN
    ComplianceStatus complianceStatus;
    
    // Metadados
    LocalDateTime created;
    String author;
}
```

### 3.2. CertificateDetailDto (Estendido)

```java
public class CertificateDetailDto extends CertificateDto {
    // Extensões X.509
    List<String> keyUsage;              // [digitalSignature, keyEncipherment]
    List<String> extendedKeyUsage;      // [serverAuth, clientAuth]
    List<String> subjectAlternativeNames; // [example.com, *.example.com]
    
    // Criptografia
    String publicKeyAlgorithm;          // RSA, ECC, DILITHIUM
    Integer keyLength;                  // 2048, 4096, etc
    String signatureAlgorithm;          // SHA256withRSA, SHA256withECDSA
    
    // Relacionamentos
    UUID raProfileUuid;                 // CA que emitiu
    UUID keyUuid;                       // Chave associada
    List<UUID> locations;               // Onde está deployado
    
    // Atributos customizados
    List<ResponseAttribute> customAttributes;
    
    // Metadados
    List<MetadataResponseDto> metadata;
    
    // Auditoria
    UUID creatorUuid;
    LocalDateTime createdAt;
    UUID lastModifiedBy;
    LocalDateTime lastModifiedAt;
    
    // Conformidade
    ComplianceStatus complianceStatus;
    Map<String, Object> complianceResult;  // JSONB deserializado
}
```

### 3.3. CertificateRequestDto (Requisição)

```java
public class CertificateRequestDto {
    // Tipo de requisição
    CertificateRequestFormat format;        // PKCS10, PKCS7, etc
    
    // CSR ou certificado
    String request;                         // PEM encoded
    
    // Configuração
    CertificateProtocol protocol;           // ACME, SCEP, CMP
    
    // Atributos de requisição
    List<RequestAttribute> requestAttributes;
    
    // Assinatura (opcional)
    String signatureAttributes;             // Assinadores, timestamping, etc
    
    // Metadados
    String description;
    Map<String, String> customFields;
}
```

### 3.4. DiscoveryCertificateDto

```java
public class DiscoveryCertificateDto {
    // Identity
    String serialNumber;
    String subjectDn;
    String issuerDn;
    
    // Validade
    LocalDateTime notBefore;
    LocalDateTime notAfter;
    
    // Status de descoberta
    CertificateDiscoveryStatus status;      // NEW, IMPORTED, UPDATED, EXPIRED
    
    // Origem
    UUID discoveryUuid;
    LocalDateTime discoveredAt;
    
    // Certificado em PEM
    String certificate;
    
    // Flag para importação
    Boolean associateWithProfile;           // Associar a RA Profile?
}
```

---

## 4. Client Operations DTOs (v2 API)

### 4.1. Sign Request

```java
public class ClientCertificateSignRequestDto {
    // CSR ou chave pública
    String certificateRequest;              // PEM encoded
    
    // Formato de input
    CertificateRequestFormat format;        // PKCS10, SPKAC
    
    // RA Profile para emissão
    UUID raProfileUuid;
    
    // Atributos de requisição
    List<RequestAttribute> requestAttributes;
    
    // Metadados
    String description;
}

public class ClientCertificateSignResponseDto {
    // Certificado emitido
    String certificate;                     // PEM encoded
    List<String> certificateChain;          // Cadeia de certificados
    
    // Metadados
    UUID certificateUuid;
    String serialNumber;
    LocalDateTime notAfter;
    
    // Status
    String status;
}
```

### 4.2. Renew Request

```java
public class ClientCertificateRenewRequestDto {
    // Certificado a renovar
    UUID certificateUuid;
    
    // RA Profile (opcional, padrão = original)
    UUID raProfileUuid;
    
    // Atributos
    List<RequestAttribute> requestAttributes;
}

public class ClientCertificateRenewResponseDto {
    // Novo certificado
    String certificate;
    List<String> certificateChain;
    
    // Links
    UUID newCertificateUuid;
    UUID oldCertificateUuid;
}
```

### 4.3. Rekey Request

```java
public class ClientCertificateRekeyRequestDto {
    // Certificado para rekey
    UUID certificateUuid;
    
    // Nova chave (gerada pelo client ou core?)
    String newPublicKey;                    // PEM encoded
    
    // RA Profile (opcional)
    UUID raProfileUuid;
    
    // Atributos
    List<RequestAttribute> requestAttributes;
}

public class ClientCertificateRekeyResponseDto {
    // Novo certificado com nova chave
    String certificate;
    List<String> certificateChain;
    
    // Informações de chave
    UUID newKeyUuid;
    UUID oldKeyUuid;
}
```

### 4.4. Revocation Request

```java
public class ClientCertificateRevocationDto {
    // Certificado a revogar
    UUID certificateUuid;
    
    // Razão de revogação
    RevocationReason reason;                // KEY_COMPROMISE, SUPERSEDED, etc
    
    // Data efetiva (opcional)
    LocalDateTime revocationDate;
}

public class ClientCertificateDataResponseDto {
    // Dados gerais
    UUID uuid;
    String commonName;
    CertificateState state;
    
    // Certificado
    String certificate;
    List<String> certificateChain;
    
    // Metadados
    LocalDateTime created;
    LocalDateTime notAfter;
}
```

---

## 5. Atributos Dinâmicos: Arquitetura

### 5.1. RequestAttribute

```java
public abstract class RequestAttribute {
    // Versionamento
    @JsonProperty("v")
    String version;                         // "V2", "V3"
    
    // Nome do atributo
    @JsonProperty("n")  
    String name;                            // "eep_id", "cert_profile"
    
    // Conteúdo polímorfo
    @JsonTypeInfo(use = JsonTypeInfo.Id.NAME, include = JsonTypeInfo.As.PROPERTY, property = "t")
    @JsonSubTypes({
        @JsonSubTypes.Type(value = StringAttribute.class, name = "string"),
        @JsonSubTypes.Type(value = IntegerAttribute.class, name = "int"),
        @JsonSubTypes.Type(value = BooleanAttribute.class, name = "boolean"),
        @JsonSubTypes.Type(value = FileAttribute.class, name = "file"),
        @JsonSubTypes.Type(value = SecretAttribute.class, name = "secret"),
        @JsonSubTypes.Type(value = ListAttribute.class, name = "list"),
        // ... outros tipos
    })
    AttributeContent content;
}

// Exemplos de conteúdo
public class StringAttribute extends AttributeContent {
    String value;                           // "example_value"
}

public class IntegerAttribute extends AttributeContent {
    Integer value;                          // 365
}

public class BooleanAttribute extends AttributeContent {
    Boolean value;                          // true
}

public class SecretAttribute extends AttributeContent {
    String value;                           // "[ENCRYPTED]"
    Boolean sensitive = true;               // Nunca retornar em GET
}

public class ListAttribute extends AttributeContent {
    List<AttributeContent> items;           // [StringAttribute, StringAttribute]
}
```

### 5.2. ResponseAttribute (Schema)

```java
public abstract class ResponseAttribute {
    // Versionamento
    String version;                         // "V2", "V3"
    
    // Nome
    String name;                            // "eep_id"
    
    // Descrição
    String description;                     // "End Entity Profile ID"
    
    // Obrigatoriedade
    Boolean required;                       // true/false
    
    // Tipo de conteúdo
    String contentType;                     // "string", "integer", "enum", "file"
    
    // Valores padrão
    Object defaultValue;                    // "GENERIC"
    
    // Constraints
    Object data;                            // Polimórfico
}

// Exemplo: Enum Schema
public class EnumResponseAttribute extends ResponseAttribute {
    // Enum specifics
    List<String> options;                   // ["GENERIC", "WEB_SSL", "CODE_SIGNING"]
    String selectedOption;                  // se default
}

// Exemplo: Range Schema
public class IntegerResponseAttribute extends ResponseAttribute {
    Integer min;                            // 30
    Integer max;                            // 3650
    Integer step;                           // 1
}

// Exemplo: File Schema
public class FileResponseAttribute extends ResponseAttribute {
    String fileType;                        // "certificate", "key", "csr"
    String[] allowedExtensions;             // [".pem", ".p12", ".der"]
    Long maxSize;                           // bytes
}
```

### 5.3. AttributeCallback (Dependências)

```java
public class AttributeCallback {
    // Atributo que mudou
    String callbackAttributeName;           // "ca_name"
    
    // Novo valor
    Object callbackAttributeValue;          // "RootCA"
    
    // Solicitar atualização de schema para dependentes
    List<String> requestedAttributeNames;   // ["eep_id", "cert_profile"]
}

// Fluxo:
// 1. Client seleciona "ca_name" = "RootCA"
// 2. Envia AttributeCallback
// 3. Core POST {connector}/callbacks/validate-attributes 
//    + callbackAttributeValue
// 4. Connector retorna novo schema para "eep_id", "cert_profile"
// 5. Dropdown atualizado dinamicamente no frontend
```

---

## 6. Enumerações Críticas

### 6.1. Certificate States

```java
public enum CertificateState {
    // Estados de requisição
    REQUESTED,                              // Just created
    PENDING_APPROVAL,                       // Awaiting approval
    PENDING_ISSUE,                          // Approval given, waiting CA
    
    // Estados finais
    ISSUED,                                 // ✓ Success
    REVOKED,                                // Revogado
    EXPIRED,                                // Expirou
    
    // Estados de falha
    FAILED,                                 // Falha geral
    REJECTED,                               // Rejeitado (approval)
    
    // Estados de ciclo de vida
    RENEWED,                                // Renovado
    REKEYED;                                // Rekey completado
}
```

### 6.2. Certificate Validation Status

```java
public enum CertificateValidationStatus {
    VALID,                                  // Todas as validações OK
    INVALID,                                // Falha crítica
    INVALID_EXPIRED,                        // Data expirada
    INVALID_NOT_YET_VALID,                  // notBefore > now
    INVALID_SIGNATURE,                      // Assinatura inválida
    INVALID_CHAIN,                          // Cadeia inválida
    UNKNOWN,                                // Não conseguiu validar (issuer não trusted)
    NOT_CHECKED;                            // Validação não executada
}
```

### 6.3. Certificate Protocols

```java
public enum CertificateProtocol {
    ACME,                                   // RFC 8555 - Let's Encrypt
    SCEP,                                   // Simple Certificate Enrollment Protocol
    CMP,                                    // Certificate Management Protocol
    CRMF,                                   // Certificate Request Message Format
    REST,                                   // REST API customizado
    EJBCA;                                  // EJBCA-specific
}
```

### 6.4. Certificate Events

```java
public enum CertificateEvent {
    // Lifecycle
    UPLOAD,                                 // Certificado importado
    DISCOVERY,                              // Descoberto automaticamente
    VALIDATION,                             // Validação executada
    ISSUE,                                  // Emitido por CA
    RENEWAL,                                // Renovado
    REKEY,                                  // Rekey executado
    REVOKE,                                 // Revogação solicitada
    REVOKED,                                // Revogação confirmada
    
    // Approval workflow
    APPROVAL_REQUESTED,                     // Aprovação requisitada
    APPROVAL_APPROVED,                      // Aprovado
    APPROVAL_REJECTED,                      // Rejeitado
    
    // Compliance
    COMPLIANCE_CHECK,                       // Conformidade validada
    
    // Expiração
    EXPIRATION_WARNING,                     // Aviso 30 dias antes
    EXPIRED;                                // Expirou
}

public enum CertificateEventStatus {
    PENDING,                                // Em progresso
    SUCCESS,                                // ✓ Completado
    FAILED;                                 // ✗ Erro
}
```

### 6.5. Function Groups

```java
public enum FunctionGroupCode {
    // Certificate Authority
    CA("AUTHORITY_PROVIDER"),
    
    // Key Management
    KEY_MANAGEMENT("CRYPTOGRAPHY_PROVIDER"),
    
    // Discovery
    DISCOVERY("DISCOVERY_PROVIDER"),
    
    // Entity Management
    ENTITY("ENTITY_PROVIDER"),
    
    // Compliance Checking
    COMPLIANCE("COMPLIANCE_PROVIDER"),
    COMPLIANCE_V2("COMPLIANCE_PROVIDER_V2"),
    
    // Notifications
    NOTIFICATION("NOTIFICATION_PROVIDER"),
    
    // Credential Management
    CREDENTIAL("CREDENTIAL_PROVIDER");
}
```

---

## 7. Validação e Exceções

### 7.1. Exception Hierarchy

```java
// Root
public class ValidationException extends Exception {
    List<ValidationError> errors;
    
    // Exemplo:
    // errors = [
    //   {code: "E001", message: "CSR signature invalid", errorDescription: "..."},
    //   {code: "E002", message: "Subject DN format invalid", errorDescription: "..."}
    // ]
}

// Conector-specific
public class ConnectorException extends Exception {
    String connectorName;
    UUID connectorUuid;
}

public class ConnectorCommunicationException extends ConnectorException {
    // Timeout, network error, etc
}

public class ConnectorServerException extends ConnectorException {
    // Connector respondeu com erro (5xx)
    int httpStatusCode;
    String responseBody;
}

// Domain-specific
public class CertificateException extends Exception {
    UUID certificateUuid;
}

public class NotFoundException extends Exception {
    String resourceType;
    UUID resourceId;
}

public class AttributeException extends Exception {
    String attributeName;
    String errorReason;
}

// Approval workflow
public class ApprovalRequiredException extends Exception {
    UUID approvalProfileUuid;
    LocalDateTime expiryAt;
    List<String> approvers;
}
```

### 7.2. Validação com Jakarta Validation

```java
public class CertificateRequestDto {
    @NotNull(message = "CSR cannot be null")
    @NotBlank(message = "CSR cannot be blank")
    String csr;
    
    @NotNull(message = "RA Profile must be specified")
    UUID raProfileUuid;
    
    @Size(min = 0, max = 100, message = "Max 100 attributes allowed")
    List<RequestAttribute> requestAttributes;
    
    @Pattern(regexp = "^[A-Za-z0-9_-]+$", message = "Invalid name format")
    String name;
}

// Validação em camada de API:
@PostMapping
public ResponseEntity<?> createCertificate(
    @Valid @RequestBody CertificateRequestDto dto) {
    // Jakarta Validation triggered automatically
    // Se inválido: 400 Bad Request com validation errors
}
```

---

## 8. Padrão de Resposta REST

### 8.1. Sucesso

```json
POST /api/v2/certificates/request
200 OK

{
    "uuid": "550e8400-e29b-41d4-a716-446655440000",
    "commonName": "example.com",
    "subjectDn": "CN=example.com,O=Example,C=US",
    "issuerDn": "CN=Root CA,O=Example,C=US",
    "serialNumber": "123456789ABC",
    "state": "ISSUED",
    "validationStatus": "VALID",
    "notBefore": "2026-01-14T10:30:00Z",
    "notAfter": "2027-01-14T10:30:00Z",
    "publicKeyAlgorithm": "RSA",
    "keyLength": 2048,
    "signatureAlgorithm": "SHA256withRSA",
    "certificate": "-----BEGIN CERTIFICATE-----...",
    "certificateChain": ["...issuer...", "...root..."],
    "customAttributes": [
        {
            "v": "V2",
            "n": "department",
            "t": "string",
            "value": "Finance"
        }
    ],
    "metadata": [
        {"key": "sourcePath", "value": "/storage/certs/example.com.pem"}
    ],
    "created": "2026-01-14T10:30:00Z",
    "author": "admin@example.com"
}
```

### 8.2. Erro de Validação (422)

```json
POST /api/v2/certificates/request
422 Unprocessable Entity

{
    "errors": [
        {
            "code": "INVALID_CSR",
            "message": "Certificate Signing Request is invalid",
            "errorDescription": "CSR signature verification failed: Invalid signature"
        },
        {
            "code": "INVALID_SUBJECT_DN",
            "message": "Subject Distinguished Name format invalid",
            "errorDescription": "CN must be a valid DNS name or IP address"
        }
    ]
}
```

### 8.3. Erro de Autenticação (401)

```json
GET /api/v2/certificates
401 Unauthorized

{
    "code": "AUTHENTICATION_FAILED",
    "message": "Authentication failed",
    "errorDescription": "Invalid or expired JWT token"
}
```

### 8.4. Erro de Autorização (403)

```json
POST /api/v2/certificates/{uuid}/revoke
403 Forbidden

{
    "code": "AUTHORIZATION_FAILED",
    "message": "Access denied",
    "errorDescription": "User lacks CERTIFICATE_REVOKE permission. Required role: COMPLIANCE_OFFICER"
}
```

### 8.5. Recurso Não Encontrado (404)

```json
GET /api/v2/certificates/00000000-0000-0000-0000-000000000000
404 Not Found

{
    "code": "CERTIFICATE_NOT_FOUND",
    "message": "Certificate not found",
    "errorDescription": "Certificate UUID 00000000-0000-0000-0000-000000000000 does not exist"
}
```

---

## 9. Versionamento de API

### 9.1. Estratégia de Versão

```
Endpoint URL: /api/v2/...
              ├─ v1: Legacy (deprecated)
              └─ v2: Current stable + breaking changes tracked

Query Parameter: ?apiVersion=2.0

Header: Accept: application/vnd.czertainly.api+json;version=2
```

### 9.2. Evolução de DTOs

```
Extensão sem breaking changes:
├─ Adicionar novos campos (com default)
└─ Nunca remover existentes

Exemplo:
// v1.0 (2024)
public class CertificateDto {
    UUID uuid;
    String commonName;
}

// v2.0 (2025) - Backward compatible
public class CertificateDto {
    UUID uuid;
    String commonName;
    String fingerprint;              // ← novo campo
    LocalDateTime created;            // ← novo campo
    // Valores antigos retornam como null/default
}

// v3.0 (Futuro) - Breaking change
// Criar nova versão se necessário remover/renomear
```

---

## 10. Serialização de Atributos

### 10.1. Custom JSON Serializers

```java
// RequestAttribute polimórfico
public class RequestAttributeDeserializer 
    extends StdDeserializer<RequestAttribute> {
    
    @Override
    public RequestAttribute deserialize(JsonParser p, DeserializationContext ctxt) {
        JsonNode node = p.getCodecRegistry().readTree(p);
        
        String version = node.get("v").asText();
        String name = node.get("n").asText();
        String contentType = node.get("t").asText();
        
        switch(contentType) {
            case "string":
                return new StringAttribute(
                    version, name, node.get("value").asText()
                );
            case "int":
                return new IntegerAttribute(
                    version, name, node.get("value").asInt()
                );
            // ... outros tipos
        }
    }
}

// Registro com ObjectMapper
ObjectMapper mapper = new ObjectMapper();
SimpleModule module = new SimpleModule();
module.addDeserializer(RequestAttribute.class, 
    new RequestAttributeDeserializer());
mapper.registerModule(module);
```

---

## 11. Callbacks: Connector → Core

### 11.1. Get Attributes Callback

```
POST {core}/api/v1/connector/callbacks/get-attributes
{
    "functionGroup": "CA",
    "functionName": "ISSUE_CERTIFICATE",
    "requestAttributes": [
        // Atributos anteriores selecionados (para dependency resolution)
    ]
}

Response: [
    {
        "v": "V2",
        "n": "eep_id",
        "description": "End Entity Profile",
        "required": true,
        "contentType": "enum",
        "data": {
            "options": ["GENERIC", "WEB_SSL"],
            "selectedOption": "GENERIC"
        }
    },
    ...
]
```

### 11.2. Validate Attributes Callback

```
POST {core}/api/v1/connector/callbacks/validate-attributes
{
    "functionGroup": "CA",
    "functionName": "ISSUE_CERTIFICATE",
    "requestAttributes": [
        {
            "v": "V2",
            "n": "eep_id",
            "t": "enum",
            "value": "GENERIC"
        }
    ]
}

Response: {
    "valid": true,
    "errors": []
}

OU (com erros):

{
    "valid": false,
    "errors": [
        {
            "code": "INVALID_EEP",
            "message": "Invalid EEP ID",
            "errorDescription": "Profile GENERIC not found in this authority"
        }
    ]
}
```

---

## Conclusão

O CZERTAINLY-Interfaces define um **contrato robusto e evoluível** para:

✓ **Comunicação REST** (JSON strongly-typed)
✓ **Atributos dinâmicos** (polimorfismo, versionamento)
✓ **Integração de conectores** (discovery automático, callbacks)
✓ **Validação** (Jakarta Validation, custom errors)
✓ **Auditoria** (eventos imutáveis, history completa)
✓ **Segurança** (encryption, RBAC, sensitive fields)

O repositório é a **ponte entre Core e Conectores**, permitindo evolução independente com compatibilidade garantida.

