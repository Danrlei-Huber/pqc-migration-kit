# Conectores e Providers - Arquitetura de Integração CZERTAINLY-Core

## 1. Visão Geral: Connector Architecture

O CZERTAINLY-Core utiliza um **padrão de plugin distribuído** onde conectores externos (rodando em Docker containers) são orquestrados pelo Core via REST API:

```
           ┌────────────────────────────┐
           │    CZERTAINLY-Core         │
           │  (Orquestração + DB)       │
           └────────────┬───────────────┘
                        │ HTTP REST
        ┌───────────────┼───────────────┐
        │               │               │
   ┌────▼─────┐   ┌─────▼────┐   ┌─────▼────┐
   │  EJBCA   │   │   Vault  │   │ AWS ACM  │
   │Connector │   │ Connector│   │Connector │
   └──────────┘   └──────────┘   └──────────┘
        │               │               │
   ┌────▼─────┐   ┌─────▼────┐   ┌─────▼────┐
   │  EJBCA   │   │ HashiCorp│   │   AWS    │
   │   (CA)   │   │  Vault   │   │  ACM     │
   └──────────┘   └──────────┘   └──────────┘
```

**Característica chave**: Core não gerencia CAs diretamente. Conectores são proxies que comunicam com infraestrutura PKI real.

---

## 2. Entidade Connector

### Mapeamento JPA

```java
@Entity
@Table(name = "connector")
public class Connector extends UniquelyIdentifiedAndAudited {
    
    @Column(name = "name")
    private String name;                    // "EJBCA Production", "Vault Dev"
    
    @Column(name = "url")
    private String url;                     // "https://connector.example.com:8080"
    
    @Enumerated(EnumType.STRING)
    @Column(name = "version")
    private ConnectorVersion version;       // V1 ou V2 (compatibilidade)
    
    @Enumerated(EnumType.STRING)
    @Column(name = "auth_type")
    private AuthType authType;              // BASIC, CERTIFICATE, API_KEY
    
    @Column(name = "auth_attributes")
    private String authAttributes;          // JSON serializado (username/password/key)
    
    @OneToMany(mappedBy = "connector")
    private Set<Connector2FunctionGroup> functionGroups;  // CA, KEY_MGMT, DISCOVERY
    
    @OneToMany(mappedBy = "connector")
    private Set<ConnectorInterfaceEntity> interfaces;     // Endpoints HTTP
    
    @Enumerated(EnumType.STRING)
    @Column(name = "status")
    private ConnectorStatus status;         // UP, DOWN, ERROR, MAINTENANCE
    
    @Column(name = "last_health_check")
    private LocalDateTime lastHealthCheck;
    
    @Column(name = "status_message")
    private String statusMessage;           // "Timeout after 30s" ou similar
}
```

### States

```
ConnectorStatus enum:
├─ UP: Connector respondendo, health check OK
├─ DOWN: Timeout/unreachable
└─ ERROR: Respondendo com erro

ConnectorVersion enum:
├─ V1: Legacy (less features)
└─ V2: Current (full capabilities)
```

### Relacionamentos Críticos

```
Connector (1) ──── (n) Connector2FunctionGroup
               │
               ├──── (n) ConnectorInterfaceEntity
               │
               ├──── (n) AuthorityInstance
               │
               └──── (n) TokenInstance (HSM/smartcard)
```

---

## 3. Function Groups: Tipologia de Conectores

### 3.1. Function Group - Categorização

```java
@Entity
class Connector2FunctionGroup {
    UUID connectorUuid;
    FunctionGroupCode code;         // CA, KEY_MGMT, DISCOVERY, etc
    String description;
    Boolean endEntityOnly;          // true = conecta apenas end entities
    Boolean endEntityCounterLimit;  // limite de entidades?
    Long endEntityCounter;          // se sim, qual?
}

enum FunctionGroupCode {
    // Autoridade Certificadora
    CA("AUTHORITY_PROVIDER"),
    
    // Gerenciamento de Chaves
    KEY_MANAGEMENT("CRYPTOGRAPHY_PROVIDER"),
    
    // Descoberta de certificados
    DISCOVERY("DISCOVERY_PROVIDER"),
    
    // Entidades (usuários, máquinas)
    ENTITY("ENTITY_PROVIDER"),
    
    // Conformidade
    COMPLIANCE("COMPLIANCE_PROVIDER"),
    
    // Notificações
    NOTIFICATION("NOTIFICATION_PROVIDER")
}
```

### 3.2. Exemplos de Conectores Reais

| Connector | Function Groups | Protocols | Descrição |
|-----------|-----------------|-----------|-----------|
| **EJBCA** | CA, KEY_MGMT, DISCOVERY, ENTITY | ACME, SCEP, CMP, REST | Suite completa de CA |
| **HashiCorp Vault** | CA, KEY_MGMT | ACME, PKI Engine | HSM + Secret Management |
| **AWS ACM** | CA, KEY_MGMT | AWS API | Cloud CA gerenciada |
| **Sectigo** | CA, DISCOVERY | ACME, REST | Public CA |
| **DigiCert** | CA, COMPLIANCE | REST | Public CA + auditorias |
| **Generic SCEP** | CA | SCEP | CA com suporte SCEP |
| **PKCS11 HSM** | KEY_MGMT | PKCS11 | Hardware Security Module |
| **Custom** | Qualquer | Qualquer | Implementação customizada |

---

## 4. Connector Registration Flow

### 4.1. Sequência de Registro

```
POST /api/v2/connectors
{
    "name": "EJBCA Production",
    "url": "https://ejbca.example.com:8080",
    "authType": "BASIC",
    "authAttributes": {
        "username": "core-admin",
        "password": "secret123"
    }
}

 ↓

ConnectorService.createConnector()

├─ STEP 1: Validação básica
│  ├─ URL não-vazia
│  └─ AuthType válido

├─ STEP 2: Health Check
│  GET {url}/api/v1/connector/info
│  └─ Response: {
│        version: "V2",
│        name: "EJBCA Connector",
│        functionGroups: ["CA", "KEY_MGMT"],
│        interfaces: ["ACME", "SCEP", "CMP"]
│      }

├─ STEP 3: Discover Function Groups
│  GET {url}/api/v1/connector/functions
│  └─ Response: {
│        functionGroups: [
│          {code: "CA", description: "Certificate Authority", endEntityOnly: false},
│          {code: "KEY_MGMT", description: "Cryptography", endEntityOnly: false}
│        ]
│      }

├─ STEP 4: Discover Attributes (Schema)
│  GET {url}/api/v1/connector/attributes
│  │  ?functionGroup=CA&functionName=ISSUE_CERTIFICATE
│  └─ Response: [
│        {name: "eep_id", type: "string", required: true},
│        {name: "cert_profile", type: "enum", values: ["RSA2048", "ECC256"]},
│        {name: "expiry_days", type: "integer", min: 1, default: 365}
│      ]

├─ STEP 5: Persist to Database
│  └─ connectorRepository.save(connector)
│     ├─ connectorFunctionGroupRepository.saveAll(functionGroups)
│     └─ connectorInterfaceRepository.saveAll(interfaces)

└─ STEP 6: Return
   └─ ConnectorDto (com status UP)
```

### 4.2. Health Check Agendado

```java
@Component
@Scheduled(fixedDelay = 300000)  // 5 minutos
public class ConnectorHealthCheckScheduler {
    
    public void performHealthCheck() {
        List<Connector> connectors = connectorRepository.findAll();
        
        for (Connector connector : connectors) {
            try {
                // GET {url}/api/v1/connector/health
                HealthResponse health = restTemplate.getForObject(
                    connector.getUrl() + "/api/v1/connector/health",
                    HealthResponse.class
                );
                
                Boolean wasUp = connector.getStatus() == ConnectorStatus.UP;
                Boolean isUp = health.getStatus() == "UP";
                
                if (wasUp != isUp) {
                    connector.setStatus(isUp ? UP : DOWN);
                    connector.setStatusMessage(health.getMessage());
                    connector.setLastHealthCheck(LocalDateTime.now());
                    connectorRepository.save(connector);
                    
                    // Publish event for alerting
                    publishEvent(new ConnectorStatusChangedEvent(connector));
                }
            } catch (Exception e) {
                connector.setStatus(ConnectorStatus.DOWN);
                connector.setStatusMessage(e.getMessage());
                connectorRepository.save(connector);
            }
        }
    }
}
```

---

## 5. Credential Management

### 5.1. Armazenamento de Credenciais

```java
@Entity
@Table(name = "credential")
public class Credential extends UniquelyIdentifiedAndAudited {
    
    @Column(name = "name")
    private String name;                    // "EJBCA Root Admin"
    
    @Column(name = "kind")
    private String kind;                    // "ca-admin-user", "api-token"
    
    @Column(name = "connector_uuid")
    private UUID connectorUuid;             // FK referenciando Connector
    
    @Column(name = "enabled")
    private Boolean enabled;                // Credencial ativa?
    
    @OneToMany(mappedBy = "credential")
    private Set<CredentialAttribute> attributes;  // username, password, etc
}

@Entity
@Table(name = "credential_attribute")
public class CredentialAttribute {
    
    @Column(name = "attribute_name")
    private String name;                    // "username", "password", "api_key"
    
    @Column(name = "attribute_value")
    private String value;                   // Encriptado em repouso
    
    @Column(name = "sensitive")
    private Boolean sensitive;              // true para passwords
    
    // ForeignKey
    UUID credentialUuid;
}
```

### 5.2. Fluxo de Proteção

```
1. Cliente envia credential
   ├─ HTTPS em trânsito (TLS 1.3)
   └─ mTLS (mutual TLS) com connector

2. Persistência
   ├─ Validar contra schema do connector
   │  POST {url}/callbacks/validate-credential-attributes
   ├─ Encriptação em repouso
   │  └─ Spring Security PasswordEncoder (BCRYPT)
   └─ Armazenar em DB

3. Recuperação
   ├─ Desencriptar apenas quando necessário
   ├─ Nunca retornar em GET response (passwords omitidas)
   └─ Audit logging de acesso

4. RBAC
   ├─ credential.read → OPA policy
   └─ credential.admin → OPA rule
```

### 5.3. Exemplo: EJBCA Credential

```java
POST /api/v2/credentials
{
    "name": "EJBCA Admin",
    "kind": "ca-admin-user",
    "connectorUuid": "...",
    "attributes": [
        {
            "name": "admin_username",
            "value": "ejbca-admin",
            "sensitive": false
        },
        {
            "name": "admin_password",
            "value": "MySecurePassword123!",
            "sensitive": true
        },
        {
            "name": "ejbca_endpoint",
            "value": "https://ejbca.example.com:8080/ejbca",
            "sensitive": false
        }
    ]
}

Persistência:
├─ Encriptação: password encriptado via PasswordEncoder
├─ Armazenamento: credential_attribute table
└─ Auditoria: username + timestamp em credential_attribute_history

GET /api/v2/credentials/{uuid}
├─ Retorna todas as attributes EXCETO sensitive=true
├─ Response: {
│    "name": "EJBCA Admin",
│    "attributes": [
│        {"name": "admin_username", "value": "ejbca-admin"},
│        {"name": "admin_password", "value": "[ENCRYPTED]"},  ← omitido
│        {"name": "ejbca_endpoint", "value": "https://..."}
│    ]
│  }
```

---

## 6. Attribute Management (AttributeEngine)

### 6.1. Descoberta de Atributos Dinâmicos

```
Cada operação do connector pode ter atributos diferentes

Exemplo: ISSUE_CERTIFICATE em EJBCA tem atributos:
├─ eep_id: String (End Entity Profile ID)
├─ cert_profile: Enum (lista de profiles suportados)
├─ ca_name: String (nome da CA)
├─ validity_days: Integer (dias de validade)
└─ san: List<String> (Subject Alternative Names)

Core descobre schema:
GET {connector_url}/callbacks/get-attributes
?functionGroup=CA
&functionName=ISSUE_CERTIFICATE

Response: [
    {
        "name": "eep_id",
        "type": "string",
        "required": true,
        "description": "End Entity Profile ID"
    },
    {
        "name": "cert_profile",
        "type": "enum",
        "required": true,
        "values": ["GENERIC", "WEB_SSL", "CODE_SIGNING"],
        "default": "GENERIC"
    },
    ...
]
```

### 6.2. Validação de Atributos

```
POST /api/v2/raprofiles/{uuid}/validate-issue-attributes
{
    "attributes": [
        {"name": "eep_id", "value": "1"},
        {"name": "cert_profile", "value": "WEB_SSL"},
        {"name": "validity_days", "value": "365"}
    ]
}

 ↓

AttributeEngine.validateAttributes()

├─ 1. Tipo-check (string value = "365", expected integer)
├─ 2. Enum validation (cert_profile in allowed values)
├─ 3. Callback validation
│  POST {connector_url}/callbacks/validate-attributes
│  └─ Connector faz validação adicional (ex: EEP_ID existe?)
├─ 4. Dependency resolution (attributeX depends on attributeY?)
└─ 5. Return
   {
       "valid": true,
       "errors": []
   }
   
   OU
   
   {
       "valid": false,
       "errors": [
           {"field": "cert_profile", "message": "Invalid profile"},
           {"field": "validity_days", "message": "Must be > 30"}
       ]
   }
```

### 6.3. AttributeEngine Responsabilidades

```java
@Component
public class AttributeEngine {
    
    // 1. Fetch schema from connector
    public List<ResponseAttribute> getAttributes(
        UUID connectorUuid,
        String functionGroup,
        String functionName) {
        POST {connector.url}/callbacks/get-attributes?fg=...&fn=...
    }
    
    // 2. Validate values
    public ValidationResult validateAttributes(
        UUID connectorUuid,
        String functionGroup,
        String functionName,
        List<RequestAttribute> attributes) {
        POST {connector.url}/callbacks/validate-attributes
    }
    
    // 3. Serialize/deserialize
    public Object serialize(RequestAttribute attr) {
        // string value → typed object
    }
    
    // 4. Type coercion
    public <T> T coerce(String value, Class<T> targetType) {
        // "365" → Integer(365)
    }
    
    // 5. Cache schema (TTL)
    private Map<String, CachedSchema> schemaCache;  // TTL 1h
}
```

---

## 7. Provider Pattern: CA Issuance

### 7.1. Fluxo Completo de Emissão

```
POST /api/v2/certificates/request
{
    "raProfileUuid": "...",
    "csr": "-----BEGIN CERTIFICATE REQUEST-----...",
    "requestAttributes": []
}

 ↓

CertificateService.requestCertificate()

├─ STEP 1: Resolve Provider Chain
│  └─ RaProfile → AuthorityInstance → Connector
│     {
│        raProfile.authorityInstanceUuid = "auth123"
│        authorityInstance.connectorUuid = "conn456"
│        connector.url = "https://ca.example.com"
│     }

├─ STEP 2: Get Connector Attributes
│  └─ AttributeEngine.getAttributes(
│         functionGroup="CA",
│         functionName="ISSUE_CERTIFICATE"
│      )

├─ STEP 3: Validate Request Attributes
│  └─ AttributeEngine.validateAttributes(attributes)

├─ STEP 4: Call Connector API
│  POST {connector.url}/v1/authorityProvider/authorities/{authId}/certificates/issue
│  
│  Body: {
│      "certificateRequest": {
│          "format": "PKCS10",
│          "csr": "-----BEGIN CERTIFICATE REQUEST-----...",
│          "requestAttributes": [...]
│      }
│  }
│  
│  Headers: {
│      "Authorization": "Bearer {token|credentialId}",
│      "Content-Type": "application/json"
│  }

├─ STEP 5: Parse Response
│  Response: {
│      "certificate": "-----BEGIN CERTIFICATE-----...",
│      "certificateChain": ["...issuer cert..."],
│      "metadata": {
│          "serialNumber": "...",
│          "issuerDn": "...",
│          "validFrom": "2026-01-01T00:00:00Z",
│          "validTo": "2027-01-01T00:00:00Z"
│      }
│  }

├─ STEP 6: Persist Certificate
│  └─ CertificateService.createCertificateAtomic(x509)

├─ STEP 7: Link to Request
│  └─ CertificateRequest.setState(APPROVED)
│     CertificateRequest.setCertificateUuid(newCertUuid)

├─ STEP 8: Publish Event
│  └─ publishEvent(CertificateIssuedEvent)
│     ├─ trigger NotificationProducer
│     └─ trigger AuditLogger

└─ STEP 9: Return
   └─ CertificateDetailDto com UUID, SN, válidade, etc
```

### 7.2. Tratamento de Erros

```
Cenários de erro do connector:

1. Validação falha (422 Unprocessable Entity)
   {
       "errors": [
           {"code": "INVALID_CSR", "message": "CSR signature invalid"},
           {"code": "PROFILE_NOT_FOUND", "message": "Profile ID not found"}
       ]
   }
   → Retornar ValidationException para cliente

2. Connector indisponível (503 Service Unavailable)
   → Retry com backoff exponencial
   → Marcar connector como DOWN
   → Publish ConnectorDownEvent

3. Timeout (30s default)
   → Connector.status = DOWN
   → Return ServiceUnavailableException

4. Authentication fails (401 Unauthorized)
   → Credential inválida
   → Notify admin
   → Return AuthenticationException
```

---

## 8. Certificate Revocation

### 8.1. Fluxo de Revogação

```
POST /api/v2/certificates/{uuid}/revoke
{
    "reason": "KEY_COMPROMISE"
}

 ↓

CertificateService.revokeCertificate()

├─ STEP 1: Buscar certificado
│  └─ Certificate cert = repository.findByUuid(uuid)

├─ STEP 2: Validar estado
│  ├─ cert.getState() != REVOKED
│  └─ cert.getState() != EXPIRED (não revogar expirado)

├─ STEP 3: Resolve provider
│  └─ RaProfile → AuthorityInstance → Connector

├─ STEP 4: Call Connector Revoke API
│  POST {connector.url}/v1/authorityProvider/authorities/{authId}/certificates/revoke
│  
│  Body: {
│      "certificateRevocation": {
│          "serialNumber": "...",
│          "reason": "KEY_COMPROMISE"
│      }
│  }

├─ STEP 5: Update Certificate
│  ├─ cert.setState(REVOKED)
│  ├─ cert.setRevocationReason("KEY_COMPROMISE")
│  └─ certificateRepository.save(cert)

├─ STEP 6: Add Event
│  └─ addEventHistory(REVOKE, SUCCESS)

└─ STEP 7: Publish Event
   └─ publishEvent(CertificateRevokedEvent)
      ├─ trigger CrlUpdater
      └─ trigger OcspUpdater
```

---

## 9. Discovery: Auto-Import de Certificados

### 9.1. Fluxo de Discovery

```
POST /api/v2/discoveries
{
    "name": "EJBCA Daily Import",
    "connectorUuid": "...",
    "attributes": [
        {"name": "authority", "value": "ManagementCA"},
        {"name": "includeSubordinates", "value": true}
    ]
}

 ↓

DiscoveryService.createDiscovery()

├─ 1. Validate connector has DISCOVERY function group
├─ 2. Create Discovery entity (persistent config)
├─ 3. Schedule periodic job (ex: daily 2 AM)

Periodic Execution (via scheduler):
├─ 1. Find all Discovery configs
├─ 2. For each discovery:
│  └─ discoveryService.runDiscovery(discoveryUuid)

discoveryService.runDiscovery():
├─ 1. Get Connector
│  └─ Discovery.connectorUuid → Connector

├─ 2. Get Attributes for Discovery
│  └─ AttributeEngine.getAttributes(
│         functionGroup="DISCOVERY",
│         functionName="DISCOVER_CERTIFICATES"
│      )

├─ 3. Call Connector Discovery Endpoint
│  POST {connector.url}/v1/discoveryProvider/discover
│  
│  Body: {
│      "discoveryCertificateRequest": {
│          "requestAttributes": [
│              {"name": "authority", "value": "ManagementCA"},
│              {"name": "includeSubordinates", "value": true}
│          ]
│      }
│  }

├─ 4. Parse Response
│  Response: {
│      "entries": [
│          {
│              "serialNumber": "...",
│              "subject": "CN=example.com,O=Example,C=US",
│              "issuer": "CN=Root CA,O=Example,C=US",
│              "notBefore": "2023-01-01T00:00:00Z",
│              "notAfter": "2024-01-01T00:00:00Z",
│              "publicKeyAlgorithm": "RSA",
│              "keyLength": 2048,
│              "certificate": "-----BEGIN CERTIFICATE-----..."
│          },
│          ...
│      ]
│  }

├─ 5. Import Each Certificate
│  For each entry:
│  ├─ Check: Já existe no DB?
│  ├─ If novo:
│  │  └─ CertificateService.createCertificateAtomic(x509)
│  │     └─ Status: NEW
│  ├─ If existe com alterações:
│  │  └─ Update metadata
│  │     └─ Status: UPDATED
│  └─ If expirado:
│     └─ Status: EXPIRED (não importar)

├─ 6. Run Compliance Check (async)
│  └─ ComplianceService.checkCertificateCompliance()

├─ 7. Create DiscoveryCertificate records
│  └─ Track: source connector, discovery timestamp, status

└─ 8. Publish Events
   ├─ DiscoveryCertificatesImportedEvent
   ├─ trigger NotificationProducer
   └─ trigger AuditLogger
```

---

## 10. Communication Protocols: Core ↔ Connector

### 10.1. Endpoints Chamados pelo Core

```
Authentication:
├─ GET /api/v1/connector/info
│  └─ Connector info + version
├─ GET /api/v1/connector/health
│  └─ Health status

Function Discovery:
├─ GET /api/v1/connector/functions
│  └─ Supported function groups

Attributes:
├─ GET /api/v1/connector/attributes?functionGroup=CA&functionName=ISSUE
│  └─ Schema dinâmico
├─ POST /api/v1/connector/callbacks/validate-attributes
│  └─ Validação customizada

Authority Operations:
├─ GET /api/v1/authorityProvider/authorities
│  └─ List CAs managed by connector
├─ POST /api/v1/authorityProvider/authorities/{id}/certificates/issue
│  └─ Emit certificate
└─ POST /api/v1/authorityProvider/authorities/{id}/certificates/revoke
   └─ Revoke certificate

Discovery:
├─ POST /api/v1/discoveryProvider/discover
│  └─ List certificates to import

Compliance:
├─ POST /api/v1/complianceProvider/validate
│  └─ Validate certificate against policies
```

### 10.2. Callbacks: Connector → Core

```
Connector chama Core para:

├─ GET /api/v1/connector/callbacks/info
│  └─ Context sobre request em execução

├─ POST /api/v1/connector/callbacks/get-attributes
│  Body: {functionGroup: "CA", functionName: "ISSUE"}
│  └─ Retorna attribute schema

├─ POST /api/v1/connector/callbacks/validate-attributes
│  Body: {attributes: [...]}
│  └─ Validação adicional pelo Core

├─ POST /api/v1/connector/callbacks/notify
│  Body: {event: "...", data: {...}}
│  └─ Enviador de eventos
```

### 10.3. HTTP Headers

```
Request:
├─ Authorization: "Bearer {token}" | "Basic {credentials}"
├─ Content-Type: application/json
├─ Accept: application/json
├─ X-Request-ID: {uuid}  (rastreamento)
└─ User-Agent: CZERTAINLY-Core/v2.0

Response:
├─ Content-Type: application/json
├─ X-Response-Time: 123ms  (telemetria)
└─ Cache-Control: (conforme endpoint)
```

---

## 11. mTLS Setup: Segurança Mutual

### 11.1. Configuração

```yaml
# application.yml
connector:
  mtls:
    enabled: true
    client-certificate: /etc/certs/core-client.p12
    client-key-password: ${CONNECTOR_CLIENT_PASSWORD}
    truststore: /etc/certs/connector-truststore.jks
    truststore-password: ${TRUSTSTORE_PASSWORD}
    verify-hostname: true
    allowed-ciphers:
      - TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
      - TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
```

### 11.2. Fluxo de Autenticação

```
1. Core inicia connection ao Connector
   ├─ Load client certificate (PKCS12)
   ├─ Load truststore (JKS com CA certs)
   └─ Verify hostname (CN/SAN do cert)

2. Handshake TLS
   ├─ Core → envia client certificate
   ├─ Connector valida: Trusted CA? CN correto?
   └─ Mutual authentication estabelecido

3. Requisição HTTP sobre TLS
   ├─ Encriptação em trânsito (AES-256-GCM)
   └─ Integridade garantida (HMAC)

4. Validação contínua
   ├─ Certificate expiry check
   ├─ CRL/OCSP check (se habilitado)
   └─ Revocation detection
```

---

## 12. Extensibilidade: Crear Novo Provider

### 12.1. Passos para Implementar Novo Connector

```
PASSO 1: Develop Connector Container
├─ Base image: OpenJDK 17 / Python 3.10 / Go 1.21
├─ Implement REST API endpoints
│  ├─ GET /api/v1/connector/info
│  ├─ GET /api/v1/connector/health
│  ├─ GET /api/v1/connector/functions
│  ├─ GET /api/v1/connector/attributes
│  ├─ POST /api/v1/{functionGroup}/{kind}/callback
│  └─ (específico para o provider)
├─ Build Docker image
│  docker build -t my-ca-connector:1.0 .
└─ Push para registry

PASSO 2: Register com Core
├─ POST /api/v2/connectors
│  {
│      "name": "My CA Connector",
│      "url": "https://connector.local:8080",
│      "authType": "CERTIFICATE",
│      "authAttributes": {...}
│  }
│
└─ Core discobre automaticamente capabilities

PASSO 3: Create Authority Instance
├─ POST /api/v2/authorities
│  {
│      "connectorUuid": "...",
│      "name": "Production CA",
│      "kind": "MY_CA_TYPE"
│  }

PASSO 4: Create RA Profile
├─ POST /api/v2/raprofiles
│  {
│      "name": "Prod Web SSL",
│      "authorityUuid": "...",
│      "attributes": [...]
│  }

PASSO 5: Issue Certificate
├─ POST /api/v2/certificates/request
│  {
│      "raProfileUuid": "...",
│      "csr": "..."
│  }

└─ Flow automation complete!
```

### 12.2. Exemplo: Simple SCEP Connector em Python

```python
# scep_connector.py
from flask import Flask, request, jsonify
import requests
from cryptography import x509

app = Flask(__name__)

# 1. Info endpoint
@app.route('/api/v1/connector/info', methods=['GET'])
def info():
    return jsonify({
        'version': 'V2',
        'name': 'Simple SCEP Connector',
        'functionGroups': ['CA'],
        'protocols': ['SCEP'],
        'interfaces': ['SCEP', 'REST']
    })

# 2. Health endpoint
@app.route('/api/v1/connector/health', methods=['GET'])
def health():
    return jsonify({'status': 'UP', 'message': 'Healthy'})

# 3. Functions endpoint
@app.route('/api/v1/connector/functions', methods=['GET'])
def functions():
    return jsonify({
        'functionGroups': [
            {
                'code': 'CA',
                'description': 'Certificate Authority',
                'endEntityOnly': False
            }
        ]
    })

# 4. Attributes discovery
@app.route('/api/v1/connector/attributes', methods=['GET'])
def attributes():
    func_group = request.args.get('functionGroup')
    func_name = request.args.get('functionName')
    
    if func_group == 'CA' and func_name == 'ISSUE_CERTIFICATE':
        return jsonify([
            {
                'name': 'scep_url',
                'type': 'string',
                'required': True,
                'description': 'SCEP Server URL'
            },
            {
                'name': 'ca_certificate',
                'type': 'file',
                'required': True,
                'description': 'CA Certificate (PEM)'
            }
        ])

# 5. Issue certificate
@app.route('/api/v1/authorityProvider/authorities/<auth_id>/certificates/issue', 
           methods=['POST'])
def issue_certificate(auth_id):
    data = request.json
    csr_text = data['certificateRequest']['csr']
    
    try:
        # Parse CSR
        csr = x509.load_pem_x509_csr(csr_text.encode())
        
        # Call real SCEP endpoint
        scep_response = requests.post(
            'https://scep.example.com/scep',
            data={'operation': 'PKCSReq', 'message': csr.public_bytes(encoding)},
            cert=('/path/to/cert.p12', cert_password)
        )
        
        # Extract issued certificate from response
        issued_cert = parse_scep_response(scep_response.content)
        
        return jsonify({
            'certificate': issued_cert,
            'certificateChain': [ca_cert],
            'metadata': {...}
        })
    
    except Exception as e:
        return jsonify({
            'errors': [
                {'code': 'ISSUE_FAILED', 'message': str(e)}
            ]
        }), 422

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, ssl_context='adhoc')
```

---

## Conclusão

O sistema de conectores do CZERTAINLY oferece:

✓ **Integração agnóstica de CA**: Múltiplos CAs via mesmo Core
✓ **Descoberta dinâmica**: Atributos + capabilities descobertos automaticamente
✓ **Segurança forte**: mTLS, encriptação de secrets, RBAC
✓ **Tratamento de erros robusto**: Health checks, retry, fallback
✓ **Extensibilidade**: Novos providers sem modificar Core
✓ **Auditoria completa**: Todas operações registradas

Conectores são a chave para fazer do CZERTAINLY uma **plataforma agnóstica de PKI*.

