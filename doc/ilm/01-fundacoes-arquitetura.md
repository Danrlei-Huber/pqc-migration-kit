# FUNDAÇÕES & ARQUITETURA: Análise Estratégica do CZERTAINLY-Core

## Visão Executiva

O CZERTAINLY-Core é uma plataforma enterprise de ciclo de vida de certificados (PKI Lifecycle Management) implementada em Java 21 com Spring Boot 3.x. Representa uma arquitetura moderna, escalável e segura, projetada para gerenciar não apenas certificados X.509 tradicionais, mas também preparada para transição para criptografia pós-quântica. Com 326+ classes Java, 65 entidades JPA e suporte a múltiplos protocolos de issuance (ACME, SCEP, CMP), o sistema demonstra maturidade arquitetural significativa.

A escolha de Java 21 é estratégica e bem-definida: permite aproveitar features modernas como virtual threads (Project Loom), pattern matching e sealed classes, enquanto mantém estabilidade com LTS (Long-Term Support) até 2029. O calendário de release do Java determina que Java 21 receberá updates de segurança críticos por aproximadamente 8 anos, o que é essencial para uma aplicação de infraestrutura que será deployada em datacenters corporativos.

Spring Boot 3.x marca a transição definitiva de javax.* para jakarta.* namespace (Jakarta EE), uma mudança que reflete a evolução do ecossistema Java para uma governança mais aberta. Para este projeto, significa:
- Acesso aos mais recentes padrões de persistência (JPA 3.1)
- Integração native com OAuth2/OIDC
- Observabilidade first-class via OpenTelemetry
- Performance improvements em startup (~3-5 segundos vs ~8-10 em Spring Boot 2.x)

## Decisões Arquiteturais Fundamentais: Por Quê Maven em 2024?

Pareça uma questão trivial, mas Maven vs Gradle reflete filosofia arquitetural. CZERTAINLY escolheu Maven 4.0.0 intencionalmente:

### Previsibilidade e Conformidade Corporativa
Maven enforça um lifecycle imutável: `validate → compile → test → package → integration-test → verify → install → deploy`. Esta estrutura rígida é **feature**, não bug. Em organizações Fortune 500 com compliance requirements (SOC 2, ISO 27001), auditores precisam entender o processo de build. Maven oferece exatamente isso: documentação pública, plugins well-known, e um modelo que qualquer desenvolvedor Java consegue entender sem curva de aprendizado.

Gradle, embora mais poderoso, permite tanta flexibilidade (e.g., custom task ordering, plugin composition complexa) que pode-se acabar com dois builds "iguais" com comportamento diferente em nuances sutis. Para um sistema que gerencia certificados—onde confiabilidade é paramount—Maven é a escolha certa.

### Reprodutibilidade Determinística
Dados os mesmos settings.xml, pom.xml, e Maven 4.0.0, todo developer na equipe, e todo CI/CD pipeline, produzirá exatamente o mesmo JAR binário (mesmos hashes, mesmas timestamps). Isto é verificável via `mvn verify -Dprojectversion=...` seguido de checksum validation.

Gradle não oferece este nível de determinismo nativo (embora seja possível com Gradle Build Cache e configuração cuidadosa).

### Ecosystem de Plugins Maduros
Para as necessidades específicas deste projeto:
- **maven-shade-plugin**: Uber JAR construction (todas dependências empacotadas)
- **maven-assembly-plugin**: Docker build artifact preparation
- **dockerfile-maven-plugin**: Build Docker images durante Maven build
- **flyway-maven-plugin**: Database migration management integrado
- **apt-maven-plugin**: QueryDSL Q-class generation (compile-phase)

Cada plugin tem 10+ anos de maturidade, milhões de usuários, e integração profunda com Maven lifecycle.

## Dependências Core: Uma Análise Estratégica

### Spring Boot Parent BOM (3.2.3)

O parent BOM é o "contract" que garante compatibilidade. Especificar `spring-boot-starter-parent:3.2.3` implica:
```xml
spring-core:6.0.x
spring-security:6.1.x
spring-data-jpa:3.1.x
hibernate-core:6.2.x
```

Todos testados como conjunto. Isto é crítico quando você adiciona `spring-boot-starter-oauth2-resource-server` – ele depends de `spring-security:6.1+`, que depends de `spring-core:6.0+`. O parent BOM garante que todas estas dependências são versões que funcionam juntas.

As implicações práticas:
1. **Menos dependency conflict resolution**: Maven resolver de dependências é determinístico; não há ambiguidade
2. **Predictable Security Updates**: Quando Spring Security lança CVE patch (e.g., CVE-2023-XXXXX para bypass de OAuth2 scope), Maven vê a nova versão no parent BOM e avisa que atualizar parent resolve a vulnerability
3. **Aligned Feature Release**: Se você precisa de novo feature em Spring Security (e.g., OAuth2.1 support), você não pode só atualizar spring-security em isolation—it's already coordinated no parent BOM

### PostgreSQL + Hibernate 6.x + JPA 3.1: O Core de Persistência

Esta tríade é a backbone do sistema. A escolha de Hibernate em vez de alternativas (EclipseLink, OpenJPA) reflete que Hibernate domina ~95% do mercado Java ORM enterprise por razões técnicas válidas:

**Hibernate 6.x oferece**:
1. **Lazy Loading Inteligente**: Proxy generation automático. Se você carrega um Certificate mas não acessa sua RaProfile relationship, a RaProfile não é queried. Isto é crucial em pagination, onde carregar 50 certificates poderia gerar 50 queries adicionais (N+1 problem) sem lazy loading.

2. **QueryDSL Integration**: A combinação `Hibernate 6.x + QueryDSL 5.1.0` permite:
```java
QCertificate certificate = QCertificate.certificate;
query.selectFrom(certificate)
   .where(certificate.subject.contains("CN=example")
          .and(certificate.validTo.after(LocalDate.now())))
   .orderBy(certificate.issued.desc())
   .fetch();
```
Isto é **type-safe**: erros de typo no property name são caught em compile-time, não em runtime (diferente de string-based `@Query`).

3. **JSONB Native Support**: PostgreSQL JSONB é armazenado como binary JSON, indexável, e queryable. Hibernate 6.x suporta via `@JdbcTypeCode(SqlTypes.JSON)`. Exemplo no projeto:
```java
@Column(columnDefinition = "jsonb")
@JdbcTypeCode(SqlTypes.JSON)
private ApprovalStep[] approvalSteps; // Array de objects
```
Sem JSONB, teríamos que criar tabelas normalizadas (ApprovalStep como entidade separada comForeignKey). Com JSONB, armazenamos estrutura complexa diretamente. Isto reduz joins nas queries e simplifica schema.

4. **Audit Listeners**: `@EntityListeners(AuditingEntityListener.class)` com `@CreatedBy`, `@CreatedDate`, `@LastModifiedBy`, `@LastModifiedDate` são preenchidas **automaticamente** pela Spring Data JPA antes de INSERT/UPDATE. Nenhum código adicional necessário.

### QueryDSL 5.1.0: Type-Safe Queries

À primeira vista, QueryDSL parece overhead quando JPA Criteria API já existe. Porém, QueryDSL é **obrigatório** para este projeto por uma razão específica: **Compliance Filtering**.

Imagine um cenário real: usuário quer listar certificados com "subject contains 'example' AND issuer is 'GlobalSign' AND validTo is after today AND certificate belongs to group 'Production'". Isto requer:
```java
// Com Criteria API (JPA default)
CriteriaBuilder cb = em.getCriteriaBuilder();
CriteriaQuery<Certificate> query = cb.createQuery(Certificate.class);
Root<Certificate> c = query.from(Certificate.class);
query.select(c).where(
    cb.and(
        cb.like(c.get("subject"), "%example%"),
        cb.equal(c.get("issuer"), "GlobalSign"),
        cb.greaterThan(c.get("validTo"), LocalDate.now()),
        // Group filter requer JOIN
        cb.isMember(groupId, c.get("groups"))
    )
);
```

Com QueryDSL (30 linhas): 
```java
QCertificate c = QCertificate.certificate;
QGroup g = QGroup.group;

return query.selectFrom(c)
    .leftJoin(c.groups, g)
    .where(
        c.subject.contains("example"),
        c.issuer.eq("GlobalSign"),
        c.validTo.after(LocalDate.now()),
        g.id.in(groupIds)
    )
    .fetch();
```

**Vantagens do QueryDSL**:
1. Type-safe: `c.subject.contains()` é validado em compile-time
2. Readable: parece com SQL mas é Java
3. Reusable: predicates podem ser parametrizadas
```java
BooleanExpression dateFilter = c.validTo.after(filterDate);
BooleanExpression issuerFilter = c.issuer.eq(issuerName);

return query.selectFrom(c)
    .where(dateFilter.and(issuerFilter))
    .fetch();
```

A geração automática de QEntity classes via `apt-maven-plugin` durante compile garante que se você renomear propriedade em Certificate entity, a quebra será imediatamente visível no código que usa QCertificate.

### OAuth2 Resource Server + Nimbus JOSE-JWT (10.5)

CZERTAINLY delegua autenticação completamente para um Authorization Server externo (Keycloak, Azure AD, Okta). Isto é moderno e defendível por razões:

1. **Separation of Concerns**: Core não gerencia usuários, senhas, ou MFA. Auth-service não gerencia certificados. Boundary é clara.
2. **Enterprise Integration**: Muitas org já têm Keycloak ou directory (LDAP/AD). Integração é via JWT token + JWKS endpoint—zero proprietary code.
3. **Scalability**: Auth-server pode estar em separate cluster com SLA difer
ente (e.g., 99.99 vs 99.9).

Nimbus JOSE-JWT 10.5 é a biblioteca battle-tested para isto. Inclui:
- JWKS fetching com caching automático (RedisCache opcional)
- JWT parsing e validation
- Múltiplos algoritmos: RS256, ES256, PS256, EdDSA
- Claims validation: `exp`, `aud`, `iss`, `sub`

Implementação em CzertainlyJwtDecoder:
```java
@Component
public class CzertainlyJwtDecoder implements JwtDecoder {
    
    public Jwt decode(String token) throws JwtException {
        // 1. Fetch JWKS from auth-server
        String jwksUri = issuerUri + "/protocol/openid-connect/certs";
        JWKSet jwkSet = JWKSet.load(new URL(jwksUri)); // com cache
        
        // 2. Parse e validar JWT
        SignedJWT jwt = SignedJWT.parse(token);
        
        // 3. Extract kid (key ID) from JWT header
        String keyId = jwt.getHeader().getKeyID();
        JWK key = jwkSet.getKeyByKeyId(keyId);
        
        // 4. Verify signature
        if (!jwt.verify(new RSASSAVerifier((RSAKey) key))) {
            throw new JwtException("Invalid signature");
        }
        
        // 5. Validate claims
        JWTClaimsSet claims = jwt.getJWTClaimsSet();
        if (claims.getExpirationTime().before(new Date())) {
            throw new JwtException("Token expired");
        }
        
        // 6. Return Spring-compatible Jwt
        return convertToSpringJwt(jwt, claims);
    }
}
```

O fluxo é:
1. Client requests endpoint `/api/v2/certificates` com header `Authorization: Bearer {token}`
2. Spring Security interceptor chama `CzertainlyJwtDecoder.decode(token)`
3. Token é validado criptograficamente
4. Claims (sub, aud, roles) são extraídas
5. Spring SecurityContext é populado
6. Endpoint é executado com `@PreAuthorize("hasRole('ADMIN')")` já verificado

Esta abordagem é **stateless** e **scalable**: não há session storage, não há token blacklist, todo JVM valida token independentemente.

### BouncyCastle 1.77: Criptografia como Primeira Classe

BouncyCastle é a spine de todas operações criptográficas. Versão 1.77 suporta:

1. **X.509 Certificate Generation**: `X509v3CertificateBuilder` para emissão de certificados
2. **CRL/OCSP**: Revocation checking
3. **PQC (Post-Quantum Cryptography)**: FALCON, Dilithium, SPHINCS+ (seção 9)
4. **AES-256-GCM**: Encriptação authenticated de secrets
5. **PKCS#8/SPKI**: Key encoding standards

Criação de certificado via BouncyCastle:
```java
X509v3CertificateBuilder builder = new X509v3CertificateBuilder(
    issuerName,
    serialNumber,
    notBefore, // LocalDate.now()
    notAfter,  // LocalDate.now().plusYears(1)
    subjectName,
    subjectPublicKeyInfo
);
builder.addExtension(Extension.basicConstraints, 
                     false, 
                     new BasicConstraints(false));
builder.addExtension(Extension.keyUsage, 
                     true, 
                     new KeyUsage(KeyUsage.digitalSignature));

X509CertificateHolder holder = builder.build(contentSigner);
Certificate certificate = new JcaX509CertificateConverter()
    .setProvider(bouncyCastleProvider)
    .getCertificate(holder);
```

### OpenTelemetry (OTLP) 1.34.1: Observabilidade Nativa

Observabilidade é first-class citizen. Integração OpenTelemetry permite instrumentação automática via meteragem:

```properties
OTEL_EXPORTER_OTLP_ENDPOINT=http://otel-collector:4318
OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf
OTEL_PROPAGATORS=tracecontext,baggage
```

**Cada operação é traced automaticamente**:
1. HTTP GET /api/v2/certificates/uuid → gera trace span
2. SELECT FROM certificate WHERE uuid = ? → DB span (via DataSource proxy)
3. CALL {connector-url}/operation → HTTP client span
4. PUBLISH message to rabbitmq → messaging span

Resultado: um único trace ID correlaciona toda a requisição, permitindo visualizar bottleneck exato. Exemplo real: "Why does certificate issuance take 5 segundos?"

Resposta, via trace dashboard:
```
Trace ID: 4f1d8c92-5a3e-4cd2
├─ POST /api/v2/certificates (1000ms)
│  ├─ CertificateService.issueCertificate (900ms)
│  │  ├─ ConnectorService.sendToConnector (700ms)  ← BOTTLENECK: externa
│  │  │  └─ HTTP POST to connector (700ms)
│  │  ├─ AuditLogService.log (50ms)
│  │  └─ RabbitTemplate.convertAndSend (30ms)
│  └─ ExceptionHandling: Catch + wrap (20ms)
```

Desta forma, você imediatamente vê: o problema é que connector está lento (700ms), não o core.

### TestContainers 1.21.4: Integration Tests Reais

Alternativa: usar H2 in-memory ou mocks para testes. TestContainers é melhor porque:

1. **PostgreSQL Real**: Migrations Flyway são testadas contra schema real, não em-memory database que pode ter comportamento diferente
2. **RabbitMQ Real**: Dead Letter Queue, message TTL, routing key behavior são todos verificados
3. **No Mock Surprises**: Testes passam em dev, falham em prod quando comportamento real do BD é diferente
4. **Container Lifecycle**: TestContainers gerencia lifecycle (start, stop) automaticamente

Exemplo teste com TestContainers:
```java
@Testcontainers
class CertificateServiceIntegrationTest {
    
    @Container
    static PostgreSQLContainer<?> postgres = 
        new PostgreSQLContainer<>("postgres:15")
            .withDatabaseName("czertainly_test")
            .withUsername("test")
            .withPassword("test");
    
    @Container
    static RabbitMQContainer rabbitmq = 
        new RabbitMQContainer("rabbitmq:3.12");
    
    @BeforeAll
    static void setup() {
        // PostgreSQL container started
        // Flyway migrations applied
        // RabbitMQ container started
    }
    
    @Test
    void testCertificateIssuance() {
        // Test com BD e messaging reais, não mocks
    }
}
```

## Topologia de Aplicação

```
┌─────────────────────────────────────────┐
│         CZERTAINLY-Core                 │
├─────────────────────────────────────────┤
│  Controllers (REST)                     │
│  ├─ CertificateManagementController     │
│  ├─ ProtocolController (ACME/SCEP/CMP)  │
│  ├─ ConnectorController                 │
│  └─ ... (30+ controllers)               │
├─────────────────────────────────────────┤
│  Services (Business Logic)              │
│  ├─ CertificateService                  │
│  ├─ ComplianceService                   │
│  ├─ RuleService (Workflow)              │
│  └─ ... (55+ services)                  │
├─────────────────────────────────────────┤
│  Repositories (Data Access)             │
│  ├─ CertificateRepository               │
│  ├─ CryptographicKeyRepository          │
│  └─ ... (59 repositories via Spring)    │
├─────────────────────────────────────────┤
│  Database Layer                         │
│  └─ PostgreSQL 15+ (JDBC, Hibernate)    │
└─────────────────────────────────────────┘
        ↕ RabbitMQ                ↕ External
    (messaging)              (Connectors via HTTPS)
```

## Database Schema: PostgreSQL Design Decisions

### JSONB Columns: Flexibilidade Controlada

PostgreSQL JSONB é usado para:
1. **Dynamic Attributes**: Atributos definidos por connector são armazenados em JSONB sem schema inflation
2. **Approval Workflow**: ApprovalStep[] como JSONB array, não tabela separada
3. **Audit Log**: Complete audit record (operação, mudanças, timestamps) como JSONB document

Exemplo:
```sql
CREATE TABLE approval (
    uuid UUID PRIMARY KEY,
    content JSONB NOT NULL,  -- Workflow steps como array
    status VARCHAR(20),
    created_at TIMESTAMP
);
```

Versus schema normalizado (50 linhas de SQL, 10 tables). JSONB oferece flexibilidade sem perder queryability:
```sql
SELECT * FROM approval 
WHERE content->'steps'->0->>'status' = 'APPROVED';
```

### UUID Primary Keys

Usando `UUID` em vez de `BIGINT SERIAL`:
- **Distribuição**: Em sistemas distribuídos, `SERIAL` cria bottleneck (central sequence server)
- **Privacy**: Não expõe quantidade de registros (UUID 4 é aleatório)
- **Merge-friendly**: em BD com replicação, UUIDs de diferentes nodes não colidem (diferente de SERIAL)

PostgreSQL suporta UUID native:
```sql
id UUID PRIMARY KEY DEFAULT gen_random_uuid()
```

### Soft Deletes via Timestamps

Nenhuma tabela usa `DELETE`. Em vez disso:
```sql
ALTER TABLE certificate ADD COLUMN deleted_at TIMESTAMP NULL;
```

Queries padrão excluem soft-deleted rows:
```java
@Query("SELECT c FROM Certificate c WHERE c.deletedAt IS NULL")
List<Certificate> findActive();
```

Benefícios:
- **Auditoria**: Saber quando certificado foi "deletado"
- **Recovery**: Restaurar via UPDATE deleted_at = NULL
- **Compliance**: Alguns regs exigem que dados nunca sejam permanentemente deletados

## Performance & Scalability Considerations

### Horizontal Scaling via Statelessness
Cada instância do Core é stateless:
- JWT validation é local (JWKS cache em memory)
- Mensagens para long-ops vão em RabbitMQ queue (múltiplas instâncias consomem)
- Database é shared (PostgreSQL single node, ou replicated)

Resultado: adicionar 50x mais instâncias é trivial.

### Bottleneck Comum: PostgreSQL Single Node
Uma limitation em escala: PostgreSQL single-node tem limit de throughput. Para 10k+ cert requests/segundo:
- Replicação PostgreSQL (primary-standby) para read scaling
- Sharding (não suportado natively, exige application logic)
- Migrar para distributed DB (e.g., CockroachDB que é Postgres-compatible)

### Caching Strategy
```java
@Cacheable(value = "settings", key = "#root.methodName")
public SettingDto getSetting(String key) {
    return settingRepository.findByKey(key);
}
```

Cacheia em memory ou Redis, evitando BD hit a cada requisição.

## Deployment & Runtime

### Containerização
Dockerfile multi-stage:
```dockerfile
FROM eclipse-temurin:21-jdk AS builder
COPY . /app
RUN mvn clean package -DskipTests

FROM eclipse-temurin:21-jre
COPY --from=builder /app/target/*.jar /app.jar
ENTRYPOINT ["java","-jar","/app.jar"]
```

Resultado: imagem ~500 MB (JRE 21 ~ 400 MB, app ~ 100 MB).

### Environment Variables
```bash
SPRING_DATASOURCE_URL=jdbc:postgresql://db:5432/czertainly
SPRING_DATASOURCE_USERNAME=czertainly
SPRING_DATASOURCE_PASSWORD_ENCRYPTED=...

SPRING_RABBITMQ_HOST=rabbitmq
SPRING_RABBITMQ_PORT=5672

OTEL_EXPORTER_OTLP_ENDPOINT=http://collector:4318

AUTH_SERVICE_URL=https://auth-service:8080
OPA_BASE_URL=https://opa:8181
```

### Health Endpoint
`GET /v1/health` retorna:
```json
{
  "status": "UP",
  "components": {
    "db": {"status": "UP"},
    "rabbit": {"status": "UP"},
    "connectorConnectivity": {"status": "UP"}
  }
}
```

Kubernets usa isto para liveness/readiness probes.

---

## 1.2 Estrutura de Build (pom.xml)

### Parent BOM
```xml
<parent>
  <groupId>org.springframework.boot</groupId>
  <artifactId>spring-boot-starter-parent</artifactId>
  <version>3.2.3</version>
</parent>
```

### Propriedades Chave
```xml
<properties>
  <java.version>21</java.version>
  <querydsl.version>5.1.0</querydsl.version>
  <log-schema.version>1.1</log-schema.version>
  <nimbus-jose-jwt.version>10.5</nimbus-jose-jwt.version>
  <bouncycastle.version>1.77</bouncycastle.version>
  <opentelemetry.version>1.34.1</opentelemetry.version>
  <testcontainers.version>1.21.4</testcontainers.version>
</properties>
```

### Dependências Core

**Web & API**:
- `spring-boot-starter-web`: MVC + REST
- `spring-doc-openapi-starter-webmvc-ui`: Swagger/OpenAPI 3.0

**Data Access**:
- `spring-boot-starter-data-jpa`: Spring Data JPA
- `spring-boot-starter-data-rest`: HATEOAS, HAL
- `org.hibernate.orm:hibernate-core`: ORM 6.x
- `com.querydsl:querydsl-jpa`: QueryDSL for JPA

**Database**:
- `org.postgresql:postgresql`: PostgreSQL driver
- `org.flywaydb:flyway-core`: Database migrations
- `org.flywaydb:flyway-database-postgresql`: Flyway PostgreSQL support

**Security**:
- `spring-boot-starter-security`: Spring Security
- `spring-security-oauth2-resource-server`: OAuth2 Resource Server
- `com.nimbusds:nimbus-jose-jwt`: JWT handling (JSON Web Token)
- `org.bouncycastle:bcprov-jdk18on`: Cryptography (1.77)
- `org.bouncycastle:bcpkix-jdk18on`: X.509 certificate handling

**Messaging**:
- `spring-boot-starter-amqp`: RabbitMQ support
- `org.springframework.amqp:spring-rabbit`: RabbitMQ template

**Monitoring & Observability**:
- `micrometer-registry-otlp`: OpenTelemetry export (OTLP)
- `spring-boot-starter-actuator`: Health/metrics endpoints
- `org.springframework.cloud:spring-cloud-starter-sleuth`: Distributed tracing

**Testing**:
- `spring-boot-starter-test`: JUnit 5, Mockito, AssertJ
- `spring-security-test`: Security testing
- `testcontainers:testcontainers`: Container-based integration tests
- `testcontainers:postgresql`: PostgreSQL test container
- `testcontainers:rabbitmq`: RabbitMQ test container

**Utilities**:
- `org.projectlombok:lombok`: Reduce boilerplate
- `org.mapstruct:mapstruct`: Object mapping (@Mapper)

---

## 1.3 Entry Point & Spring Boot Configuration

### Application Class
**Arquivo**: `src/main/java/com/czertainly/core/Application.java`

```java
@SpringBootApplication
@EnableAsync
public class Application {
    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }
}
```

**Anotações**:
- `@SpringBootApplication`: Enables auto-configuration, component scanning
- `@EnableAsync`: Habilita `@Async` em métodos para operações assíncronas

### Beans Principais Configuration

**Arquivo**: `src/main/java/com/czertainly/core/config/ApplicationConfig.java`

```java
@Configuration
@EnableJpaAuditing
@EnableScheduling
public class ApplicationConfig {
    
    // 150+ Bean definitions
    
    @Bean
    public AuditorAware<String> auditorAware() {
        // Retorna usuário atual do SecurityContext
        return () -> Optional.ofNullable(SecurityContextHolder.getContext()
            .getAuthentication()
            .getName());
    }
    
    @Bean
    public LocalValidatorFactoryBean validator() {
        // Validação de constraints
    }
    
    @Bean
    public ObjectMapper objectMapper() {
        // Jackson configuration
    }
}
```

**Habilitações**:
- `@EnableJpaAuditing`: Auto-populate `createdBy`, `lastModifiedBy`, `createdDate`, `lastModifiedDate`
- `@EnableScheduling`: Habilita `@Scheduled` em beans

---

## 1.4 Security Configuration

**Arquivo**: `src/main/java/com/czertainly/core/config/SecurityConfig.java`

### OAuth2 Resource Server Setup
```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {
    
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .oauth2ResourceServer(oauth2 -> oauth2.jwt(jwt -> 
                jwt.decoder(jwtDecoder())))
            .authorizeHttpRequests(authz -> authz
                .requestMatchers("/actuator/**").permitAll()
                .requestMatchers("/swagger-ui.html", "/v3/api-docs/**").permitAll()
                .requestMatchers("/acme/directory", "/scep/**").permitAll()
                .anyRequest().authenticated())
            .csrf().disable(); // REST APIs, stateless
        
        return http.build();
    }
    
    @Bean
    public JwtDecoder jwtDecoder() {
        return new CzertainlyJwtDecoder();
    }
}
```

### Authentication Converter
- Implementação: `CzertainlyJwtAuthenticationConverter`
- Extrai claims: username, roles, permissions, scope
- Mapeia para Spring Security GrantedAuthority

### TLS/SSL Configuration

**Arquivo**: `src/main/java/com/czertainly/core/config/TrustedCertificatesConfig.java`

```java
@Configuration
public class TrustedCertificatesConfig {
    
    @Bean
    public RestTemplate restTemplate() {
        // Custom SSL context para mTLS com conectores
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(keyManagerFactory.getKeyManagers(), 
                        trustManagerFactory.getTrustManagers(), 
                        new SecureRandom());
        
        HttpClient httpClient = HttpClientBuilder.create()
            .setSSLContext(sslContext)
            .build();
        
        return new RestTemplateBuilder()
            .requestFactory(() -> new HttpComponentsClientHttpRequestFactory(httpClient))
            .build();
    }
}
```

---

## 1.5 Web Application Configuration

**Arquivo**: `src/main/java/com/czertainly/core/config/WebAppConfig.java`

```java
@Configuration
public class WebAppConfig implements WebMvcConfigurer {
    
    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/api/**")
            .allowedOrigins("*")
            .allowedMethods("GET", "POST", "PUT", "DELETE", "OPTIONS")
            .maxAge(3600);
    }
    
    @Override
    public void configureMessageConverters(
            List<HttpMessageConverter<?>> converters) {
        // Jackson2HttpMessageConverter para content-type application/json
        converters.add(new MappingJackson2HttpMessageConverter());
    }
}
```

**Features**:
- CORS configuration
- Content negotiation (JSON default)
- HTTPMessageConverters

---

## 1.6 Database Configuration

### Hibernate Configuration
**Arquivo**: `application.yml`

```yaml
spring:
  jpa:
    hibernate:
      ddl-auto: none  # Migrations handled by Flyway
    properties:
      hibernate:
        dialect: org.hibernate.dialect.PostgreSQLDialect
        generate_statistics: false
        jdbc:
          batch_size: 20
          fetch_size: 50
        order_inserts: true
        order_updates: true
        open_in_view: false  # Best practice: handle transactions explicitly
    open-in-view: false
```

### JDBC/Connection Pool
```yaml
datasource:
  url: jdbc:postgresql://${DB_HOST:localhost}:${DB_PORT:5432}/${DB_NAME:czertainly}
  username: ${DB_USER:postgres}
  password: ${DB_PASSWORD}
  hikari:
    maximum-pool-size: 20
    minimum-idle: 5
    connection-timeout: 30000
    idle-timeout: 600000
```

### QueryDSL Setup
**Plugin** (pom.xml):
```xml
<plugin>
  <groupId>com.mysema.maven</groupId>
  <artifactId>apt-maven-plugin</artifactId>
  <version>1.1.3</version>
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

**Gera**: QEntity classes para type-safe queries (exemplo: QCertificate, QCryptographicKey)

---

## 1.7 Flyway Migrations

**Localização**: `src/main/db/`

### Schema
**Arquivo**: `01_tables.sql` (~5000+ linhas)

Cria tabelas principais:
- `certificate` (certificados)
- `cryptographic_key` (chaves)
- `ra_profile`, `acme_profile`, `scep_profile`, `cmp_profile` (perfis)
- `connector`, `endpoint` (plugin system)
- `location`, `entity_instance_reference` (armazenamento)
- `approval`, `approval_profile` (workflow)
- `rule`, `trigger`, `action`, `execution` (automation)
- `notification_profile`, `notification_instance` (notificações)
- `audit_log` (auditoria)
- `attribute_definition`, `custom_oidt_entry` (customização)
- E mais 40+ tabelas

### Dados Iniciais
**Arquivo**: `02_data.sql`
- Insere enums como registros
- Insere configurações padrão
- Insere perfis default

### Migrações Versionadas
**Diretório**: `updates/`
- `V1.0.0__initial_schema.sql`
- `V2.0.0__add_pqc_support.sql` (PQC columns)
- `V2.5.0__add_cmp_support.sql` (CMP tables)
- Etc.

**Pattern**: `V{version}__description.sql`

---

## 1.8 Environment Configuration

### External Config File
**Localização**: `/etc/czertainly-backend/czertainly-backend.properties`

**Precedência**: Application properties file > env vars > application.yml

### Key Environment Variables

```bash
# Authentication & Authorization
AUTH_SERVICE_BASE_URL=https://auth-service:8080/api/auth
OPA_BASE_URL=https://opa:8181

# Database
DB_HOST=postgres
DB_PORT=5432
DB_NAME=czertainly-db
DB_USER=czertainly
DB_PASSWORD=<encrypted>

# RabbitMQ
RABBITMQ_HOST=rabbitmq
RABBITMQ_PORT=5672
RABBITMQ_USER=guest
RABBITMQ_PASSWORD=guest
RABBITMQ_VHOST=/

# OpenTelemetry (Observability)
OTEL_EXPORTER_OTLP_ENDPOINT=http://otel-collector:4317
OTEL_SERVICE_NAME=czertainly-core
OTEL_TRACES_EXPORTER=otlp
OTEL_METRICS_EXPORTER=otlp

# Scheduler
SCHEDULER_BASE_URL=https://scheduler:8080/api/scheduler

# Logging
CZERTAINLY_LOG_LEVEL=INFO
CZERTAINLY_LOG_FORMAT=JSON

# CMP Protocol
CMP_PROFILE_POLLING_TIMEOUT_SECONDS=20
CMP_PROFILE_VERBOSE_MODE=false

# Proxy (se necessário)
HTTP_PROXY_HOST=proxy.company.com
HTTP_PROXY_PORT=8080
```

---

## 1.9 Logging Configuration

**Arquivo**: `logback-spring.xml` (ou via application.yml)

### JSON Logging Format
```xml
<appender name="STDOUT" class="ch.qos.logback.core.ConsoleAppender">
  <encoder class="net.logstash.logback.encoder.LogstashEncoder">
    <customFields>{"service":"czertainly-core"}</customFields>
  </encoder>
</appender>
```

**Output Example**:
```json
{
  "timestamp": "2024-03-31T10:30:45.123Z",
  "level": "INFO",
  "logger_name": "com.czertainly.core.service.impl.CertificateService",
  "message": "Certificate issued successfully",
  "trace_id": "abc123def456",
  "mdc": { "user": "admin", "request_id": "req-789" },
  "service": "czertainly-core"
}
```

---

## 1.10 Health & Actuator

**Endpoints**: `/v1/health`, `/v1/metrics`, `/v1/info`

### HealthCheck Components
```yaml
management:
  health:
    livenessState:
      enabled: true
    readinessState:
      enabled: true
    diskspace:
      enabled: true
    db:
      enabled: true
  endpoint:
    health:
      show-details: when-authorized
```

**Probes**:
- **Liveness**: Aplicação está viva (responde)?
- **Readiness**: Aplicação está pronta para receber tráfego?
- **Startup**: Aplicação completou inicialização?

---

## 1.11 OpenTelemetry Integration

**Configuração**: Auto-configured by Spring Boot 3.2+

```yaml
management:
  otlp:
    metrics:
      export:
        enabled: true
        endpoint: http://otel-collector:4317
    tracing:
      endpoint: http://otel-collector:4317
      sampler:
        type: always_on
```

**Exporta**:
- Traces (tracing distribuído)
- Metrics (Prometheus-format)
- Logs (OTLP log format)

---

## 1.12 Transactional Semantics

### Default Transaction Configuration
```java
@Configuration
@EnableTransactionManagement
public class TransactionConfig {
    
    @Bean
    public PlatformTransactionManager transactionManager(EntityManagerFactory emf) {
        return new JpaTransactionManager(emf);
    }
}
```

### Service Layer Transactions
```java
@Service
@Transactional
public class CertificateService {
    
    @Transactional(readOnly = true)
    public Page<CertificateDto> listCertificates(Pageable pageable) {
        // Read-only transaction for fetching
    }
    
    @Transactional(rollbackFor = Exception.class)
    public CertificateDto issueCertificate(CertificateRequestDto request) {
        // Read-write transaction, rollback on any exception
    }
}
```

---

## 1.13 Async Processing

```java
@Configuration
@EnableAsync
public class AsyncConfig implements AsyncConfigurer {
    
    @Bean(name = "taskExecutor")
    public Executor taskExecutor() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setCorePoolSize(10);
        executor.setMaxPoolSize(20);
        executor.setQueueCapacity(500);
        executor.setThreadNamePrefix("czertainly-async-");
        executor.initialize();
        return executor;
    }
}
```

**Uso**:
```java
@Async("taskExecutor")
public CompletableFuture<CertificateDto> issueCertificateAsync(
        CertificateRequestDto request) {
    // Async operation
}
```

---

## 1.14 Proxy Configuration

**Arquivo**: `src/main/java/com/czertainly/core/config/proxy/ProxyConfiguration.java`

```java
@Configuration
@ConditionalOnProperty(name = "proxy.enabled", havingValue = "true")
public class ProxyConfiguration {
    
    @Bean
    public RestTemplate restTemplateWithProxy() {
        SimpleClientHttpRequestFactory requestFactory = 
            new SimpleClientHttpRequestFactory();
        
        Proxy proxy = new Proxy(Proxy.Type.HTTP, 
            new InetSocketAddress("${proxy.host}", ${proxy.port}));
        requestFactory.setProxy(proxy);
        
        return new RestTemplate(requestFactory);
    }
}
```

---

## 1.15 Application Deployment Readiness

A aplicação está pronta para:
- ✅ Container deployment (Docker)
- ✅ Cloud deployment (Kubernetes, OpenShift)
- ✅ Monitoring & observability (OpenTelemetry)
- ✅ High availability (stateless design, horizontal scaling)
- ✅ Security (OAuth2, mTLS, encryption)
- ✅ Multi-database support (PostgreSQL, extensível a others)

---

## Resumo das Fundações

| Componente | Tecnologia | Versão | Propósito |
|-----------|-----------|--------|----------|
| Runtime | Java | 21 | Modern language features, LTS |
| Framework | Spring Boot | 3.2.x | Enterprise Java framework |
| Build | Maven | 4.0.0 | Dependency management |
| Database | PostgreSQL | 14+ | Relational data storage |
| ORM | Hibernate | 6.x | Object-relational mapping |
| Queries | QueryDSL | 5.1.0 | Type-safe dynamic queries |
| Security | Spring Security + OAuth2 | 6.x | Authentication/authorization |
| API | Spring MVC + OpenAPI | 3.0 | REST APIs with documentation |
| Async | Spring Task | 6.x | Asynchronous processing |
| Observability | OpenTelemetry | 1.34.1 | Tracing, metrics, logs |
| Testing | TestContainers | 1.21.4 | Integration test containers |
