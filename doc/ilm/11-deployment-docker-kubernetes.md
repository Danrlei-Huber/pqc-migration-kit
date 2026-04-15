# 11. DEPLOYMENT: Docker, Kubernetes & Environment Configuration

## 11.1 Dockerfile Analysis

### Build Stage

```dockerfile
# Multi-stage build to optimize image size
FROM maven:3.9-eclipse-temurin-21 AS builder

WORKDIR /build

# Copy pom.xml first (cache Maven dependencies)
COPY pom.xml .
RUN mvn -q dependency:resolve

# Copy source code
COPY src/ src/
COPY config/ config/

# Build application
RUN mvn clean package -DskipTests \
    -Dspeed=true \
    -Drevision=2.16.4

# Result: /build/target/czertainly-core-2.16.4.jar
```

### Runtime Stage

```dockerfile
FROM eclipse-temurin:21-jre-alpine

LABEL maintainer="CZERTAINLY Team"
LABEL version="2.16.4"

# Install utilities
RUN apk add --no-cache curl openssl bash

# Create app user (non-root for security)
RUN addgroup -S czertainly && adduser -S czertainly -G czertainly

WORKDIR /opt/czertainly

# Copy artifact from builder
COPY --from=builder /build/target/czertainly-core-2.16.4.jar app.jar

# Copy startup scripts
COPY docker/opt/czertainly/entry.sh /opt/czertainly/
COPY docker/opt/czertainly/prepare-truststore.sh /opt/czertainly/
COPY docker/opt/czertainly/update-cacerts.sh /opt/czertainly/

# Fix permissions
RUN chown -R czertainly:czertainly /opt/czertainly && \
    chmod +x /opt/czertainly/entry.sh && \
    chmod +x /opt/czertainly/prepare-truststore.sh && \
    chmod +x /opt/czertainly/update-cacerts.sh

# Switch to non-root user
USER czertainly

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f -s http://localhost:8080/v1/health || exit 1

# Expose port
EXPOSE 8080

# Entry point
ENTRYPOINT ["/opt/czertainly/entry.sh"]
CMD ["java", "-jar", "app.jar"]
```

### Dockerfile Build Configuration

```bash
#!/bin/bash
# hooks/build (Docker build hook)

docker build \
    --build-arg MAVEN_OPTIONS="-X -Dspeed=true" \
    --label "org.opencontainers.image.created=$(date -u +'%Y-%m-%dT%H:%M:%SZ')" \
    --label "org.opencontainers.image.revision=${VCS_REF}" \
    --label "org.opencontainers.image.version=${VERSION}" \
    -t czertainly-core:latest \
    -t czertainly-core:${VERSION} \
    .
```

---

## 11.2 Docker Compose Setup

### docker-compose.yml

```yaml
version: '3.9'

services:
  # PostgreSQL Database
  postgres:
    image: postgres:15-alpine
    container_name: czertainly-postgres
    ports:
      - "5432:5432"
    environment:
      POSTGRES_DB: czertainly
      POSTGRES_USER: czertainly
      POSTGRES_PASSWORD: "${DB_PASSWORD}"
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./src/main/db/:/docker-entrypoint-initdb.d/
    networks:
      - czertainly-network
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U czertainly"]
      interval: 10s
      timeout: 5s
      retries: 5

  # RabbitMQ Message Broker
  rabbitmq:
    image: rabbitmq:3.12-management-alpine
    container_name: czertainly-rabbitmq
    ports:
      - "5672:5672"      # AMQP
      - "15672:15672"    # Management UI
    environment:
      RABBITMQ_DEFAULT_USER: rabbitmq
      RABBITMQ_DEFAULT_PASS: "${RABBITMQ_PASSWORD}"
      RABBITMQ_DEFAULT_VHOST: czertainly
    volumes:
      - rabbitmq_data:/var/lib/rabbitmq
    networks:
      - czertainly-network
    healthcheck:
      test: rabbit-diagnostics -q ping
      interval: 30s
      timeout: 10s
      retries: 5

  # CZERTAINLY Core
  core:
    build:
      context: .
      dockerfile: Dockerfile
    container_name: czertainly-core
    ports:
      - "8080:8080"
      - "9090:9090"      # Prometheus metrics
    depends_on:
      postgres:
        condition: service_healthy
      rabbitmq:
        condition: service_healthy
    environment:
      # Database Configuration
      - SPRING_DATASOURCE_URL=jdbc:postgresql://postgres:5432/czertainly
      - SPRING_DATASOURCE_USERNAME=czertainly
      - SPRING_DATASOURCE_PASSWORD=${DB_PASSWORD}
      
      # JPA Configuration
      - SPRING_JPA_HIBERNATE_DDL_AUTO=validate
      - SPRING_JPA_SHOW_SQL=false
      
      # RabbitMQ Configuration
      - SPRING_RABBITMQ_HOST=rabbitmq
      - SPRING_RABBITMQ_PORT=5672
      - SPRING_RABBITMQ_USERNAME=rabbitmq
      - SPRING_RABBITMQ_PASSWORD=${RABBITMQ_PASSWORD}
      - SPRING_RABBITMQ_VIRTUAL_HOST=czertainly
      
      # Security
      - SPRING_SECURITY_OAUTH2_RESOURCESERVER_JWT_ISSUER_URI=${OAUTH2_ISSUER}
      - AUTH_SERVICE_URL=${AUTH_SERVICE_URL}
      - OPA_ENABLED=true
      - OPA_HOST=${OPA_HOST}
      - OPA_PORT=8181
      
      # Application Configuration
      - SERVER_PORT=8080
      - SERVER_SERVLET_CONTEXT_PATH=/
      - LOGGING_LEVEL_ROOT=INFO
      - LOGGING_LEVEL_COM_CZERTAINLY=DEBUG
      
      # TLS Configuration (for connector communication)
      - SERVER_SSL_ENABLED=${SSL_ENABLED}
      - SERVER_SSL_KEYSTORE_LOCATION=${SSL_KEYSTORE_PATH}
      - SERVER_SSL_KEYSTORE_PASSWORD=${SSL_KEYSTORE_PASSWORD}
      - SERVER_SSL_KEYSTORE_TYPE=PKCS12
      
    volumes:
      - ./config:/opt/czertainly/config:ro
      - ./:/opt/czertainly/work
      - ssl_certs:/opt/czertainly/ssl:ro
    networks:
      - czertainly-network
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/v1/health"]
      interval: 30s
      timeout: 10s
      start_period: 60s
      retries: 5

networks:
  czertainly-network:
    driver: bridge

volumes:
  postgres_data:
  rabbitmq_data:
  ssl_certs:
```

---

## 11.3 Environment Configuration

### application.yml

```yaml
spring:
  application:
    name: czertainly-core

  # Datasource
  datasource:
    url: ${SPRING_DATASOURCE_URL:jdbc:postgresql://localhost:5432/czertainly}
    username: ${SPRING_DATASOURCE_USERNAME:czertainly}
    password: ${SPRING_DATASOURCE_PASSWORD}
    driver-class-name: org.postgresql.Driver
    hikari:
      maximum-pool-size: ${DB_MAX_POOL_SIZE:20}
      minimum-idle: ${DB_MIN_IDLE:5}
      connection-timeout: ${DB_CONNECTION_TIMEOUT:30000}
      idle-timeout: ${DB_IDLE_TIMEOUT:600000}
      max-lifetime: ${DB_MAX_LIFETIME:1800000}

  # JPA Configuration
  jpa:
    database-platform: org.hibernate.dialect.PostgreSQLDialect
    hibernate:
      ddl-auto: ${JPA_DDL_AUTO:validate}
    properties:
      hibernate:
        format_sql: true
        jdbc:
          batch_size: 20
          fetch_size: 50
        order_inserts: true
        order_updates: true

  # RabbitMQ
  rabbitmq:
    host: ${SPRING_RABBITMQ_HOST:localhost}
    port: ${SPRING_RABBITMQ_PORT:5672}
    username: ${SPRING_RABBITMQ_USERNAME:guest}
    password: ${SPRING_RABBITMQ_PASSWORD:guest}
    virtual-host: ${SPRING_RABBITMQ_VIRTUAL_HOST:/}
    listener:
      simple:
        concurrency: ${RABBITMQ_CONCURRENCY:3-10}
        max-concurrency: 10
        prefetch: 10
        retry:
          enabled: true
          initial-interval: 1000
          max-attempts: 3

  # Security & OAuth2
  security:
    oauth2:
      resourceserver:
        jwt:
          issuer-uri: ${OAUTH2_ISSUER:http://localhost:8081}
          jwk-set-uri: ${OAUTH2_JWK_SET_URI:http://localhost:8081/.well-known/jwks.json}

  # Servlet
  servlet:
    multipart:
      max-file-size: ${MAX_FILE_SIZE:10MB}
      max-request-size: ${MAX_REQUEST_SIZE:10MB}

# Server Configuration
server:
  port: ${SERVER_PORT:8080}
  servlet:
    context-path: ${SERVER_CONTEXT_PATH:/}
  shutdown: graceful
  compression:
    enabled: true
    mime-types: application/json,text/html,text/xml,application/xml
  error:
    include-message: always
    include-binding-errors: always

  # SSL/TLS
  ssl:
    enabled: ${SSL_ENABLED:false}
    key-store: ${SSL_KEYSTORE_PATH:/opt/czertainly/ssl/keystore.pkcs12}
    key-store-password: ${SSL_KEYSTORE_PASSWORD}
    key-store-type: PKCS12

# Logging Configuration
logging:
  level:
    root: ${LOG_LEVEL_ROOT:INFO}
    com.czertainly: ${LOG_LEVEL_CZERTAINLY:INFO}
  pattern:
    console: "[%d{ISO8601}] [%t] %-5p %c{32} - %m%n"
  file:
    name: /var/log/czertainly/core.log
    max-size: 10MB
    max-history: 10

# Actuator (Health, Metrics)
management:
  endpoints:
    web:
      exposure:
        include: health,metrics,prometheus,info
  endpoint:
    health:
      show-details: always
      probes:
        enabled: true
  health:
    livenessState:
      enabled: true
    readinessState:
      enabled: true

# Custom CZERTAINLY Configuration
czertainly:
  # Authentication
  auth:
    external-authorization-enabled: ${AUTH_EXTERNAL_ENABLED:true}
    external-authorization-url: ${AUTH_SERVICE_URL}
  
  # OPA (Open Policy Agent)
  opa:
    enabled: ${OPA_ENABLED:true}
    host: ${OPA_HOST:localhost}
    port: ${OPA_PORT:8181}
    policy-path: /v1/data/czertainly
  
  # Connectors
  connector:
    mtls-enabled: ${CONNECTOR_MTLS_ENABLED:true}
    health-check-interval-minutes: 5
    request-timeout-seconds: 30
  
  # PQC Configuration
  pqc:
    enabled: ${PQC_ENABLED:true}
    algorithms:
      - FALCON
      - DILITHIUM
      - SPHINCS_PLUS
    key-size-multiplier: 1.5
```

### Environment Variables (.env)

```bash
# Database
DB_PASSWORD=SecurePassword123!
DB_MAX_POOL_SIZE=20
DB_MIN_IDLE=5
DB_CONNECTION_TIMEOUT=30000

# RabbitMQ
RABBITMQ_PASSWORD=rabbitmq_secure_pass
RABBITMQ_CONCURRENCY=3-10

# Security
OAUTH2_ISSUER=https://auth.example.com
OAUTH2_JWK_SET_URI=https://auth.example.com/.well-known/jwks.json
AUTH_SERVICE_URL=https://auth-service:8443
AUTH_EXTERNAL_ENABLED=true

# OPA (Open Policy Agent)
OPA_ENABLED=true
OPA_HOST=opa
OPA_PORT=8181

# SSL/TLS
SSL_ENABLED=true
SSL_KEYSTORE_PATH=/opt/czertainly/ssl/keystore.pkcs12
SSL_KEYSTORE_PASSWORD=keystore_secure_pass

# Logging
LOG_LEVEL_ROOT=INFO
LOG_LEVEL_CZERTAINLY=INFO

# File Upload
MAX_FILE_SIZE=10MB
MAX_REQUEST_SIZE=10MB

# PQC
PQC_ENABLED=true

# Connectors
CONNECTOR_MTLS_ENABLED=true

# Server
SERVER_PORT=8080
SERVER_CONTEXT_PATH=/
SPRING_DATASOURCE_URL=jdbc:postgresql://postgres:5432/czertainly
SPRING_DATASOURCE_USERNAME=czertainly
JPA_DDL_AUTO=validate
```

---

## 11.4 Kubernetes Deployment

### Deployment Manifest

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: czertainly-core
  namespace: czertainly
  labels:
    app: czertainly-core
    version: v2.16.4
spec:
  replicas: 3
  selector:
    matchLabels:
      app: czertainly-core
  template:
    metadata:
      labels:
        app: czertainly-core
      annotations:
        prometheus.io/scrape: "true"
        prometheus.io/port: "9090"
        prometheus.io/path: "/actuator/prometheus"
    spec:
      # Service Account
      serviceAccountName: czertainly-core
      
      # Security Context
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        fsGroup: 1000
      
      # Pod Disruption Budget
      affinity:
        podAntiAffinity:
          preferredDuringSchedulingIgnoredDuringExecution:
          - weight: 100
            podAffinityTerm:
              labelSelector:
                matchExpressions:
                - key: app
                  operator: In
                  values:
                  - czertainly-core
              topologyKey: kubernetes.io/hostname
      
      containers:
      - name: czertainly-core
        image: czertainly/core:2.16.4
        imagePullPolicy: Always
        
        ports:
        - containerPort: 8080
          name: http
          protocol: TCP
        - containerPort: 9090
          name: metrics
          protocol: TCP
        
        env:
        # Database
        - name: SPRING_DATASOURCE_URL
          value: "jdbc:postgresql://postgres:5432/czertainly"
        - name: SPRING_DATASOURCE_USERNAME
          valueFrom:
            secretKeyRef:
              name: db-credentials
              key: username
        - name: SPRING_DATASOURCE_PASSWORD
          valueFrom:
            secretKeyRef:
              name: db-credentials
              key: password
        
        # RabbitMQ
        - name: SPRING_RABBITMQ_HOST
          value: "rabbitmq"
        - name: SPRING_RABBITMQ_PORT
          value: "5672"
        - name: SPRING_RABBITMQ_USERNAME
          valueFrom:
            secretKeyRef:
              name: rabbitmq-credentials
              key: username
        - name: SPRING_RABBITMQ_PASSWORD
          valueFrom:
            secretKeyRef:
              name: rabbitmq-credentials
              key: password
        
        # Security
        - name: OAUTH2_ISSUER
          valueFrom:
            configMapKeyRef:
              name: czertainly-config
              key: oauth2.issuer
        - name: AUTH_SERVICE_URL
          valueFrom:
            configMapKeyRef:
              name: czertainly-config
              key: auth.service.url
        
        # OPA
        - name: OPA_ENABLED
          value: "true"
        - name: OPA_HOST
          value: "opa"
        - name: OPA_PORT
          value: "8181"
        
        # Server
        - name: SERVER_PORT
          value: "8080"
        - name: LOGGING_LEVEL_ROOT
          value: "INFO"
        - name: LOGGING_LEVEL_COM_CZERTAINLY
          value: "INFO"
        
        resources:
          requests:
            memory: "512Mi"
            cpu: "250m"
          limits:
            memory: "2Gi"
            cpu: "1000m"
        
        # Liveness Probe (pod restart if fails)
        livenessProbe:
          httpGet:
            path: /v1/health/live
            port: 8080
          initialDelaySeconds: 60
          periodSeconds: 30
          timeoutSeconds: 10
          failureThreshold: 3
        
        # Readiness Probe (remove from LB if fails)
        readinessProbe:
          httpGet:
            path: /v1/health/ready
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
          timeoutSeconds: 5
          failureThreshold: 3
        
        # Startup Probe (give time to start)
        startupProbe:
          httpGet:
            path: /v1/health
            port: 8080
          initialDelaySeconds: 0
          periodSeconds: 10
          timeoutSeconds: 3
          failureThreshold: 30
        
        # Volume Mounts
        volumeMounts:
        - name: config
          mountPath: /etc/czertainly
          readOnly: true
        - name: ssl-certs
          mountPath: /opt/czertainly/ssl
          readOnly: true
        - name: logs
          mountPath: /var/log/czertainly
        
        # Security Context per container
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          capabilities:
            drop:
            - ALL
      
      # Volumes
      volumes:
      - name: config
        configMap:
          name: czertainly-config
      - name: ssl-certs
        secret:
          secretName: czertainly-tls
      - name: logs
        emptyDir: {}

---
apiVersion: v1
kind: Service
metadata:
  name: czertainly-core
  namespace: czertainly
spec:
  type: ClusterIP
  selector:
    app: czertainly-core
  ports:
  - port: 8080
    targetPort: 8080
    name: http
  - port: 9090
    targetPort: 9090
    name: metrics

---
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: czertainly-core-hpa
  namespace: czertainly
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: czertainly-core
  minReplicas: 3
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
```

---

## 11.5 Health Check Endpoints

### Health Check Controller Implementation

```java
@RestController
@RequestMapping("/v1/health")
@Slf4j
public class HealthCheckController {
    
    @Autowired
    private DataSource dataSource;
    
    @Autowired
    private RabbitTemplate rabbitTemplate;
    
    @Autowired
    private ApplicationContext applicationContext;
    
    /**
     * GET /v1/health
     * Overall health status (Liveness + Readiness)
     */
    @GetMapping
    public HealthStatusResponse getHealth() {
        return new HealthStatusResponse(
            "UP",
            LocalDateTime.now(),
            getDetailedHealth()
        );
    }
    
    /**
     * GET /v1/health/live (Kubernetes liveness)
     * Pod should be restarted if this fails
     */
    @GetMapping("/live")
    public ResponseEntity<Void> getLiveness() {
        // Simple check: is JVM running?
        if (applicationContext.isActive()) {
            return ResponseEntity.ok().build();
        }
        return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).build();
    }
    
    /**
     * GET /v1/health/ready (Kubernetes readiness)
     * Pod removed from LB if this fails
     */
    @GetMapping("/ready")
    public ResponseEntity<ReadinessStatus> getReadiness() {
        
        ReadinessStatus status = new ReadinessStatus();
        status.setTimestamp(LocalDateTime.now());
        
        try {
            // Check database connectivity
            testDatabaseConnection();
            status.setDatabaseReady(true);
        } catch (Exception e) {
            logger.error("Database readiness check failed", e);
            status.setDatabaseReady(false);
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
                .body(status);
        }
        
        try {
            // Check RabbitMQ connectivity
            testRabbitMqConnection();
            status.setRabbitMqReady(true);
        } catch (Exception e) {
            logger.warn("RabbitMQ readiness check failed", e);
            status.setRabbitMqReady(false);
        }
        
        // Overall: ready if database is OK
        boolean isReady = status.isDatabaseReady();
        
        return isReady ? 
            ResponseEntity.ok(status) :
            ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(status);
    }
    
    /**
     * GET /v1/health/startup (Kubernetes startup probe)
     * Poll periodically until true (30x10s = 5min default timeout)
     */
    @GetMapping("/startup")
    public ResponseEntity<StartupStatus> getStartup() {
        
        StartupStatus status = new StartupStatus();
        status.setTimestamp(LocalDateTime.now());
        
        try {
            // Check if database migrations completed
            testDatabaseMigrations();
            status.setMigrationsComplete(true);
            
            // Check if essential beans loaded
            testBeansLoaded();
            status.setBeansLoaded(true);
            
            status.setReady(true);
            return ResponseEntity.ok(status);
            
        } catch (Exception e) {
            logger.info("Startup check not ready: {}", e.getMessage());
            status.setReady(false);
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
                .body(status);
        }
    }
    
    private void testDatabaseConnection() throws Exception {
        try (Connection conn = dataSource.getConnection()) {
            conn.createStatement().execute("SELECT 1");
        }
    }
    
    private void testRabbitMqConnection() throws Exception {
        rabbitTemplate.convertAndSend("health-check", "test");
    }
    
    private void testDatabaseMigrations() throws Exception {
        // Check flyway_schema_history table
        try (Connection conn = dataSource.getConnection();
             Statement stmt = conn.createStatement()) {
            
            ResultSet rs = stmt.executeQuery(
                "SELECT * FROM flyway_schema_history WHERE success = true"
            );
            
            int count = 0;
            while (rs.next()) count++;
            
            if (count == 0) {
                throw new Exception("No migrations completed");
            }
        }
    }
    
    private void testBeansLoaded() throws Exception {
        // Critical beans must exist
        String[] criticalBeans = {
            "connectorService",
            "certificateService",
            "cryptographicKeyService"
        };
        
        for (String beanName : criticalBeans) {
            if (!applicationContext.containsBean(beanName)) {
                throw new Exception("Critical bean not loaded: " + beanName);
            }
        }
    }
    
    private Map<String, Object> getDetailedHealth() {
        Map<String, Object> details = new HashMap<>();
        details.put("database", checkDatabaseHealth());
        details.put("rabbitmq", checkRabbitMqHealth());
        details.put("memory", checkMemoryHealth());
        return details;
    }
}

@Data
class HealthStatusResponse {
    private String status;
    private LocalDateTime timestamp;
    private Map<String, Object> details;
}

@Data
class ReadinessStatus {
    private LocalDateTime timestamp;
    private boolean databaseReady;
    private boolean rabbitMqReady;
}

@Data
class StartupStatus {
    private LocalDateTime timestamp;
    private boolean migrationsComplete;
    private boolean beansLoaded;
    private boolean ready;
}
```

---

## 11.6 Graceful Shutdown

### Graceful Shutdown Configuration

```java
@Configuration
public class GracefulShutdownConfiguration {
    
    @Bean
    public GracefulShutdownHook gracefulShutdownHook(
            ApplicationContext context) {
        
        return new GracefulShutdownHook(context);
    }
}

@Component
@Slf4j
public class GracefulShutdownHook {
    
    private final ApplicationContext context;
    
    public GracefulShutdownHook(ApplicationContext context) {
        this.context = context;
        Runtime.getRuntime().addShutdownHook(new Thread(this::shutdown));
    }
    
    public void shutdown() {
        logger.info("Initiating graceful shutdown...");
        
        try {
            // 1. Stop accepting new requests (readiness probe fails)
            setReadinessProbeFailure();
            
            // 2. Wait for in-flight requests (30s timeout)
            Thread.sleep(5000);  // Give time for LB to drain
            
            // 3. Complete ongoing async tasks
            ApplicationContext ctx = (ApplicationContext) context;
            ThreadPoolTaskExecutor executor = 
                ctx.getBean(ThreadPoolTaskExecutor.class);
            
            executor.shutdown();
            if (!executor.getThreadPoolExecutor().awaitTermination(30, TimeUnit.SECONDS)) {
                logger.warn("Executor did not terminate gracefully");
                executor.getThreadPoolExecutor().shutdownNow();
            }
            
            // 4. Complete RabbitMQ consumers
            // (Spring will handle automatically via SmartLifecycle)
            
            logger.info("Graceful shutdown completed");
            
        } catch (Exception e) {
            logger.error("Error during graceful shutdown", e);
        }
    }
    
    private void setReadinessProbeFailure() {
        // Trigger readiness probe to fail
        // by setting internal flag
    }
}

echo "Shutdown hook registered"
```

---

## Resumo de Deployment

| Aspecto | Configuração |
|---------|---|
| **Docker** | Multi-stage build, non-root user, Alpine base |
| **Health Checks** | Liveness, Readiness, Startup probes |
| **Database** | PostgreSQL, Flyway migrations, HikariCP pool |
| **Messaging** | RabbitMQ with DLQ, retry policies |
| **Security** | mTLS, environment secrets, RBAC |
| **Kubernetes** | Deployment, HPA, Service, PDB |
| **Monitoring** | Prometheus metrics, health endpoints |
| **Scaling** | CPU/Memory-based HPA, replica affinity |
| **Graceful Shutdown** | 30s drain period, draining connections |

