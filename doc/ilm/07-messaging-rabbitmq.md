# 7. MESSAGING: RabbitMQ, Retry, DLQ & Processamento Assíncrono

## 7.1 Visão Estratégica de Messaging

### Questão: Por que Messaging?

**Cenário**: Usuário emite certificado

```
❌ Síncron (bad):
User → [Emit Certificate] → [Send Email] → [Log Audit] → Return (pode demorar 10s!)

✅ Assíncrono (good):
User → [Emit Certificate] → [QUEUE] → Return (50ms!)
         └─→ Background: [Send Email] (async)
         └─→ Background: [Log Audit] (async)
         └─→ Background: [Update Metrics] (async)
```

### Topologia de Messaging CZERTAINLY-Core

```
┌──────────────────────────────────────┐
│ Core Application (Sync)              │
│ ┌──────────────────────────────┐     │
│ │ Emitir Certificado           │     │
│ │ • Gera chave privada         │     │
│ │ • Solicita CA (sync)         │     │
│ │ • Salva no BD                │     │
│ └────────────┬──────────────────┘     │
└─────────────┞──────────────────────────┘
              │
        [ASYNC EVENTS]
              │
  ┌───────────┼───────────┐
  ▼           ▼           ▼
┌─────────┐ ┌──────────┐ ┌──────────┐
│Notific. │ │ Audit    │ │ Compliance
│Queue    │ │ Queue    │ │ Check Q.
│ • Email │ │ • Log    │ │ • Verify
│ • SMS   │ │   event  │ │   rules
└─────────┘ └──────────┘ └──────────┘
  │ (1 worker) (2 workers) (1 worker)
  ▼
┌────────────────────────────┐
│ Dead Letter Queue (DLQ)    │
│ (Retry strategy: 3x)       │
│ • Failed emails            │
│ • Poison messages          │
└────────────────────────────┘
```

### Garantias de Entrega (Delivery Semantics)

| Tipo | Garantia | Implementação | Quando usar |
|------|---|---|---|
| **At Most Once** | 0 ou 1 | ACK imediato | Logs, métricas (pode perder) |
| **At Least Once** | 1 ou mais | Manual ACK + Retry | Emails, notificações (duplicatas OK) |
| **Exactly Once** | 1 | Idempotência + tracking | Financeiro, certificados (crítico) |

**CZERTAINLY**: At Least Once + Idempotency (combine)

+ **Retry logic** com backoff exponencial
- **Idempotent handlers** (detecta duplicatas)

---

## 7.2 RabbitMQ Queue Architecture

### Configuration com Dead Letter Queues

**Arquivo**: `src/main/java/com/czertainly/core/messaging/RabbitMQConfiguration.java`

```java
@Configuration
public class RabbitMQConfiguration {
    
    // ==================== Primary Exchanges ====================
    
    @Bean
    public DirectExchange notificationExchange() {
        return new DirectExchange("notification-exchange", true, false);
    }
    
    // ==================== Primary Queues ====================
    
    /**
     * TTL (Time To Live) para Dead Letter:
     * - Mensagem rejeita N vezes
     * - Move para DLQ após TTL
     */
    @Bean
    public Queue notificationQueue() {
        return QueueBuilder
            .durable("notification-queue")
            .withArgument("x-dead-letter-exchange", "notification-dlx")
            .withArgument("x-dead-letter-routing-key", "notification.dlq")
            .withArgument("x-message-ttl", 3600000)  // 1h before DLQ
            .build();
    }
    
    @Bean
    public Binding notificationBinding() {
        return BindingBuilder
            .bind(notificationQueue())
            .to(notificationExchange())
            .with("notification.*");
    }
    
    // ==================== Dead Letter Exchanges & Queues ====================
    
    /**
     * DLX (Dead Letter Exchange) recebe mensagens que falharam N vezes
     * Permite análise + reprocessamento manual
     */
    @Bean
    public DirectExchange notificationDlx() {
        return new DirectExchange("notification-dlx", true, false);
    }
    
    @Bean
    public Queue notificationDlq() {
        return QueueBuilder
            .durable("notification-queue-dlq")
            .build();
    }
    
    @Bean
    public Binding notificationDlqBinding() {
        return BindingBuilder
            .bind(notificationDlq())
            .to(notificationDlx())
            .with("notification.dlq");
    }
    
    // ==================== Connection Factory ====================
    
    @Bean
    public SimpleRabbitListenerContainerFactory rabbitListenerContainerFactory(
            ConnectionFactory connectionFactory,
            MessageConverter messageConverter) {
        
        SimpleRabbitListenerContainerFactory factory = 
            new SimpleRabbitListenerContainerFactory();
        
        factory.setConnectionFactory(connectionFactory);
        factory.setMessageConverter(messageConverter);
        
        // Concurrency: processa N mensagens em paralelo
        factory.setConcurrentConsumers(3);
        factory.setMaxConcurrentConsumers(10);
        
        // Prefetch: N mensagens máximo por consumer
        factory.setPrefetchCount(5);
        
        // Retry: AUTO ack = não retry após falha
        // MANUAL ack = controle total
        factory.setAcknowledgeMode(AcknowledgeMode.MANUAL);
        
        // Default requeue (se não ACK)
        factory.setDefaultRequeueRejected(false);  // Envia para DLQ
        
        return factory;
    }
    
    @Bean
    public MessageConverter jsonMessageConverter() {
        return new Jackson2JsonMessageConverter();
    }
}
```

### application.yml

```yaml
spring:
  rabbitmq:
    host: ${RABBITMQ_HOST:rabbitmq}
    port: ${RABBITMQ_PORT:5672}
    username: ${RABBITMQ_USER:guest}
    password: ${RABBITMQ_PASSWORD:guest}
    virtual-host: /
    
    # Connection pooling
    addresses: rabbitmq:5672
    channel-cache-size: 50
    
    # Listener settings
    listener:
      simple:
        acknowledge-mode: MANUAL  # Explicit ACK
        prefetch: 5               # Process 5 messages at a time
        concurrency: 3            # 3 parallel consumers
        max-concurrency: 10
        
        # Retry configuration (Spring Retry)
        retry:
          enabled: true
          initial-interval: 1000       # 1s first retry
          multiplier: 2.0              # Exponential backoff
          max-attempts: 3              # Total attempts: 1 + 3 retries
          max-interval: 10000          # Cap at 10s
```

---

## 7.3 Event Publishers (Producers)

### Notification Publisher - Real Example

```java
@Component
@Slf4j
public class NotificationPublisher {
    
    @Autowired
    private RabbitTemplate rabbitTemplate;
    
    /**
     * Publica evento de notificação (email/SMS)
     * 
     * Event Flow:
     * 1. Service cria NotificationEvent
     * 2. Publisher envia para RabbitMQ
     * 3. Retorna IMEDIATAMENTE para cliente
     * 4. Consumer processa assincronamente
     * 5. Se falhar N vezes: move para DLQ
     */
    @Transactional
    public String publishCertificateIssuedNotification(
            String recipientEmail, 
            Certificate certificate) {
        
        NotificationEvent event = NotificationEvent.builder()
            .eventType(EventType.CERTIFICATE_ISSUED)
            .timestamp(Instant.now())
            .recipient(recipientEmail)
            .certificateSn(certificate.getSerialNumber())
            .certificateSubject(certificate.getSubject())
            .build();
        
        String routingKey = "notification.certificate.issued";
        String correlationId = UUID.randomUUID().toString();
        
        try {
            // Send to RabbitMQ
            rabbitTemplate.convertAndSend(
                "notification-exchange",
                routingKey,
                event,
                message -> {
                    // Set headers
                    MessageProperties props = message.getMessageProperties();
                    props.setCorrelationId(correlationId);
                    props.setHeader("event-type", event.getEventType().name());
                    props.setTimestamp(System.currentTimeMillis());
                    props.setContentType("application/json");
                    
                    return message;
                }
            );
            
            log.info("Notification event published: {} (correlationId: {})", 
                     event.getEventType(), correlationId);
            
            return correlationId;
            
        } catch (Exception e) {
            log.error("Failed to publish notification event", e);
            throw new MessagingException("Cannot publish event", e);
        }
    }
}
```

---

## 7.4 Event Consumers (Listeners) - Retry & DLQ Handling

### Email Consumer with Retry

```java
@Component
@Slf4j
public class NotificationConsumer {
    
    @Autowired
    private EmailService emailService;
    
    @Autowired
    private AuditLogService auditLogService;
    
    /**
     * Consome eventos de notificação
     * 
     * Retry Strategy:
     * - MAX 3 tentativas
     * - Exponential backoff (1s, 2s, 4s)
     * - Se falhar 3x: move para DLQ
     */
    @RabbitListener(queues = "notification-queue")
    public void handleCertificateIssuedNotification(
            @Payload NotificationEvent event,
            @Headers Map<String, ?> headers,
            Channel channel,
            Message message) {
        
        String correlationId = (String) headers.get("correlation-id");
        long deliveryTag = message.getMessageProperties().getDeliveryTag();
        int retryCount = (Integer) headers.getOrDefault("x-death-count", 0);
        
        log.info("Processing notification: {} (retry: {})", 
                 correlationId, retryCount);
        
        try {
            // =============== Business Logic ===============
            handleNotification(event);
            
            // Success: ACK the message
            channel.basicAck(deliveryTag, false);
            
            log.info("Notification processed successfully: {}", correlationId);
            
        } catch (EmailServiceException e) {
            // Retry: NACK + requeue
            log.warn("Failed to send email (retry count: {}): {}", 
                     retryCount, e.getMessage());
            
            if (retryCount < 2) {  // Max 3 attempts total
                try {
                    // Requeue = vai voltar para queue
                    channel.basicNack(deliveryTag, false, true);
                } catch (IOException ioEx) {
                    log.error("Failed to NACK message", ioEx);
                }
            } else {
                // Max retries reached: send to DLQ via NACK without requeue
                try {
                    channel.basicNack(deliveryTag, false, false);
                    log.error("Message sent to DLQ after {} retries", retryCount);
                } catch (IOException ioEx) {
                    log.error("Failed to send to DLQ", ioEx);
                }
            }
        } catch (Exception e) {
            log.error("Unexpected error processing notification", e);
            try {
                channel.basicNack(deliveryTag, false, false);
            } catch (IOException ioEx) {
                log.error("Failed to NACK on error", ioEx);
            }
        }
    }
    
    private void handleNotification(NotificationEvent event) {
        
        // Validate event
        if (event == null || event.getRecipient() == null) {
            throw new IllegalArgumentException("Invalid notification event");
        }
        
        // Send email
        emailService.sendCertificateIssuanceEmail(
            event.getRecipient(),
            event.getCertificateSubject(),
            event.getCertificateSn()
        );
        
        // Log to audit
        auditLogService.log(AuditEvent.builder()
            .module(Module.NOTIFICATION)
            .operation(Operation.SEND)
            .resourceType("CERTIFICATE")
            .resourceId(event.getCertificateSn())
            .operationResult(OperationResult.SUCCESS)
            .build());
    }
}
```

### DLQ Consumer - Dead Letter Handler

```java
@Component
@Slf4j
public class DeadLetterQueueConsumer {
    
    @Autowired
    private AlertService alertService;
    
    /**
     * Consome mensagens que falharam N vezes
     * Estratégia: alertar admin para investigação manual
     */
    @RabbitListener(queues = "notification-queue-dlq")
    public void handleDeadLetter(
            @Payload String payload,
            @Headers Map<String, ?> headers,
            Channel channel,
            Message message) {
        
        long deliveryTag = message.getMessageProperties().getDeliveryTag();
        String correlationId = (String) headers.get("correlation-id");
        Integer deathCount = (Integer) headers.get("x-death-count");
        
        log.error("Dead Letter received: {} (failed {} times)", 
                 correlationId, deathCount);
        
        try {
            // Alert admin
            alertService.sendAlert(
                "Message failed after retries",
                "CorrelationID: " + correlationId + 
                "\nFailed: " + deathCount + " times\n" +
                "Payload: " + payload
            );
            
            // ACK to remove from DLQ
            channel.basicAck(deliveryTag, false);
            
        } catch (Exception e) {
            log.error("Error in DLQ handler", e);
        }
    }
}
```

---

## 7.5 Message Idempotency Pattern

### Problem: Duplicate Messages

```
Cenário: Email sent successfully, mas ACK lost
┌─────────────┐
│ RabbitMQ    │ ← ACK timeout (network issue)
│ Requeue msg │
└─────────────┘
     ▼
┌─────────────┐
│ Consumer 2  │ ← Processa NOVAMENTE
│ Envia email │ (user recebe 2x)
└─────────────┘
```

### Solution: Idempotency Key

```java
@Component
public class IdempotentNotificationConsumer {
    
    @Autowired
    private IdempotencyService idempotencyService;  // Redis-backed
    
    @RabbitListener(queues = "notification-queue")
    public void handleNotification(@Payload NotificationEvent event, 
                                   @Headers Map<String, ?> headers) {
        
        String idempotencyKey = generateKey(event, headers);
        
        // Check if already processed
        if (idempotencyService.isDuplicate(idempotencyKey)) {
            log.warn("Duplicate message detected: {}", idempotencyKey);
            return;  // Skip processing
        }
        
        try {
            // Process
            handleNotification(event);
            
            // Mark as processed
            idempotencyService.markProcessed(idempotencyKey);
            
        } catch (Exception e) {
            log.error("Processing failed", e);
            throw e;
        }
    }
    
    private String generateKey(NotificationEvent event, Map<String, ?> headers) {
        String correlationId = (String) headers.get("correlation-id");
        return "notification:" + correlationId + ":" + 
               event.getRecipient() + ":" + 
               event.getEventType();
    }
}
```

### IdempotencyService

```java
@Service
public class IdempotencyService {
    
    @Autowired
    private RedisTemplate<String, String> redisTemplate;
    
    private static final Duration IDEMPOTENCY_TTL = Duration.ofHours(24);
    
    public boolean isDuplicate(String idempotencyKey) {
        Boolean exists = redisTemplate.hasKey(idempotencyKey);
        return Boolean.TRUE.equals(exists);
    }
    
    public void markProcessed(String idempotencyKey) {
        redisTemplate.opsForValue().set(
            idempotencyKey, 
            "processed", 
            IDEMPOTENCY_TTL
        );
    }
}
```

---

## 7.6 Monitoring & Health Checks

### RabbitMQ Health

```java
@Component
public class RabbitMQHealthIndicator extends AbstractHealthIndicator {
    
    @Autowired
    private RabbitTemplate rabbitTemplate;
    
    @Override
    protected void doHealthCheck(Health.Builder builder) {
        try {
            // Test connection
            rabbitTemplate.execute(channel ->
                channel.queueDeclarePassive("notification-queue")
            );
            
            builder.up()
                .withDetail("status", "RabbitMQ connected");
                
        } catch (Exception e) {
            builder.down()
                .withDetail("error", e.getMessage());
        }
    }
}
```

---

## 7.7 Message Patterns & Trade-offs

### Messaging Patterns Comparison

| Pattern | Use Case | Trade-off |
|---------|----------|-----------|
| **Pub/Sub** | Broadcast (1 event → N consumers) | Loose coupling but hard to debug |
| **Work Queue** | Load distribution | Complex retry logic |
| **RPC** | Sync response from async | Blocking, defeats async benefit |
| **Saga** |Distributed transactions | State management complexity |

**CZERTAINLY**: Pub/Sub + Work Queue (hybrid)
    
    @Bean
    public DirectExchange notificationDlqExchange() {
        return new DirectExchange("notification-queue-dlq-exchange", true, false);
    }
    
    @Bean
    public Binding notificationDlqBinding(Queue notificationDlq, DirectExchange notificationDlqExchange) {
        return BindingBuilder.bind(notificationDlq)
            .to(notificationDlqExchange)
            .with("notification.*");
    }
    
    // ==================== MESSAGE CONVERTER ====================
    
    @Bean
    public MessageConverter jsonMessageConverter() {
        return new Jackson2JsonMessageConverter();
    }
    
    // ==================== CONNECTION FACTORY ====================
    
    @Bean
    public SimpleRabbitListenerContainerFactory rabbitListenerContainerFactory(
            ConnectionFactory connectionFactory,
            MessageConverter messageConverter) {
        
        SimpleRabbitListenerContainerFactory factory = new SimpleRabbitListenerContainerFactory();
        factory.setConnectionFactory(connectionFactory);
        factory.setMessageConverter(messageConverter);
        factory.setConcurrentConsumers(3);  // Default concurrency
        factory.setMaxConcurrentConsumers(10);
        factory.setDefaultRequeueRejected(true);
        factory.setAcknowledgeMode(AcknowledgeMode.AUTO);
        
        return factory;
    }
}
```

### Application Configuration

**application.yml**:
```yaml
spring:
  rabbitmq:
    host: ${RABBITMQ_HOST:rabbitmq}
    port: ${RABBITMQ_PORT:5672}
    username: ${RABBITMQ_USER:guest}
    password: ${RABBITMQ_PASSWORD:guest}
    virtual-host: ${RABBITMQ_VHOST:/}
    connection-timeout: 10000
    listener:
      simple:
        acknowledge-mode: AUTO  # or MANUAL for explicit ACK
        retry:
          enabled: true
          initial-interval: 1000
          multiplier: 2.0
          max-attempts: 3
```

---

## 7.2 Event Producers (Publishers)

### NotificationProducer

```java
@Component
@Slf4j
public class NotificationProducer {
    
    @Autowired
    private RabbitTemplate rabbitTemplate;
    
    /**
     * Publica evento de notificação
     */
    public void publishNotificationEvent(NotificationEvent event) {
        
        String routingKey = "notification." + event.getNotificationType().toLowerCase();
        
        try {
            rabbitTemplate.convertAndSend(
                "notification-exchange",
                routingKey,
                event,
                message -> {
                    // Set custom headers
                    message.getMessageProperties().setHeader("event-type", 
                        event.getNotificationType());
                    message.getMessageProperties().setHeader("timestamp", 
                        Instant.now().toString());
                    message.getMessageProperties().setCorrelationId(
                        UUID.randomUUID().toString()
                    );
                    
                    return message;
                }
            );
            
            log.info("Published notification event: {} to routing key: {}", 
                event.getId(), routingKey);
            
        } catch (Exception e) {
            log.error("Failed to publish notification event", e);
            // Event will be retried or sent to DLQ by RabbitMQ
        }
    }
}

@Data
@AllArgsConstructor
public class NotificationEvent {
    private UUID id;
    private String notificationType;  // EMAIL, WEBHOOK, IN_APP
    private String recipientId;
    private String subject;
    private String message;
    private Map<String, Object> metadata;
    private Instant timestamp = Instant.now();
}
```

### AuditEventProducer

```java
@Component
@Slf4j
public class AuditEventProducer {
    
    @Autowired
    private RabbitTemplate rabbitTemplate;
    
    /**
     * Publica evento de auditoria para logging assíncrono
     */
    public void publishAuditEvent(AuditLog auditLog) {
        
        String routingKey = "audit." + auditLog.getModule().value().toLowerCase();
        
        AuditEventDto auditEvent = convertToEventDto(auditLog);
        
        rabbitTemplate.convertAndSend(
            "audit-event-exchange",
            routingKey,
            auditEvent,
            message -> {
                message.getMessageProperties().setHeader("module", auditLog.getModule().toString());
                message.getMessageProperties().setHeader("operation", auditLog.getOperation().toString());
                message.getMessageProperties().setDeliveryMode(MessageDeliveryMode.PERSISTENT);
                
                return message;
            }
        );
        
        log.debug("Published audit event: {} for operation: {}", 
            auditLog.getId(), auditLog.getOperation());
    }
}
```

### ComplianceProducer

```java
@Component
@Slf4j
public class ComplianceProducer {
    
    @Autowired
    private RabbitTemplate rabbitTemplate;
    
    /**
     * Publica evento para verificação de compliance
     */
    public void publishComplianceCheckEvent(ComplianceCheckEvent event) {
        
        rabbitTemplate.convertAndSend(
            "compliance-check-exchange",
            "compliance.check",
            event
        );
        
        log.info("Published compliance check event for certificate: {}", 
            event.getCertificateUuid());
    }
}

@Data
public class ComplianceCheckEvent {
    private UUID certificateUuid;
    private UUID complianceProfileUuid;  // Optional
    private Instant timestamp = Instant.now();
    private String triggeredBy;  // MANUAL, SCHEDULED, CERT_ISSUED, etc
}
```

### DiscoveryProducer

```java
@Component
@Slf4j
public class DiscoveryProducer {
    
    @Autowired
    private RabbitTemplate rabbitTemplate;
    
    /**
     * Publica evento para descoberta de certificados
     */
    public void publishDiscoveryEvent(CertificateDiscoveryEvent event) {
        
        rabbitTemplate.convertAndSend(
            "certificate-discovery-exchange",
            "discovery.certificate",
            event
        );
        
        log.info("Published discovery event for location: {}", event.getLocationUuid());
    }
}
```

---

## 7.3 Event Listeners (Consumers)

### NotificationListener

```java
@Component
@Slf4j
public class NotificationListener {
    
    @Autowired
    private NotificationService notificationService;
    
    /**
     * Processa eventos de notificação
     */
    @RabbitListener(queues = "notification-queue")
    public void handleNotificationEvent(NotificationEvent event) {
        
        log.info("Processing notification event: {} of type: {}", 
            event.getId(), event.getNotificationType());
        
        try {
            // Process notification based on type
            if ("EMAIL".equals(event.getNotificationType())) {
                notificationService.sendEmailNotification(event);
            } else if ("WEBHOOK".equals(event.getNotificationType())) {
                notificationService.sendWebhookNotification(event);
            } else if ("IN_APP".equals(event.getNotificationType())) {
                notificationService.createInAppNotification(event);
            }
            
            log.info("Notification processed successfully: {}", event.getId());
            
        } catch (Exception e) {
            log.error("Error processing notification event: {}", event.getId(), e);
            throw e;  // Requeue on error
        }
    }
    
    @RabbitListener(queues = "notification-queue-dlq")
    public void handleNotificationDlqEvent(NotificationEvent event) {
        log.error("Notification event moved to DLQ after retries: {}", event.getId());
        
        // Log to database for manual review
        notificationService.recordFailedNotification(event);
    }
}
```

### AuditEventListener

```java
@Component
@Slf4j
public class AuditEventListener {
    
    @Autowired
    private AuditLogService auditLogService;
    
    @Autowired
    private ElasticsearchService elasticsearchService;
    
    /**
     * Processa eventos de auditoria
     * (indexação em Elasticsearch para busca rápida)
     */
    @RabbitListener(queues = "audit-event-queue")
    @Transactional
    public void handleAuditEvent(AuditEventDto auditEvent) {
        
        log.debug("Processing audit event: {} for module: {}", 
            auditEvent.getId(), auditEvent.getModule());
        
        try {
            // Index in Elasticsearch for full-text search
            elasticsearchService.indexAuditEvent(auditEvent);
            
            // Optional: Send to external SIEM system
            if (shouldSendToSIEM(auditEvent)) {
                sendToSIEM(auditEvent);
            }
            
        } catch (Exception e) {
            log.error("Error processing audit event", e);
            throw e;
        }
    }
}
```

### ComplianceCheckListener

```java
@Component
@Slf4j
public class ComplianceCheckListener {
    
    @Autowired
    private ComplianceService complianceService;
    
    @Autowired
    private NotificationProducer notificationProducer;
    
    /**
     * Processa eventos de verificação de compliance
     * (operação potencialmente cara)
     */
    @RabbitListener(queues = "compliance-check-queue", concurrency = "3-5")
    @Transactional
    public void handleComplianceCheckEvent(ComplianceCheckEvent event) {
        
        log.info("Processing compliance check event for certificate: {}", 
            event.getCertificateUuid());
        
        try {
            // Execute compliance check
            ComplianceCheckResult result = complianceService
                .checkCompliance(event.getCertificateUuid());
            
            // If non-compliant, trigger notification
            if (!result.isPassed()) {
                notificationProducer.publishNotificationEvent(
                    new NotificationEvent(
                        UUID.randomUUID(),
                        "EMAIL",
                        "admin@company.com",
                        "Certificate Non-Compliant",
                        "Certificate " + event.getCertificateUuid() + 
                            " is non-compliant with policy",
                        Map.of("violations", result.getViolations()),
                        Instant.now()
                    )
                );
            }
            
        } catch (Exception e) {
            log.error("Error checking compliance for certificate: {}", 
                event.getCertificateUuid(), e);
            throw e;
        }
    }
}
```

### DiscoveryListener

```java
@Component
@Slf4j
public class DiscoveryListener {
    
    @Autowired
    private CertificateService certificateService;
    
    @Autowired
    private LocationService locationService;
    
    /**
     * Processa eventos de descoberta (long-running operation)
     */
    @RabbitListener(queues = "certificate-discovery-queue", concurrency = "1")
    @Transactional
    public void handleDiscoveryEvent(CertificateDiscoveryEvent event) {
        
        log.info("Processing discovery event for location: {}", event.getLocationUuid());
        
        try {
            // Discover certificates from location/entity provider
            locationService.discoverCertificates(event.getLocationUuid());
            
            // Log success
            log.info("Discovery completed for location: {}", event.getLocationUuid());
            
        } catch (Exception e) {
            log.error("Error discovering certificates for location: {}", 
                event.getLocationUuid(), e);
            throw e;
        }
    }
}
```

---

## 7.4 Error Handling & Retry

### RabbitMQ Retry Configuration

```java
@Configuration
public class RetryConfiguration {
    
    @Bean
    public RabbitRetryTemplateFactory retryTemplateFactory() {
        return new RabbitRetryTemplateFactory(
            backOffPolicy(),
            recoveryCallback()
        );
    }
    
    @Bean
    public FixedBackOffPolicy backOffPolicy() {
        FixedBackOffPolicy policy = new FixedBackOffPolicy();
        policy.setBackOffPeriod(1000);  // 1 second between retries
        return policy;
    }
    
    @Bean
    public RecoveryCallback<Object> recoveryCallback() {
        return context -> {
            log.error("Message processing failed after retries: {}", 
                context.attributeValue("message"));
            // Message goes to DLQ automatically
            return null;
        };
    }
}
```

### Custom Error Handler

```java
@Component
@Slf4j
public class RabbitErrorHandler implements ErrorHandler {
    
    @Autowired
    private AuditLogService auditLogService;
    
    @Override
    public void handleError(Throwable t) {
        
        if (t instanceof ListenerExecutionFailedException) {
            ListenerExecutionFailedException ex = 
                (ListenerExecutionFailedException) t;
            
            log.error("Listener execution failed for message: {}", 
                ex.getFailedMessage(), t);
            
            // Log error for manual intervention
            auditLogService.logError(
                "MESSAGE_PROCESSING_ERROR",
                ex.getFailedMessage().toString(),
                t.getMessage()
            );
        }
    }
}
```

---

## 7.5 Event Schema (Domain Events)

### Base Event Structure

```java
@Data
@MappedSuperclass
public abstract class DomainEvent {
    
    private UUID eventId = UUID.randomUUID();
    private Instant timestamp = Instant.now();
    private String eventType;
    private String correlationId;  // para rastrear distributed transactions
}

// ========== Certificate Events ==========

@Data
public class CertificateIssuedEvent extends DomainEvent {
    private UUID certificateUuid;
    private String subject;
    private String issuer;
    private String serialNumber;
    private LocalDateTime validFrom;
    private LocalDateTime validTo;
    private UUID raProfileUuid;
}

@Data
public class CertificateRevokedEvent extends DomainEvent {
    private UUID certificateUuid;
    private String reason;
    private LocalDateTime revokedAt;
    private String revokedBy;
}

@Data
public class CertificateExpiringEvent extends DomainEvent {
    private UUID certificateUuid;
    private LocalDateTime expirationDate;
    private int daysUntilExpiration;
}

// ========== Key Events ==========

@Data
public class CryptographicKeyCreatedEvent extends DomainEvent {
    private UUID keyUuid;
    private String name;
    private String keyType;  // RSA, EC, PQC
    private int keySize;
}

@Data
public class CryptographicKeyCompromisedEvent extends DomainEvent {
    private UUID keyUuid;
    private String reason;
    private LocalDateTime compromisedAt;
}

// ========== Approval Events ==========

@Data
public class ApprovalInitiatedEvent extends DomainEvent {
    private UUID approvalUuid;
    private String resourceType;
    private UUID resourceUuid;
    private List<String> approvers;
}

@Data
public class ApprovalApprovedEvent extends DomainEvent {
    private UUID approvalUuid;
    private String approvedBy;
    private LocalDateTime approvedAt;
    private int currentStep;
    private int totalSteps;
}

@Data
public class ApprovalRejectedEvent extends DomainEvent {
    private UUID approvalUuid;
    private String rejectedBy;
    private String reason;
    private LocalDateTime rejectedAt;
}
```

---

## 7.6 Event Publishing Integration

### Publishing from Services

```java
@Service
@Transactional
public class CertificateService {
    
    @Autowired
    private ApplicationEventPublisher eventPublisher;
    
    @Autowired
    private CertificateRepository certificateRepository;
    
    public void issueCertificate(CertificateIssuanceRequest request) {
        
        // ... issuance logic ...
        
        Certificate certificate = certificateRepository.save(cert);
        
        // Publish domain event
        // (Spring will handle sending to RabbitMQ via Listener)
        eventPublisher.publishEvent(
            new CertificateIssuedEvent(
                certificate.getUuid(),
                certificate.getSubject(),
                certificate.getIssuer(),
                certificate.getSerialNumber(),
                certificate.getValidFrom(),
                certificate.getValidTo(),
                certificate.getRaProfile().getUuid()
            )
        );
    }
    
    public void revokeCertificate(UUID certificateUuid, RevocationReason reason) {
        
        Certificate cert = certificateRepository.findById(certificateUuid)
            .orElseThrow();
        
        cert.setState(CertificateState.REVOKED);
        cert.setRevocationReason(reason.toString());
        cert.setRevokedAt(LocalDateTime.now());
        
        certificateRepository.save(cert);
        
        // Publish revocation event
        eventPublisher.publishEvent(
            new CertificateRevokedEvent(
                cert.getUuid(),
                reason.toString(),
                cert.getRevokedAt(),
                getCurrentUser()
            )
        );
    }
}
```

### Event Listener for Publishing to RabbitMQ

```java
@Component
@Slf4j
public class DomainEventListener {
    
    @Autowired
    private NotificationProducer notificationProducer;
    
    @Autowired
    private AuditEventProducer auditEventProducer;
    
    @Autowired
    private ComplianceProducer complianceProducer;
    
    /**
     * Listener para eventos de domínio
     * (converte para mensagens RabbitMQ)
     */
    @EventListener
    @Async("taskExecutor")
    public void onCertificateIssued(CertificateIssuedEvent event) {
        log.info("Certificate issued event: {}", event.getCertificateUuid());
        
        // Trigger compliance check
        complianceProducer.publishComplianceCheckEvent(
            new ComplianceCheckEvent(
                event.getCertificateUuid(),
                null,
                Instant.now(),
                "CERT_ISSUED"
            )
        );
        
        // Notify administrators
        notificationProducer.publishNotificationEvent(
            new NotificationEvent(
                UUID.randomUUID(),
                "IN_APP",
                "admin",
                "Certificate Issued",
                "Certificate " + event.getSerialNumber() + " has been issued",
                Map.of("certificate_uuid", event.getCertificateUuid()),
                Instant.now()
            )
        );
    }
    
    @EventListener
    @Async("taskExecutor")
    public void onCertificateExpiring(CertificateExpiringEvent event) {
        
        // Send notification when expiring in 30 days
        if (event.getDaysUntilExpiration() == 30) {
            notificationProducer.publishNotificationEvent(
                new NotificationEvent(
                    UUID.randomUUID(),
                    "EMAIL",
                    "admin@company.com",
                    "Certificate Expiring Soon",
                    "Certificate " + event.getCertificateUuid() + 
                        " will expire in 30 days",
                    null,
                    Instant.now()
                )
            );
        }
    }
}
```

---

## 7.7 Monitoring & Observability

### Message Tracing

```java
@Component
@Slf4j
public class MessageTracingInterceptor {
    
    @Bean
    public RabbitTemplate rabbitTemplate(ConnectionFactory connectionFactory) {
        
        RabbitTemplate template = new RabbitTemplate(connectionFactory);
        
        // Add interceptor para tracing
        template.setBeforePublishPostProcessors(message -> {
            String traceId = UUID.randomUUID().toString();
            message.getMessageProperties().setHeader("X-Trace-ID", traceId);
            
            MDC.put("trace_id", traceId);
            log.debug("Publishing message with trace ID: {}", traceId);
            
            return message;
        });
        
        return template;
    }
}
```

### Queue/Consumer Monitoring

```java
@Component
@Scheduled(fixedDelay = 60000)  // Every 1 minute
public class QueueMonitoring {
    
    @Autowired
    private RabbitAdmin rabbitAdmin;
    
    public void monitorQueues() {
        
        List<String> queues = Arrays.asList(
            "notification-queue",
            "audit-event-queue",
            "compliance-check-queue",
            "discovery-queue"
        );
        
        queues.forEach(queue -> {
            QueueInformation info = rabbitAdmin.getQueueInfo(queue);
            
            if (info != null) {
                long messageCount = info.getMessageCount();
                long consumerCount = info.getConsumerCount();
                
                if (messageCount > 1000) {
                    logger.warn("Queue {} has {} pending messages", 
                        queue, messageCount);
                }
                
                logger.info("Queue {} - Messages: {}, Consumers: {}", 
                    queue, messageCount, consumerCount);
            }
        });
    }
}
```

---

## Resumo de Messaging

| Componente | Foco | Quantidade |
|-----------|------|-----------|
| **Exchanges** | DirectExchange (topic routing) | 4+ |
| **Queues** | Durable queues + DLQ | 8+ (4 + 4 DLQ) |
| **Producers** | Event publishing | 4 (Notification, Audit, Compliance, Discovery) |
| **Listeners** | Event consumption | 4 |
| **Event Types** | Domain events | 8+ |
| **Features** | Retry, DLQ, Tracing | Full |

**Pattern**: Producer → Exchange → Queue → Listener (async processing)  
**Reliability**: Durable queues, DLQ, consumer acknowledgment  
**Observability**: Tracing, MDC, queue monitoring  

