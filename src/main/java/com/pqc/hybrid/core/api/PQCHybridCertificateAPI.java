package com.pqc.hybrid.core.api;

import com.pqc.hybrid.core.config.CryptographicProviderFactory;
import com.pqc.hybrid.core.config.HybridAlgorithmPair;
import com.pqc.hybrid.core.config.HybridCertificateConfig;
import com.pqc.hybrid.core.keygen.HybridKeyGenerator;
import com.pqc.hybrid.core.keygen.HybridKeyPair;
import com.pqc.hybrid.core.signature.HybridSignatureManager;
import com.pqc.hybrid.core.signature.HybridSignaturePair;
import com.pqc.hybrid.core.signature.DualSignatureValidator;
import com.pqc.hybrid.core.certificate.HybridX509CertificateBuilder;
import com.pqc.hybrid.core.certificate.HybridCertificateValidator;
import com.pqc.hybrid.core.certificate.CertificateSigningRequestBuilder;
import com.pqc.hybrid.core.exception.PQCHybridException;
import com.pqc.hybrid.core.exception.CertificateException;
import com.pqc.hybrid.core.exception.InvalidSignatureException;

import javax.security.auth.x500.X500Principal;
import java.security.cert.X509Certificate;
import java.util.Objects;
import java.util.logging.Logger;

/**
 * Main public API for the PQC Hybrid Certificates Library.
 * 
 * This is the primary entry point for all hybrid cryptographic operations.
 * Provides high-level methods for:
 * - Generating hybrid key pairs
 * - Creating and verifying hybrid signatures
 * - Building hybrid X.509 certificates
 * - Creating Certificate Signing Requests (CSRs)
 *
 * All operations use BouncyCastle 1.77+ with NIST-standardized PQC algorithms.
 *
 * Example Usage:
 * ```java
 * // Initialize the library
 * PQCHybridCertificateAPI api = new PQCHybridCertificateAPI();
 * api.initialize();
 *
 * // Generate a hybrid key pair
 * HybridKeyPair keyPair = api.generateHybridKeyPair(128);  // 128-bit security
 *
 * // Sign data with both classical and PQC algorithms
 * byte[] data = "Important message".getBytes();
 * HybridSignaturePair signature = api.signData(data, keyPair);
 *
 * // Verify the hybrid signature
 * boolean isValid = api.verifySignature(data, signature, keyPair);
 *
 * // Create a hybrid certificate
 * HybridCertificateConfig config = HybridCertificateConfig.builder()
 *     .withAlgorithmPair(HybridAlgorithmPair.recommended(128))
 *     .withSubjectDN("CN=example.com,O=Example,C=US")
 *     .withIssuerDN("CN=Example CA,O=Example,C=US")
 *     .build();
 * X509Certificate cert = api.generateHybridCertificate(config, keyPair);
 * ```
 *
 * @author PQC Hybrid Team
 * @version 1.0.0-BETA
 */
public final class PQCHybridCertificateAPI {

    private static final Logger logger = Logger.getLogger(PQCHybridCertificateAPI.class.getName());
    private static final String VERSION = "1.0.0-BETA";
    private boolean initialized = false;

    /**
     * Creates a new PQCHybridCertificateAPI instance.
     * Call initialize() before using the API.
     */
    public PQCHybridCertificateAPI() {
    }

    /**
     * Initializes the PQC Hybrid Certificates API.
     * Must be called once before any cryptographic operations.
     *
     * @throws PQCHybridException if initialization fails
     */
    public void initialize() throws PQCHybridException {
        if (initialized) {
            logger.fine("API already initialized");
            return;
        }

        try {
            CryptographicProviderFactory.initialize();
            CryptographicProviderFactory.validateRequiredAlgorithms();
            initialized = true;
            logger.info("PQCHybridCertificateAPI initialized successfully (v" + VERSION + ")");
        } catch (Exception e) {
            throw new PQCHybridException("Failed to initialize PQC Hybrid Certificates API", e);
        }
    }

    /**
     * Checks if the API is initialized.
     */
    public boolean isInitialized() {
        return initialized;
    }

    /**
     * Gets the API version.
     */
    public String getVersion() {
        return VERSION;
    }

    /**
     * Generates a hybrid key pair with recommended algorithms for a security level.
     *
     * @param securityLevelBits the desired security level (128, 192, or 256 bits)
     * @return the generated HybridKeyPair
     * @throws PQCHybridException if generation fails
     */
    public HybridKeyPair generateHybridKeyPair(int securityLevelBits) throws PQCHybridException {
        ensureInitialized();
        HybridAlgorithmPair recommendedPair = HybridAlgorithmPair.recommended(securityLevelBits);
        return HybridKeyGenerator.generate(recommendedPair);
    }

    /**
     * Generates a hybrid key pair with a specific algorithm pair.
     *
     * @param algorithmPair the hybrid algorithm pair to use
     * @return the generated HybridKeyPair
     * @throws PQCHybridException if generation fails
     */
    public HybridKeyPair generateHybridKeyPair(HybridAlgorithmPair algorithmPair) 
            throws PQCHybridException {
        ensureInitialized();
        Objects.requireNonNull(algorithmPair, "Algorithm pair cannot be null");
        return HybridKeyGenerator.generate(algorithmPair);
    }

    /**
     * Signs data with both classical and PQC algorithms.
     *
     * @param data the data to sign
     * @param keyPair the hybrid key pair
     * @return the hybrid signature pair
     * @throws PQCHybridException if signing fails
     */
    public HybridSignaturePair signData(byte[] data, HybridKeyPair keyPair) 
            throws PQCHybridException {
        ensureInitialized();
        Objects.requireNonNull(data, "Data cannot be null");
        Objects.requireNonNull(keyPair, "Key pair cannot be null");
        return HybridSignatureManager.sign(data, keyPair);
    }

    /**
     * Verifies a hybrid signature. Both classical and PQC signatures must be valid.
     *
     * @param data the original data
     * @param signature the hybrid signature to verify
     * @param keyPair the hybrid key pair (public keys used for verification)
     * @return true if both signatures are valid, false otherwise
     * @throws InvalidSignatureException if verification fails unexpectedly
     */
    public boolean verifySignature(byte[] data, HybridSignaturePair signature, HybridKeyPair keyPair) 
            throws InvalidSignatureException {
        ensureInitialized();
        Objects.requireNonNull(data, "Data cannot be null");
        Objects.requireNonNull(signature, "Signature cannot be null");
        Objects.requireNonNull(keyPair, "Key pair cannot be null");
        return HybridSignatureManager.verify(data, signature, keyPair);
    }

    /**
     * Validates a hybrid signature for structural integrity.
     *
     * @param signature the signature to validate
     * @return validation result with detailed information
     */
    public DualSignatureValidator.ValidationResult validateSignatureStructure(HybridSignaturePair signature) {
        ensureInitialized();
        Objects.requireNonNull(signature, "Signature cannot be null");
        return DualSignatureValidator.validateComprehensive(signature);
    }

    /**
     * Generates a hybrid X.509 certificate.
     *
     * @param config the certificate configuration
     * @param keyPair the hybrid key pair
     * @return the generated X509Certificate
     * @throws CertificateException if certificate generation fails
     */
    public X509Certificate generateHybridCertificate(HybridCertificateConfig config, HybridKeyPair keyPair) 
            throws CertificateException {
        ensureInitialized();
        Objects.requireNonNull(config, "Config cannot be null");
        Objects.requireNonNull(keyPair, "Key pair cannot be null");

        HybridX509CertificateBuilder builder = new HybridX509CertificateBuilder(config, keyPair);
        return builder.build();
    }

    /**
     * Validates an X.509 certificate.
     *
     * @param certificate the certificate to validate
     * @param issuerPublicKey the issuer's public key (null for self-signed)
     * @return validation result with detailed information
     */
    public HybridCertificateValidator.ValidationResult validateCertificate(X509Certificate certificate, 
                                                                           java.security.PublicKey issuerPublicKey) {
        ensureInitialized();
        Objects.requireNonNull(certificate, "Certificate cannot be null");
        return HybridCertificateValidator.validateComprehensive(certificate, issuerPublicKey);
    }

    /**
     * Creates a hybrid PKCS#10 Certificate Signing Request.
     *
     * @param subjectDN the subject Distinguished Name
     * @param keyPair the hybrid key pair
     * @return the PKCS10CertificationRequest
     * @throws CertificateException if CSR generation fails
     */
    public org.bouncycastle.pkcs.PKCS10CertificationRequest generateCertificateSigningRequest(
            String subjectDN, HybridKeyPair keyPair) throws CertificateException {
        ensureInitialized();
        Objects.requireNonNull(subjectDN, "Subject DN cannot be null");
        Objects.requireNonNull(keyPair, "Key pair cannot be null");

        CertificateSigningRequestBuilder builder = 
                new CertificateSigningRequestBuilder(subjectDN, keyPair);
        return builder.build();
    }

    /**
     * Performs a complete end-to-end hybrid certificate workflow.
     *
     * Operations:
     * 1. Generate hybrid key pair
     * 2. Create and sign certificate
     * 3. Validate certificate
     *
     * @param securityLevel the security level (128, 192, or 256)
     * @param subjectDN the subject Distinguished Name
     * @param issuerDN the issuer Distinguished Name
     * @param validityDays the certificate validity period
     * @return the complete certificate (ready to use)
     * @throws Exception if any step fails
     */
    public X509Certificate generateCompleteHybridCertificate(int securityLevel, 
                                                              String subjectDN,
                                                              String issuerDN,
                                                              long validityDays) throws Exception {
        ensureInitialized();

        logger.info("Starting complete hybrid certificate generation workflow");

        // Step 1: Generate key pair
        HybridKeyPair keyPair = generateHybridKeyPair(securityLevel);
        logger.info("Generated hybrid key pair: " + keyPair.getLabel());

        // Step 2: Create certificate config
        HybridCertificateConfig config = HybridCertificateConfig.builder()
                .withAlgorithmPair(HybridAlgorithmPair.recommended(securityLevel))
                .withSubjectDN(subjectDN)
                .withIssuerDN(issuerDN)
                .withValidityDays(validityDays)
                .build();
        logger.info("Created certificate configuration");

        // Step 3: Generate certificate
        X509Certificate certificate = generateHybridCertificate(config, keyPair);
        logger.info("Generated hybrid certificate for: " + subjectDN);

        // Step 4: Validate certificate
        HybridCertificateValidator.ValidationResult result = 
                validateCertificate(certificate, null);  // Self-signed, so no issuer key
        logger.info("Certificate validation: " + result);

        return certificate;
    }

    /**
     * Ensures the API is initialized before operations.
     */
    private void ensureInitialized() {
        if (!initialized) {
            throw new IllegalStateException("API not initialized. Call initialize() first.");
        }
    }

    /**
     * Gets the library version information.
     */
    public static String getLibraryInfo() {
        return String.format("PQC Hybrid Certificates Library v%s (BouncyCastle 1.77+, Java 21+)", VERSION);
    }

    @Override
    public String toString() {
        return String.format("PQCHybridCertificateAPI{version=%s, initialized=%b}", VERSION, initialized);
    }
}
