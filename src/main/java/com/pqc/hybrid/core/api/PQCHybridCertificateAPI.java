package com.pqc.hybrid.core.api;

import com.pqc.hybrid.core.config.CryptographicProviderFactory;
import com.pqc.hybrid.core.config.HybridAlgorithmPair;
import com.pqc.hybrid.core.config.HybridCertificateConfig;
import com.pqc.hybrid.core.keygen.HybridKeyGenerator;
import com.pqc.hybrid.core.keygen.HybridKeyPair;
import com.pqc.hybrid.core.signature.HybridSignatureManager;
import com.pqc.hybrid.core.signature.HybridSignaturePair;
import com.pqc.hybrid.core.signature.DualSignatureStrategy;
import com.pqc.hybrid.core.signature.DualSignatureValidator;
import com.pqc.hybrid.core.certificate.HybridX509CertificateBuilder;
import com.pqc.hybrid.core.certificate.HybridCertificateValidator;
import com.pqc.hybrid.core.certificate.CertificateSigningRequestBuilder;
import com.pqc.hybrid.core.certificate.HybridCertificateAuthority;
import com.pqc.hybrid.core.certificate.HybridSigner;
import com.pqc.hybrid.core.model.HybridCertificateInfo;
import com.pqc.hybrid.core.exception.PQCHybridException;
import com.pqc.hybrid.core.exception.CertificateException;
import com.pqc.hybrid.core.exception.InvalidSignatureException;

import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import javax.security.auth.x500.X500Principal;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.List;
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
 * All operations use BouncyCastle 1.84 with NIST-standardized PQC algorithms.
 *
 * <p>Example usage:
 * <pre>{@code
 * // Initialize the library
 * PQCHybridCertificateAPI api = new PQCHybridCertificateAPI();
 * api.initialize();
 *
 * // Generate a hybrid key pair
 * HybridKeyPair keyPair = api.generateHybridKeyPair(128);  // 128-bit security
 *
 * // Sign data with both classical and PQC algorithms
 * byte[] data = "Important message".getBytes();
 * byte[] signature = api.signData(data, keyPair);
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
 * }</pre>
 *
 * @author PQC Hybrid Team
 * @version 1.0.0-BETA
 */
public final class PQCHybridCertificateAPI {

    private static final Logger logger = Logger.getLogger(PQCHybridCertificateAPI.class.getName());
    private static final String VERSION = "1.0.0-BETA";
    private boolean initialized = false;
    private HybridSignatureStrategy strategy;

    /**
     * Creates a new PQCHybridCertificateAPI instance with the Dual signature strategy.
     * Call initialize() before using the API.
     */
    public PQCHybridCertificateAPI() {
        this.strategy = new DualSignatureStrategy();
    }

    /**
     * Creates a new PQCHybridCertificateAPI instance with a specific signature strategy.
     * Call initialize() before using the API.
     *
     * @param strategy the hybrid signature strategy to use
     */
    public PQCHybridCertificateAPI(HybridSignatureStrategy strategy) {
        this.strategy = Objects.requireNonNull(strategy, "Strategy cannot be null");
    }

    /**
     * Sets the hybrid signature strategy to use for signing, verification,
     * key generation, and certificate operations.
     *
     * @param strategy the hybrid signature strategy
     */
    public void setSignatureStrategy(HybridSignatureStrategy strategy) {
        this.strategy = Objects.requireNonNull(strategy, "Strategy cannot be null");
    }

    /**
     * Gets the current hybrid signature strategy.
     *
     * @return the current strategy
     */
    public HybridSignatureStrategy getSignatureStrategy() {
        return strategy;
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
     * Generates a hybrid key pair using the configured signature strategy.
     *
     * @param securityLevelBits the desired security level (128, 192, or 256)
     * @return the generated HybridKeyPair
     * @throws PQCHybridException if generation fails
     */
    public HybridKeyPair generateHybridKeyPairWithStrategy(int securityLevelBits) throws PQCHybridException {
        ensureInitialized();
        return strategy.generateKeyPair(securityLevelBits);
    }

    /**
     * Signs data using the configured signature strategy.
     *
     * @param data the data to sign
     * @param keyPair the hybrid key pair
     * @return the signature bytes
     * @throws PQCHybridException if signing fails
     */
    public byte[] signData(byte[] data, HybridKeyPair keyPair) 
            throws PQCHybridException {
        ensureInitialized();
        Objects.requireNonNull(data, "Data cannot be null");
        Objects.requireNonNull(keyPair, "Key pair cannot be null");
        return strategy.signData(data, keyPair);
    }

    /**
     * Signs data with a context parameter using the configured signature strategy.
     *
     * @param data the data to sign
     * @param keyPair the hybrid key pair
     * @param ctx the context (max 255 bytes, empty by default)
     * @return the signature bytes
     * @throws PQCHybridException if signing fails
     */
    public byte[] signData(byte[] data, HybridKeyPair keyPair, byte[] ctx) 
            throws PQCHybridException {
        ensureInitialized();
        Objects.requireNonNull(data, "Data cannot be null");
        Objects.requireNonNull(keyPair, "Key pair cannot be null");
        return strategy.signData(data, keyPair, ctx);
    }

    /**
     * Verifies a hybrid signature using the configured strategy.
     *
     * @param data the original data
     * @param signature the signature bytes to verify
     * @param keyPair the hybrid key pair (public keys used for verification)
     * @return true if the signature is valid
     * @throws InvalidSignatureException if verification fails unexpectedly
     */
    public boolean verifySignature(byte[] data, byte[] signature, HybridKeyPair keyPair) 
            throws InvalidSignatureException {
        ensureInitialized();
        Objects.requireNonNull(data, "Data cannot be null");
        Objects.requireNonNull(signature, "Signature cannot be null");
        Objects.requireNonNull(keyPair, "Key pair cannot be null");
        return strategy.verifySignature(data, signature, keyPair);
    }

    /**
     * Verifies a hybrid signature with a context parameter using the configured strategy.
     *
     * @param data the original data
     * @param signature the signature bytes to verify
     * @param keyPair the hybrid key pair (public keys used for verification)
     * @param ctx the context (must match the context used during signing)
     * @return true if the signature is valid
     * @throws InvalidSignatureException if verification fails unexpectedly
     */
    public boolean verifySignature(byte[] data, byte[] signature, HybridKeyPair keyPair, byte[] ctx) 
            throws InvalidSignatureException {
        ensureInitialized();
        Objects.requireNonNull(data, "Data cannot be null");
        Objects.requireNonNull(signature, "Signature cannot be null");
        Objects.requireNonNull(keyPair, "Key pair cannot be null");
        return strategy.verifySignature(data, signature, keyPair, ctx);
    }

    /**
     * Verifies a hybrid signature against the original data.
     * Both classical and PQC signatures must be valid.
     *
     * @deprecated Use {@link #verifySignature(byte[], byte[], HybridKeyPair)} instead.
     *             This method is kept for backward compatibility.
     */
    @Deprecated
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
     * Generates a hybrid X.509 certificate using the configured signature strategy.
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
        return strategy.buildCertificate(config, keyPair);
    }

    public X509Certificate generateHybridCertificateWithPQCExtensions(HybridCertificateConfig config,
                                                                      HybridKeyPair keyPair,
                                                                      boolean includePQCExtensions)
            throws CertificateException {
        ensureInitialized();
        Objects.requireNonNull(config, "Config cannot be null");
        Objects.requireNonNull(keyPair, "Key pair cannot be null");

        HybridX509CertificateBuilder builder = new HybridX509CertificateBuilder(config, keyPair)
                .withPQCExtensions(includePQCExtensions);
        return builder.build();
    }

    /**
     * Layer 1 (signer-agnostic) certificate generation: builds a hybrid X.509 certificate from the
     * subject's public keys and an externally-supplied {@link HybridSigner}. The signers may be
     * HSM/token-backed (e.g. CZERTAINLY {@code TokenContentSigner}), KMS-backed, or in-memory — no
     * private key needs to live in this JVM.
     *
     * @param config                    the certificate configuration (DNs, validity, serial, flags)
     * @param subjectClassicalPublicKey the subject's classical public key
     * @param subjectPqcPublicKey       the subject's PQC public key (may be {@code null} only for a
     *                                  classical-only {@code issuerSigner})
     * @param issuerSigner              the issuer's signer(s); classical-only when its PQC signer is null
     * @param issuerCertificate         the issuer's certificate (issuer DN + AKI); {@code null} => self-signed
     * @return the generated X509Certificate
     * @throws CertificateException if certificate generation fails
     */
    public X509Certificate generateHybridCertificate(HybridCertificateConfig config,
                                                     PublicKey subjectClassicalPublicKey,
                                                     PublicKey subjectPqcPublicKey,
                                                     HybridSigner issuerSigner,
                                                     X509Certificate issuerCertificate)
            throws CertificateException {
        ensureInitialized();
        Objects.requireNonNull(config, "Config cannot be null");
        Objects.requireNonNull(subjectClassicalPublicKey, "Subject classical public key cannot be null");
        Objects.requireNonNull(issuerSigner, "Issuer signer cannot be null");
        return HybridX509CertificateBuilder.build(config, subjectClassicalPublicKey, subjectPqcPublicKey,
                issuerSigner, issuerCertificate);
    }

    public HybridCertificateInfo getCertificateInfo(X509Certificate certificate, HybridKeyPair keyPair) {
        ensureInitialized();
        Objects.requireNonNull(certificate, "Certificate cannot be null");
        return HybridCertificateValidator.extractCertificateInfo(certificate, keyPair);
    }

    public boolean validatePQCExtensions(X509Certificate certificate) {
        ensureInitialized();
        Objects.requireNonNull(certificate, "Certificate cannot be null");
        return HybridCertificateValidator.validatePQCExtensions(certificate);
    }

    public boolean validatePQCSignature(X509Certificate certificate, HybridKeyPair keyPair)
            throws InvalidSignatureException {
        ensureInitialized();
        Objects.requireNonNull(certificate, "Certificate cannot be null");
        Objects.requireNonNull(keyPair, "Key pair cannot be null");
        return HybridCertificateValidator.validatePQCSignature(certificate, keyPair);
    }

    /**
     * Validates an X.509 certificate.
     *
     * @param certificate the certificate to validate
     * @param issuerPublicKey the issuer's public key (null for self-signed)
     * @return validation result with detailed information
     */
    public HybridCertificateValidator.ValidationResult validateCertificate(X509Certificate certificate,
                                                                           PublicKey issuerPublicKey) {
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
    public PKCS10CertificationRequest generateCertificateSigningRequest(
            String subjectDN, HybridKeyPair keyPair) throws CertificateException {
        ensureInitialized();
        Objects.requireNonNull(subjectDN, "Subject DN cannot be null");
        Objects.requireNonNull(keyPair, "Key pair cannot be null");

        CertificateSigningRequestBuilder builder =
                new CertificateSigningRequestBuilder(subjectDN, keyPair);
        return builder.build();
    }

    /**
     * Layer 1 (signer-agnostic) CSR generation: builds a hybrid PKCS#10 CSR from the subject's
     * public keys and an externally-supplied {@link HybridSigner}. The signers may be HSM/token/KMS
     * backed or in-memory. A classical-only CSR is produced when {@code signer.pqc()} is {@code null}.
     *
     * @param subjectDN                 the subject Distinguished Name
     * @param subjectClassicalPublicKey the subject's classical public key
     * @param subjectPqcPublicKey       the subject's PQC public key (may be {@code null} only for a
     *                                  classical-only signer)
     * @param signer                    the subject's signer(s)
     * @return the PKCS10CertificationRequest
     * @throws CertificateException if CSR generation fails
     */
    public PKCS10CertificationRequest generateCertificateSigningRequest(
            String subjectDN,
            PublicKey subjectClassicalPublicKey,
            PublicKey subjectPqcPublicKey,
            HybridSigner signer) throws CertificateException {
        ensureInitialized();
        Objects.requireNonNull(subjectDN, "Subject DN cannot be null");
        Objects.requireNonNull(subjectClassicalPublicKey, "Subject classical public key cannot be null");
        Objects.requireNonNull(signer, "Signer cannot be null");
        return CertificateSigningRequestBuilder.build(subjectDN, subjectClassicalPublicKey,
                subjectPqcPublicKey, signer);
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
     * @throws PQCHybridException if key generation or signing fails
     * @throws CertificateException if certificate construction or validation fails
     */
    public X509Certificate generateCompleteHybridCertificate(int securityLevel,
                                                               String subjectDN,
                                                               String issuerDN,
                                                               long validityDays)
            throws PQCHybridException, CertificateException {
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
     * Creates a self-signed hybrid root Certificate Authority.
     *
     * @param config    the root CA certificate configuration (should be marked as a CA via
     *                  {@code asCertificateAuthority(true)})
     * @param caKeyPair the root CA's hybrid key pair
     * @return a ready-to-use {@link HybridCertificateAuthority}
     * @throws CertificateException if the root certificate cannot be built
     */
    public HybridCertificateAuthority createRootCA(HybridCertificateConfig config, HybridKeyPair caKeyPair)
            throws CertificateException {
        ensureInitialized();
        Objects.requireNonNull(config, "Config cannot be null");
        Objects.requireNonNull(caKeyPair, "CA key pair cannot be null");
        return HybridCertificateAuthority.createRoot(config, caKeyPair);
    }

    /**
     * Issues a hybrid certificate (sub-CA or end-entity) signed by the given CA.
     *
     * @param ca             the issuing Certificate Authority
     * @param subjectConfig  the subject certificate configuration
     * @param subjectKeyPair the subject's hybrid key pair (only public keys are used)
     * @return the issued X.509 certificate
     * @throws CertificateException if the certificate cannot be built
     */
    public X509Certificate issueCertificate(HybridCertificateAuthority ca,
                                            HybridCertificateConfig subjectConfig,
                                            HybridKeyPair subjectKeyPair) throws CertificateException {
        ensureInitialized();
        Objects.requireNonNull(ca, "CA cannot be null");
        Objects.requireNonNull(subjectConfig, "Subject config cannot be null");
        Objects.requireNonNull(subjectKeyPair, "Subject key pair cannot be null");
        return ca.issueCertificate(subjectConfig, subjectKeyPair);
    }

    /**
     * Validates a full hybrid certificate chain (ordered leaf → … → root) in both the
     * classical (PKIX) and post-quantum dimensions.
     *
     * @param chain the ordered certificate chain (leaf first, self-signed root last)
     * @return the chain validation result
     */
    public HybridCertificateValidator.HybridChainValidationResult validateCertificateChain(
            List<X509Certificate> chain) {
        ensureInitialized();
        Objects.requireNonNull(chain, "Chain cannot be null");
        return HybridCertificateValidator.validateHybridChain(chain);
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
        return String.format("PQC Hybrid Certificates Library v%s (BouncyCastle 1.84, Java 21+)", VERSION);
    }

    @Override
    public String toString() {
        return String.format("PQCHybridCertificateAPI{version=%s, initialized=%b}", VERSION, initialized);
    }
}
