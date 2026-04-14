package com.pqc.hybrid.core.keygen;

import com.pqc.hybrid.core.config.ClassicalAlgorithm;
import com.pqc.hybrid.core.config.CryptographicProviderFactory;
import com.pqc.hybrid.core.config.HybridAlgorithmPair;
import com.pqc.hybrid.core.config.PQCAlgorithm;
import com.pqc.hybrid.core.exception.InvalidKeyException;
import com.pqc.hybrid.core.exception.PQCHybridException;

import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.Objects;
import java.util.logging.Logger;

/**
 * Generates hybrid key pairs combining classical and PQC algorithms.
 * 
 * This class manages the generation of both key pair components:
 * - Classical key pair (RSA or ECDSA)
 * - PQC key pair (ML-DSA, Falcon, or SLH-DSA)
 *
 * Key generation is performed using BouncyCastle's cryptographic provider
 * and follows NIST standards for both classical and PQC algorithms.
 *
 * @author PQC Hybrid Team
 * @version 1.0.0-BETA
 */
public final class HybridKeyGenerator {

    private static final Logger logger = Logger.getLogger(HybridKeyGenerator.class.getName());
    private static final java.security.SecureRandom RANDOM = new java.security.SecureRandom();

    /**
     * Generates a hybrid key pair using the specified algorithm pair.
     *
     * @param algorithmPair the hybrid algorithm pair
     * @return the generated HybridKeyPair
     * @throws PQCHybridException if key generation fails
     */
    public static HybridKeyPair generate(HybridAlgorithmPair algorithmPair) {
        Objects.requireNonNull(algorithmPair, "Algorithm pair cannot be null");
        
        try {
            CryptographicProviderFactory.initialize();
            Provider provider = CryptographicProviderFactory.getProvider();

            // Generate classical key pair
            KeyPair classicalKeyPair = generateClassicalKeyPair(
                    algorithmPair.classicalAlgorithm(), provider);

            // Generate PQC key pair
            KeyPair pqcKeyPair = generatePQCKeyPair(
                    algorithmPair.pqcAlgorithm(), provider);

            HybridKeyPair hybridPair = new HybridKeyPair(
                    classicalKeyPair.getPublic(),
                    classicalKeyPair.getPrivate(),
                    pqcKeyPair.getPublic(),
                    pqcKeyPair.getPrivate(),
                    algorithmPair.classicalAlgorithm().getAlgorithmName(),
                    algorithmPair.pqcAlgorithm().getName()
            );

            logger.info("Generated hybrid key pair: " + hybridPair.getLabel());
            return hybridPair;

        } catch (NoSuchAlgorithmException | java.security.InvalidAlgorithmParameterException e) {
            throw new PQCHybridException("Algorithm not available for key generation", e);
        }
    }

    /**
     * Generates only a classical key pair.
     *
     * @param algorithm the classical algorithm
     * @return the KeyPair
     * @throws PQCHybridException if generation fails
     */
    public static KeyPair generateClassicalKeyPair(ClassicalAlgorithm algorithm) {
        Objects.requireNonNull(algorithm, "Algorithm cannot be null");
        CryptographicProviderFactory.initialize();
        Provider provider = CryptographicProviderFactory.getProvider();
        try {
            return generateClassicalKeyPair(algorithm, provider);
        } catch (NoSuchAlgorithmException | java.security.InvalidAlgorithmParameterException e) {
            throw new PQCHybridException("Classical key generation failed: " + e.getMessage(), e);
        } catch (Exception e) {
            throw new PQCHybridException("Classical key generation failed: " + e.getMessage(), e);
        }
    }

    /**
     * Generates only a PQC key pair.
     *
     * @param algorithm the PQC algorithm
     * @return the KeyPair
     * @throws PQCHybridException if generation fails
     */
    public static KeyPair generatePQCKeyPair(PQCAlgorithm algorithm) {
        Objects.requireNonNull(algorithm, "Algorithm cannot be null");
        CryptographicProviderFactory.initialize();
        Provider provider = CryptographicProviderFactory.getProvider();
        try {
            return generatePQCKeyPair(algorithm, provider);
        } catch (NoSuchAlgorithmException e) {
            throw new PQCHybridException("PQC key generation failed: " + e.getMessage(), e);
        } catch (Exception e) {
            throw new PQCHybridException("PQC key generation failed: " + e.getMessage(), e);
        }
    }

    /**
     * Internal method to generate a classical key pair using a specific provider.
     */
    private static KeyPair generateClassicalKeyPair(ClassicalAlgorithm algorithm, Provider provider) 
            throws NoSuchAlgorithmException, java.security.InvalidAlgorithmParameterException {
        
        String keyAlgorithm = algorithm.getAlgorithmName();
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(keyAlgorithm, provider);

        // Initialize with appropriate key size
        if ("RSA".equals(keyAlgorithm)) {
            kpg.initialize(algorithm.getKeySize(), RANDOM);
        } else if ("ECDSA".equals(keyAlgorithm)) {
            // For ECDSA, initialize with curve name
            String curveName = mapECDSACurveName(algorithm);
            kpg.initialize(mapECDSASpec(curveName), RANDOM);
        } else {
            kpg.initialize(algorithm.getKeySize(), RANDOM);
        }

        return kpg.generateKeyPair();
    }

    /**
     * Internal method to generate a PQC key pair using a specific provider.
     */
    private static KeyPair generatePQCKeyPair(PQCAlgorithm algorithm, Provider provider) 
            throws NoSuchAlgorithmException {
        
        String algorithmName = algorithm.getName();
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(algorithmName, provider);
        // PQC algorithms use defaults or spec-based initialization
        // We don't call initialize() - let BouncyCastle use defaults
        
        return kpg.generateKeyPair();
    }

    /**
     * Maps ECDSA algorithms to their curve names.
     */
    private static String mapECDSACurveName(ClassicalAlgorithm algorithm) {
        return switch (algorithm.getKeySize()) {
            case 256 -> "secp256r1";   // P-256
            case 384 -> "secp384r1";   // P-384
            case 521 -> "secp521r1";   // P-521
            default -> throw new IllegalArgumentException("Unsupported ECDSA key size: " + algorithm.getKeySize());
        };
    }

    /**
     * Maps ECDSA curve names to AlgorithmParameterSpec.
     * Simplified version - in production would use proper spec objects.
     */
    private static java.security.spec.AlgorithmParameterSpec mapECDSASpec(String curveName) 
            throws NoSuchAlgorithmException {
        try {
            java.security.spec.ECGenParameterSpec spec = new java.security.spec.ECGenParameterSpec(curveName);
            return spec;
        } catch (Exception e) {
            throw new NoSuchAlgorithmException("Cannot initialize ECDSA with curve: " + curveName, e);
        }
    }

    /**
     * Validates a hybrid key pair for completeness.
     *
     * @param keyPair the key pair to validate
     * @throws InvalidKeyException if validation fails
     */
    public static void validate(HybridKeyPair keyPair) throws InvalidKeyException {
        Objects.requireNonNull(keyPair, "Key pair cannot be null");

        if (keyPair.getClassicalPublicKey() == null) {
            throw new InvalidKeyException("Classical public key is null");
        }
        if (keyPair.getClassicalPrivateKey() == null) {
            throw new InvalidKeyException("Classical private key is null");
        }
        if (keyPair.getPQCPublicKey() == null) {
            throw new InvalidKeyException("PQC public key is null");
        }
        if (keyPair.getPQCPrivateKey() == null) {
            throw new InvalidKeyException("PQC private key is null");
        }

        logger.fine("Hybrid key pair validation passed: " + keyPair.getLabel());
    }

    // Helper class for secure random
    static final class SecureRandom {
        private static final java.security.SecureRandom instance = new java.security.SecureRandom();

        public static java.security.SecureRandom getInstance() {
            return instance;
        }
    }
}
