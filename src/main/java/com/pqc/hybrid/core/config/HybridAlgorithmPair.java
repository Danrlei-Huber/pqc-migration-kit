package com.pqc.hybrid.core.config;

import java.util.Objects;

/**
 * Represents a hybrid cryptographic algorithm pair combining a classical algorithm
 * with a PQC algorithm for dual-signature functionality in hybrid certificates.
 *
 * This record immutably combines one classical algorithm with one PQC signature algorithm,
 * ensuring both are compatible and suitable for hybrid certificate generation.
 *
 * @param classicalAlgorithm the classical algorithm (RSA or ECDSA)
 * @param pqcAlgorithm the PQC algorithm (ML-DSA, Falcon, or SLH-DSA)
 *
 * @author PQC Hybrid Team
 * @version 1.0.0-BETA
 */
public record HybridAlgorithmPair(ClassicalAlgorithm classicalAlgorithm, PQCAlgorithm pqcAlgorithm) {

    /**
     * Creates a new HybridAlgorithmPair with validation.
     *
     * @param classicalAlgorithm the classical algorithm
     * @param pqcAlgorithm the PQC algorithm
     */
    public HybridAlgorithmPair {
        Objects.requireNonNull(classicalAlgorithm, "Classical algorithm cannot be null");
        Objects.requireNonNull(pqcAlgorithm, "PQC algorithm cannot be null");
        
        // Ensure PQC algorithm is a signature algorithm (not KEM-only)
        if (pqcAlgorithm.getCategory() != PQCAlgorithm.AlgorithmCategory.SIGNATURE) {
            throw new IllegalArgumentException("PQC algorithm must be a signature algorithm: " + pqcAlgorithm.getName());
        }
    }

    /**
     * Gets the classical algorithm component.
     *
     * @return the classical algorithm
     */
    @Override
    public ClassicalAlgorithm classicalAlgorithm() {
        return classicalAlgorithm;
    }

    /**
     * Gets the PQC algorithm component.
     *
     * @return the PQC algorithm
     */
    @Override
    public PQCAlgorithm pqcAlgorithm() {
        return pqcAlgorithm;
    }

    /**
     * Gets a descriptive name for this hybrid pair.
     * Example: "RSA-2048 + ML-DSA-65"
     *
     * @return the descriptive name
     */
    public String getDescription() {
        return String.format("%s-%d + %s",
                classicalAlgorithm.getAlgorithmName(),
                classicalAlgorithm.getKeySize(),
                pqcAlgorithm.getName());
    }

    /**
     * Indicates whether the security level of both algorithms is balanced.
     * For good security practices, both should provide similar security levels.
     *
     * @return true if security levels are approximately equal
     */
    public boolean isSecurityBalanced() {
        int diff = Math.abs(classicalAlgorithm.getSecurityLevel() - pqcAlgorithm.getSecurityLevel());
        return diff <= 64;  // Allow 64-bit difference
    }

    /**
     * Indicates whether both algorithms are NIST-standardized.
     *
     * @return true if both algorithms are NIST-standardized
     */
    public boolean areNistStandardized() {
        // All enums in this library are NIST-standardized
        return true;
    }

    /**
     * Gets a recommended hybrid pair for a given security level.
     *
     * @param securityLevel the desired security level in bits (128, 192, or 256)
     * @return a recommended HybridAlgorithmPair
     * @throws IllegalArgumentException if the security level is not supported
     */
    public static HybridAlgorithmPair recommended(int securityLevel) {
        return switch (securityLevel) {
            case 128 -> new HybridAlgorithmPair(ClassicalAlgorithm.ECDSA_P256, PQCAlgorithm.ML_DSA_44);
            case 192 -> new HybridAlgorithmPair(ClassicalAlgorithm.ECDSA_P384, PQCAlgorithm.ML_DSA_65);
            case 256 -> new HybridAlgorithmPair(ClassicalAlgorithm.ECDSA_P521, PQCAlgorithm.ML_DSA_87);
            default -> throw new IllegalArgumentException("Unsupported security level: " + securityLevel);
        };
    }

    /**
     * All recommended hybrid algorithm pairs.
     *
     * @return array of recommended pairs
     */
    public static HybridAlgorithmPair[] allRecommended() {
        return new HybridAlgorithmPair[]{
                new HybridAlgorithmPair(ClassicalAlgorithm.ECDSA_P256, PQCAlgorithm.ML_DSA_44),
                new HybridAlgorithmPair(ClassicalAlgorithm.ECDSA_P256, PQCAlgorithm.ML_KEM_512),
                new HybridAlgorithmPair(ClassicalAlgorithm.ECDSA_P384, PQCAlgorithm.ML_DSA_65),
                new HybridAlgorithmPair(ClassicalAlgorithm.ECDSA_P521, PQCAlgorithm.ML_DSA_87),
                new HybridAlgorithmPair(ClassicalAlgorithm.RSA_2048, PQCAlgorithm.ML_DSA_44),
                new HybridAlgorithmPair(ClassicalAlgorithm.RSA_3072, PQCAlgorithm.ML_DSA_65),
                new HybridAlgorithmPair(ClassicalAlgorithm.RSA_4096, PQCAlgorithm.ML_DSA_87)
        };
    }

    @Override
    public String toString() {
        return getDescription();
    }
}
