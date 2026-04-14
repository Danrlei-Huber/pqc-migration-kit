package com.pqc.hybrid.core.hybrid;

import java.util.Arrays;

/**
 * Represents a paired signature from both classical and PQC algorithms.
 * 
 * A hybrid signature consists of two independent signatures:
 * 1. Classical signature (e.g., RSA-2048-SHA256): provides established security guarantees
 * 2. PQC signature (e.g., ML-DSA-65): provides quantum-resistance
 * 
 * Both signatures are over the same message and can be verified independently.
 * A valid hybrid signature requires both parts to be valid.
 * 
 * Design Notes:
 * - Immutable record type (Java 21+)
 * - Contains no key material, only signature data
 * - Sizes depend on algorithms used:
 *   - RSA-2048 signature: 256 bytes
 *   - ML-DSA-65 signature: 3293 bytes
 *   - Total for RSA+ML-DSA-65: ~3549 bytes
 * 
 * Example:
 * <pre>
 *     HybridSignaturePair sigs = new HybridSignaturePair(
 *        classicalSig,       // RSA signature bytes
 *        pqcSig,             // ML-DSA signature bytes
 *        HybridSignatureScheme.RSA_2048_ML_DSA_65
 *     );
 * </pre>
 * 
 * @author PQC Hybrid Team
 * @version 1.0.0
 * @since 2026-04-14
 */
public record HybridSignaturePair(
        /** The classical signature (e.g., RSA-SHA256) */
        byte[] classicalSignature,
        
        /** The PQC signature (e.g., ML-DSA) */
        byte[] pqcSignature,
        
        /** The hybrid scheme used */
        HybridSignatureScheme scheme
) {

    /**
     * Constructs a hybrid signature pair with validation.
     * 
     * Constructor ensures both signatures are present and non-empty.
     * 
     * @param classicalSignature the classical signature (must not be null or empty)
     * @param pqcSignature the PQC signature (must not be null or empty)
     * @param scheme the hybrid scheme used (must not be null)
     * @throws IllegalArgumentException if any parameter is invalid
     */
    public HybridSignaturePair {
        if (classicalSignature == null) {
            throw new IllegalArgumentException("Classical signature cannot be null");
        }
        if (pqcSignature == null) {
            throw new IllegalArgumentException("PQC signature cannot be null");
        }
        if (scheme == null) {
            throw new IllegalArgumentException("Hybrid signature scheme cannot be null");
        }
        if (classicalSignature.length == 0) {
            throw new IllegalArgumentException("Classical signature cannot be empty");
        }
        if (pqcSignature.length == 0) {
            throw new IllegalArgumentException("PQC signature cannot be empty");
        }
    }

    /**
     * Gets the size of the classical signature in bytes.
     * 
     * @return classical signature size
     */
    public int classicalSignatureSize() {
        return classicalSignature.length;
    }

    /**
     * Gets the size of the PQC signature in bytes.
     * 
     * @return PQC signature size
     */
    public int pqcSignatureSize() {
        return pqcSignature.length;
    }

    /**
     * Gets the total size of both signatures.
     * 
     * @return combined size (classical + PQC + overhead)
     */
    public int totalSignatureSize() {
        return classicalSignature.length + pqcSignature.length;
    }

    /**
     * Creates a copy with classical signature cleared (zeroed).
     * 
     * Useful for cleanup when classical signature is no longer needed.
     * 
     * @return a new HybridSignaturePair with zeroed classical signature
     */
    public HybridSignaturePair withClearedClassicalSignature() {
        byte[] cleared = new byte[classicalSignature.length];
        return new HybridSignaturePair(cleared, pqcSignature.clone(), scheme);
    }

    /**
     * Creates a copy with PQC signature cleared (zeroed).
     * 
     * Useful for cleanup when PQC signature is no longer needed.
     * 
     * @return a new HybridSignaturePair with zeroed PQC signature
     */
    public HybridSignaturePair withClearedPQCSignature() {
        byte[] cleared = new byte[pqcSignature.length];
        return new HybridSignaturePair(classicalSignature.clone(), cleared, scheme);
    }

    /**
     * Securely clears both signatures from memory.
     * 
     * Note: Since records are immutable, this only zeros the arrays themselves.
     * The record object should be discarded after calling this method.
     */
    public void clearAll() {
        Arrays.fill(classicalSignature, (byte) 0);
        Arrays.fill(pqcSignature, (byte) 0);
    }

    /**
     * Returns a string representation of this hybrid signature pair.
     * 
     * Does NOT include actual signature data for security.
     * 
     * @return a description of this signature pair
     */
    @Override
    public String toString() {
        return "HybridSignaturePair{" +
                "scheme=" + scheme.name() +
                ", classicalSize=" + classicalSignature.length +
                ", pqcSize=" + pqcSignature.length +
                ", totalSize=" + totalSignatureSize() +
                '}';
    }
}
