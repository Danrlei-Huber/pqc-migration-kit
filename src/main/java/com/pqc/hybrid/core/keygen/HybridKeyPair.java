package com.pqc.hybrid.core.keygen;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Objects;

/**
 * Represents a hybrid cryptographic key pair combining classical and PQC keys.
 * 
 * A hybrid key pair consists of:
 * - A classical key pair (RSA or ECDSA) for legacy compatibility
 * - A PQC key pair (ML-DSA, Falcon, or SLH-DSA) for quantum resistance
 *
 * Both key pairs are kept in sync and used together for hybrid signing and verification.
 *
 * @author PQC Hybrid Team
 * @version 1.0.0-BETA
 */
public final class HybridKeyPair {

    private final PublicKey classicalPublicKey;
    private final PrivateKey classicalPrivateKey;
    private final PublicKey pqcPublicKey;
    private final PrivateKey pqcPrivateKey;
    private final String classicalAlgorithm;
    private final String pqcAlgorithm;
    private final long generationTime;

    /**
     * Creates a new HybridKeyPair.
     *
     * @param classicalPublicKey the classical public key
     * @param classicalPrivateKey the classical private key
     * @param pqcPublicKey the PQC public key
     * @param pqcPrivateKey the PQC private key
     * @param classicalAlgorithm the classical algorithm name
     * @param pqcAlgorithm the PQC algorithm name
     */
    public HybridKeyPair(PublicKey classicalPublicKey, PrivateKey classicalPrivateKey,
                         PublicKey pqcPublicKey, PrivateKey pqcPrivateKey,
                         String classicalAlgorithm, String pqcAlgorithm) {
        this.classicalPublicKey = Objects.requireNonNull(classicalPublicKey, "Classical public key cannot be null");
        this.classicalPrivateKey = Objects.requireNonNull(classicalPrivateKey, "Classical private key cannot be null");
        this.pqcPublicKey = Objects.requireNonNull(pqcPublicKey, "PQC public key cannot be null");
        this.pqcPrivateKey = Objects.requireNonNull(pqcPrivateKey, "PQC private key cannot be null");
        this.classicalAlgorithm = Objects.requireNonNull(classicalAlgorithm, "Classical algorithm name cannot be null");
        this.pqcAlgorithm = Objects.requireNonNull(pqcAlgorithm, "PQC algorithm name cannot be null");
        this.generationTime = System.currentTimeMillis();
    }

    /**
     * Gets the classical public key.
     */
    public PublicKey getClassicalPublicKey() {
        return classicalPublicKey;
    }

    /**
     * Gets the classical private key.
     * Use with caution - this is sensitive cryptographic material.
     */
    public PrivateKey getClassicalPrivateKey() {
        return classicalPrivateKey;
    }

    /**
     * Gets the PQC public key.
     */
    public PublicKey getPQCPublicKey() {
        return pqcPublicKey;
    }

    /**
     * Gets the PQC private key.
     * Use with caution - this is sensitive cryptographic material.
     */
    public PrivateKey getPQCPrivateKey() {
        return pqcPrivateKey;
    }

    /**
     * Gets the classical algorithm name.
     */
    public String getClassicalAlgorithm() {
        return classicalAlgorithm;
    }

    /**
     * Gets the PQC algorithm name.
     */
    public String getPQCAlgorithm() {
        return pqcAlgorithm;
    }

    /**
     * Gets the time when this key pair was generated.
     */
    public long getGenerationTime() {
        return generationTime;
    }

    /**
     * Gets a descriptive label for this key pair.
     */
    public String getLabel() {
        return String.format("%s + %s", classicalAlgorithm, pqcAlgorithm);
    }

    @Override
    public String toString() {
        return String.format("HybridKeyPair{%s + %s, generated: %d}", 
                classicalAlgorithm, pqcAlgorithm, generationTime);
    }
}
