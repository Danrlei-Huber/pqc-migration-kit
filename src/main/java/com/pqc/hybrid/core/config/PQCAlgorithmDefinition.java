package com.pqc.hybrid.core.config;

/**
 * Definition of a Post-Quantum Cryptography (PQC) algorithm.
 * Extends AlgorithmDefinition with PQC-specific properties.
 *
 * @author PQC Hybrid Team
 * @version 1.0.0-BETA
 */
public final class PQCAlgorithmDefinition extends AlgorithmDefinition {

    private final int publicKeySize;  // bytes
    private final PQCAlgorithm.AlgorithmCategory category;
    private final PQCAlgorithm algorithm;

    /**
     * Creates a new PQCAlgorithmDefinition from a PQCAlgorithm enum.
     *
     * @param algorithm the PQC algorithm enum
     */
    public PQCAlgorithmDefinition(PQCAlgorithm algorithm) {
        super(algorithm.getName(), algorithm.getOid(), algorithm.getSecurityLevel());
        this.algorithm = algorithm;
        this.publicKeySize = algorithm.getPublicKeySize();
        this.category = algorithm.getCategory();
    }

    /**
     * Gets the approximate public key size in bytes.
     */
    public int getPublicKeySize() {
        return publicKeySize;
    }

    /**
     * Gets the algorithm category.
     */
    public PQCAlgorithm.AlgorithmCategory getCategory() {
        return category;
    }

    /**
     * Gets the underlying enum.
     */
    public PQCAlgorithm getAlgorithm() {
        return algorithm;
    }

    /**
     * Indicates whether this is a signature algorithm.
     */
    public boolean isSignatureAlgorithm() {
        return category == PQCAlgorithm.AlgorithmCategory.SIGNATURE;
    }

    /**
     * Indicates whether this is a key encapsulation mechanism (KEM).
     */
    public boolean isKeyEncapsulation() {
        return category == PQCAlgorithm.AlgorithmCategory.KEY_ENCAPSULATION;
    }

    @Override
    public boolean isPQC() {
        return true;
    }

    @Override
    public boolean isClassical() {
        return false;
    }

    @Override
    public String toString() {
        return String.format("%s (OID: %s, Security: %d-bit, PubKey: ~%d bytes)",
                name, oid, securityLevel, publicKeySize);
    }
}
