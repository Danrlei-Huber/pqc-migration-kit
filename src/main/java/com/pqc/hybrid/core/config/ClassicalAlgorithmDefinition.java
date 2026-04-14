package com.pqc.hybrid.core.config;

/**
 * Definition of a classical cryptographic algorithm.
 * Extends AlgorithmDefinition with classical-specific properties.
 *
 * @author PQC Hybrid Team
 * @version 1.0.0-BETA
 */
public final class ClassicalAlgorithmDefinition extends AlgorithmDefinition {

    private final int keySize;  // bits
    private final String signatureAlgorithm;
    private final ClassicalAlgorithm algorithm;

    /**
     * Creates a new ClassicalAlgorithmDefinition from a ClassicalAlgorithm enum.
     *
     * @param algorithm the classical algorithm enum
     */
    public ClassicalAlgorithmDefinition(ClassicalAlgorithm algorithm) {
        super(algorithm.getAlgorithmName(), algorithm.getOid(), algorithm.getSecurityLevel());
        this.algorithm = algorithm;
        this.keySize = algorithm.getKeySize();
        this.signatureAlgorithm = algorithm.getSignatureAlgorithm();
    }

    /**
     * Gets the key size in bits.
     */
    public int getKeySize() {
        return keySize;
    }

    /**
     * Gets the signature algorithm name.
     */
    public String getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    /**
     * Gets the underlying enum.
     */
    public ClassicalAlgorithm getAlgorithm() {
        return algorithm;
    }

    @Override
    public boolean isPQC() {
        return false;
    }

    @Override
    public boolean isClassical() {
        return true;
    }

    @Override
    public String toString() {
        return String.format("%s-%d (OID: %s, Security: %d-bit)",
                name, keySize, oid, securityLevel);
    }
}
