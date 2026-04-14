package com.pqc.hybrid.core.config;

import java.util.Objects;

/**
 * Complete definition of a cryptographic algorithm with metadata.
 * Combines algorithm identification, OID, security parameters, and implementation details.
 *
 * @author PQC Hybrid Team
 * @version 1.0.0-BETA
 */
public abstract sealed class AlgorithmDefinition permits ClassicalAlgorithmDefinition, PQCAlgorithmDefinition {

    protected final String name;
    protected final String oid;
    protected final int securityLevel;  // bits

    /**
     * Creates a new AlgorithmDefinition.
     *
     * @param name the algorithm name
     * @param oid the algorithm OID
     * @param securityLevel the security level in bits
     */
    protected AlgorithmDefinition(String name, String oid, int securityLevel) {
        this.name = Objects.requireNonNull(name, "Algorithm name cannot be null");
        this.oid = Objects.requireNonNull(oid, "OID cannot be null");
        this.securityLevel = securityLevel;
    }

    /**
     * Gets the algorithm name.
     */
    public String getName() {
        return name;
    }

    /**
     * Gets the OID.
     */
    public String getOid() {
        return oid;
    }

    /**
     * Gets the security level in bits.
     */
    public int getSecurityLevel() {
        return securityLevel;
    }

    /**
     * Indicates whether this is a PQC algorithm.
     */
    public abstract boolean isPQC();

    /**
     * Indicates whether this is a classical algorithm.
     */
    public abstract boolean isClassical();

    @Override
    public String toString() {
        return String.format("%s (OID: %s, Security: %d-bit)", name, oid, securityLevel);
    }
}
