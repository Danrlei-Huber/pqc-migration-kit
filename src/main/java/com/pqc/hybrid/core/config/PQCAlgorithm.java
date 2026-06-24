package com.pqc.hybrid.core.config;

import com.pqc.hybrid.core.common.oid.AlgorithmOIDRegistry;

/**
 * Enumeration of supported Post-Quantum Cryptography (PQC) signature algorithms.
 * This module's PQC support is ML-DSA only (NIST FIPS 204), the lattice-based
 * quantum-resistant digital signature algorithm.
 *
 * @author PQC Hybrid Team
 * @version 1.0.0-BETA
 */
public enum PQCAlgorithm {

    /**
     * ML-DSA (Module-Lattice-Based Digital Signature Algorithm)
     * NIST FIPS 204 OIDs: 2.16.840.1.101.3.4.3.x
     */
    ML_DSA_44("ML-DSA-44", AlgorithmOIDRegistry.OID_ML_DSA_44, 128, 1312),
    ML_DSA_65("ML-DSA-65", AlgorithmOIDRegistry.OID_ML_DSA_65, 192, 1952),
    ML_DSA_87("ML-DSA-87", AlgorithmOIDRegistry.OID_ML_DSA_87, 256, 2592);

    private final String name;
    private final String oid;
    private final int securityLevel;  // bits of classical equivalent security
    private final int publicKeySize;  // approximate size in bytes

    PQCAlgorithm(String name, String oid, int securityLevel, int publicKeySize) {
        this.name = name;
        this.oid = oid;
        this.securityLevel = securityLevel;
        this.publicKeySize = publicKeySize;
    }

    /**
     * Gets the algorithm name.
     *
     * @return the algorithm name (e.g., "ML-DSA-65")
     */
    public String getName() {
        return name;
    }

    /**
     * Gets the OID (Object Identifier) for this algorithm.
     *
     * @return the OID string (e.g., "2.16.840.1.101.3.4.3.18")
     */
    public String getOid() {
        return oid;
    }

    /**
     * Gets the security level (equivalent classical bits).
     *
     * @return security level in bits
     */
    public int getSecurityLevel() {
        return securityLevel;
    }

    /**
     * Gets the approximate public key size.
     *
     * @return size in bytes
     */
    public int getPublicKeySize() {
        return publicKeySize;
    }

    /**
     * Categorizes the algorithm type.
     *
     * @return the algorithm category
     */
    public AlgorithmCategory getCategory() {
        if (name.startsWith("ML-DSA")) {
            return AlgorithmCategory.SIGNATURE;
        }
        return AlgorithmCategory.UNKNOWN;
    }

    /**
     * Finds a PQC algorithm by its name.
     *
     * @param name the algorithm name
     * @return the PQCAlgorithm, or null if not found
     */
    public static PQCAlgorithm fromName(String name) {
        for (PQCAlgorithm algo : values()) {
            if (algo.name.equalsIgnoreCase(name)) {
                return algo;
            }
        }
        return null;
    }

    /**
     * Finds a PQC algorithm by its OID.
     *
     * @param oid the OID string
     * @return the PQCAlgorithm, or null if not found
     */
    public static PQCAlgorithm fromOid(String oid) {
        for (PQCAlgorithm algo : values()) {
            if (algo.oid.equals(oid)) {
                return algo;
            }
        }
        return null;
    }

    /**
     * Algorithm categories.
     */
    public enum AlgorithmCategory {
        SIGNATURE,
        UNKNOWN
    }
}
