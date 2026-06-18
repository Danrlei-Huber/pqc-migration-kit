package com.pqc.hybrid.core.config;

import com.pqc.hybrid.core.common.oid.AlgorithmOIDRegistry;

/**
 * Enumeration of supported Post-Quantum Cryptography (PQC) algorithms.
 * These are lattice-based, hash-based, and other quantum-resistant algorithms
 * that have been standardized by NIST as of 2024.
 *
 * @author PQC Hybrid Team
 * @version 1.0.0-BETA
 */
public enum PQCAlgorithm {
    
    /**
     * ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism)
     * Formerly known as Kyber. Standard NIST PQC for key establishment.
     * OID: 2.16.840.1.114027.8.1.1
     */
    ML_KEM_512("ML-KEM-512", AlgorithmOIDRegistry.OID_ML_KEM_512, 128, 768),
    ML_KEM_768("ML-KEM-768", AlgorithmOIDRegistry.OID_ML_KEM_768, 192, 1088),
    ML_KEM_1024("ML-KEM-1024", AlgorithmOIDRegistry.OID_ML_KEM_1024, 256, 1568),

    /**
     * ML-DSA (Module-Lattice-Based Digital Signature Algorithm)
     * NIST FIPS 204 OIDs: 2.16.840.1.101.3.4.3.x
     */
    ML_DSA_44("ML-DSA-44", AlgorithmOIDRegistry.OID_ML_DSA_44, 128, 1312),
    ML_DSA_65("ML-DSA-65", AlgorithmOIDRegistry.OID_ML_DSA_65, 192, 1952),
    ML_DSA_87("ML-DSA-87", AlgorithmOIDRegistry.OID_ML_DSA_87, 256, 2592),

    /**
     * SLH-DSA (Stateless Hash-Based Digital Signature Algorithm)
     * NIST FIPS 205 OIDs: 2.16.840.1.101.3.4.3.x
     */
    SLH_DSA_SHA2_128S("SLH-DSA-SHA2-128s", AlgorithmOIDRegistry.OID_SLH_DSA_SHA2_128S, 128, 2144),
    SLH_DSA_SHA2_128F("SLH-DSA-SHA2-128f", AlgorithmOIDRegistry.OID_SLH_DSA_SHA2_128F, 128, 4784),
    SLH_DSA_SHA2_192S("SLH-DSA-SHA2-192s", AlgorithmOIDRegistry.OID_SLH_DSA_SHA2_192S, 192, 3104),
    SLH_DSA_SHA2_192F("SLH-DSA-SHA2-192f", AlgorithmOIDRegistry.OID_SLH_DSA_SHA2_192F, 192, 7036),
    SLH_DSA_SHA2_256S("SLH-DSA-SHA2-256s", AlgorithmOIDRegistry.OID_SLH_DSA_SHA2_256S, 256, 4784),
    SLH_DSA_SHA2_256F("SLH-DSA-SHA2-256f", AlgorithmOIDRegistry.OID_SLH_DSA_SHA2_256F, 256, 9076),

    /**
     * Falcon (Fast-Fourier Lattice-based Compact Signatures over NTRU)
     * Alternative lattice-based signature algorithm.
     * OID: 1.3.9999.3
     */
    FALCON_512("Falcon-512", "1.3.9999.3.1", 128, 666),
    FALCON_1024("Falcon-1024", "1.3.9999.3.4", 256, 1280);

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
     * @return the algorithm name (e.g., "ML-KEM-512")
     */
    public String getName() {
        return name;
    }

    /**
     * Gets the OID (Object Identifier) for this algorithm.
     *
     * @return the OID string (e.g., "2.16.840.1.114027.8.1.1")
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
        if (name.startsWith("ML-KEM")) {
            return AlgorithmCategory.KEY_ENCAPSULATION;
        } else if (name.startsWith("ML-DSA") || name.startsWith("Falcon") || name.startsWith("SLH-DSA")) {
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
        KEY_ENCAPSULATION,
        UNKNOWN
    }
}
