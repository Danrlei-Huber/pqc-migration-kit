package com.pqc.hybrid.core.hybrid;

/**
 * Enumeration of supported hybrid signature schemes.
 * 
 * A hybrid signature scheme combines a classical signature algorithm with a
 * post-quantum signature algorithm to provide both classical security guarantees
 * and quantum-resistance.
 * 
 * Each scheme specifies a classical + PQC combination along with recommended
 * security metadata.
 * 
 * Example:
 * - RSA_2048_ML_DSA_65: RSA-2048 (classical) + ML-DSA-65 (post-quantum)
 *   Provides 192-bit security level with dual certification
 * 
 * @author PQC Hybrid Team
 * @version 1.0.0
 * @since 2026-04-14
 */
public enum HybridSignatureScheme {
    
    /**
     * RSA-2048 (classical) + ML-DSA-44 (128-bit PQC)
     * Combined security: NIST level 2 (256-bit equivalent)
     */
    RSA_2048_ML_DSA_44(
        "SHA256withRSA",      // Classical signature algorithm
        "ML-DSA-44",           // PQC signature algorithm
        2048,                  // RSA key size
        128                    // ML-DSA security level (bits)
    ),
    
    /**
     * RSA-2048 (classical) + ML-DSA-65 (192-bit PQC) - RECOMMENDED
     * Combined security: NIST level 3 (256-bit+ equivalent)
     * This is the primary recommended hybrid scheme
     */
    RSA_2048_ML_DSA_65(
        "SHA256withRSA",
        "ML-DSA-65",
        2048,
        192
    ),
    
    /**
     * RSA-3072 (classical) + ML-DSA-65 (192-bit PQC)
     * Combined security: NIST level 3 (256-bit equivalent)
     */
    RSA_3072_ML_DSA_65(
        "SHA384withRSA",
        "ML-DSA-65",
        3072,
        192
    ),
    
    /**
     * RSA-3072 (classical) + ML-DSA-87 (256-bit PQC)
     * Combined security: NIST level 5 (256-bit equivalent)
     */
    RSA_3072_ML_DSA_87(
        "SHA384withRSA",
        "ML-DSA-87",
        3072,
        256
    ),
    
    /**
     * ECDSA-P256 (classical) + ML-DSA-44 (128-bit PQC)
     * Combined security: NIST level 2 (256-bit equivalent)
     */
    ECDSA_P256_ML_DSA_44(
        "SHA256withECDSA",
        "ML-DSA-44",
        256,
        128
    ),
    
    /**
     * ECDSA-P256 (classical) + ML-DSA-65 (192-bit PQC)
     * Combined security: NIST level 3 (256-bit equivalent)
     */
    ECDSA_P256_ML_DSA_65(
        "SHA256withECDSA",
        "ML-DSA-65",
        256,
        192
    );

    private final String classicalAlgorithm;
    private final String pqcAlgorithm;
    private final int classicalKeySize;
    private final int pqcSecurityLevel;

    /**
     * Constructs a hybrid signature scheme.
     * 
     * @param classicalAlgorithm the classical signature algorithm (e.g., "SHA256withRSA")
     * @param pqcAlgorithm the PQC signature algorithm (e.g., "ML-DSA-65")
     * @param classicalKeySize the classical key size in bits
     * @param pqcSecurityLevel the PQC security level in bits
     */
    HybridSignatureScheme(
            String classicalAlgorithm,
            String pqcAlgorithm,
            int classicalKeySize,
            int pqcSecurityLevel) {
        this.classicalAlgorithm = classicalAlgorithm;
        this.pqcAlgorithm = pqcAlgorithm;
        this.classicalKeySize = classicalKeySize;
        this.pqcSecurityLevel = pqcSecurityLevel;
    }

    /**
     * Gets the classical signature algorithm.
     * 
     * @return e.g., "SHA256withRSA"
     */
    public String getClassicalAlgorithm() {
        return classicalAlgorithm;
    }

    /**
     * Gets the PQC signature algorithm.
     * 
     * @return e.g., "ML-DSA-65"
     */
    public String getPQCAlgorithm() {
        return pqcAlgorithm;
    }

    /**
     * Gets the classical key size in bits.
     * 
     * @return key size (2048, 3072, etc.)
     */
    public int getClassicalKeySize() {
        return classicalKeySize;
    }

    /**
     * Gets the PQC security level in bits.
     * 
     * @return security level (128, 192, 256, etc.)
     */
    public int getPQCSecurityLevel() {
        return pqcSecurityLevel;
    }

    /**
     * Gets the minimum combined security level (maximum of classical and PQC levels).
     * 
     * @return minimum security level in bits
     */
    public int getCombinedSecurityLevel() {
        return Math.max(classicalKeySize / 8, pqcSecurityLevel);
    }

    /**
     * Gets a description of this scheme.
     * 
     * @return a human-readable description
     */
    @Override
    public String toString() {
        return name() + " (" + classicalAlgorithm + " + " + pqcAlgorithm + ")";
    }
}
