package com.pqc.hybrid.core.config;

/**
 * Enumeration of supported Classical Cryptographic algorithms.
 * These are the traditional, well-established algorithms that provide baseline security
 * and are combined with PQC algorithms in hybrid certificates.
 *
 * @author PQC Hybrid Team
 * @version 1.0.0-BETA
 */
public enum ClassicalAlgorithm {
    
    /**
     * RSA (Rivest-Shamir-Adleman) with 2048-bit keys.
     * OID: 1.2.840.113549.1.1.1
     */
    RSA_2048("RSA", 2048, "1.2.840.113549.1.1.1", "RSA/ECB/PKCS1Padding", 128),
    
    /**
     * RSA with 3072-bit keys.
     */
    RSA_3072("RSA", 3072, "1.2.840.113549.1.1.1", "RSA/ECB/PKCS1Padding", 128),
    
    /**
     * RSA with 4096-bit keys.
     */
    RSA_4096("RSA", 4096, "1.2.840.113549.1.1.1", "RSA/ECB/PKCS1Padding", 256),

    /**
     * ECDSA (Elliptic Curve Digital Signature Algorithm) with P-256 curve.
     * OID: 1.2.840.10045.2.1
     */
    ECDSA_P256("ECDSA", 256, "1.2.840.10045.2.1", "SHA256withECDSA", 128),
    
    /**
     * ECDSA with P-384 curve.
     */
    ECDSA_P384("ECDSA", 384, "1.2.840.10045.2.1", "SHA384withECDSA", 192),
    
    /**
     * ECDSA with P-521 curve.
     */
    ECDSA_P521("ECDSA", 521, "1.2.840.10045.2.1", "SHA512withECDSA", 256);

    private final String algorithmName;
    private final int keySize;        // in bits
    private final String oid;
    private final String signatureAlgorithm;  // for signature operations
    private final int securityLevel;   // equivalent security in bits

    ClassicalAlgorithm(String algorithmName, int keySize, String oid, 
                       String signatureAlgorithm, int securityLevel) {
        this.algorithmName = algorithmName;
        this.keySize = keySize;
        this.oid = oid;
        this.signatureAlgorithm = signatureAlgorithm;
        this.securityLevel = securityLevel;
    }

    /**
     * Gets the algorithm name.
     *
     * @return the algorithm name (e.g., "RSA", "ECDSA")
     */
    public String getAlgorithmName() {
        return algorithmName;
    }

    /**
     * Gets the key size in bits.
     *
     * @return the key size
     */
    public int getKeySize() {
        return keySize;
    }

    /**
     * Gets the OID.
     *
     * @return the OID string
     */
    public String getOid() {
        return oid;
    }

    /**
     * Gets the signature algorithm name (for use with Java Signature class).
     *
     * @return the signature algorithm name
     */
    public String getSignatureAlgorithm() {
        return signatureAlgorithm;
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
     * Finds a classical algorithm by name and key size.
     *
     * @param algorithmName the algorithm name (e.g., "RSA", "ECDSA")
     * @param keySize the key size in bits
     * @return the ClassicalAlgorithm, or null if not found
     */
    public static ClassicalAlgorithm fromNameAndSize(String algorithmName, int keySize) {
        for (ClassicalAlgorithm algo : values()) {
            if (algo.algorithmName.equalsIgnoreCase(algorithmName) && algo.keySize == keySize) {
                return algo;
            }
        }
        return null;
    }

    /**
     * Finds a classical algorithm by OID.
     *
     * @param oid the OID string
     * @return array of matching algorithms (may have multiple sizes)
     */
    public static ClassicalAlgorithm[] fromOid(String oid) {
        return java.util.Arrays.stream(values())
                .filter(algo -> algo.oid.equals(oid))
                .toArray(ClassicalAlgorithm[]::new);
    }
}
