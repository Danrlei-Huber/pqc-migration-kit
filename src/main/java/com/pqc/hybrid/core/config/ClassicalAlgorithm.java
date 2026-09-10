package com.pqc.hybrid.core.config;

import com.pqc.hybrid.core.exception.AlgorithmNotSupportedException;

import java.security.Key;
import java.security.interfaces.ECKey;
import java.security.interfaces.RSAKey;
import java.util.Objects;

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
    RSA_2048("RSA", 2048, "1.2.840.113549.1.1.1", "SHA256withRSA", 112),
    
    /**
     * RSA with 3072-bit keys.
     */
    RSA_3072("RSA", 3072, "1.2.840.113549.1.1.1", "SHA256withRSA", 128),
    
    /**
     * RSA with 4096-bit keys.
     */
    RSA_4096("RSA", 4096, "1.2.840.113549.1.1.1", "SHA512withRSA", 152),

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
    /**
     * Equivalent symmetric security in bits, per NIST SP 800-57 Part 1 Rev 5, Table 2:
     * RSA-2048 gives 112 bits, RSA-3072 gives 128, and RSA-4096 sits between the 128- and
     * 192-bit tiers at roughly 152 — it does not reach 192, let alone 256. The NIST curves
     * give 128, 192 and 256 bits respectively.
     */
    private final int securityLevel;

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

    /**
     * Resolves the exact algorithm variant from actual key material.
     * <p>
     * The variant is determined from the key itself — the curve field size for EC keys, the
     * modulus length for RSA keys — so the result cannot drift from the key it describes. Both
     * public and private keys are accepted.
     *
     * @param key the classical key (public or private)
     * @return the matching ClassicalAlgorithm, or {@code null} if the key is not one of the
     *         supported RSA/ECDSA variants
     */
    public static ClassicalAlgorithm fromKey(Key key) {
        Objects.requireNonNull(key, "Key cannot be null");
        if (key instanceof ECKey ecKey) {
            return fromNameAndSize("ECDSA", ecKey.getParams().getCurve().getField().getFieldSize());
        }
        if (key instanceof RSAKey rsaKey) {
            return fromNameAndSize("RSA", rsaKey.getModulus().bitLength());
        }
        return null;
    }

    /**
     * Gets the Java Signature algorithm name appropriate for the given key.
     * <p>
     * This is the correct way to choose a signature algorithm: the digest is selected to match
     * the strength of the key, so a P-384 key signs with {@code SHA384withECDSA} rather than
     * being silently downgraded to SHA-256.
     *
     * @param key the classical signing or verification key
     * @return the signature algorithm name (e.g., {@code "SHA384withECDSA"})
     * @throws AlgorithmNotSupportedException if the key is not one of the supported
     *         RSA-2048/3072/4096 or ECDSA P-256/P-384/P-521 variants
     */
    public static String getSignatureAlgorithmForKey(Key key) {
        ClassicalAlgorithm algo = fromKey(key);
        if (algo == null) {
            throw new AlgorithmNotSupportedException(describeKey(key),
                    "supported classical keys are RSA-2048/3072/4096 and ECDSA P-256/P-384/P-521");
        }
        return algo.signatureAlgorithm;
    }

    /**
     * Builds a human-readable description of a key for error messages, without exposing
     * key material.
     */
    private static String describeKey(Key key) {
        if (key instanceof ECKey ecKey) {
            return "ECDSA-" + ecKey.getParams().getCurve().getField().getFieldSize();
        }
        if (key instanceof RSAKey rsaKey) {
            return "RSA-" + rsaKey.getModulus().bitLength();
        }
        return String.valueOf(key.getAlgorithm());
    }

    /**
     * Gets the Java Signature algorithm name for a given classical algorithm name.
     *
     * @param algorithmName the classical algorithm name (e.g., "RSA", "ECDSA")
     * @return the signature algorithm name (e.g., "SHA256withRSA")
     * @throws IllegalArgumentException if no matching algorithm is found
     * @deprecated A bare algorithm name does not identify a key size, so this method returns the
     *             first declared variant — {@code SHA256withRSA} for any RSA key and
     *             {@code SHA256withECDSA} for any EC curve. Signing a P-384 or P-521 key through
     *             this method silently caps the digest at SHA-256, breaking the security-level
     *             balance the hybrid pairs are built on. Use {@link #getSignatureAlgorithmForKey(Key)},
     *             which resolves the variant from the key itself.
     */
    @Deprecated(forRemoval = true)
    public static String getSignatureAlgorithmForName(String algorithmName) {
        for (ClassicalAlgorithm algo : values()) {
            if (algo.algorithmName.equalsIgnoreCase(algorithmName)) {
                return algo.signatureAlgorithm;
            }
        }
        throw new IllegalArgumentException("Unknown classical algorithm: " + algorithmName);
    }
}
