package com.pqc.hybrid.core.config;

import com.pqc.hybrid.core.common.oid.AlgorithmOIDRegistry;

/**
 * <b>EXPERIMENTAL.</b> Registry of composite algorithm combinations
 * ({@code draft-ietf-lamps-pq-composite-sigs}).
 *
 * <p>Consumed only by the parallel <i>Composite</i> path, which is <b>not wired
 * into {@link com.pqc.hybrid.core.api.PQCHybridCertificateAPI}</b> (production
 * uses the Catalyst / dual-signature model). APIs here may change without notice.
 */
public enum CompositeAlgorithm {

    MLDSA44_RSA2048_PSS_SHA256(
            "COMPSIG-MLDSA44-RSA2048-PSS-SHA256",
            AlgorithmOIDRegistry.OID_COMPOSITE_MLDSA44_RSA2048_PSS_SHA256,
            PQCAlgorithm.ML_DSA_44, "RSA", 2048, "SHA-256", 128,
            1312, 32, 2420,
            "RSA", "SHA256withRSA"),
    MLDSA44_RSA2048_PKCS15_SHA256(
            "COMPSIG-MLDSA44-RSA2048-PKCS15-SHA256",
            AlgorithmOIDRegistry.OID_COMPOSITE_MLDSA44_RSA2048_PKCS15_SHA256,
            PQCAlgorithm.ML_DSA_44, "RSA", 2048, "SHA-256", 128,
            1312, 32, 2420,
            "RSA", "SHA256withRSA"),
    MLDSA44_ED25519_SHA512(
            "COMPSIG-MLDSA44-Ed25519-SHA512",
            AlgorithmOIDRegistry.OID_COMPOSITE_MLDSA44_ED25519_SHA512,
            PQCAlgorithm.ML_DSA_44, "Ed25519", 256, "SHA-512", 128,
            1312, 32, 2420,
            "Ed25519", "Ed25519"),
    MLDSA44_ECDSA_P256_SHA256(
            "COMPSIG-MLDSA44-ECDSA-P256-SHA256",
            AlgorithmOIDRegistry.OID_COMPOSITE_MLDSA44_ECDSA_P256_SHA256,
            PQCAlgorithm.ML_DSA_44, "ECDSA", 256, "SHA-256", 128,
            1312, 32, 2420,
            "EC", "SHA256withECDSA"),

    MLDSA65_RSA3072_PSS_SHA512(
            "COMPSIG-MLDSA65-RSA3072-PSS-SHA512",
            AlgorithmOIDRegistry.OID_COMPOSITE_MLDSA65_RSA3072_PSS_SHA512,
            PQCAlgorithm.ML_DSA_65, "RSA", 3072, "SHA-512", 192,
            1952, 32, 3309,
            "RSA", "SHA512withRSA"),
    MLDSA65_RSA3072_PKCS15_SHA512(
            "COMPSIG-MLDSA65-RSA3072-PKCS15-SHA512",
            AlgorithmOIDRegistry.OID_COMPOSITE_MLDSA65_RSA3072_PKCS15_SHA512,
            PQCAlgorithm.ML_DSA_65, "RSA", 3072, "SHA-512", 192,
            1952, 32, 3309,
            "RSA", "SHA512withRSA"),
    MLDSA65_RSA4096_PSS_SHA512(
            "COMPSIG-MLDSA65-RSA4096-PSS-SHA512",
            AlgorithmOIDRegistry.OID_COMPOSITE_MLDSA65_RSA4096_PSS_SHA512,
            PQCAlgorithm.ML_DSA_65, "RSA", 4096, "SHA-512", 192,
            1952, 32, 3309,
            "RSA", "SHA512withRSA"),
    MLDSA65_RSA4096_PKCS15_SHA512(
            "COMPSIG-MLDSA65-RSA4096-PKCS15-SHA512",
            AlgorithmOIDRegistry.OID_COMPOSITE_MLDSA65_RSA4096_PKCS15_SHA512,
            PQCAlgorithm.ML_DSA_65, "RSA", 4096, "SHA-512", 192,
            1952, 32, 3309,
            "RSA", "SHA512withRSA"),
    MLDSA65_ECDSA_P256_SHA512(
            "COMPSIG-MLDSA65-ECDSA-P256-SHA512",
            AlgorithmOIDRegistry.OID_COMPOSITE_MLDSA65_ECDSA_P256_SHA512,
            PQCAlgorithm.ML_DSA_65, "ECDSA", 256, "SHA-512", 192,
            1952, 32, 3309,
            "EC", "SHA512withECDSA"),
    MLDSA65_ECDSA_P384_SHA512(
            "COMPSIG-MLDSA65-ECDSA-P384-SHA512",
            AlgorithmOIDRegistry.OID_COMPOSITE_MLDSA65_ECDSA_P384_SHA512,
            PQCAlgorithm.ML_DSA_65, "ECDSA", 384, "SHA-512", 192,
            1952, 32, 3309,
            "EC", "SHA512withECDSA"),
    MLDSA65_ECDSA_BP256_SHA512(
            "COMPSIG-MLDSA65-ECDSA-BP256-SHA512",
            AlgorithmOIDRegistry.OID_COMPOSITE_MLDSA65_ECDSA_BP256_SHA512,
            PQCAlgorithm.ML_DSA_65, "ECDSA", 256, "SHA-512", 192,
            1952, 32, 3309,
            "EC", "SHA512withECDSA"),
    MLDSA65_ED25519_SHA512(
            "COMPSIG-MLDSA65-Ed25519-SHA512",
            AlgorithmOIDRegistry.OID_COMPOSITE_MLDSA65_ED25519_SHA512,
            PQCAlgorithm.ML_DSA_65, "Ed25519", 256, "SHA-512", 192,
            1952, 32, 3309,
            "Ed25519", "Ed25519"),

    MLDSA87_ECDSA_P384_SHA512(
            "COMPSIG-MLDSA87-ECDSA-P384-SHA512",
            AlgorithmOIDRegistry.OID_COMPOSITE_MLDSA87_ECDSA_P384_SHA512,
            PQCAlgorithm.ML_DSA_87, "ECDSA", 384, "SHA-512", 256,
            2592, 32, 4627,
            "EC", "SHA512withECDSA"),
    MLDSA87_ECDSA_BP384_SHA512(
            "COMPSIG-MLDSA87-ECDSA-BP384-SHA512",
            AlgorithmOIDRegistry.OID_COMPOSITE_MLDSA87_ECDSA_BP384_SHA512,
            PQCAlgorithm.ML_DSA_87, "ECDSA", 384, "SHA-512", 256,
            2592, 32, 4627,
            "EC", "SHA512withECDSA"),
    MLDSA87_ED448_SHAKE256(
            "COMPSIG-MLDSA87-Ed448-SHAKE256",
            AlgorithmOIDRegistry.OID_COMPOSITE_MLDSA87_ED448_SHAKE256,
            PQCAlgorithm.ML_DSA_87, "Ed448", 456, "SHAKE256", 256,
            2592, 32, 4627,
            "Ed448", "Ed448"),
    MLDSA87_RSA3072_PSS_SHA512(
            "COMPSIG-MLDSA87-RSA3072-PSS-SHA512",
            AlgorithmOIDRegistry.OID_COMPOSITE_MLDSA87_RSA3072_PSS_SHA512,
            PQCAlgorithm.ML_DSA_87, "RSA", 3072, "SHA-512", 256,
            2592, 32, 4627,
            "RSA", "SHA512withRSA"),
    MLDSA87_RSA4096_PSS_SHA512(
            "COMPSIG-MLDSA87-RSA4096-PSS-SHA512",
            AlgorithmOIDRegistry.OID_COMPOSITE_MLDSA87_RSA4096_PSS_SHA512,
            PQCAlgorithm.ML_DSA_87, "RSA", 4096, "SHA-512", 256,
            2592, 32, 4627,
            "RSA", "SHA512withRSA"),
    MLDSA87_ECDSA_P521_SHA512(
            "COMPSIG-MLDSA87-ECDSA-P521-SHA512",
            AlgorithmOIDRegistry.OID_COMPOSITE_MLDSA87_ECDSA_P521_SHA512,
            PQCAlgorithm.ML_DSA_87, "ECDSA", 521, "SHA-512", 256,
            2592, 32, 4627,
            "EC", "SHA512withECDSA");

    private final String label;
    private final String oid;
    private final PQCAlgorithm pqcAlgorithm;
    private final String tradAlgorithmName;
    private final int tradKeySize;
    private final String preHashAlgorithm;
    private final int securityLevel;
    private final int mldsaPublicKeySize;
    private final int mldsaSeedSize;
    private final int mldsaSignatureSize;
    private final String tradKeyAlgorithm;
    private final String tradSignatureAlgorithm;

    CompositeAlgorithm(String label, String oid, PQCAlgorithm pqcAlgorithm,
                       String tradAlgorithmName, int tradKeySize, String preHashAlgorithm,
                       int securityLevel, int mldsaPublicKeySize, int mldsaSeedSize,
                       int mldsaSignatureSize, String tradKeyAlgorithm, String tradSignatureAlgorithm) {
        this.label = label;
        this.oid = oid;
        this.pqcAlgorithm = pqcAlgorithm;
        this.tradAlgorithmName = tradAlgorithmName;
        this.tradKeySize = tradKeySize;
        this.preHashAlgorithm = preHashAlgorithm;
        this.securityLevel = securityLevel;
        this.mldsaPublicKeySize = mldsaPublicKeySize;
        this.mldsaSeedSize = mldsaSeedSize;
        this.mldsaSignatureSize = mldsaSignatureSize;
        this.tradKeyAlgorithm = tradKeyAlgorithm;
        this.tradSignatureAlgorithm = tradSignatureAlgorithm;
    }

    public String getLabel() { return label; }
    public String getOid() { return oid; }
    public PQCAlgorithm getPQCAlgorithm() { return pqcAlgorithm; }
    public String getTradAlgorithmName() { return tradAlgorithmName; }
    public int getTradKeySize() { return tradKeySize; }
    public String getPreHashAlgorithm() { return preHashAlgorithm; }
    public int getSecurityLevel() { return securityLevel; }
    public int getMldsaPublicKeySize() { return mldsaPublicKeySize; }
    public int getMldsaSeedSize() { return mldsaSeedSize; }
    public int getMldsaSignatureSize() { return mldsaSignatureSize; }
    public String getTradKeyAlgorithm() { return tradKeyAlgorithm; }
    public String getTradSignatureAlgorithm() { return tradSignatureAlgorithm; }

    public int getCompositePublicKeySize() {
        return mldsaPublicKeySize + getTradPublicKeySize();
    }

    public int getCompositeSignatureSize() {
        return mldsaSignatureSize + getTradSignatureSize();
    }

    private int getTradPublicKeySize() {
        return switch (tradAlgorithmName) {
            case "RSA" -> switch (tradKeySize) { case 2048 -> 294; case 3072 -> 422; case 4096 -> 550; default -> 512; };
            case "ECDSA" -> switch (tradKeySize) { case 256 -> 65; case 384 -> 97; case 521 -> 133; default -> 65; };
            case "Ed25519" -> 32;
            case "Ed448" -> 57;
            default -> 128;
        };
    }

    private int getTradSignatureSize() {
        return switch (tradAlgorithmName) {
            case "RSA" -> tradKeySize / 8;
            case "ECDSA" -> switch (tradKeySize) { case 256 -> 72; case 384 -> 104; case 521 -> 140; default -> 72; };
            case "Ed25519" -> 64;
            case "Ed448" -> 114;
            default -> 128;
        };
    }

    public boolean isECDSABased() {
        return "ECDSA".equals(tradAlgorithmName);
    }

    public static CompositeAlgorithm fromOid(String oid) {
        for (CompositeAlgorithm algo : values()) {
            if (algo.oid.equals(oid)) return algo;
        }
        return null;
    }

    public static CompositeAlgorithm fromLabel(String label) {
        for (CompositeAlgorithm algo : values()) {
            if (algo.label.equals(label)) return algo;
        }
        return null;
    }

    public static CompositeAlgorithm recommended(int securityLevel) {
        return switch (securityLevel) {
            case 128 -> MLDSA44_ECDSA_P256_SHA256;
            case 192 -> MLDSA65_ECDSA_P256_SHA512;
            case 256 -> MLDSA87_ECDSA_P521_SHA512;
            default -> throw new IllegalArgumentException("Unsupported security level: " + securityLevel);
        };
    }
}
