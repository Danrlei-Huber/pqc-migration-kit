package com.pqc.hybrid.core.common.oid;

import org.bouncycastle.asn1.x509.Extension;

import java.util.HashMap;
import java.util.Map;

/**
 * Central registry for NIST-standardized PQC and hybrid algorithm OIDs.
 * 
 * This class provides a single source of truth for algorithm object identifiers,
 * supporting lookup by OID (string) or algorithm name, and providing utility
 * methods for hybrid scheme identification.
 * 
 * OID Standards:
 * - ML-DSA (Digital Signature): 2.16.840.1.101.3.4.3.x (NIST 2024)
 * - Classical (RSA, ECDSA): Standard X.509 OIDs
 * - X.509 Hybrid Extensions: RFC 5280 / draft-ounsworth-pqc-hybrid-x509
 * 
 * @author PQC Hybrid Team
 * @version 2.0.0
 * @since 2026-04-14
 */
public final class AlgorithmOIDRegistry {

    // ============================================================================
    // ML-DSA OIDs (Module-Lattice-Based Digital Signature Algorithm)
    // NIST FIPS 204: 2.16.840.1.101.3.4.3.x
    // ============================================================================
    
    /** OID for ML-DSA-44 (128-bit security, NIST level 2) */
    public static final String OID_ML_DSA_44 = "2.16.840.1.101.3.4.3.17";
    
    /** OID for ML-DSA-65 (192-bit security, NIST level 3) */
    public static final String OID_ML_DSA_65 = "2.16.840.1.101.3.4.3.18";
    
    /** OID for ML-DSA-87 (256-bit security, NIST level 5) */
    public static final String OID_ML_DSA_87 = "2.16.840.1.101.3.4.3.19";


    // ============================================================================
    // Classical Algorithm OIDs (for hybrid schemes)
    // ============================================================================
    
    /** OID for RSA (1.2.840.113549.1.1.1) */
    public static final String OID_RSA = "1.2.840.113549.1.1.1";
    
    /** OID for ECDSA (1.2.840.10045.2.1) */
    public static final String OID_ECDSA = "1.2.840.10045.2.1";
    
    /** OID for SHA256withRSAEncryption (1.2.840.113549.1.1.11) */
    public static final String OID_SHA256_WITH_RSA = "1.2.840.113549.1.1.11";
    
    /** OID for ECDSA with SHA-256 (1.2.840.10045.4.3.2) */
    public static final String OID_ECDSA_WITH_SHA256 = "1.2.840.10045.4.3.2";


    // ============================================================================
    // X.509 "Alternative" Certificate Extension OIDs (ITU-T X.509 (2019) / id-ce)
    // Catalyst hybrid model. Values mirror the BouncyCastle Extension constants,
    // which are the single source of truth (confirmed: id-ce 72/73/74).
    // ============================================================================

    /** OID for altSignatureAlgorithm extension (2.5.29.73), non-critical */
    public static final String OID_ALT_SIGNATURE_ALGORITHM = Extension.altSignatureAlgorithm.getId();

    /** OID for altSignatureValue extension (2.5.29.74), non-critical */
    public static final String OID_ALT_SIGNATURE_VALUE = Extension.altSignatureValue.getId();

    /** OID for subjectAltPublicKeyInfo extension (2.5.29.72), non-critical */
    public static final String OID_SUBJECT_ALT_PUBLIC_KEY_INFO = Extension.subjectAltPublicKeyInfo.getId();


    // ============================================================================
    // Lookup Maps (initialized statically)
    // ============================================================================
    
    private static final Map<String, String> OID_TO_NAME = new HashMap<>();
    private static final Map<String, String> NAME_TO_OID = new HashMap<>();
    private static final Map<String, AlgorithmType> OID_TO_TYPE = new HashMap<>();

    static {
        // ML-DSA mappings
        registerOID(OID_ML_DSA_44, "ML-DSA-44", AlgorithmType.PQC_SIGNATURE);
        registerOID(OID_ML_DSA_65, "ML-DSA-65", AlgorithmType.PQC_SIGNATURE);
        registerOID(OID_ML_DSA_87, "ML-DSA-87", AlgorithmType.PQC_SIGNATURE);

        // Classical mappings
        registerOID(OID_RSA, "RSA", AlgorithmType.CLASSICAL);
        registerOID(OID_ECDSA, "ECDSA", AlgorithmType.CLASSICAL);
        registerOID(OID_SHA256_WITH_RSA, "SHA256withRSA", AlgorithmType.CLASSICAL_SIGNATURE);
        registerOID(OID_ECDSA_WITH_SHA256, "ECDSA-with-SHA256", AlgorithmType.CLASSICAL_SIGNATURE);
        
        // X.509 Extension mappings
        registerOID(OID_ALT_SIGNATURE_ALGORITHM, "altSignatureAlgorithm", AlgorithmType.X509_EXTENSION);
        registerOID(OID_ALT_SIGNATURE_VALUE, "altSignatureValue", AlgorithmType.X509_EXTENSION);
        registerOID(OID_SUBJECT_ALT_PUBLIC_KEY_INFO, "subjectAltPublicKeyInfo", AlgorithmType.X509_EXTENSION);
    }

    /**
     * Gets the algorithm name for a given OID.
     * 
     * @param oid the object identifier (e.g., "2.16.840.1.101.3.4.3.18")
     * @return the algorithm name (e.g., "ML-DSA-65"), or null if not found
     */
    public static String getAlgorithmName(String oid) {
        return OID_TO_NAME.get(oid);
    }

    /**
     * Gets the OID for a given algorithm name.
     * 
     * @param algorithmName the algorithm name (e.g., "ML-DSA-65")
     * @return the OID string, or null if not found
     */
    public static String getOID(String algorithmName) {
        return NAME_TO_OID.get(algorithmName);
    }

    /**
     * Gets the algorithm type for a given OID.
     * 
     * @param oid the object identifier
     * @return the algorithm type (PQC_SIGNATURE, PQC_KEM, CLASSICAL, etc.), or null if not found
     */
    public static AlgorithmType getAlgorithmType(String oid) {
        return OID_TO_TYPE.get(oid);
    }

    /**
     * Checks if the given OID corresponds to a PQC algorithm.
     * 
     * @param oid the object identifier
     * @return true if the OID is for a post-quantum algorithm, false otherwise
     */
    public static boolean isPQC(String oid) {
        AlgorithmType type = getAlgorithmType(oid);
        return type != null && (type == AlgorithmType.PQC_SIGNATURE || type == AlgorithmType.PQC_KEM);
    }

    /**
     * Checks if the given OID corresponds to a classical (non-PQC) algorithm.
     * 
     * @param oid the object identifier
     * @return true if the OID is for a classical algorithm, false otherwise
     */
    public static boolean isClassical(String oid) {
        AlgorithmType type = getAlgorithmType(oid);
        return type != null && (type == AlgorithmType.CLASSICAL || type == AlgorithmType.CLASSICAL_SIGNATURE);
    }

    /**
     * Checks if the given OID corresponds to a hybrid certificate extension.
     * 
     * @param oid the object identifier
     * @return true if the OID is for a hybrid X.509 extension, false otherwise
     */
    public static boolean isHybridExtension(String oid) {
        return getAlgorithmType(oid) == AlgorithmType.X509_EXTENSION;
    }

    /**
     * Registers an OID with its name and type in the internal maps.
     * 
     * @param oid the object identifier
     * @param name the algorithm name
     * @param type the algorithm type
     */
    private static void registerOID(String oid, String name, AlgorithmType type) {
        OID_TO_NAME.put(oid, name);
        NAME_TO_OID.put(name, oid);
        OID_TO_TYPE.put(oid, type);
    }

    // ============================================================================
    // Utility Methods
    // ============================================================================

    /**
     * Returns a formatted string representation of this OID registry.
     * 
     * @return a string with all registered OIDs
     */
    public static String dumpRegistry() {
        StringBuilder sb = new StringBuilder();
        sb.append("=== NIST PQC OID Registry ===\n");
        sb.append("ML-DSA Algorithms:\n");
        sb.append("  ML-DSA-44: ").append(OID_ML_DSA_44).append("\n");
        sb.append("  ML-DSA-65: ").append(OID_ML_DSA_65).append("\n");
        sb.append("  ML-DSA-87: ").append(OID_ML_DSA_87).append("\n");
        sb.append("Hybrid Extensions:\n");
        sb.append("  altSignatureAlgorithm: ").append(OID_ALT_SIGNATURE_ALGORITHM).append("\n");
        sb.append("  altSignatureValue: ").append(OID_ALT_SIGNATURE_VALUE).append("\n");
        sb.append("  subjectAltPublicKeyInfo: ").append(OID_SUBJECT_ALT_PUBLIC_KEY_INFO).append("\n");
        return sb.toString();
    }

    // ============================================================================
    // Enum: Algorithm Type
    // ============================================================================

    /**
     * Enumeration of algorithm types for classification.
     */
    public enum AlgorithmType {
        /** Post-quantum signature algorithm (ML-DSA) */
        PQC_SIGNATURE,

        /** Post-quantum key encapsulation mechanism (reserved; unused) */
        PQC_KEM,

        /** Classical asymmetric algorithm (RSA, ECDSA) */
        CLASSICAL,
        
        /** Classical signature scheme (SHA256withRSA, etc.) */
        CLASSICAL_SIGNATURE,
        
        /** X.509 v3 extension for hybrid certificates */
        X509_EXTENSION;
    }

    // Prevent instantiation
    private AlgorithmOIDRegistry() {
    }
}
