package com.pqc.hybrid.core.common.oid;

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
 * - ML-KEM (Key Encapsulation): 2.16.840.1.101.3.4.4.x (NIST 2024)
 * - SLH-DSA (Stateless Hash-Based): 2.16.840.1.101.3.4.3.x (NIST 2024)
 * - Falcon (Alternate): 1.3.9999.3.x (NIST 2022)
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
    // ML-KEM OIDs (Module-Lattice-Based Key-Encapsulation Mechanism)
    // NIST FIPS 203: 2.16.840.1.101.3.4.4.x
    // ============================================================================
    
    /** OID for ML-KEM-512 (128-bit security, NIST level 1) */
    public static final String OID_ML_KEM_512 = "2.16.840.1.101.3.4.4.1";
    
    /** OID for ML-KEM-768 (192-bit security, NIST level 3) */
    public static final String OID_ML_KEM_768 = "2.16.840.1.101.3.4.4.2";
    
    /** OID for ML-KEM-1024 (256-bit security, NIST level 5) */
    public static final String OID_ML_KEM_1024 = "2.16.840.1.101.3.4.4.3";


    // ============================================================================
    // SLH-DSA OIDs (Stateless Hash-Based Digital Signature Algorithm)
    // NIST FIPS 205: 2.16.840.1.101.3.4.3.x (same range as ML-DSA)
    // ============================================================================
    
    /** OID for SLH-DSA-SHA2-128s (128-bit security, SHA-256 small) */
    public static final String OID_SLH_DSA_SHA2_128S = "2.16.840.1.101.3.4.3.20";
    
    /** OID for SLH-DSA-SHA2-128f (128-bit security, SHA-256 fast) */
    public static final String OID_SLH_DSA_SHA2_128F = "2.16.840.1.101.3.4.3.21";
    
    /** OID for SLH-DSA-SHA2-192s (192-bit security, SHA-256 small) */
    public static final String OID_SLH_DSA_SHA2_192S = "2.16.840.1.101.3.4.3.22";
    
    /** OID for SLH-DSA-SHA2-192f (192-bit security, SHA-256 fast) */
    public static final String OID_SLH_DSA_SHA2_192F = "2.16.840.1.101.3.4.3.23";
    
    /** OID for SLH-DSA-SHA2-256s (256-bit security, SHA-256 small) */
    public static final String OID_SLH_DSA_SHA2_256S = "2.16.840.1.101.3.4.3.24";
    
    /** OID for SLH-DSA-SHA2-256f (256-bit security, SHA-256 fast) */
    public static final String OID_SLH_DSA_SHA2_256F = "2.16.840.1.101.3.4.3.25";


    // ============================================================================
    // Falcon OIDs (Alternate lattice-based signature algorithm)
    // Not yet NIST standardized (provisional): 1.3.9999.3.x
    // ============================================================================
    
    /** OID for Falcon-512 (128-bit security) */
    public static final String OID_FALCON_512 = "1.3.9999.3.1";
    
    /** OID for Falcon-1024 (256-bit security) */
    public static final String OID_FALCON_1024 = "1.3.9999.3.4";


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
    // X.509 Hybrid Certificate Extension OIDs (RFC 5280 / draft-hybrid-x509)
    // ============================================================================
    
    /** OID for altSignatureAlgorithm extension (2.5.29.62) - CRITICAL */
    public static final String OID_ALT_SIGNATURE_ALGORITHM = "2.5.29.62";
    
    /** OID for altSignatureValue extension (2.5.29.63) - CRITICAL */
    public static final String OID_ALT_SIGNATURE_VALUE = "2.5.29.63";
    
    /** OID for subjectAltPublicKeyInfo extension (2.5.29.72) - CRITICAL */
    public static final String OID_SUBJECT_ALT_PUBLIC_KEY_INFO = "2.5.29.72";


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
        
        // ML-KEM mappings
        registerOID(OID_ML_KEM_512, "ML-KEM-512", AlgorithmType.PQC_KEM);
        registerOID(OID_ML_KEM_768, "ML-KEM-768", AlgorithmType.PQC_KEM);
        registerOID(OID_ML_KEM_1024, "ML-KEM-1024", AlgorithmType.PQC_KEM);
        
        // SLH-DSA mappings
        registerOID(OID_SLH_DSA_SHA2_128S, "SLH-DSA-SHA2-128s", AlgorithmType.PQC_SIGNATURE);
        registerOID(OID_SLH_DSA_SHA2_128F, "SLH-DSA-SHA2-128f", AlgorithmType.PQC_SIGNATURE);
        registerOID(OID_SLH_DSA_SHA2_192S, "SLH-DSA-SHA2-192s", AlgorithmType.PQC_SIGNATURE);
        registerOID(OID_SLH_DSA_SHA2_192F, "SLH-DSA-SHA2-192f", AlgorithmType.PQC_SIGNATURE);
        registerOID(OID_SLH_DSA_SHA2_256S, "SLH-DSA-SHA2-256s", AlgorithmType.PQC_SIGNATURE);
        registerOID(OID_SLH_DSA_SHA2_256F, "SLH-DSA-SHA2-256f", AlgorithmType.PQC_SIGNATURE);
        
        // Falcon mappings
        registerOID(OID_FALCON_512, "Falcon-512", AlgorithmType.PQC_SIGNATURE);
        registerOID(OID_FALCON_1024, "Falcon-1024", AlgorithmType.PQC_SIGNATURE);
        
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
        sb.append("ML-KEM Algorithms:\n");
        sb.append("  ML-KEM-512: ").append(OID_ML_KEM_512).append("\n");
        sb.append("  ML-KEM-768: ").append(OID_ML_KEM_768).append("\n");
        sb.append("  ML-KEM-1024: ").append(OID_ML_KEM_1024).append("\n");
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
        /** Post-quantum signature algorithm (ML-DSA, SLH-DSA, Falcon) */
        PQC_SIGNATURE,
        
        /** Post-quantum key encapsulation mechanism (ML-KEM) */
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
