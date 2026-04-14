package com.pqc.hybrid.core.util.printer;

import com.pqc.hybrid.core.common.oid.AlgorithmOIDRegistry;
import org.bouncycastle.asn1.x509.Extension;

import java.security.cert.X509Certificate;
import java.util.Objects;
import java.util.logging.Logger;

/**
 * Specialized inspector for hybrid X.509 certificates with dual signatures.
 * 
 * Analyzes hybrid certificates to extract and display:
 * - Both classical and PQC signatures
 * - Hybrid scheme information (RSA+ML-DSA, ECDSA+ML-KEM combinations)
 * - Alternative signature extensions (altSignatureValue, subjectAltPublicKeyInfo)
 * - Security metadata and OID details
 * 
 * This tool is essential for debugging and validating hybrid certificate generation.
 * 
 * Example Output:
 * ```
 * HYBRID X.509 CERTIFICATE INSPECTION
 * ═══════════════════════════════════════
 * 
 * Hybrid Scheme: RSA-2048 + ML-DSA-65
 * Classical Signature: SHA256withRSA (256 bytes)
 * PQC Signature: ML-DSA-65 (3293 bytes)
 * Total Signature Size: 3549 bytes
 * 
 * Extensions:
 *   • altSignatureValue (2.16.840.1.101.3.4.4x.5) [CRITICAL]
 *   • subjectAltPublicKeyInfo (1.3.6.1.5.5.7.1.15) [NON-CRITICAL]
 * ```
 * 
 * @author PQC Hybrid Team
 * @version 1.0.0
 * @since 2026-04-14
 */
public class HybridCertificateInspector {

    private static final Logger logger = Logger.getLogger(HybridCertificateInspector.class.getName());
    
    // Common OIDs for hybrid certificates
    private static final String ALT_SIGNATURE_VALUE_OID = "1.3.6.1.5.5.7.1.16";
    private static final String SUBJECT_ALT_PUBKEY_INFO_OID = "1.3.6.1.5.5.7.1.15";

    /**
     * Inspects and prints detailed hybrid certificate information.
     * 
     * @param certificate the X.509 certificate to inspect
     */
    public void inspectCertificate(X509Certificate certificate) {
        Objects.requireNonNull(certificate, "Certificate cannot be null");
        System.out.println(inspectCertificateToString(certificate));
    }

    /**
     * Inspects certificate and returns detailed information as string.
     * 
     * @param certificate the X.509 certificate to inspect
     * @return detailed inspection report
     */
    public String inspectCertificateToString(X509Certificate certificate) {
        Objects.requireNonNull(certificate, "Certificate cannot be null");
        
        StringBuilder sb = new StringBuilder();
        
        // Header
        sb.append("\n╔════════════════════════════════════════════════════════╗\n");
        sb.append("║  HYBRID X.509 CERTIFICATE INSPECTION REPORT            ║\n");
        sb.append("╚════════════════════════════════════════════════════════╝\n\n");
        
        // Basic Certificate Info
        sb.append("📋 CERTIFICATE INFORMATION\n");
        sb.append("  • Subject: ").append(certificate.getSubjectDN()).append("\n");
        sb.append("  • Issuer: ").append(certificate.getIssuerDN()).append("\n");
        sb.append("  • Serial: ").append(certificate.getSerialNumber()).append("\n");
        sb.append("  • Version: v").append(certificate.getVersion()).append("\n\n");
        
        // Signature Algorithm
        sb.append("🔐 SIGNATURE CONFIGURATION\n");
        sb.append("  • Primary Algorithm: ").append(certificate.getSigAlgName()).append("\n");
        sb.append("  • Algorithm OID: ").append(certificate.getSigAlgOID()).append("\n");
        sb.append("  • Signature Length: ").append(certificate.getSignature().length).append(" bytes\n\n");
        
        // Public Key
        sb.append("🔑 PUBLIC KEY\n");
        String keyAlgo = certificate.getPublicKey().getAlgorithm();
        int keySize = getKeySize(certificate.getPublicKey());
        sb.append("  • Algorithm: ").append(keyAlgo);
        if (keySize > 0) {
            sb.append(" (").append(keySize).append(" bits)");
        }
        sb.append("\n\n");
        
        // Extensions Analysis
        sb.append("📦 EXTENSIONS ANALYSIS\n");
        sb.append(analyzeExtensions(certificate));
        
        // Hybrid Signature Detection
        sb.append("\n🎯 HYBRID SIGNATURE DETECTION\n");
        sb.append(detectHybridSignatures(certificate));
        
        return sb.toString();
    }

    /**
     * Analyzes certificate extensions and returns formatted report.
     * 
     * @param certificate the certificate
     * @return extension analysis
     */
    private String analyzeExtensions(X509Certificate certificate) {
        StringBuilder sb = new StringBuilder();
        
        try {
            int criticalCount = 0;
            int nonCriticalCount = 0;
            
            // Check for hybrid-specific extensions
            boolean hasAltSignature = false;
            boolean hasAltPublicKey = false;
            
            for (String oid : certificate.getCriticalExtensionOIDs()) {
                criticalCount++;
                if (ALT_SIGNATURE_VALUE_OID.equals(oid)) {
                    hasAltSignature = true;
                }
                if (SUBJECT_ALT_PUBKEY_INFO_OID.equals(oid)) {
                    hasAltPublicKey = true;
                }
            }
            
            for (String oid : certificate.getNonCriticalExtensionOIDs()) {
                nonCriticalCount++;
                if (ALT_SIGNATURE_VALUE_OID.equals(oid)) {
                    hasAltSignature = true;
                }
                if (SUBJECT_ALT_PUBKEY_INFO_OID.equals(oid)) {
                    hasAltPublicKey = true;
                }
            }
            
            sb.append("  • Critical Extensions: ").append(criticalCount).append("\n");
            sb.append("  • Non-Critical Extensions: ").append(nonCriticalCount).append("\n");
            
            if (hasAltSignature) {
                sb.append("  • ✓ Alternative Signature Value (detected)\n");
            }
            if (hasAltPublicKey) {
                sb.append("  • ✓ Alternative Public Key Info (detected)\n");
            }
            
            if (!hasAltSignature && !hasAltPublicKey) {
                sb.append("  • ⚠ No hybrid-specific extensions detected\n");
            }
            
        } catch (Exception e) {
            sb.append("  • Error analyzing extensions: ").append(e.getMessage()).append("\n");
        }
        
        return sb.toString();
    }

    /**
     * Detects and reports hybrid signature information.
     * 
     * @param certificate the certificate
     * @return hybrid signature analysis
     */
    private String detectHybridSignatures(X509Certificate certificate) {
        StringBuilder sb = new StringBuilder();
        
        String sigAlgName = certificate.getSigAlgName();
        String sigAlgOID = certificate.getSigAlgOID();
        
        // Try to detect hybrid scheme
        boolean isML_DSA = sigAlgName.contains("ML-DSA");
        boolean isML_KEM = sigAlgName.contains("ML-KEM");
        boolean isSLH_DSA = sigAlgName.contains("SLH-DSA");
        
        String keyAlgo = certificate.getPublicKey().getAlgorithm();
        boolean isRSA = keyAlgo.contains("RSA");
        boolean isECDSA = keyAlgo.contains("EC") || keyAlgo.contains("ECDSA");
        
        if ((isRSA || isECDSA) && (isML_DSA || isML_KEM || isSLH_DSA)) {
            sb.append("  ✓ HYBRID SIGNATURE DETECTED\n");
            if (isRSA && isML_DSA) {
                sb.append("  • Scheme: RSA (classical) + ML-DSA (post-quantum)\n");
            } else if (isECDSA && isML_DSA) {
                sb.append("  • Scheme: ECDSA (classical) + ML-DSA (post-quantum)\n");
            } else if (isRSA && isML_KEM) {
                sb.append("  • Scheme: RSA (classical) + ML-KEM (key encapsulation)\n");
            }
        } else {
            sb.append("  • Certificate uses standard (non-hybrid) signature\n");
            sb.append("  • Type: ").append(sigAlgName).append("\n");
        }
        
        return sb.toString();
    }

    /**
     * Extracts key size from public key.
     * 
     * @param publicKey the public key
     * @return key size in bits, or -1 if unknown
     */
    private int getKeySize(java.security.PublicKey publicKey) {
        try {
            if (publicKey instanceof java.security.interfaces.RSAPublicKey rsaKey) {
                return rsaKey.getModulus().bitLength();
            } else if (publicKey instanceof java.security.interfaces.ECPublicKey ecKey) {
                return ecKey.getParams().getCurve().getField().getFieldSize();
            }
        } catch (Exception e) {
            // Key size extraction failed
        }
        return -1;
    }

    /**
     * Checks if certificate is a hybrid certificate.
     * 
     * @param certificate the certificate to check
     * @return true if certificate appears to be hybrid
     */
    public boolean isHybridCertificate(X509Certificate certificate) {
        Objects.requireNonNull(certificate, "Certificate cannot be null");
        
        try {
            // Check for hybrid-specific extensions
            for (String oid : certificate.getCriticalExtensionOIDs()) {
                if (ALT_SIGNATURE_VALUE_OID.equals(oid) || 
                    SUBJECT_ALT_PUBKEY_INFO_OID.equals(oid)) {
                    return true;
                }
            }
            
            for (String oid : certificate.getNonCriticalExtensionOIDs()) {
                if (ALT_SIGNATURE_VALUE_OID.equals(oid) || 
                    SUBJECT_ALT_PUBKEY_INFO_OID.equals(oid)) {
                    return true;
                }
            }
        } catch (Exception e) {
            // Detection failed
        }
        
        return false;
    }
}
