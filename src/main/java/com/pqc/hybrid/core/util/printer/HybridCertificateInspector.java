package com.pqc.hybrid.core.util.printer;

import com.pqc.hybrid.core.common.oid.AlgorithmOIDRegistry;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
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
 */
public class HybridCertificateInspector {

    private static final Logger logger = Logger.getLogger(HybridCertificateInspector.class.getName());
    
    // Canonical ITU-T X.509 (2019) alternative-signature extension OIDs — the production
    // "Catalyst" path (2.5.29.72/73/74). Sourced from the shared registry so the inspector
    // stays in sync with the rest of the library.
    private static final String ALT_SIGNATURE_ALGORITHM_OID = AlgorithmOIDRegistry.OID_ALT_SIGNATURE_ALGORITHM;
    private static final String ALT_SIGNATURE_VALUE_OID = AlgorithmOIDRegistry.OID_ALT_SIGNATURE_VALUE;
    private static final String SUBJECT_ALT_PUBKEY_INFO_OID = AlgorithmOIDRegistry.OID_SUBJECT_ALT_PUBLIC_KEY_INFO;

    // Legacy draft OIDs (draft-ietf-lamps-*) kept ONLY as a fallback so older/reference
    // certificates are still recognised; they are not used by the production path.
    private static final String LEGACY_ALT_SIGNATURE_VALUE_OID = "1.3.6.1.5.5.7.1.16";
    private static final String LEGACY_SUBJECT_ALT_PUBKEY_INFO_OID = "1.3.6.1.5.5.7.1.15";

    private static boolean isAltSignatureValueOid(String oid) {
        return ALT_SIGNATURE_VALUE_OID.equals(oid) || LEGACY_ALT_SIGNATURE_VALUE_OID.equals(oid);
    }

    private static boolean isSubjectAltPubKeyOid(String oid) {
        return SUBJECT_ALT_PUBKEY_INFO_OID.equals(oid) || LEGACY_SUBJECT_ALT_PUBKEY_INFO_OID.equals(oid);
    }

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
        sb.append("CERTIFICATE INFORMATION\n");
        sb.append("  • Subject: ").append(certificate.getSubjectDN()).append("\n");
        sb.append("  • Issuer: ").append(certificate.getIssuerDN()).append("\n");
        sb.append("  • Serial: ").append(certificate.getSerialNumber()).append("\n");
        sb.append("  • Version: v").append(certificate.getVersion()).append("\n\n");

        // Signature Algorithm
        sb.append("SIGNATURE CONFIGURATION\n");
        sb.append("  • Primary Algorithm: ").append(certificate.getSigAlgName()).append("\n");
        sb.append("  • Algorithm OID: ").append(certificate.getSigAlgOID()).append("\n");
        sb.append("  • Signature Length: ").append(certificate.getSignature().length).append(" bytes\n\n");

        // Public Key
        sb.append("PUBLIC KEY\n");
        String keyAlgo = certificate.getPublicKey().getAlgorithm();
        int keySize = getKeySize(certificate.getPublicKey());
        sb.append("  • Algorithm: ").append(keyAlgo);
        if (keySize > 0) {
            sb.append(" (").append(keySize).append(" bits)");
        }
        sb.append("\n\n");

        // Extensions Analysis
        sb.append("EXTENSIONS ANALYSIS\n");
        sb.append(analyzeExtensions(certificate));

        // Hybrid Signature Detection
        sb.append("\nHYBRID SIGNATURE DETECTION\n");
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
                if (isAltSignatureValueOid(oid)) {
                    hasAltSignature = true;
                }
                if (isSubjectAltPubKeyOid(oid)) {
                    hasAltPublicKey = true;
                }
            }

            for (String oid : certificate.getNonCriticalExtensionOIDs()) {
                nonCriticalCount++;
                if (isAltSignatureValueOid(oid)) {
                    hasAltSignature = true;
                }
                if (isSubjectAltPubKeyOid(oid)) {
                    hasAltPublicKey = true;
                }
            }
            
            sb.append("  • Critical Extensions: ").append(criticalCount).append("\n");
            sb.append("  • Non-Critical Extensions: ").append(nonCriticalCount).append("\n");
            
            if (hasAltSignature) {
                sb.append("  • Alternative Signature Value (detected)\n");
            }
            if (hasAltPublicKey) {
                sb.append("  • Alternative Public Key Info (detected)\n");
            }

            if (!hasAltSignature && !hasAltPublicKey) {
                sb.append("  • No hybrid-specific extensions detected\n");
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

        String keyAlgo = certificate.getPublicKey().getAlgorithm();
        boolean isRSA = keyAlgo.contains("RSA");
        boolean isECDSA = keyAlgo.contains("EC") || keyAlgo.contains("ECDSA");

        // Production "Catalyst" model: the PRIMARY signature is classical (RSA/ECDSA) and the
        // post-quantum side lives in the alternative-signature extensions (2.5.29.72/73/74).
        // Also handle the inline case where the primary signature itself is PQC.
        boolean primaryIsPQC = sigAlgName.contains("ML-DSA")
                || sigAlgName.contains("SLH-DSA")
                || sigAlgName.contains("ML-KEM");
        boolean hasAltPQC = isHybridCertificate(certificate);

        if ((isRSA || isECDSA) && (hasAltPQC || primaryIsPQC)) {
            String classical = isRSA ? "RSA" : "ECDSA";
            String pqc = resolveAltSignatureAlgorithmName(certificate);
            if (pqc == null) {
                pqc = primaryIsPQC ? sigAlgName : "PQC (alt-signature)";
            }
            sb.append("  HYBRID SIGNATURE DETECTED\n");
            sb.append("  • Scheme: ").append(classical).append(" (classical) + ")
                    .append(pqc).append(" (post-quantum)\n");
            sb.append("  • Primary signature: ").append(sigAlgName).append("\n");
            sb.append("  • PQC carried in: ")
                    .append(hasAltPQC ? "alternative-signature extensions (Catalyst)"
                                      : "primary signature (inline)")
                    .append("\n");
        } else {
            sb.append("  • Certificate uses standard (non-hybrid) signature\n");
            sb.append("  • Type: ").append(sigAlgName).append("\n");
        }

        return sb.toString();
    }

    /**
     * Resolves the human-readable algorithm name from the certificate's
     * {@code altSignatureAlgorithm} (2.5.29.73) extension, e.g. {@code "ML-DSA-87"}.
     * Returns {@code null} if the extension is absent or cannot be parsed.
     *
     * @param certificate the certificate
     * @return the PQC algorithm name, its OID if unmapped, or {@code null}
     */
    private String resolveAltSignatureAlgorithmName(X509Certificate certificate) {
        try {
            byte[] extValue = certificate.getExtensionValue(ALT_SIGNATURE_ALGORITHM_OID);
            if (extValue == null) {
                return null;
            }
            ASN1OctetString octetStr = ASN1OctetString.getInstance(extValue);
            AlgorithmIdentifier algId = AlgorithmIdentifier.getInstance(octetStr.getOctets());
            String oid = algId.getAlgorithm().getId();
            String name = AlgorithmOIDRegistry.getAlgorithmName(oid);
            return name != null ? name : oid;
        } catch (Exception e) {
            logger.fine("Could not resolve altSignatureAlgorithm name: " + e.getMessage());
            return null;
        }
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
                if (isAltSignatureValueOid(oid) || isSubjectAltPubKeyOid(oid)) {
                    return true;
                }
            }

            for (String oid : certificate.getNonCriticalExtensionOIDs()) {
                if (isAltSignatureValueOid(oid) || isSubjectAltPubKeyOid(oid)) {
                    return true;
                }
            }
        } catch (Exception e) {
            // Detection failed
        }

        return false;
    }
}
