package com.pqc.hybrid.core.util.printer;

import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Objects;
import java.util.logging.Logger;

/**
 * Pretty-prints X.509 certificate details to terminal/console.
 * 
 * Formats certificate information in a human-readable hierarchical structure,
 * suitable for debugging and inspection in terminal environments.
 * 
 * Displays:
 * - Subject DN and Issuer DN
 * - Validity dates (not before, not after)
 * - Serial number
 * - Public key algorithm and size
 * - Extensions and their criticality
 * - Signature algorithm
 * 
 * Example Output:
 * ```
 * X.509v3 Certificate
 * ├── Subject: CN=example.com,O=Company
 * ├── Issuer: CN=CA,O=Company
 * ├── Validity:
 * │   ├── Not Before: 2026-04-14 10:00:00
 * │   └── Not After: 2027-04-14 10:00:00
 * ├── Public Key: RSA-2048
 * └── Signature: SHA256withRSA
 * ```
 * 
 * @author PQC Hybrid Team
 * @version 1.0.0
 * @since 2026-04-14
 */
public class CertificatePrinter {

    private static final Logger logger = Logger.getLogger(CertificatePrinter.class.getName());
    private static final String INDENT = "  ";
    private static final String TREE_BRANCH = "├── ";
    private static final String TREE_END = "└── ";
    private static final String TREE_CONTINUE = "│   ";

    /**
     * Prints certificate details to console.
     * 
     * @param certificate the certificate to print
     */
    public void printCertificate(X509Certificate certificate) {
        Objects.requireNonNull(certificate, "Certificate cannot be null");
        
        System.out.println("\n" + formatCertificate(certificate));
    }

    /**
     * Returns certificate details as formatted string.
     * 
     * @param certificate the certificate to format
     * @return formatted certificate details
     */
    public String formatCertificate(X509Certificate certificate) {
        Objects.requireNonNull(certificate, "Certificate cannot be null");
        
        StringBuilder sb = new StringBuilder();
        
        // Header
        sb.append("X.509v3 Certificate\n");
        
        // Subject
        sb.append(TREE_BRANCH).append("Subject: ").append(certificate.getSubjectDN()).append("\n");
        
        // Issuer
        sb.append(TREE_BRANCH).append("Issuer: ").append(certificate.getIssuerDN()).append("\n");
        
        // Serial Number
        sb.append(TREE_BRANCH).append("Serial: ").append(certificate.getSerialNumber()).append("\n");
        
        // Validity
        sb.append(TREE_BRANCH).append("Validity:\n");
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        sb.append(TREE_CONTINUE).append(TREE_BRANCH)
                .append("Not Before: ").append(sdf.format(certificate.getNotBefore())).append("\n");
        sb.append(TREE_CONTINUE).append(TREE_END)
                .append("Not After: ").append(sdf.format(certificate.getNotAfter())).append("\n");
        
        // Public Key
        String keyAlgo = certificate.getPublicKey().getAlgorithm();
        int keySize = getKeySize(certificate.getPublicKey());
        sb.append(TREE_BRANCH).append("Public Key: ").append(keyAlgo);
        if (keySize > 0) {
            sb.append("-").append(keySize);
        }
        sb.append("\n");
        
        // Signature Algorithm
        sb.append(TREE_BRANCH).append("Signature Algorithm: ").append(certificate.getSigAlgName()).append("\n");
        
        // Extensions
        sb.append(TREE_BRANCH).append("Extensions: ").append(formatExtensions(certificate)).append("\n");
        
        // Signature (partial)
        byte[] signature = certificate.getSignature();
        sb.append(TREE_END).append("Signature Length: ").append(signature.length).append(" bytes");
        
        return sb.toString();
    }

    /**
     * Formats extension information.
     * 
     * @param certificate the certificate
     * @return extension summary
     */
    private String formatExtensions(X509Certificate certificate) {
        try {
            int count = 0;
            boolean hasCritical = false;
            
            for (String oid : certificate.getCriticalExtensionOIDs()) {
                count++;
                hasCritical = true;
                break;
            }
            
            for (String oid : certificate.getNonCriticalExtensionOIDs()) {
                count++;
            }
            
            String label = count + " extension" + (count != 1 ? "s" : "");
            if (hasCritical) {
                label += " (including critical)";
            }
            return label;
            
        } catch (NullPointerException e) {
            return "0 extensions";
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
     * Prints certificate in compact single-line format.
     * 
     * @param certificate the certificate
     * @return single-line summary
     */
    public String formatCompact(X509Certificate certificate) {
        Objects.requireNonNull(certificate, "Certificate cannot be null");
        
        String subject = certificate.getSubjectDN().toString();
        String algo = certificate.getPublicKey().getAlgorithm();
        String sigAlgo = certificate.getSigAlgName();
        
        return String.format("Cert[%s] %s [%s/%s]", 
            certificate.getSerialNumber(),
            subject.length() > 40 ? subject.substring(0, 37) + "..." : subject,
            algo,
            sigAlgo);
    }
}
