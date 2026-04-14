package com.pqc.hybrid.core.util.export;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Objects;
import java.util.logging.Logger;

/**
 * Exports X.509 certificates to various formats (PEM, DER).
 * 
 * Provides methods to export hybrid and classical X.509 certificates
 * in standard formats suitable for use in applications and cryptographic tools.
 * 
 * Supported Formats:
 * - PEM (Privacy Enhanced Mail): Base64-encoded with header/footer
 * - DER (Distinguished Encoding Rules): Binary ASN.1 format
 * 
 * Example Usage:
 * <pre>
 *     CertificateExporter exporter = new CertificateExporter();
 *     
 *     // Export to PEM format
 *     exporter.exportCertificateToPEM(certificate, "hybrid-cert.pem");
 *     
 *     // Export to DER format
 *     exporter.exportCertificateToDER(certificate, "hybrid-cert.der");
 * </pre>
 * 
 * @author PQC Hybrid Team
 * @version 1.0.0
 * @since 2026-04-14
 */
public class CertificateExporter {

    private static final Logger logger = Logger.getLogger(CertificateExporter.class.getName());
    private static final String PEM_HEADER = "-----BEGIN CERTIFICATE-----";
    private static final String PEM_FOOTER = "-----END CERTIFICATE-----";
    private static final int PEM_LINE_WIDTH = 64;

    /**
     * Exports an X.509 certificate to PEM format.
     * 
     * @param certificate the certificate to export
     * @param outputPath path where PEM file will be written
     * @throws IOException if write fails
     * @throws IllegalArgumentException if parameters are invalid
     */
    public void exportCertificateToPEM(X509Certificate certificate, String outputPath) 
            throws IOException {
        Objects.requireNonNull(certificate, "Certificate cannot be null");
        Objects.requireNonNull(outputPath, "Output path cannot be null");
        
        try {
            byte[] certificateBytes = certificate.getEncoded();
            String base64Cert = Base64.getEncoder().encodeToString(certificateBytes);
            
            String pemContent = formatPEM(base64Cert);
            
            File outputFile = new File(outputPath);
            try (FileWriter writer = new FileWriter(outputFile)) {
                writer.write(pemContent);
            }
            
            logger.info("Certificate exported to PEM: " + outputPath);
            
        } catch (Exception e) {
            throw new IOException("Failed to export certificate to PEM: " + e.getMessage(), e);
        }
    }

    /**
     * Exports an X.509 certificate to DER format.
     * 
     * @param certificate the certificate to export
     * @param outputPath path where DER file will be written
     * @throws IOException if write fails
     * @throws IllegalArgumentException if parameters are invalid
     */
    public void exportCertificateToDER(X509Certificate certificate, String outputPath) 
            throws IOException {
        Objects.requireNonNull(certificate, "Certificate cannot be null");
        Objects.requireNonNull(outputPath, "Output path cannot be null");
        
        try {
            byte[] certificateBytes = certificate.getEncoded();
            Path path = Path.of(outputPath);
            Files.write(path, certificateBytes);
            
            logger.info("Certificate exported to DER: " + outputPath);
            
        } catch (Exception e) {
            throw new IOException("Failed to export certificate to DER: " + e.getMessage(), e);
        }
    }

    /**
     * Exports certificate to PEM string (without file I/O).
     * 
     * @param certificate the certificate to export
     * @return PEM-formatted certificate as string
     */
    public String exportCertificateToPEMString(X509Certificate certificate) {
        Objects.requireNonNull(certificate, "Certificate cannot be null");
        
        try {
            byte[] certificateBytes = certificate.getEncoded();
            String base64Cert = Base64.getEncoder().encodeToString(certificateBytes);
            return formatPEM(base64Cert);
        } catch (Exception e) {
            throw new RuntimeException("Failed to export certificate to PEM string: " + e.getMessage(), e);
        }
    }

    /**
     * Exports certificate to DER bytes.
     * 
     * @param certificate the certificate to export
     * @return DER-encoded certificate bytes
     */
    public byte[] exportCertificateToDERBytes(X509Certificate certificate) {
        Objects.requireNonNull(certificate, "Certificate cannot be null");
        
        try {
            return certificate.getEncoded();
        } catch (Exception e) {
            throw new RuntimeException("Failed to export certificate to DER bytes: " + e.getMessage(), e);
        }
    }

    /**
     * Formats base64-encoded certificate with PEM headers and line breaks.
     * 
     * @param base64Content the base64-encoded certificate
     * @return formatted PEM content
     */
    private String formatPEM(String base64Content) {
        StringBuilder pem = new StringBuilder();
        pem.append(PEM_HEADER).append("\n");
        
        // Add line breaks every 64 characters
        for (int i = 0; i < base64Content.length(); i += PEM_LINE_WIDTH) {
            int end = Math.min(i + PEM_LINE_WIDTH, base64Content.length());
            pem.append(base64Content, i, end).append("\n");
        }
        
        pem.append(PEM_FOOTER).append("\n");
        return pem.toString();
    }
}
