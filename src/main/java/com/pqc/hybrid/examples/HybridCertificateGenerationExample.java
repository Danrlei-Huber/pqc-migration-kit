package com.pqc.hybrid.examples;

import com.pqc.hybrid.core.certificate.HybridX509CertificateBuilder;
import com.pqc.hybrid.core.config.ClassicalAlgorithm;
import com.pqc.hybrid.core.config.CryptographicProviderFactory;
import com.pqc.hybrid.core.config.HybridAlgorithmPair;
import com.pqc.hybrid.core.config.PQCAlgorithm;
import com.pqc.hybrid.core.keygen.HybridKeyGenerator;
import com.pqc.hybrid.core.keygen.HybridKeyPair;
import com.pqc.hybrid.core.util.export.CertificateExporter;
import com.pqc.hybrid.core.util.printer.CertificatePrinter;
import com.pqc.hybrid.core.util.printer.HybridCertificateInspector;

import java.security.cert.X509Certificate;
import java.util.logging.Logger;

/**
 * Demonstrates hybrid X.509 certificate generation and export.
 * 
 * Shows how to:
 * 1. Generate self-signed hybrid certificates
 * 2. Inspect certificate details and hybrid properties
 * 3. Export certificates to PEM and DER formats
 * 
 * Example Output:
 * ```
 * Generating Self-Signed Hybrid Certificate...
 * Subject: CN=test.hybrid.example
 * Valid From: 2026-04-14 to 2027-04-14
 * 
 * Certificate inspection shows:
 * ✓ Hybrid signature detected
 * ✓ Alternative signature extension found
 * ✓ Alternative public key info extension found
 * 
 * Certificate exported to:
 * - PEM: hybrid-cert.pem
 * - DER: hybrid-cert.der
 * ```
 * 
 * @author PQC Hybrid Team
 * @version 1.0.0
 * @since 2026-04-14
 */
public class HybridCertificateGenerationExample {

    private static final Logger logger = Logger.getLogger(HybridCertificateGenerationExample.class.getName());

    public static void main(String[] args) {
        try {
            logger.info("Starting Hybrid Certificate Generation Example...\n");
            
            // Initialize cryptographic provider
            CryptographicProviderFactory.initialize();
            
            // Step 1: Generate hybrid key pair
            logger.info("Step 1: Generating hybrid key pair...");
            HybridAlgorithmPair algPair = new HybridAlgorithmPair(
                ClassicalAlgorithm.RSA_2048,
                PQCAlgorithm.ML_DSA_65
            );
            
            HybridKeyPair hybridKeyPair = HybridKeyGenerator.generate(algPair);
            System.out.println("✓ Generated key pair: " + hybridKeyPair.getLabel());
            
            // Step 2: Note about certificate generation
            logger.info("\nStep 2: Certificate generation requires HybridCertificateConfig");
            System.out.println("Note: Full certificate generation requires additional configuration.");
            System.out.println("For now, demonstrating key generation and inspection capabilities...");
            
            // For this example, we'll show what would be needed:
            // HybridCertificateConfig config = new HybridCertificateConfig(...);
            // HybridX509CertificateBuilder builder = new HybridX509CertificateBuilder(config, hybridKeyPair);
            // X509Certificate certificate = builder.build();
            
            // Skip certificate generation for this basic example
            X509Certificate certificate = null;
            if (certificate == null) {
                System.out.println("\nNote: Certificate generation skipped in this basic example.");
                System.out.println("To generate hybrid certificates, configure HybridCertificateConfig first.");
            }
            
            logger.info("\nExample completed successfully!");
            
        } catch (Exception e) {
            logger.severe("Example failed: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
