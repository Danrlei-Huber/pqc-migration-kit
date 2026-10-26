package com.pqc.hybrid.examples;

import com.pqc.hybrid.core.api.PQCHybridCertificateAPI;
import com.pqc.hybrid.core.config.ClassicalAlgorithm;
import com.pqc.hybrid.core.config.HybridAlgorithmPair;
import com.pqc.hybrid.core.config.HybridCertificateConfig;
import com.pqc.hybrid.core.config.PQCAlgorithm;
import com.pqc.hybrid.core.keygen.HybridKeyPair;
import com.pqc.hybrid.core.util.export.CertificateExporter;
import com.pqc.hybrid.core.util.printer.CertificatePrinter;
import com.pqc.hybrid.core.util.printer.HybridCertificateInspector;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.util.logging.LogManager;

/**
 * Demonstrates hybrid X.509 certificate generation, inspection and export.
 *
 * Shows how to:
 * 1. Initialize the library through the public API
 * 2. Generate a hybrid key pair (RSA-2048 + ML-DSA-65)
 * 3. Configure and build a self-signed hybrid certificate
 * 4. Inspect certificate details and hybrid (Catalyst) properties
 * 5. Export the certificate to PEM and DER files
 *
 * Output files are written under {@code target/examples-output/} (git-ignored).
 *
 * <p>Pass {@code -v} / {@code --verbose} to keep the library's INFO log lines.
 *
 * @author PQC Hybrid Team
 * @version 1.0.0-BETA
 */
public class HybridCertificateGenerationExample {

    public static void main(String[] args) {
        boolean verbose = args.length > 0 && (args[0].equals("-v") || args[0].equals("--verbose"));
        if (!verbose) {
            LogManager.getLogManager().reset();
        }

        System.out.println("╔════════════════════════════════════════════════════════════╗");
        System.out.println("║  PQC Hybrid Certificates - Generation, Inspection & Export  ║");
        System.out.println("╚════════════════════════════════════════════════════════════╝\n");

        try {
            // Step 1: Initialize the library through the public API.
            System.out.println("Step 1: Initialize PQC Hybrid Library...");
            PQCHybridCertificateAPI api = new PQCHybridCertificateAPI();
            api.initialize();
            System.out.println("   API initialized (v" + api.getVersion() + ")\n");

            // Step 2: Generate the hybrid key pair.
            System.out.println("Step 2: Generate Hybrid Key Pair (RSA-2048 + ML-DSA-65)...");
            HybridAlgorithmPair algPair = new HybridAlgorithmPair(
                    ClassicalAlgorithm.RSA_2048, PQCAlgorithm.ML_DSA_65);
            HybridKeyPair keyPair = api.generateHybridKeyPair(algPair);
            System.out.println("   Key pair: " + keyPair.getLabel() + "\n");

            // Step 3: Configure and build a self-signed hybrid certificate.
            System.out.println("Step 3: Build Self-Signed Hybrid Certificate...");
            String subjectDN = "CN=test.hybrid.example,O=PQC TCC,C=BR";
            HybridCertificateConfig config = HybridCertificateConfig.builder()
                    .withAlgorithmPair(algPair)
                    .withSubjectDN(subjectDN)
                    .withIssuerDN(subjectDN)   // self-signed: subject == issuer
                    .withValidityDays(365)
                    .build();
            X509Certificate certificate = api.generateHybridCertificate(config, keyPair);
            System.out.println("   Certificate built for: " + certificate.getSubjectX500Principal() + "\n");

            // Step 4: Inspect the certificate and its hybrid (Catalyst) properties.
            System.out.println("Step 4: Inspect Certificate...");
            new CertificatePrinter().printCertificate(certificate);
            HybridCertificateInspector inspector = new HybridCertificateInspector();
            inspector.inspectCertificate(certificate);
            System.out.println("   Detected as hybrid: " + inspector.isHybridCertificate(certificate) + "\n");

            // Step 5: Export the certificate to PEM and DER.
            System.out.println("Step 5: Export Certificate (PEM + DER)...");
            Path outDir = Path.of("target", "examples-output");
            Files.createDirectories(outDir);
            String pemPath = outDir.resolve("hybrid-cert.pem").toString();
            String derPath = outDir.resolve("hybrid-cert.der").toString();
            CertificateExporter exporter = new CertificateExporter();
            exporter.exportCertificateToPEM(certificate, pemPath);
            exporter.exportCertificateToDER(certificate, derPath);
            System.out.println("   PEM: " + pemPath);
            System.out.println("   DER: " + derPath + "\n");

            System.out.println("Certificate generation example completed successfully!\n");

        } catch (Exception e) {
            System.err.println("Example failed: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }
}
