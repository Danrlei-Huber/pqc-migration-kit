package com.pqc.hybrid.examples;

import com.pqc.hybrid.core.api.PQCHybridCertificateAPI;
import com.pqc.hybrid.core.config.HybridAlgorithmPair;
import com.pqc.hybrid.core.config.HybridCertificateConfig;
import com.pqc.hybrid.core.certificate.HybridX509CertificateBuilder;
import com.pqc.hybrid.core.keygen.HybridKeyPair;
import com.pqc.hybrid.core.exception.PQCHybridException;

import java.security.cert.X509Certificate;
import java.util.Date;

/**
 * Example: Generate a Hybrid X.509 Digital Certificate
 * 
 * This example demonstrates how to:
 * 1. Initialize the PQC Hybrid Library
 * 2. Choose security level and algorithm pair
 * 3. Generate hybrid key pair (classical + PQC)
 * 4. Configure certificate parameters
 * 5. Build and generate a hybrid certificate
 * 
 * Output: A hybrid X.509 certificate with dual classical + PQC signatures
 * 
 * @author PQC Hybrid Team
 * @version 1.0.0-BETA
 */
public class GenerateCertificateExample {

    public static void main(String[] args) {
        System.out.println("╔════════════════════════════════════════════════════════════╗");
        System.out.println("║  PQC Hybrid Certificates - Certificate Generation Example   ║");
        System.out.println("╚════════════════════════════════════════════════════════════╝\n");

        try {
            // ═══════════════════════════════════════════════════════════════════════════
            // Step 1: Initialize API
            // ═══════════════════════════════════════════════════════════════════════════
            System.out.println("📦 Step 1: Initialize PQC Hybrid Library...");
            PQCHybridCertificateAPI api = new PQCHybridCertificateAPI();
            api.initialize();
            System.out.println("   ✅ API initialized (v" + api.getVersion() + ")");
            System.out.println();

            // ═══════════════════════════════════════════════════════════════════════════
            // Step 2: Choose Security Level
            // ═══════════════════════════════════════════════════════════════════════════
            System.out.println("🔐 Step 2: Choose Security Level...");
            int securityLevel = 192;  // 128, 192, or 256 bits
            System.out.println("   Selected security level: " + securityLevel + " bits");
            HybridAlgorithmPair algorithmPair = HybridAlgorithmPair.recommended(securityLevel);
            System.out.println("   Algorithms: " + algorithmPair.getDescription());
            System.out.println("   Balanced: " + algorithmPair.isSecurityBalanced());
            System.out.println("   NIST Standardized: " + algorithmPair.areNistStandardized());
            System.out.println();

            // ═══════════════════════════════════════════════════════════════════════════
            // Step 3: Generate Hybrid Key Pair
            // ═══════════════════════════════════════════════════════════════════════════
            System.out.println("🔑 Step 3: Generate Hybrid Key Pair...");
            long startTime = System.currentTimeMillis();
            HybridKeyPair keyPair = api.generateHybridKeyPair(algorithmPair);
            long endTime = System.currentTimeMillis();
            System.out.println("   ✅ Key pair generated: " + keyPair.getLabel());
            System.out.println("   Generation time: " + (endTime - startTime) + " ms");
            System.out.println("   Classical algorithm: " + keyPair.getClassicalAlgorithm());
            System.out.println("   PQC algorithm: " + keyPair.getPQCAlgorithm());
            System.out.println();

            // ═══════════════════════════════════════════════════════════════════════════
            // Step 4: Configure Certificate
            // ═══════════════════════════════════════════════════════════════════════════
            System.out.println("📋 Step 4: Configure Certificate Parameters...");
            HybridCertificateConfig config = HybridCertificateConfig.builder()
                .withAlgorithmPair(algorithmPair)
                .withSubjectDN("CN=secure.example.com,O=Example Organization,C=BR")
                .withIssuerDN("CN=Example CA,O=Example Organization,C=BR")
                .withValidityDays(365)
                .withSerialNumber(1)
                .build();
            System.out.println("   Subject DN: " + config.getSubjectDN());
            System.out.println("   Issuer DN:  " + config.getIssuerDN());
            System.out.println("   Validity: " + config.getValidityDays() + " days");
            System.out.println();

            // ═══════════════════════════════════════════════════════════════════════════
            // Step 5: Build Certificate
            // ═══════════════════════════════════════════════════════════════════════════
            System.out.println("🏗️  Step 5: Build Hybrid X.509 Certificate...");
            startTime = System.currentTimeMillis();
            X509Certificate certificate = new HybridX509CertificateBuilder(config, keyPair)
                .build();
            endTime = System.currentTimeMillis();
            System.out.println("   ✅ Certificate built successfully");
            System.out.println("   Build time: " + (endTime - startTime) + " ms");
            System.out.println();

            // ═══════════════════════════════════════════════════════════════════════════
            // Display Certificate Information
            // ═══════════════════════════════════════════════════════════════════════════
            System.out.println("📜 Certificate Information:");
            System.out.println("   Subject: " + certificate.getSubjectDN());
            System.out.println("   Issuer:  " + certificate.getIssuerDN());
            System.out.println("   Serial#: " + certificate.getSerialNumber());
            System.out.println("   Valid From: " + certificate.getNotBefore());
            System.out.println("   Valid Until: " + certificate.getNotAfter());
            System.out.println("   Signature Algorithm: " + certificate.getSigAlgName());
            System.out.println("   Public Key Algorithm: " + certificate.getPublicKey().getAlgorithm());
            System.out.println("   Extensions Count: " + certificate.getExtensionValue("2.5.29.14")); // subjectKeyIdentifier
            System.out.println();

            // ═══════════════════════════════════════════════════════════════════════════
            // Display Signature Sizes
            // ═══════════════════════════════════════════════════════════════════════════
            System.out.println("📊 Hybrid Signature Details:");
            byte[] signature = certificate.getSignature();
            System.out.println("   Primary Signature Size: " + signature.length + " bytes");
            System.out.println();

            System.out.println("✅ Certificate generation example completed successfully!");
            System.out.println();

        } catch (PQCHybridException e) {
            System.err.println("❌ PQC Hybrid Error: " + e.getMessage());
            e.printStackTrace();
        } catch (Exception e) {
            System.err.println("❌ Unexpected Error: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
