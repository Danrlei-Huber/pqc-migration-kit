package com.pqc.hybrid.examples;

import com.pqc.hybrid.core.api.PQCHybridCertificateAPI;
import com.pqc.hybrid.core.keygen.HybridKeyPair;
import com.pqc.hybrid.core.signature.HybridSignaturePair;
import com.pqc.hybrid.core.exception.PQCHybridException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Example: Sign and Verify Data with Hybrid Signatures
 * 
 * This example demonstrates how to:
 * 1. Generate a hybrid key pair
 * 2. Sign data with both classical and PQC algorithms
 * 3. Verify signatures (both must be valid)
 * 4. Handle tampered data detection
 * 
 * Output: Hybrid signatures demonstrating dual security
 * 
 * @author PQC Hybrid Team
 * @version 1.0.0-BETA
 */
public class SignAndVerifyExample {

    public static void main(String[] args) {
        System.out.println("╔════════════════════════════════════════════════════════════╗");
        System.out.println("║  PQC Hybrid Certificates - Sign & Verify Example            ║");
        System.out.println("╚════════════════════════════════════════════════════════════╝\n");

        try {
            // ═══════════════════════════════════════════════════════════════════════════
            // Step 1: Initialize and Generate Keys
            // ═══════════════════════════════════════════════════════════════════════════
            System.out.println("📦 Step 1: Initialize API and Generate Keys...");
            PQCHybridCertificateAPI api = new PQCHybridCertificateAPI();
            api.initialize();
            
            HybridKeyPair keyPair = api.generateHybridKeyPair(256);  // Maximum security
            System.out.println("   ✅ Generated key pair: " + keyPair.getLabel());
            System.out.println("   Classical Algorithm: " + keyPair.getClassicalAlgorithm());
            System.out.println("   PQC Algorithm: " + keyPair.getPQCAlgorithm());
            System.out.println();

            // ═══════════════════════════════════════════════════════════════════════════
            // Step 2: Sign Data
            // ═══════════════════════════════════════════════════════════════════════════
            System.out.println("✍️  Step 2: Sign Important Data...");
            byte[] data = "This is a critical document that needs dual-algorithm protection".getBytes(StandardCharsets.UTF_8);
            System.out.println("   Data to sign: " + new String(data, StandardCharsets.UTF_8));
            System.out.println("   Data size: " + data.length + " bytes");

            long startTime = System.currentTimeMillis();
            HybridSignaturePair signature = api.signData(data, keyPair);
            long endTime = System.currentTimeMillis();
            
            System.out.println("   ✅ Signatures generated:");
            System.out.println("      Classical Signature: " + signature.getClassicalSignatureSize() + " bytes");
            System.out.println("      PQC Signature: " + signature.getPQCSignatureSize() + " bytes");
            System.out.println("      Total: " + (signature.getClassicalSignatureSize() + signature.getPQCSignatureSize()) + " bytes");
            System.out.println("      Signing time: " + (endTime - startTime) + " ms");
            System.out.println();

            // Display signature samples (Base64 encoded)
            System.out.println("   Classical Signature (Base64, first 80 chars):");
            String classicalB64 = Base64.getEncoder().encodeToString(signature.getClassicalSignature());
            System.out.println("      " + classicalB64.substring(0, Math.min(80, classicalB64.length())) + "...");

            System.out.println("   PQC Signature (Base64, first 80 chars):");
            String pqcB64 = Base64.getEncoder().encodeToString(signature.getPQCSignature());
            System.out.println("      " + pqcB64.substring(0, Math.min(80, pqcB64.length())) + "...");
            System.out.println();

            // ═══════════════════════════════════════════════════════════════════════════
            // Step 3: Verify Valid Signature
            // ═══════════════════════════════════════════════════════════════════════════
            System.out.println("✅ Step 3: Verify Valid Signature...");
            startTime = System.currentTimeMillis();
            boolean isValid = api.verifySignature(data, signature, keyPair);
            endTime = System.currentTimeMillis();

            System.out.println("   Verification result: " + (isValid ? "✅ VALID" : "❌ INVALID"));
            System.out.println("   Verification time: " + (endTime - startTime) + " ms");
            System.out.println("   ⚠️  NOTE: Both classical AND PQC signatures must be valid for success");
            System.out.println();

            // ═══════════════════════════════════════════════════════════════════════════
            // Step 4: Detect Tampered Data
            // ═══════════════════════════════════════════════════════════════════════════
            System.out.println("🔍 Step 4: Detect Tampered Data...");
            byte[] tamperedData = "This is a FORGED document".getBytes(StandardCharsets.UTF_8);
            System.out.println("   Tampered data: " + new String(tamperedData, StandardCharsets.UTF_8));

            startTime = System.currentTimeMillis();
            boolean isTamperedValid = api.verifySignature(tamperedData, signature, keyPair);
            endTime = System.currentTimeMillis();

            System.out.println("   Verification result: " + (isTamperedValid ? "✅ VALID" : "❌ INVALID (TAMPERING DETECTED)"));
            System.out.println("   Verification time: " + (endTime - startTime) + " ms");
            System.out.println();

            // ═══════════════════════════════════════════════════════════════════════════
            // Step 5: Detect Corrupted Signature
            // ═══════════════════════════════════════════════════════════════════════════
            System.out.println("🔍 Step 5: Detect Corrupted Signature...");
            byte[] corruptedSignatureBytes = signature.getClassicalSignature().clone();
            if (corruptedSignatureBytes.length > 0) {
                corruptedSignatureBytes[0] ^= 0xFF;  // Flip bits in first byte
            }
            HybridSignaturePair corruptedSignature = new HybridSignaturePair(
                corruptedSignatureBytes,
                signature.getPQCSignature(),
                signature.getClassicalAlgorithm(),
                signature.getPQCAlgorithm(),
                signature.getMessageHash()
            );

            startTime = System.currentTimeMillis();
            boolean isCorruptedValid = api.verifySignature(data, corruptedSignature, keyPair);
            endTime = System.currentTimeMillis();

            System.out.println("   Note: Modified classical signature, PQC remains intact");
            System.out.println("   Verification result: " + (isCorruptedValid ? "✅ VALID" : "❌ INVALID (CORRUPTION DETECTED)"));
            System.out.println("   Verification time: " + (endTime - startTime) + " ms");
            System.out.println();

            // ═══════════════════════════════════════════════════════════════════════════
            // Summary
            // ═══════════════════════════════════════════════════════════════════════════
            System.out.println("📊 Summary:");
            System.out.println("   ✅ Original signature: " + (isValid ? "VALID" : "INVALID"));
            System.out.println("   ✅ Tampered data: " + (!isTamperedValid ? "DETECTED" : "MISSED"));
            System.out.println("   ✅ Corrupted signature: " + (!isCorruptedValid ? "DETECTED" : "MISSED"));
            System.out.println();
            System.out.println("✅ Sign & Verify example completed successfully!");
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
