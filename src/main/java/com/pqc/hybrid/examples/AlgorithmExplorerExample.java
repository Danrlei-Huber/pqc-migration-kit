package com.pqc.hybrid.examples;

import com.pqc.hybrid.core.api.PQCHybridCertificateAPI;
import com.pqc.hybrid.core.config.ClassicalAlgorithm;
import com.pqc.hybrid.core.config.PQCAlgorithm;
import com.pqc.hybrid.core.config.HybridAlgorithmPair;
import com.pqc.hybrid.core.keygen.HybridKeyPair;
import com.pqc.hybrid.core.exception.PQCHybridException;

/**
 * Example: Explore Supported Algorithms
 * 
 * This example demonstrates how to:
 * 1. Understand supported classical algorithms
 * 2. Understand supported PQC algorithms
 * 3. Get recommended algorithm pairs for different security levels
 * 4. Compare security levels and sizes
 * 
 * Output: Information about all supported algorithms
 * 
 * @author PQC Hybrid Team
 * @version 1.0.0-BETA
 */
public class AlgorithmExplorerExample {

    public static void main(String[] args) {
        System.out.println("╔════════════════════════════════════════════════════════════╗");
        System.out.println("║  PQC Hybrid Certificates - Algorithm Explorer               ║");
        System.out.println("╚════════════════════════════════════════════════════════════╝\n");

        try {
            // ═══════════════════════════════════════════════════════════════════════════
            // Initialize API
            // ═══════════════════════════════════════════════════════════════════════════
            System.out.println("📦 Initialize API...");
            PQCHybridCertificateAPI api = new PQCHybridCertificateAPI();
            api.initialize();
            System.out.println("   ✅ API initialized\n");

            // ═══════════════════════════════════════════════════════════════════════════
            // Classical Algorithms
            // ═══════════════════════════════════════════════════════════════════════════
            System.out.println("🔐 CLASSICAL ALGORITHMS:");
            System.out.println("   " + String.format("%-15s %-10s %-15s",
                "Algorithm", "Key Size", "Security Level"));
            System.out.println("   " + "-".repeat(50));
            
            for (ClassicalAlgorithm algo : ClassicalAlgorithm.values()) {
                System.out.println("   " + String.format("%-15s %-10d %-15d",
                    algo.getAlgorithmName(),
                    algo.getKeySize(),
                    algo.getSecurityLevel()
                ));
            }
            System.out.println();

            // ═══════════════════════════════════════════════════════════════════════════
            // PQC Algorithms - Signatures
            // ═══════════════════════════════════════════════════════════════════════════
            System.out.println("📋 PQC SIGNATURE ALGORITHMS:");
            System.out.println("   " + String.format("%-20s %-15s %-15s",
                "Algorithm", "Security Level", "Public Key (B)"));
            System.out.println("   " + "-".repeat(55));

            PQCAlgorithm[] sigAlgorithms = {
                PQCAlgorithm.ML_DSA_44,
                PQCAlgorithm.ML_DSA_65,
                PQCAlgorithm.ML_DSA_87,
                PQCAlgorithm.SLH_DSA_SHA2_128S,
                PQCAlgorithm.SLH_DSA_SHA2_128F,
                PQCAlgorithm.SLH_DSA_SHA2_192S,
                PQCAlgorithm.SLH_DSA_SHA2_192F,
                PQCAlgorithm.SLH_DSA_SHA2_256S,
                PQCAlgorithm.SLH_DSA_SHA2_256F,
                PQCAlgorithm.FALCON_512,
                PQCAlgorithm.FALCON_1024
            };

            for (PQCAlgorithm algo : sigAlgorithms) {
                System.out.println("   " + String.format("%-20s %-15d %-15d",
                    algo.getName(),
                    algo.getSecurityLevel(),
                    algo.getPublicKeySize()
                ));
            }
            System.out.println();

            // ═══════════════════════════════════════════════════════════════════════════
            // PQC Algorithms - KEM
            // ═══════════════════════════════════════════════════════════════════════════
            System.out.println("🔑 PQC KEM ALGORITHMS:");
            System.out.println("   " + String.format("%-20s %-15s %-15s",
                "Algorithm", "Security Level", "Public Key (B)"));
            System.out.println("   " + "-".repeat(55));

            PQCAlgorithm[] kemAlgorithms = {
                PQCAlgorithm.ML_KEM_512,
                PQCAlgorithm.ML_KEM_768,
                PQCAlgorithm.ML_KEM_1024
            };

            for (PQCAlgorithm algo : kemAlgorithms) {
                System.out.println("   " + String.format("%-20s %-15d %-15d",
                    algo.getName(),
                    algo.getSecurityLevel(),
                    algo.getPublicKeySize()
                ));
            }
            System.out.println();

            // ═══════════════════════════════════════════════════════════════════════════
            // Recommended Pairs by Security Level
            // ═══════════════════════════════════════════════════════════════════════════
            System.out.println("🎯 RECOMMENDED HYBRID PAIRS BY SECURITY LEVEL:");
            System.out.println();

            int[] securityLevels = {128, 192, 256};
            for (int level : securityLevels) {
                HybridAlgorithmPair pair = HybridAlgorithmPair.recommended(level);
                System.out.println("   Security Level: " + level + " bits");
                System.out.println("      Classical: " + pair.classicalAlgorithm().getAlgorithmName() + 
                    "-" + pair.classicalAlgorithm().getKeySize());
                System.out.println("      PQC: " + pair.pqcAlgorithm().getName());
                System.out.println("      Description: " + pair.getDescription());
                System.out.println("      Balanced: " + (pair.isSecurityBalanced() ? "Yes" : "No"));
                System.out.println("      NIST Standardized: " + (pair.areNistStandardized() ? "Yes" : "No"));
                System.out.println();
            }

            // ═══════════════════════════════════════════════════════════════════════════
            // Generate and Compare Keys for Each Level
            // ═══════════════════════════════════════════════════════════════════════════
            System.out.println("📊 KEY GENERATION PERFORMANCE:");
            System.out.println("   " + String.format("%-15s %-15s %-15s %s",
                "Security Level", "Algorithm Pair", "Time (ms)", "Status"));
            System.out.println("   " + "-".repeat(65));

            for (int level : securityLevels) {
                HybridAlgorithmPair pair = HybridAlgorithmPair.recommended(level);
                
                long startTime = System.currentTimeMillis();
                HybridKeyPair keyPair = api.generateHybridKeyPair(level);
                long endTime = System.currentTimeMillis();
                long duration = endTime - startTime;

                System.out.println("   " + String.format("%-15d %-15s %-15d %s",
                    level,
                    pair.getDescription().substring(0, Math.min(15, pair.getDescription().length())),
                    duration,
                    "✅ Generated"
                ));
            }
            System.out.println();

            System.out.println("✅ Algorithm explorer example completed successfully!");
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
