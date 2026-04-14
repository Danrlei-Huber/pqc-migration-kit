package com.pqc.hybrid.core.util.printer;

import com.pqc.hybrid.core.hybrid.HybridSignaturePair;
import com.pqc.hybrid.core.hybrid.HybridSignatureScheme;
import java.util.Base64;
import java.util.Objects;
import java.util.logging.Logger;

/**
 * Utility for printing and analyzing hybrid signature information.
 * 
 * Displays formatted details about dual signatures including:
 * - Scheme information (classical + PQC combination)
 * - Individual signature sizes and statistics
 * - Encoded representations
 * - Verification status
 * 
 * Example Output:
 * ```
 * Hybrid Signature Pair
 * ├── Scheme: RSA-2048 + ML-DSA-65
 * ├── Classical Signature:
 * │   ├── Size: 256 bytes
 * │   └── Algorithm: SHA256withRSA
 * ├── PQC Signature:
 * │   ├── Size: 3293 bytes
 * │   └── Algorithm: ML-DSA-65
 * └── Total: 3549 bytes (3.5 KB)
 * ```
 * 
 * @author PQC Hybrid Team
 * @version 1.0.0
 * @since 2026-04-14
 */
public class SignaturePrinter {

    private static final Logger logger = Logger.getLogger(SignaturePrinter.class.getName());
    private static final int DISPLAY_LENGTH = 48;

    /**
     * Prints hybrid signature pair information to console.
     * 
     * @param signatures the hybrid signature pair to print
     * @param scheme the hybrid signature scheme used
     */
    public void printHybridSignature(HybridSignaturePair signatures, HybridSignatureScheme scheme) {
        Objects.requireNonNull(signatures, "Signature pair cannot be null");
        Objects.requireNonNull(scheme, "Scheme cannot be null");
        System.out.println(formatHybridSignature(signatures, scheme));
    }

    /**
     * Formats hybrid signature information as string.
     * 
     * @param signatures the hybrid signature pair
     * @param scheme the hybrid scheme
     * @return formatted signature information
     */
    public String formatHybridSignature(HybridSignaturePair signatures, HybridSignatureScheme scheme) {
        Objects.requireNonNull(signatures, "Signature pair cannot be null");
        Objects.requireNonNull(scheme, "Scheme cannot be null");
        
        StringBuilder sb = new StringBuilder();
        
        sb.append("Hybrid Signature Pair\n");
        sb.append("├── Scheme: ").append(scheme.name()).append("\n");
        sb.append("│   ├── Classical: ").append(scheme.getClassicalAlgorithm()).append(" (").append(scheme.getClassicalKeySize()).append("-bit)\n");
        sb.append("│   └── PQC: ").append(scheme.getPQCAlgorithm()).append(" (").append(scheme.getPQCSecurityLevel()).append("-bit security)\n");
        
        // Classical Signature
        byte[] classicalSig = signatures.classicalSignature();
        sb.append("├── Classical Signature:\n");
        sb.append("│   ├── Size: ").append(classicalSig.length).append(" bytes\n");
        sb.append("│   ├── Algorithm: ").append(scheme.getClassicalAlgorithm()).append("\n");
        sb.append("│   └── Base64: ").append(truncateBase64(classicalSig)).append("\n");
        
        // PQC Signature
        byte[] pqcSig = signatures.pqcSignature();
        sb.append("├── PQC Signature:\n");
        sb.append("│   ├── Size: ").append(pqcSig.length).append(" bytes\n");
        sb.append("│   ├── Algorithm: ").append(scheme.getPQCAlgorithm()).append("\n");
        sb.append("│   └── Base64: ").append(truncateBase64(pqcSig)).append("\n");
        
        // Totals
        int totalSize = signatures.totalSignatureSize();
        double sizeKB = totalSize / 1024.0;
        sb.append("└── Total Size: ").append(totalSize).append(" bytes (");
        sb.append(String.format("%.2f KB", sizeKB)).append(")");
        
        return sb.toString();
    }

    /**
     * Prints signature comparison (classical vs PQC).
     * 
     * @param signatures the signature pair
     */
    public void printSignatureComparison(HybridSignaturePair signatures) {
        Objects.requireNonNull(signatures, "Signature pair cannot be null");
        System.out.println(formatSignatureComparison(signatures));
    }

    /**
     * Formats signature comparison as string.
     * 
     * @param signatures the signature pair
     * @return comparison table
     */
    public String formatSignatureComparison(HybridSignaturePair signatures) {
        Objects.requireNonNull(signatures, "Signature pair cannot be null");
        
        StringBuilder sb = new StringBuilder();
        
        byte[] classicalSig = signatures.classicalSignature();
        byte[] pqcSig = signatures.pqcSignature();
        
        sb.append("Signature Comparison\n");
        sb.append("┌─────────────────┬───────┬─────────┐\n");
        sb.append("│ Type            │ Bytes │ Percent │\n");
        sb.append("├─────────────────┼───────┼─────────┤\n");
        
        int total = classicalSig.length + pqcSig.length;
        double classPct = (classicalSig.length * 100.0) / total;
        double pqcPct = (pqcSig.length * 100.0) / total;
        
        sb.append(String.format("│ Classical       │ %5d │ %5.1f%% │%n", classicalSig.length, classPct));
        sb.append(String.format("│ PQC             │ %5d │ %5.1f%% │%n", pqcSig.length, pqcPct));
        sb.append("├─────────────────┼───────┼─────────┤\n");
        sb.append(String.format("│ Total           │ %5d │ 100.0%% │%n", total));
        sb.append("└─────────────────┴───────┴─────────┘");
        
        return sb.toString();
    }

    /**
     * Prints signature statistics.
     * 
     * @param signatures the signature pair
     */
    public void printSignatureStatistics(HybridSignaturePair signatures) {
        Objects.requireNonNull(signatures, "Signature pair cannot be null");
        System.out.println(formatSignatureStatistics(signatures));
    }

    /**
     * Formats signature statistics as string.
     * 
     * @param signatures the signature pair
     * @return statistics summary
     */
    public String formatSignatureStatistics(HybridSignaturePair signatures) {
        Objects.requireNonNull(signatures, "Signature pair cannot be null");
        
        StringBuilder sb = new StringBuilder();
        
        byte[] classicalSig = signatures.classicalSignature();
        byte[] pqcSig = signatures.pqcSignature();
        int total = signatures.totalSignatureSize();
        
        sb.append("Signature Statistics\n");
        sb.append("  Classical Signature:\n");
        sb.append("    • Size: ").append(classicalSig.length).append(" bytes\n");
        sb.append("    • Ratio: ").append(String.format("%.1f%%", (classicalSig.length * 100.0) / total)).append(" of total\n");
        
        sb.append("  PQC Signature:\n");
        sb.append("    • Size: ").append(pqcSig.length).append(" bytes\n");
        sb.append("    • Ratio: ").append(String.format("%.1f%%", (pqcSig.length * 100.0) / total)).append(" of total\n");
        
        sb.append("  Combined:\n");
        sb.append("    • Total: ").append(total).append(" bytes\n");
        sb.append("    • Total (KB): ").append(String.format("%.2f KB", total / 1024.0)).append("\n");
        sb.append("    • Overhead: ").append(String.format("%.1f%%", ((total - classicalSig.length) * 100.0) / classicalSig.length)).append(" vs. classical only");
        
        return sb.toString();
    }

    /**
     * Truncates base64-encoded data for display.
     * 
     * @param data the binary data
     * @return truncated base64 string with ellipsis
     */
    private String truncateBase64(byte[] data) {
        String encoded = Base64.getEncoder().encodeToString(data);
        if (encoded.length() > DISPLAY_LENGTH) {
            return encoded.substring(0, DISPLAY_LENGTH) + "...";
        }
        return encoded;
    }

    /**
     * Gets readable signature size.
     * 
     * @param signatures the signature pair
     * @return formatted size string (e.g., "3.5 KB")
     */
    public String getReadableSize(HybridSignaturePair signatures) {
        Objects.requireNonNull(signatures, "Signature pair cannot be null");
        
        int bytes = signatures.totalSignatureSize();
        
        if (bytes < 1024) {
            return bytes + " bytes";
        } else if (bytes < 1024 * 1024) {
            return String.format("%.2f KB", bytes / 1024.0);
        } else {
            return String.format("%.2f MB", bytes / (1024.0 * 1024.0));
        }
    }
}
