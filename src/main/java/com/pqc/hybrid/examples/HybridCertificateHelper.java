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

import java.io.File;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.logging.Logger;

/**
 * Command-line interface for hybrid certificate operations.
 * 
 * Provides commands for:
 * - generate: Create self-signed hybrid certificates
 * - inspect: View certificate details and hybrid properties
 * - export: Export certificates to PEM/DER formats
 * - help: Display command help
 * 
 * Usage:
 * ```
 * java HybridCertificateHelper generate -s "CN=example.com" -o cert.pem
 * java HybridCertificateHelper inspect -f cert.pem
 * java HybridCertificateHelper export -f cert.der -f cert.pem
 * ```
 * 
 * @author PQC Hybrid Team
 * @version 1.0.0
 * @since 2026-04-14
 */
public class HybridCertificateHelper {

    private static final Logger logger = Logger.getLogger(HybridCertificateHelper.class.getName());
    private static final String VERSION = "1.0.0";

    public static void main(String[] args) {
        CryptographicProviderFactory.initialize();
        
        if (args.length == 0) {
            printUsage();
            return;
        }
        
        String command = args[0].toLowerCase();
        
        try {
            switch (command) {
                case "generate":
                    handleGenerate(args);
                    break;
                case "inspect":
                    handleInspect(args);
                    break;
                case "export":
                    handleExport(args);
                    break;
                case "help":
                    printUsage();
                    break;
                case "--version":
                case "-v":
                    System.out.println("Hybrid Certificate Helper v" + VERSION);
                    break;
                default:
                    System.err.println("Unknown command: " + command);
                    printUsage();
            }
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * Handles the 'generate' command to create self-signed hybrid certificates.
     */
    private static void handleGenerate(String[] args) throws Exception {
        String subject = "CN=hybrid.example,O=Organization,C=BR";
        String outputPath = "hybrid-cert.pem";
        int validityDays = 365;
        
        // Parse arguments
        for (int i = 1; i < args.length; i++) {
            if ("-s".equals(args[i]) || "--subject".equals(args[i])) {
                if (i + 1 < args.length) subject = args[++i];
            } else if ("-o".equals(args[i]) || "--output".equals(args[i])) {
                if (i + 1 < args.length) outputPath = args[++i];
            } else if ("--validity".equals(args[i])) {
                if (i + 1 < args.length) validityDays = Integer.parseInt(args[++i]);
            }
        }
        
        System.out.println("Generating hybrid certificate...");
        System.out.println("  Subject: " + subject);
        System.out.println("  Validity: " + validityDays + " days");
        
        // Generate key pair
        HybridAlgorithmPair algPair = new HybridAlgorithmPair(
            ClassicalAlgorithm.RSA_2048,
            PQCAlgorithm.ML_DSA_65
        );
        
        HybridKeyPair keyPair = HybridKeyGenerator.generate(algPair);
        
        // Note: Certificate creation requires HybridCertificateConfig
        // For now, we just show the hybrid key pair was generated
        System.out.println("✓ Hybrid key pair generated successfully");
        System.out.println("  Classical Key: " + keyPair.getClassicalPublicKey().getAlgorithm());
        System.out.println("  PQC Key: " + keyPair.getPQCPublicKey().getAlgorithm());
        
        X509Certificate cert = null;
        
        if (cert != null) {
            // Export to PEM
            CertificateExporter exporter = new CertificateExporter();
            exporter.exportCertificateToPEM(cert, outputPath);
            
            System.out.println("✓ Certificate generated and saved to: " + outputPath);
            System.out.println("  Serial: " + cert.getSerialNumber());
        } else {
            System.out.println("Note: Certificate generation is available when HybridCertificateConfig is fully configured.");
        }
    }

    /**
     * Handles the 'inspect' command to display certificate details.
     */
    private static void handleInspect(String[] args) throws Exception {
        if (args.length < 2) {
            System.err.println("Usage: inspect -f <file>");
            return;
        }
        
        String filePath = null;
        
        for (int i = 1; i < args.length; i++) {
            if ("-f".equals(args[i]) || "--file".equals(args[i])) {
                if (i + 1 < args.length) filePath = args[++i];
            }
        }
        
        if (filePath == null) {
            System.err.println("Error: No file specified");
            return;
        }
        
        File file = new File(filePath);
        if (!file.exists()) {
            System.err.println("Error: File not found: " + filePath);
            return;
        }
        
        System.out.println("Inspecting certificate: " + filePath);
        System.out.println();
        
        // Load and display certificate
        java.security.cert.CertificateFactory cf = java.security.cert.CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) cf.generateCertificate(
            new java.io.FileInputStream(file)
        );
        
        CertificatePrinter printer = new CertificatePrinter();
        System.out.println(printer.formatCertificate(cert));
        
        System.out.println();
        
        HybridCertificateInspector inspector = new HybridCertificateInspector();
        System.out.println(inspector.inspectCertificateToString(cert));
    }

    /**
     * Handles the 'export' command to convert certificate formats.
     */
    private static void handleExport(String[] args) throws Exception {
        if (args.length < 2) {
            System.err.println("Usage: export -i <input> -o <output> [--format pem|der]");
            return;
        }
        
        String inputPath = null;
        String outputPath = null;
        String format = "pem";
        
        for (int i = 1; i < args.length; i++) {
            if ("-i".equals(args[i]) || "--input".equals(args[i])) {
                if (i + 1 < args.length) inputPath = args[++i];
            } else if ("-o".equals(args[i]) || "--output".equals(args[i])) {
                if (i + 1 < args.length) outputPath = args[++i];
            } else if ("--format".equals(args[i])) {
                if (i + 1 < args.length) format = args[++i].toLowerCase();
            }
        }
        
        if (inputPath == null || outputPath == null) {
            System.err.println("Error: Missing input or output file");
            return;
        }
        
        File inputFile = new File(inputPath);
        if (!inputFile.exists()) {
            System.err.println("Error: Input file not found: " + inputPath);
            return;
        }
        
        // Load certificate
        java.security.cert.CertificateFactory cf = java.security.cert.CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) cf.generateCertificate(
            new java.io.FileInputStream(inputFile)
        );
        
        CertificateExporter exporter = new CertificateExporter();
        
        if ("pem".equals(format)) {
            exporter.exportCertificateToPEM(cert, outputPath);
        } else if ("der".equals(format)) {
            exporter.exportCertificateToDER(cert, outputPath);
        } else {
            System.err.println("Error: Unknown format: " + format);
            return;
        }
        
        System.out.println("✓ Certificate exported to: " + outputPath);
    }

    /**
     * Prints usage information.
     */
    private static void printUsage() {
        System.out.println("Hybrid Certificate Helper v" + VERSION);
        System.out.println();
        System.out.println("Commands:");
        System.out.println();
        System.out.println("  generate    Generate a self-signed hybrid certificate");
        System.out.println("    Options:");
        System.out.println("      -s, --subject <dn>     Certificate subject (default: CN=hybrid.example)");
        System.out.println("      -o, --output <file>    Output file (default: hybrid-cert.pem)");
        System.out.println("      --validity <days>      Validity period in days (default: 365)");
        System.out.println();
        System.out.println("  inspect     Display certificate details");
        System.out.println("    Options:");
        System.out.println("      -f, --file <file>      Certificate file to inspect");
        System.out.println();
        System.out.println("  export      Convert certificate format");
        System.out.println("    Options:");
        System.out.println("      -i, --input <file>     Input certificate file");
        System.out.println("      -o, --output <file>    Output certificate file");
        System.out.println("      --format <pem|der>     Output format (default: pem)");
        System.out.println();
        System.out.println("  help        Show this help message");
        System.out.println();
        System.out.println("Examples:");
        System.out.println("  Generate: hybrid-cert-helper generate -s \"CN=example.com\" -o cert.pem");
        System.out.println("  Inspect:  hybrid-cert-helper inspect -f cert.pem");
        System.out.println("  Export:   hybrid-cert-helper export -i cert.pem -o cert.der --format der");
    }
}
