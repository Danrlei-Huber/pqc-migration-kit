package com.pqc.hybrid.examples;

import com.pqc.hybrid.core.config.ClassicalAlgorithm;
import com.pqc.hybrid.core.config.CryptographicProviderFactory;
import com.pqc.hybrid.core.config.HybridAlgorithmPair;
import com.pqc.hybrid.core.config.PQCAlgorithm;
import com.pqc.hybrid.core.hybrid.HybridSignaturePair;
import com.pqc.hybrid.core.hybrid.HybridSignatureScheme;
import com.pqc.hybrid.core.hybrid.HybridSigner;
import com.pqc.hybrid.core.hybrid.HybridVerifier;
import com.pqc.hybrid.core.keygen.HybridKeyPair;
import com.pqc.hybrid.core.keygen.HybridKeyGenerator;
import com.pqc.hybrid.core.util.printer.KeyInfoPrinter;
import com.pqc.hybrid.core.util.printer.SignaturePrinter;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.logging.Logger;

/**
 * Demonstrates hybrid signature generation and verification.
 * 
 * Shows how to:
 * 1. Generate hybrid key pairs (classical + PQC)
 * 2. Sign data with both algorithms simultaneously
 * 3. Verify hybrid signatures where both parts must be valid
 * 
 * Example Output:
 * ```
 * Generating Hybrid Key Pair...
 * Classical Key: RSA Public Key (2048 bits)
 * PQC Key: ML-DSA-65 Public Key
 * 
 * Signing Message with Both Algorithms...
 * Hybrid Signature: RSA-2048 + ML-DSA-65
 * Classical Signature: 256 bytes
 * PQC Signature: 3293 bytes
 * 
 * Verification Result: ✓ VALID (Both signatures accepted)
 * ```
 * 
 * @author PQC Hybrid Team
 * @version 1.0.0
 * @since 2026-04-14
 */
public class HybridSignatureExample {

    private static final Logger logger = Logger.getLogger(HybridSignatureExample.class.getName());

    public static void main(String[] args) {
        try {
            logger.info("Starting Hybrid Signature Example...\n");
            
            // Initialize cryptographic provider
            CryptographicProviderFactory.initialize();
            
            // Step 1: Generate Hybrid Key Pair
            HybridAlgorithmPair algPair = new HybridAlgorithmPair(
                ClassicalAlgorithm.RSA_2048,
                PQCAlgorithm.ML_DSA_65
            );
            
            logger.info("Generating hybrid key pair: " + algPair);
            HybridKeyPair hybridKeyPair = HybridKeyGenerator.generate(algPair);
            
            // Display key information
            KeyInfoPrinter keyPrinter = new KeyInfoPrinter();
            System.out.println("\n📝 Generated Keys:");
            System.out.println(keyPrinter.formatKeyCompact(hybridKeyPair.getClassicalPublicKey()));
            System.out.println(keyPrinter.formatKeyCompact(hybridKeyPair.getPQCPublicKey()));
            
            // Step 2: Prepare message to sign
            String message = "This is a hybrid cryptographic test message";
            byte[] messageBytes = message.getBytes();
            
            System.out.println("\n📄 Message to Sign: \"" + message + "\"");
            System.out.println("   Length: " + messageBytes.length + " bytes");
            
            // Step 3: Sign with both algorithms
            System.out.println("\n🔐 Signing with Hybrid Algorithm...");
            HybridSigner signer = new HybridSigner();
            
            HybridSignaturePair signatures = signer.sign(
                messageBytes,
                hybridKeyPair.getClassicalPrivateKey(),
                hybridKeyPair.getPQCPrivateKey(),
                HybridSignatureScheme.RSA_2048_ML_DSA_65
            );
            
            // Display signature information
            SignaturePrinter sigPrinter = new SignaturePrinter();
            System.out.println(sigPrinter.formatHybridSignature(signatures, HybridSignatureScheme.RSA_2048_ML_DSA_65));
            
            // Step 4: Verify hybrid signature
            System.out.println("\n\n✅ Verifying Hybrid Signature...");
            HybridVerifier verifier = new HybridVerifier();
            
            boolean isValid = verifier.verify(
                messageBytes,
                signatures,
                hybridKeyPair.getClassicalPublicKey(),
                hybridKeyPair.getPQCPublicKey()
            );
            
            if (isValid) {
                System.out.println("✓ SIGNATURE VERIFICATION SUCCESSFUL");
                System.out.println("  Both classical and PQC signatures are valid!");
            } else {
                System.out.println("✗ SIGNATURE VERIFICATION FAILED");
                System.out.println("  One or both signatures are invalid");
            }
            
            // Step 5: Test with tampered message
            System.out.println("\n\n🧪 Testing with Tampered Message...");
            byte[] tamperedMessage = "This message has been modified".getBytes();
            
            boolean tamperedValid = verifier.verify(
                tamperedMessage,
                signatures,
                hybridKeyPair.getClassicalPublicKey(),
                hybridKeyPair.getPQCPublicKey()
            );
            
            if (!tamperedValid) {
                System.out.println("✓ Correctly rejected tampered message");
                System.out.println("  Hybrid signature verification prevents tampering!");
            } else {
                System.out.println("✗ ERROR: Tampered message was validated!");
            }
            
            // Step 6: Show statistics
            System.out.println("\n\n📊 Signature Statistics:");
            System.out.println(sigPrinter.formatSignatureComparison(signatures));
            System.out.println("\n" + sigPrinter.formatSignatureStatistics(signatures));
            
            logger.info("\nExample completed successfully!");
            
        } catch (Exception e) {
            logger.severe("Example failed: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
