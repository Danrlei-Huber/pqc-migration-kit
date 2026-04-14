package com.pqc.hybrid.core.hybrid;

import java.security.PrivateKey;
import java.security.Signature;

/**
 * Performs hybrid signing operations on data using both classical and PQC algorithms.
 * 
 * HybridSigner orchestrates the dual-signature process:
 * 1. Signs the message with classical algorithm (e.g., RSA-2048 with SHA-256)
 * 2. Signs the same message with PQC algorithm (e.g., ML-DSA-65)
 * 3. Returns both signatures in a HybridSignaturePair
 * 
 * Both signatures are produced over the SAME data, allowing independent verification.
 * This approach provides immediate security (classical) plus future-proofing (PQC).
 * 
 * Cryptographic Properties:
 * - Produces valid classical signature using established algorithms
 * - Produces valid ML-DSA signature for quantum-resistance  
 * - Each signature can be verified independently
 * - Signature sizes combine: typically 3.5-5 KB for RSA+ML-DSA combinations
 * 
 * Thread Safety:
 * This class is thread-safe. Each thread should call sign() methods with its own
 * private keys to avoid contention on JCA Signature instances.
 * 
 * Example Usage:
 * <pre>
 *     HybridSigner signer = new HybridSigner();
 *     byte[] message = "Important document".getBytes();
 *     
 *     HybridSignaturePair signatures = signer.sign(
 *         message,
 *         rsaPrivateKey,
 *         mlDsaPrivateKey,
 *         HybridSignatureScheme.RSA_2048_ML_DSA_65
 *     );
 * </pre>
 * 
 * @author PQC Hybrid Team
 * @version 1.0.0
 * @since 2026-04-14
 */
public class HybridSigner {

    private static final String BC_PROVIDER = "BC";

    /**
     * Signs data with both classical and PQC algorithms.
     * 
     * Produces two independent signatures over the same data:
     * 1. Classical signature using scheme's classical algorithm
     * 2. PQC signature using scheme's PQC algorithm
     * 
     * @param data the message to sign (must not be null or empty)
     * @param classicalPrivateKey the private key for classical signature (e.g., RSA key)
     * @param pqcPrivateKey the private key for PQC signature (e.g., ML-DSA key)
     * @param scheme the hybrid scheme specifying which algorithms to use
     * @return HybridSignaturePair containing both signatures
     * @throws IllegalArgumentException if parameters are invalid
     * @throws RuntimeException if algorithms are not available or signing fails
     */
    public HybridSignaturePair sign(
            byte[] data,
            PrivateKey classicalPrivateKey,
            PrivateKey pqcPrivateKey,
            HybridSignatureScheme scheme) {

        if (data == null || data.length == 0) {
            throw new IllegalArgumentException("Data to sign cannot be null or empty");
        }
        if (classicalPrivateKey == null) {
            throw new IllegalArgumentException("Classical private key cannot be null");
        }
        if (pqcPrivateKey == null) {
            throw new IllegalArgumentException("PQC private key cannot be null");
        }
        if (scheme == null) {
            throw new IllegalArgumentException("Hybrid signature scheme cannot be null");
        }

        try {
            // Sign with classical algorithm
            byte[] classicalSignature = signWithClassicalAlgorithm(data, classicalPrivateKey, scheme);

            // Sign with PQC algorithm
            byte[] pqcSignature = signWithPQCAlgorithm(data, pqcPrivateKey, scheme);

            return new HybridSignaturePair(classicalSignature, pqcSignature, scheme);

        } catch (Exception e) {
            throw new RuntimeException("Hybrid signing failed: " + e.getMessage(), e);
        }
    }

    /**
     * Signs data using the classical algorithm from the scheme.
     * 
     * @param data the message to sign
     * @param privateKey the classical private key
     * @param scheme the hybrid scheme containing classical algorithm name
     * @return the classical signature bytes
     * @throws Exception if signing fails
     */
    private byte[] signWithClassicalAlgorithm(
            byte[] data,
            PrivateKey privateKey,
            HybridSignatureScheme scheme) throws Exception {

        String algorithm = scheme.getClassicalAlgorithm();
        Signature sig = Signature.getInstance(algorithm, BC_PROVIDER);
        sig.initSign(privateKey);
        sig.update(data);
        return sig.sign();
    }

    /**
     * Signs data using the PQC algorithm from the scheme.
     * 
     * @param data the message to sign
     * @param privateKey the PQC private key (e.g., ML-DSA key)
     * @param scheme the hybrid scheme containing PQC algorithm name
     * @return the PQC signature bytes
     * @throws Exception if signing fails
     */
    private byte[] signWithPQCAlgorithm(
            byte[] data,
            PrivateKey privateKey,
            HybridSignatureScheme scheme) throws Exception {

        String algorithm = scheme.getPQCAlgorithm();
        Signature sig = Signature.getInstance(algorithm, BC_PROVIDER);
        sig.initSign(privateKey);
        sig.update(data);
        return sig.sign();
    }
}
