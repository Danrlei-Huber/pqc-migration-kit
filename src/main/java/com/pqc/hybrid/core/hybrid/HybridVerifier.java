package com.pqc.hybrid.core.hybrid;

import java.security.PublicKey;
import java.security.Signature;

/**
 * Verifies hybrid signatures by validating both classical and PQC components.
 * 
 * HybridVerifier validates that both signature components are valid:
 * 1. Classical signature verification (e.g., RSA-SHA256)
 * 2. PQC signature verification (e.g., ML-DSA)
 * 3. Both must be valid for the overall verification to succeed
 * 
 * Verification Rules:
 * - BOTH signatures must be valid (AND logic, not OR)
 * - Any invalid signature fails the entire verification
 * - Each signature is independent and uses its corresponding public key
 * - The message being verified must be exactly the same as when signed
 * 
 * Security Properties:
 * - The hybrid signature is only valid if both components verify
 * - Protects against:
 *   - Classical algorithm compromise (falls back to PQC component)
 *   - PQC algorithm early failure (falls back to classical component)
 *   - Both providing defense-in-depth
 * 
 * Example Usage:
 * <pre>
 *     HybridVerifier verifier = new HybridVerifier();
 *     boolean isValid = verifier.verify(
 *         message,
 *         hybridSignaturePair,
 *         rsaPublicKey,
 *         mlDsaPublicKey
 *     );
 * </pre>
 * 
 * @author PQC Hybrid Team
 * @version 1.0.0
 * @since 2026-04-14
 */
public class HybridVerifier {

    private static final String BC_PROVIDER = "BC";

    /**
     * Verifies a hybrid signature pair against the original data.
     * 
     * Both signatures must be valid for verification to succeed.
     * 
     * @param data the original message that was signed
     * @param signatures the hybrid signature pair containing both signatures
     * @param classicalPublicKey the public key for classical signature verification
     * @param pqcPublicKey the public key for PQC signature verification
     * @return true if BOTH signatures are valid, false otherwise
     * @throws IllegalArgumentException if parameters are invalid
     * @throws RuntimeException if verification encounters an error
     */
    public boolean verify(
            byte[] data,
            HybridSignaturePair signatures,
            PublicKey classicalPublicKey,
            PublicKey pqcPublicKey) {

        if (data == null || data.length == 0) {
            throw new IllegalArgumentException("Data to verify cannot be null or empty");
        }
        if (signatures == null) {
            throw new IllegalArgumentException("Hybrid signature pair cannot be null");
        }
        if (classicalPublicKey == null) {
            throw new IllegalArgumentException("Classical public key cannot be null");
        }
        if (pqcPublicKey == null) {
            throw new IllegalArgumentException("PQC public key cannot be null");
        }

        try {
            // Verify classical component
            boolean classicalValid = verifyClassicalSignature(
                    data,
                    signatures.classicalSignature(),
                    classicalPublicKey,
                    signatures.scheme());

            if (!classicalValid) {
                return false;
            }

            // Verify PQC component
            boolean pqcValid = verifyPQCSignature(
                    data,
                    signatures.pqcSignature(),
                    pqcPublicKey,
                    signatures.scheme());

            return pqcValid;

        } catch (Exception e) {
            throw new RuntimeException("Hybrid verification failed: " + e.getMessage(), e);
        }
    }

    /**
     * Verifies just the classical component of a hybrid signature.
     * 
     * @param data the original message
     * @param classicalSignature the classical signature bytes
     * @param publicKey the classical public key
     * @param scheme the hybrid scheme containing classical algorithm name
     * @return true if the classical signature is valid
     * @throws Exception if verification fails or encounters an error
     */
    private boolean verifyClassicalSignature(
            byte[] data,
            byte[] classicalSignature,
            PublicKey publicKey,
            HybridSignatureScheme scheme) throws Exception {

        String algorithm = scheme.getClassicalAlgorithm();
        Signature sig = Signature.getInstance(algorithm, BC_PROVIDER);
        sig.initVerify(publicKey);
        sig.update(data);

        try {
            sig.verify(classicalSignature);
            return true;
        } catch (java.security.SignatureException e) {
            return false;
        }
    }

    /**
     * Verifies just the PQC component of a hybrid signature.
     * 
     * @param data the original message
     * @param pqcSignature the PQC signature bytes
     * @param publicKey the PQC public key
     * @param scheme the hybrid scheme containing PQC algorithm name
     * @return true if the PQC signature is valid
     * @throws Exception if verification fails or encounters an error
     */
    private boolean verifyPQCSignature(
            byte[] data,
            byte[] pqcSignature,
            PublicKey publicKey,
            HybridSignatureScheme scheme) throws Exception {

        String algorithm = scheme.getPQCAlgorithm();
        Signature sig = Signature.getInstance(algorithm, BC_PROVIDER);
        sig.initVerify(publicKey);
        sig.update(data);

        try {
            sig.verify(pqcSignature);
            return true;
        } catch (java.security.SignatureException e) {
            return false;
        }
    }
}
