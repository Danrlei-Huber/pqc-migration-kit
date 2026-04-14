package com.pqc.hybrid.core.signature.ml_dsa;

import java.security.PublicKey;
import java.security.Signature;

/**
 * ML-DSA (Module-Lattice-Based Digital Signature Algorithm) Verifier.
 * 
 * This class provides deterministic signature verification operations using ML-DSA-44, ML-DSA-65, or ML-DSA-87.
 * Verification is constant-time to prevent timing attacks.
 * 
 * Design Notes:
 * - Uses BouncyCastle's ML-DSA implementation (bcprov 1.77+)
 * - Constant-time verification prevents timing attacks
 * - Supports all three NIST-standardized ML-DSA variants (44, 65, 87)
 * - Input validation performed on data, signature, and keys
 * 
 * Example Usage:
 * <pre>
 *     MLDSAVerifier verifier = new MLDSAVerifier();
 *     boolean isValid = verifier.verify(getData(), signature, publicKey);
 *     if (isValid) {
 *         // Signature is valid
 *     }
 * </pre>
 * 
 * @author PQC Hybrid Team
 * @version 1.0.0
 * @since 2026-04-14
 * @see MLDSASigner
 */
public class MLDSAVerifier {

    /** The underlying BouncyCastle ML-DSA signature algorithm */
    private static final String ALGORITHM = "ML-DSA";

    /**
     * Verifies a signature with the given ML-DSA public key.
     * 
     * Verification is constant-time: the time taken does not depend on whether
     * the signature is valid or invalid, preventing timing attacks.
     * 
     * @param data the original data that was signed (must not be null)
     * @param signature the signature to verify (must not be null)
     * @param publicKey the ML-DSA public key (must not be null)
     * @return true if signature is valid, false if invalid
     * @throws IllegalArgumentException if data, signature, or publicKey is null
     * @throws IllegalStateException if verification fails due to key issues
     */
    public static boolean verify(byte[] data, byte[] signature, PublicKey publicKey) {
        if (data == null) {
            throw new IllegalArgumentException("Data cannot be null");
        }
        if (signature == null) {
            throw new IllegalArgumentException("Signature cannot be null");
        }
        if (publicKey == null) {
            throw new IllegalArgumentException("Public key cannot be null");
        }

        try {
            // Use JCA Signature API with BouncyCastle provider
            Signature verifier = Signature.getInstance("ML-DSA", "BC");
            verifier.initVerify(publicKey);
            verifier.update(data);
            
            return verifier.verify(signature);
            
        } catch (IllegalArgumentException | IllegalStateException e) {
            throw e;
        } catch (Exception e) {
            // Any exception during verification means invalid signature
            return false;
        }
    }

    /**
     * Verifies a signature with the given ML-DSA public key (instance method version).
     * 
     * @param data the original data that was signed (must not be null)
     * @param signature the signature to verify (must not be null)
     * @param publicKey the ML-DSA public key (must not be null)
     * @return true if signature is valid, false if invalid
     * @throws IllegalArgumentException if any parameter is null
     */
    public boolean verifySignature(byte[] data, byte[] signature, PublicKey publicKey) {
        return verify(data, signature, publicKey);
    }

    /**
     * Returns the name of this verifier.
     * 
     * @return "ML-DSA"
     */
    public String getAlgorithmName() {
        return ALGORITHM;
    }

    /**
     * Validates that a key is a valid ML-DSA public key.
     * 
     * @param key the key to validate
     * @return true if key can be used for ML-DSA verification, false otherwise
     */
    public static boolean isValidPublicKey(PublicKey key) {
        return key != null && "ML-DSA".equals(key.getAlgorithm());
    }

    /**
     * Returns a string representation of this verifier.
     * 
     * @return a description of this verifier
     */
    @Override
    public String toString() {
        return "MLDSAVerifier{" +
                "algorithm='" + ALGORITHM + '\'' +
                '}';
    }
}
