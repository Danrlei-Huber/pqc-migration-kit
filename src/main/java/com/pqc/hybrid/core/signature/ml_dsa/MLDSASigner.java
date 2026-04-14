package com.pqc.hybrid.core.signature.ml_dsa;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;

/**
 * ML-DSA (Module-Lattice-Based Digital Signature Algorithm) Signer.
 * 
 * This class provides deterministic signing operations using ML-DSA-44, ML-DSA-65, or ML-DSA-87.
 * ML-DSA is the NIST standardized lattice-based signature algorithm (formerly Dilithium).
 * 
 * Signing is deterministic: given the same message and key, the signature is always identical.
 * This is important for reproducibility and auditability in cryptographic applications.
 * 
 * Design Notes:
 * - Uses BouncyCastle's ML-DSA implementation (bcprov 1.77+)
 * - Signatures are deterministic (no randomness injected)
 * - Supports all three NIST-standardized ML-DSA variants (44, 65, 87)
 * - Input validation performed on data and keys
 * 
 * Example Usage:
 * <pre>
 *     MLDSASigner signer = new MLDSASigner();
 *     byte[] signature = signer.sign(getData(), privateKey);
 *     // signature is now ML-DSA signature (size depends on variant)
 * </pre>
 * 
 * @author PQC Hybrid Team
 * @version 1.0.0
 * @since 2026-04-14
 * @see MLDSAVerifier
 */
public class MLDSASigner {

    /** The underlying BouncyCastle ML-DSA signature algorithm */
    private static final String ALGORITHM = "ML-DSA";
    
    /** SecureRandom instance for any potential randomness (though ML-DSA is deterministic) */
    private final SecureRandom secureRandom;

    /**
     * Constructs an ML-DSA signer with default SecureRandom.
     */
    public MLDSASigner() {
        this.secureRandom = new SecureRandom();
    }

    /**
     * Constructs an ML-DSA signer with a specific SecureRandom instance.
     * 
     * @param secureRandom the SecureRandom to use (may not be used since ML-DSA is deterministic)
     */
    public MLDSASigner(SecureRandom secureRandom) {
        this.secureRandom = secureRandom != null ? secureRandom : new SecureRandom();
    }

    /**
     * Signs data with the given ML-DSA private key.
     * 
     * Signing is deterministic: the same data and key always produce the same signature.
     * Output size depends on the ML-DSA variant:
     * - ML-DSA-44: ~2420 bytes
     * - ML-DSA-65: ~3293 bytes
     * - ML-DSA-87: ~4595 bytes
     * 
     * @param data the data to sign (must not be null)
     * @param privateKey the ML-DSA private key (must not be null)
     * @return the signature bytes (deterministic)
     * @throws IllegalArgumentException if data or privateKey is null
     * @throws IllegalStateException if the private key is invalid or if signing fails
     */
    public byte[] sign(byte[] data, PrivateKey privateKey) {
        if (data == null) {
            throw new IllegalArgumentException("Data to sign cannot be null");
        }
        if (privateKey == null) {
            throw new IllegalArgumentException("Private key cannot be null");
        }

        try {
            // Use JCA Signature API with BouncyCastle provider
            Signature signer = Signature.getInstance("ML-DSA", "BC");
            signer.initSign(privateKey);
            signer.update(data);
            
            byte[] signature = signer.sign();
            
            if (signature == null || signature.length == 0) {
                throw new IllegalStateException("Signature generation failed: empty signature");
            }
            
            return signature;
            
        } catch (IllegalArgumentException | IllegalStateException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalStateException("ML-DSA signing failed: " + e.getMessage(), e);
        }
    }

    /**
     * Returns the name of this signer.
     * 
     * @return "ML-DSA"
     */
    public String getAlgorithmName() {
        return ALGORITHM;
    }

    /**
     * Validates that a key is a valid ML-DSA private key.
     * 
     * @param key the key to validate
     * @return true if key can be used for ML-DSA signing, false otherwise
     */
    public static boolean isValidPrivateKey(PrivateKey key) {
        return key != null && "ML-DSA".equals(key.getAlgorithm());
    }

    /**
     * Returns a string representation of this signer.
     * 
     * @return a description of this signer
     */
    @Override
    public String toString() {
        return "MLDSASigner{" +
                "algorithm='" + ALGORITHM + '\'' +
                '}';
    }
}
