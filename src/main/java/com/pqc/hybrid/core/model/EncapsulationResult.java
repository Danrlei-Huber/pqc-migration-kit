package com.pqc.hybrid.core.model;

import java.util.Arrays;

/**
 * Represents the result of a Key Encapsulation Mechanism (KEM) encapsulation operation.
 * 
 * A KEM encapsulation produces two outputs:
 * 1. A ciphertext that can only be decapsulated by the holder of the private key
 * 2. A shared secret that is deterministically derived from the ephemeral randomness
 * 
 * The shared secret is suitable for use as key material in symmetric encryption or key derivation functions.
 * The ciphertext must be transmitted to the other party for decapsulation.
 * 
 * Design Notes:
 * - Immutable record type (Java 21+)
 * - Secure: contains no private key material
 * - Size depends on KEM variant:
 *   - ML-KEM-512: ciphertext=768B, sharedSecret=32B
 *   - ML-KEM-768: ciphertext=1088B, sharedSecret=32B
 *   - ML-KEM-1024: ciphertext=1568B, sharedSecret=32B
 * 
 * Example Usage:
 * <pre>
 *     MLKEMEncapsulator encapsulator = new MLKEMEncapsulator();
 *     EncapsulationResult result = encapsulator.encapsulate(publicKey);
 *     
 *     // Send ciphertext to recipient
 *     byte[] ciphertext = result.ciphertext();
 *     
 *     // Keep shared secret for key derivation
 *     byte[] ss = result.sharedSecret();
 * </pre>
 * 
 * @author PQC Hybrid Team
 * @version 1.0.0
 * @since 2026-04-14
 */
public record EncapsulationResult(
        /** The ciphertext to be transmitted to the decapsulator */
        byte[] ciphertext,
        
        /** The shared secret (typically 32 bytes for ML-KEM) */
        byte[] sharedSecret
) {

    /**
     * Constructs an EncapsulationResult with ciphertext and shared secret.
     * 
     * Constructor validation ensures neither component is null.
     * 
     * @param ciphertext the encapsulated ciphertext (must not be null)
     * @param sharedSecret the derived shared secret (must not be null)
     * @throws IllegalArgumentException if either parameter is null
     */
    public EncapsulationResult {
        if (ciphertext == null) {
            throw new IllegalArgumentException("Ciphertext cannot be null");
        }
        if (sharedSecret == null) {
            throw new IllegalArgumentException("Shared secret cannot be null");
        }
        if (ciphertext.length == 0) {
            throw new IllegalArgumentException("Ciphertext cannot be empty");
        }
        if (sharedSecret.length == 0) {
            throw new IllegalArgumentException("Shared secret cannot be empty");
        }
    }

    /**
     * Returns the size of the ciphertext in bytes.
     * 
     * @return ciphertext length
     */
    public int ciphertextSize() {
        return ciphertext.length;
    }

    /**
     * Returns the size of the shared secret in bytes.
     * 
     * @return shared secret length
     */
    public int sharedSecretSize() {
        return sharedSecret.length;
    }

    /**
     * Creates a copy of this result with zeroed shared secret for cleanup.
     * 
     * WARNING: The returned object has zeros in place of the original shared secret.
     * This should be used carefully to avoid losing the actual shared secret.
     * 
     * @return a new EncapsulationResult with zeroed shared secret
     */
    public EncapsulationResult withZeroedSecret() {
        byte[] zeroedSecret = new byte[sharedSecret.length];
        return new EncapsulationResult(ciphertext.clone(), zeroedSecret);
    }

    /**
     * Securely zeros the shared secret in the current record.
     * 
     * Note: Since records are immutable, this only returns a zeroed copy.
     * The original bytes may still be in memory.
     */
    public void clearSharedSecret() {
        Arrays.fill(sharedSecret, (byte) 0);
    }

    /**
     * Returns a string representation of this encapsulation result.
     * 
     * Does NOT include the actual secret values for security.
     * 
     * @return a description of this result
     */
    @Override
    public String toString() {
        return "EncapsulationResult{" +
                "ciphertextSize=" + ciphertext.length +
                ", sharedSecretSize=" + sharedSecret.length +
                '}';
    }
}
