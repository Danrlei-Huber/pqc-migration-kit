package com.pqc.hybrid.core.keygen;

import java.util.Arrays;
import java.util.Objects;

/**
 * Result of a key encapsulation (KEM) operation.
 * 
 * Contains:
 * - sharedSecret: The shared secret derived from the encapsulation
 * - ciphertext: The encapsulated public data (safe to transmit)
 *
 * The ciphertext is deterministically generated from the shared secret
 * and can be decapsulated by the private key holder to recover the shared secret.
 *
 * @author PQC Hybrid Team
 * @version 1.0.0-BETA
 */
public final class EncapsulationResult {

    private final byte[] sharedSecret;
    private final byte[] ciphertext;
    private final long operationTime;

    /**
     * Creates a new EncapsulationResult.
     *
     * @param sharedSecret the shared secret (sensitive)
     * @param ciphertext the encapsulated public data
     */
    public EncapsulationResult(byte[] sharedSecret, byte[] ciphertext) {
        this.sharedSecret = Objects.requireNonNull(sharedSecret, "Shared secret cannot be null").clone();
        this.ciphertext = Objects.requireNonNull(ciphertext, "Ciphertext cannot be null").clone();
        this.operationTime = System.nanoTime();
    }

    /**
     * Gets the shared secret.
     * The returned array is a copy - modifications don't affect the original.
     *
     * @return the shared secret
     */
    public byte[] getSharedSecret() {
        return sharedSecret.clone();
    }

    /**
     * Gets the ciphertext.
     * The returned array is a copy - modifications don't affect the original.
     *
     * @return the ciphertext
     */
    public byte[] getCiphertext() {
        return ciphertext.clone();
    }

    /**
     * Gets the shared secret size in bytes.
     */
    public int getSharedSecretSize() {
        return sharedSecret.length;
    }

    /**
     * Gets the ciphertext size in bytes.
     */
    public int getCiphertextSize() {
        return ciphertext.length;
    }

    /**
     * Gets the operation time in nanoseconds.
     */
    public long getOperationTimeNanos() {
        return operationTime;
    }

    /**
     * Securely wipes the shared secret from memory.
     * After calling this method, the shared secret is no longer accessible.
     */
    public void wipeSharedSecret() {
        Arrays.fill(sharedSecret, (byte) 0);
    }

    /**
     * Securely wipes both shared secret and ciphertext from memory.
     */
    public void wipeAll() {
        Arrays.fill(sharedSecret, (byte) 0);
        Arrays.fill(ciphertext, (byte) 0);
    }

    @Override
    public String toString() {
        return String.format("EncapsulationResult{sharedSecret: %d bytes, ciphertext: %d bytes}",
                sharedSecret.length, ciphertext.length);
    }
}
