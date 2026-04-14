package com.pqc.hybrid.core.signature;

import java.util.Arrays;
import java.util.Objects;

/**
 * Represents a hybrid digital signature combining classical and PQC signatures.
 * 
 * A hybrid signature consists of:
 * - A classical signature (RSA or ECDSA) for backward compatibility
 * - A PQC signature (ML-DSA, Falcon, or SLH-DSA) for quantum resistance
 *
 * Both signatures are computed over the same message and must both validate
 * for the hybrid signature to be considered authentic.
 *
 * @author PQC Hybrid Team
 * @version 1.0.0-BETA
 */
public final class HybridSignaturePair {

    private final byte[] classicalSignature;
    private final byte[] pqcSignature;
    private final String classicalAlgorithm;
    private final String pqcAlgorithm;
    private final byte[] messageHash;
    private final long signatureTime;

    /**
     * Creates a new HybridSignaturePair.
     *
     * @param classicalSignature the classical algorithm signature
     * @param pqcSignature the PQC algorithm signature
     * @param classicalAlgorithm the classical algorithm name
     * @param pqcAlgorithm the PQC algorithm name
     * @param messageHash the hash of the signed message
     */
    public HybridSignaturePair(byte[] classicalSignature, byte[] pqcSignature,
                               String classicalAlgorithm, String pqcAlgorithm, byte[] messageHash) {
        this.classicalSignature = Objects.requireNonNull(classicalSignature, 
                "Classical signature cannot be null").clone();
        this.pqcSignature = Objects.requireNonNull(pqcSignature, 
                "PQC signature cannot be null").clone();
        this.classicalAlgorithm = Objects.requireNonNull(classicalAlgorithm, 
                "Classical algorithm cannot be null");
        this.pqcAlgorithm = Objects.requireNonNull(pqcAlgorithm, 
                "PQC algorithm cannot be null");
        this.messageHash = messageHash != null ? messageHash.clone() : null;
        this.signatureTime = System.currentTimeMillis();
    }

    /**
     * Gets the classical algorithm signature.
     * The returned array is a copy - modifications don't affect the original.
     */
    public byte[] getClassicalSignature() {
        return classicalSignature.clone();
    }

    /**
     * Gets the PQC algorithm signature.
     * The returned array is a copy - modifications don't affect the original.
     */
    public byte[] getPQCSignature() {
        return pqcSignature.clone();
    }

    /**
     * Gets the classical algorithm name.
     */
    public String getClassicalAlgorithm() {
        return classicalAlgorithm;
    }

    /**
     * Gets the PQC algorithm name.
     */
    public String getPQCAlgorithm() {
        return pqcAlgorithm;
    }

    /**
     * Gets the message hash (if available).
     */
    public byte[] getMessageHash() {
        return messageHash != null ? messageHash.clone() : null;
    }

    /**
     * Gets the classical signature size in bytes.
     */
    public int getClassicalSignatureSize() {
        return classicalSignature.length;
    }

    /**
     * Gets the PQC signature size in bytes.
     */
    public int getPQCSignatureSize() {
        return pqcSignature.length;
    }

    /**
     * Gets the total size of both signatures.
     */
    public int getTotalSize() {
        return classicalSignature.length + pqcSignature.length;
    }

    /**
     * Gets the time when this signature was created.
     */
    public long getSignatureTime() {
        return signatureTime;
    }

    /**
     * Gets a descriptive label for this signature.
     */
    public String getLabel() {
        return String.format("%s + %s", classicalAlgorithm, pqcAlgorithm);
    }

    /**
     * Securely wipes both signatures from memory.
     * After calling this method, the signatures are no longer accessible.
     */
    public void wipeSignatures() {
        Arrays.fill(classicalSignature, (byte) 0);
        Arrays.fill(pqcSignature, (byte) 0);
        if (messageHash != null) {
            Arrays.fill(messageHash, (byte) 0);
        }
    }

    @Override
    public String toString() {
        return String.format("HybridSignaturePair{%s + %s, classical: %d bytes, PQC: %d bytes}",
                classicalAlgorithm, pqcAlgorithm,
                classicalSignature.length, pqcSignature.length);
    }
}
