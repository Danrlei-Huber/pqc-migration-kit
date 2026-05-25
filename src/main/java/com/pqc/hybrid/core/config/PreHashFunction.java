package com.pqc.hybrid.core.config;

import java.security.MessageDigest;

/**
 * <b>EXPERIMENTAL.</b> Pre-hash functions used by the composite signature path
 * ({@code draft-ietf-lamps-pq-composite-sigs}).
 *
 * <p>Consumed only by {@link com.pqc.hybrid.core.signature.MessageRepresentativeBuilder},
 * part of the <i>Composite</i> path that is <b>not wired into
 * {@link com.pqc.hybrid.core.api.PQCHybridCertificateAPI}</b>. APIs here may
 * change without notice.
 */
public enum PreHashFunction {

    SHA256("SHA-256", 32),
    SHA512("SHA-512", 64),
    SHAKE256("SHAKE256", 32);

    private final String algorithmName;
    private final int outputLength;

    PreHashFunction(String algorithmName, int outputLength) {
        this.algorithmName = algorithmName;
        this.outputLength = outputLength;
    }

    public String getAlgorithmName() { return algorithmName; }
    public int getOutputLength() { return outputLength; }

    public byte[] hash(byte[] data) {
        try {
            MessageDigest md = MessageDigest.getInstance(algorithmName, "BC");
            return md.digest(data);
        } catch (Exception e) {
            throw new RuntimeException("Pre-hash failed: " + algorithmName, e);
        }
    }

    public static PreHashFunction fromName(String name) {
        for (PreHashFunction f : values()) {
            if (f.algorithmName.equalsIgnoreCase(name)) return f;
        }
        return SHA256;
    }
}
