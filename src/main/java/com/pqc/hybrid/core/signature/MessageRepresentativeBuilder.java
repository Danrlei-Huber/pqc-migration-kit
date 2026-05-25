package com.pqc.hybrid.core.signature;

import com.pqc.hybrid.core.config.CompositeAlgorithm;
import com.pqc.hybrid.core.config.PreHashFunction;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;

/**
 * <b>EXPERIMENTAL.</b> Builds the message representative (domain-separated,
 * optionally pre-hashed) consumed by the composite signature path
 * ({@code draft-ietf-lamps-pq-composite-sigs}).
 *
 * <p>Used only by {@link CompositeSigner}/{@link CompositeVerifier}, which are
 * <b>not wired into {@link com.pqc.hybrid.core.api.PQCHybridCertificateAPI}</b>.
 * APIs here may change without notice.
 */
public final class MessageRepresentativeBuilder {

    private static final byte[] PREFIX = "CompositeAlgorithmSignatures2025".getBytes(StandardCharsets.US_ASCII);

    private MessageRepresentativeBuilder() {
        throw new AssertionError("Cannot instantiate MessageRepresentativeBuilder");
    }

    public static byte[] build(byte[] data, CompositeAlgorithm algorithm) {
        return build(data, algorithm, new byte[0]);
    }

    public static byte[] build(byte[] data, CompositeAlgorithm algorithm, byte[] ctx) {
        if (ctx == null) ctx = new byte[0];
        if (ctx.length > 255) {
            throw new IllegalArgumentException("Context length must not exceed 255 bytes");
        }

        PreHashFunction ph = PreHashFunction.fromName(algorithm.getPreHashAlgorithm());
        byte[] phOutput = ph.hash(data);
        byte[] labelBytes = algorithm.getLabel().getBytes(StandardCharsets.US_ASCII);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.writeBytes(PREFIX);
        baos.writeBytes(labelBytes);
        baos.write((byte) ctx.length);
        if (ctx.length > 0) {
            baos.writeBytes(ctx);
        }
        baos.writeBytes(phOutput);
        return baos.toByteArray();
    }
}
