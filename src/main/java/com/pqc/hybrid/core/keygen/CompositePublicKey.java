package com.pqc.hybrid.core.keygen;

import com.pqc.hybrid.core.config.CompositeAlgorithm;

import java.security.PublicKey;
import java.util.Arrays;

/**
 * <b>EXPERIMENTAL.</b> Composite public key (classical + ML-DSA) for the composite
 * signature path ({@code draft-ietf-lamps-pq-composite-sigs}).
 *
 * <p>Part of the parallel <i>Composite</i> path; <b>not wired into
 * {@link com.pqc.hybrid.core.api.PQCHybridCertificateAPI}</b>. APIs here may
 * change without notice.
 */
public final class CompositePublicKey implements PublicKey {

    private final byte[] encoded;
    private final CompositeAlgorithm algorithm;
    private final PublicKey mldsaPublicKey;
    private final PublicKey tradPublicKey;

    public CompositePublicKey(PublicKey mldsaPublicKey, PublicKey tradPublicKey, CompositeAlgorithm algorithm) {
        this.mldsaPublicKey = mldsaPublicKey;
        this.tradPublicKey = tradPublicKey;
        this.algorithm = algorithm;

        byte[] mldsaEnc = mldsaPublicKey.getEncoded();
        byte[] tradEnc = tradPublicKey.getEncoded();
        this.encoded = new byte[mldsaEnc.length + tradEnc.length];
        System.arraycopy(mldsaEnc, 0, this.encoded, 0, mldsaEnc.length);
        System.arraycopy(tradEnc, 0, this.encoded, mldsaEnc.length, tradEnc.length);
    }

    public PublicKey getMldsaPublicKey() { return mldsaPublicKey; }
    public PublicKey getTradPublicKey() { return tradPublicKey; }
    public CompositeAlgorithm getCompositeAlgorithm() { return algorithm; }

    @Override
    public String getAlgorithm() {
        return "Composite-ML-DSA";
    }

    @Override
    public String getFormat() {
        return "RAW";
    }

    @Override
    public byte[] getEncoded() {
        return encoded.clone();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof CompositePublicKey that)) return false;
        return Arrays.equals(encoded, that.encoded);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(encoded);
    }
}
