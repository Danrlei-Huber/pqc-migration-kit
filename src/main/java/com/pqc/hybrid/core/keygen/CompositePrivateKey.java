package com.pqc.hybrid.core.keygen;

import com.pqc.hybrid.core.config.CompositeAlgorithm;

import java.security.PrivateKey;
import java.util.Arrays;
import javax.security.auth.Destroyable;
import javax.security.auth.DestroyFailedException;

/**
 * <b>EXPERIMENTAL.</b> Composite private key (classical + ML-DSA) for the composite
 * signature path ({@code draft-ietf-lamps-pq-composite-sigs}).
 *
 * <p>Part of the parallel <i>Composite</i> path; <b>not wired into
 * {@link com.pqc.hybrid.core.api.PQCHybridCertificateAPI}</b>. APIs here may
 * change without notice.
 */
public final class CompositePrivateKey implements PrivateKey, Destroyable {

    private final byte[] encoded;
    private final CompositeAlgorithm algorithm;
    private final PrivateKey mldsaPrivateKey;
    private final PrivateKey tradPrivateKey;
    private volatile boolean destroyed;

    public CompositePrivateKey(PrivateKey mldsaPrivateKey, PrivateKey tradPrivateKey,
                               byte[] mldsaSeed, CompositeAlgorithm algorithm) {
        this.mldsaPrivateKey = mldsaPrivateKey;
        this.tradPrivateKey = tradPrivateKey;
        this.algorithm = algorithm;
        this.destroyed = false;

        byte[] tradEnc = tradPrivateKey.getEncoded();
        this.encoded = new byte[mldsaSeed.length + tradEnc.length];
        System.arraycopy(mldsaSeed, 0, this.encoded, 0, mldsaSeed.length);
        System.arraycopy(tradEnc, 0, this.encoded, mldsaSeed.length, tradEnc.length);
    }

    public PrivateKey getMldsaPrivateKey() {
        checkDestroyed();
        return mldsaPrivateKey;
    }

    public PrivateKey getTradPrivateKey() {
        checkDestroyed();
        return tradPrivateKey;
    }

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
        checkDestroyed();
        return encoded.clone();
    }

    @Override
    public void destroy() {
        if (!destroyed) {
            destroyed = true;
            Arrays.fill(encoded, (byte) 0);
            // Best-effort wipe of the underlying keys. Many JCA/BC private-key
            // implementations declare destroy() but throw DestroyFailedException
            // (the JDK default does); the encoded copy above is already zeroed,
            // so a failure here is non-fatal and intentionally ignored.
            destroyQuietly(mldsaPrivateKey);
            destroyQuietly(tradPrivateKey);
        }
    }

    private static void destroyQuietly(PrivateKey key) {
        if (key instanceof Destroyable d) {
            try {
                d.destroy();
            } catch (DestroyFailedException ignored) {
                // see destroy(): best-effort, encoded bytes already zeroed
            }
        }
    }

    @Override
    public boolean isDestroyed() {
        return destroyed;
    }

    private void checkDestroyed() {
        if (destroyed) throw new IllegalStateException("Key has been destroyed");
    }
}
