package com.pqc.hybrid.core.signature.ml_dsa;

import com.pqc.hybrid.core.config.CryptographicProviderFactory;
import com.pqc.hybrid.core.exception.PQCHybridException;

import org.bouncycastle.jcajce.spec.ContextParameterSpec;

import java.security.PrivateKey;
import java.security.Provider;
import java.security.Signature;
import java.util.Objects;

/**
 * Centralized ML-DSA (Module-Lattice-Based Digital Signature Algorithm, FIPS 204, formerly
 * Dilithium) signing.
 *
 * <p>ML-DSA is the post-quantum half of every hybrid signature and certificate produced by this
 * library. All ML-DSA signing in the active path flows through this class, so the algorithm lives
 * in a single, testable place instead of being duplicated as inline {@code Signature.getInstance}
 * calls. Signing delegates to BouncyCastle's JCA provider; the concrete parameter set
 * (ML-DSA-44/65/87) is selected by the {@code algorithm} name passed in.
 *
 * <p>Signing uses the provider's default (hedged) randomness, exactly like a direct JCA call.
 *
 * @author PQC Hybrid Team
 * @version 1.0.0-BETA
 * @see MLDSAVerifier
 */
public final class MLDSASigner {

    private MLDSASigner() {
        throw new AssertionError("Cannot instantiate MLDSASigner");
    }

    /**
     * Signs {@code data} with an ML-DSA private key.
     *
     * @param data       the data to sign
     * @param privateKey the ML-DSA private key
     * @param algorithm  the ML-DSA parameter set name (e.g. {@code "ML-DSA-44"})
     * @return the ML-DSA signature bytes
     * @throws NullPointerException if any argument is null
     * @throws PQCHybridException   if signing fails
     */
    public static byte[] sign(byte[] data, PrivateKey privateKey, String algorithm) {
        return sign(data, privateKey, algorithm, null);
    }

    /**
     * Signs {@code data} with an ML-DSA private key under a context string.
     *
     * <p>The context is the FIPS 204 {@code ctx} parameter: it is bound into the signature, so a
     * signature produced under one context does not verify under another. Use it to keep
     * signatures from one purpose from being replayed as signatures for a different purpose.
     * A {@code null} or empty context means the FIPS 204 default (the empty context), which is
     * exactly what {@link #sign(byte[], PrivateKey, String)} produces.
     *
     * @param data       the data to sign
     * @param privateKey the ML-DSA private key
     * @param algorithm  the ML-DSA parameter set name (e.g. {@code "ML-DSA-44"})
     * @param context    the context string, at most 255 bytes; may be null or empty
     * @return the ML-DSA signature bytes
     * @throws NullPointerException if data, privateKey or algorithm is null
     * @throws PQCHybridException   if signing fails or the context exceeds 255 bytes
     */
    public static byte[] sign(byte[] data, PrivateKey privateKey, String algorithm, byte[] context) {
        Objects.requireNonNull(data, "Data cannot be null");
        Objects.requireNonNull(privateKey, "Private key cannot be null");
        Objects.requireNonNull(algorithm, "Algorithm cannot be null");

        try {
            CryptographicProviderFactory.initialize();
            Provider provider = CryptographicProviderFactory.getProvider();

            Signature signer = Signature.getInstance(algorithm, provider);
            // initSign must come first: the provider rejects a context before it holds a key.
            signer.initSign(privateKey);
            applyContext(signer, context);
            signer.update(data);
            return signer.sign();
        } catch (Exception e) {
            throw new PQCHybridException("ML-DSA signing failed: " + e.getMessage(), e);
        }
    }

    /**
     * Applies a FIPS 204 context string to an initialised {@link Signature}, treating null and
     * empty alike as the default empty context so that no parameter is set at all.
     */
    static void applyContext(Signature signature, byte[] context)
            throws java.security.InvalidAlgorithmParameterException {
        if (context != null && context.length > 0) {
            signature.setParameter(new ContextParameterSpec(context));
        }
    }

    /**
     * Checks whether a key can be used for ML-DSA signing.
     *
     * @param key the key to check
     * @return true if the key's algorithm is an ML-DSA parameter set
     */
    public static boolean isValidPrivateKey(PrivateKey key) {
        return key != null && key.getAlgorithm() != null && key.getAlgorithm().startsWith("ML-DSA");
    }
}
