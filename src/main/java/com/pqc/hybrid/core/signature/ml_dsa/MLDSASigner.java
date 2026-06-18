package com.pqc.hybrid.core.signature.ml_dsa;

import com.pqc.hybrid.core.config.CryptographicProviderFactory;
import com.pqc.hybrid.core.exception.PQCHybridException;

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
        Objects.requireNonNull(data, "Data cannot be null");
        Objects.requireNonNull(privateKey, "Private key cannot be null");
        Objects.requireNonNull(algorithm, "Algorithm cannot be null");

        try {
            CryptographicProviderFactory.initialize();
            Provider provider = CryptographicProviderFactory.getProvider();

            Signature signer = Signature.getInstance(algorithm, provider);
            signer.initSign(privateKey);
            signer.update(data);
            return signer.sign();
        } catch (Exception e) {
            throw new PQCHybridException("ML-DSA signing failed: " + e.getMessage(), e);
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
