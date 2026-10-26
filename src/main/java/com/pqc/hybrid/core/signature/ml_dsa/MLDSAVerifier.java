package com.pqc.hybrid.core.signature.ml_dsa;

import com.pqc.hybrid.core.config.CryptographicProviderFactory;
import com.pqc.hybrid.core.exception.PQCHybridException;

import java.security.Provider;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Objects;

/**
 * Centralized ML-DSA (Module-Lattice-Based Digital Signature Algorithm, FIPS 204, formerly
 * Dilithium) signature verification.
 *
 * <p>Counterpart of {@link MLDSASigner}: all ML-DSA verification in the active path (hybrid
 * signature verification and the Catalyst alternative-signature check on certificates) flows
 * through this class. Verification delegates to BouncyCastle's JCA provider, with the concrete
 * parameter set (ML-DSA-44/65/87) selected by the {@code algorithm} name passed in.
 *
 * <p>A well-formed but incorrect signature returns {@code false}; a structural failure (unknown
 * algorithm, malformed signature, unusable key) raises {@link PQCHybridException} so callers can
 * distinguish "not authentic" from "could not verify".
 *
 * @author PQC Hybrid Team
 * @version 1.0.0-BETA
 * @see MLDSASigner
 */
public final class MLDSAVerifier {

    private MLDSAVerifier() {
        throw new AssertionError("Cannot instantiate MLDSAVerifier");
    }

    /**
     * Verifies an ML-DSA signature over {@code data}.
     *
     * @param data      the original signed data
     * @param signature the signature to verify
     * @param publicKey the ML-DSA public key
     * @param algorithm the ML-DSA parameter set name (e.g. {@code "ML-DSA-44"})
     * @return true if the signature is valid, false if it is well-formed but does not match
     * @throws NullPointerException if any argument is null
     * @throws PQCHybridException   if verification cannot be performed
     */
    public static boolean verify(byte[] data, byte[] signature, PublicKey publicKey, String algorithm) {
        return verify(data, signature, publicKey, algorithm, null);
    }

    /**
     * Verifies an ML-DSA signature over {@code data} under a context string.
     *
     * <p>The context must be the same one used to produce the signature: a signature made under a
     * different context, or under none, does not verify here. A {@code null} or empty context
     * means the FIPS 204 default (the empty context).
     *
     * @param data      the original signed data
     * @param signature the signature to verify
     * @param publicKey the ML-DSA public key
     * @param algorithm the ML-DSA parameter set name (e.g. {@code "ML-DSA-44"})
     * @param context   the context string the signature was produced under; may be null or empty
     * @return true if the signature is valid, false if it is well-formed but does not match
     * @throws NullPointerException if data, signature, publicKey or algorithm is null
     * @throws PQCHybridException   if verification cannot be performed
     */
    public static boolean verify(byte[] data, byte[] signature, PublicKey publicKey,
                                 String algorithm, byte[] context) {
        Objects.requireNonNull(data, "Data cannot be null");
        Objects.requireNonNull(signature, "Signature cannot be null");
        Objects.requireNonNull(publicKey, "Public key cannot be null");
        Objects.requireNonNull(algorithm, "Algorithm cannot be null");

        try {
            CryptographicProviderFactory.initialize();
            Provider provider = CryptographicProviderFactory.getProvider();

            Signature verifier = Signature.getInstance(algorithm, provider);
            // initVerify must come first: the provider rejects a context before it holds a key.
            verifier.initVerify(publicKey);
            MLDSASigner.applyContext(verifier, context);
            verifier.update(data);
            return verifier.verify(signature);
        } catch (Exception e) {
            throw new PQCHybridException("ML-DSA verification failed: " + e.getMessage(), e);
        }
    }

    /**
     * Checks whether a key can be used for ML-DSA verification.
     *
     * @param key the key to check
     * @return true if the key's algorithm is an ML-DSA parameter set
     */
    public static boolean isValidPublicKey(PublicKey key) {
        return key != null && key.getAlgorithm() != null && key.getAlgorithm().startsWith("ML-DSA");
    }
}
