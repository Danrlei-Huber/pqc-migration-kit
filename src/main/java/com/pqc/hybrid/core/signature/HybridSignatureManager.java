package com.pqc.hybrid.core.signature;

import com.pqc.hybrid.core.config.CryptographicProviderFactory;
import com.pqc.hybrid.core.config.ClassicalAlgorithm;
import com.pqc.hybrid.core.keygen.HybridKeyPair;
import com.pqc.hybrid.core.exception.PQCHybridException;
import com.pqc.hybrid.core.exception.InvalidSignatureException;
import com.pqc.hybrid.core.signature.ml_dsa.MLDSASigner;
import com.pqc.hybrid.core.signature.ml_dsa.MLDSAVerifier;

import java.security.MessageDigest;
import java.security.Provider;
import java.security.Signature;
import java.util.Objects;
import java.util.logging.Logger;

/**
 * Manager for hybrid digital signature operations.
 * 
 * Provides methods to:
 * - Sign data with both classical and PQC algorithms
 * - Verify hybrid signatures (both components must validate)
 * - Get signature metadata
 *
 * Uses BouncyCastle as the cryptographic provider for both classical
 * and PQC algorithms.
 *
 * @author PQC Hybrid Team
 * @version 1.0.0-BETA
 */
public final class HybridSignatureManager {

    private static final Logger logger = Logger.getLogger(HybridSignatureManager.class.getName());

    /**
     * Private constructor - use static factory methods.
     */
    private HybridSignatureManager() {
        throw new AssertionError("Cannot instantiate HybridSignatureManager");
    }

    /**
     * Signs data with a hybrid key pair, producing both classical and PQC signatures.
     *
     * @param data the data to sign
     * @param keyPair the hybrid key pair
     * @return the hybrid signature pair
     * @throws PQCHybridException if signing fails
     */
    public static HybridSignaturePair sign(byte[] data, HybridKeyPair keyPair) {
        return sign(data, keyPair, null);
    }

    /**
     * Signs data with a hybrid key pair under a context string.
     *
     * <p>The context is the FIPS 204 {@code ctx} parameter and is bound into the
     * <b>post-quantum</b> half of the signature, so a hybrid signature produced under one context
     * does not verify under another. Classical signature algorithms (RSA, ECDSA) have no
     * equivalent parameter, so the classical half is unaffected; because verification requires
     * both halves, the pair as a whole is still domain-separated. A {@code null} or empty context
     * is the FIPS 204 default and behaves exactly like {@link #sign(byte[], HybridKeyPair)}.
     *
     * @param data the data to sign
     * @param keyPair the hybrid key pair
     * @param context the context string, at most 255 bytes; may be null or empty
     * @return the hybrid signature pair
     * @throws PQCHybridException if signing fails
     */
    public static HybridSignaturePair sign(byte[] data, HybridKeyPair keyPair, byte[] context) {
        Objects.requireNonNull(data, "Data cannot be null");
        Objects.requireNonNull(keyPair, "Key pair cannot be null");

        try {
            CryptographicProviderFactory.initialize();
            Provider provider = CryptographicProviderFactory.getProvider();

            // Sign with classical algorithm
            byte[] classicalSignature = signWithClassical(data, keyPair, provider);

            // Sign with PQC algorithm (ML-DSA)
            byte[] pqcSignature = signWithPQC(data, keyPair, context);

            HybridSignaturePair signaturePair = new HybridSignaturePair(
                    classicalSignature,
                    pqcSignature,
                    keyPair.getClassicalAlgorithm(),
                    keyPair.getPQCAlgorithm(),
                    hashData(data)
            );

            logger.info("Signed data with hybrid signature: " + signaturePair.getLabel());
            return signaturePair;

        } catch (PQCHybridException e) {
            throw e;
        } catch (Exception e) {
            throw new PQCHybridException("Hybrid signature generation failed", e);
        }
    }

    /**
     * Verifies a hybrid signature against data and a hybrid key pair.
     * Both classical and PQC components must validate successfully.
     *
     * @param data the original data
     * @param signaturePair the hybrid signature to verify
     * @param keyPair the hybrid key pair (public keys used for verification)
     * @return true if both signatures verify, false otherwise
     * @throws InvalidSignatureException if verification fails unexpectedly
     */
    public static boolean verify(byte[] data, HybridSignaturePair signaturePair, HybridKeyPair keyPair)
            throws InvalidSignatureException {
        return verify(data, signaturePair, keyPair, null);
    }

    /**
     * Verifies a hybrid signature produced under a context string. The context must match the one
     * used to sign; both classical and PQC components must validate.
     *
     * @param data the original data
     * @param signaturePair the hybrid signature to verify
     * @param keyPair the hybrid key pair (public keys used for verification)
     * @param context the context string the signature was produced under; may be null or empty
     * @return true if both signatures verify, false otherwise
     * @throws InvalidSignatureException if verification fails unexpectedly
     */
    public static boolean verify(byte[] data, HybridSignaturePair signaturePair, HybridKeyPair keyPair,
                                 byte[] context) throws InvalidSignatureException {
        Objects.requireNonNull(data, "Data cannot be null");
        Objects.requireNonNull(signaturePair, "Signature pair cannot be null");
        Objects.requireNonNull(keyPair, "Key pair cannot be null");

        try {
            CryptographicProviderFactory.initialize();
            Provider provider = CryptographicProviderFactory.getProvider();

            // Verify classical signature
            boolean classicalValid = verifyClassical(data, signaturePair, keyPair, provider);

            // Verify PQC signature (ML-DSA)
            boolean pqcValid = verifyPQC(data, signaturePair, keyPair, context);

            // Both must be valid for hybrid signature to pass
            boolean result = classicalValid && pqcValid;

            logger.fine("Hybrid signature verification: classical=" + classicalValid + 
                       ", PQC=" + pqcValid + ", combined=" + result);

            return result;

        } catch (InvalidSignatureException e) {
            throw e;
        } catch (Exception e) {
            throw new InvalidSignatureException("Hybrid signature verification failed", e);
        }
    }

    /**
     * Verifies only the classical component of a hybrid signature.
     * Useful for backward compatibility checks.
     */
    public static boolean verifyClassicalOnly(byte[] data, HybridSignaturePair signaturePair, 
                                              HybridKeyPair keyPair) throws InvalidSignatureException {
        Objects.requireNonNull(data, "Data cannot be null");
        Objects.requireNonNull(signaturePair, "Signature pair cannot be null");
        Objects.requireNonNull(keyPair, "Key pair cannot be null");

        try {
            CryptographicProviderFactory.initialize();
            Provider provider = CryptographicProviderFactory.getProvider();
            return verifyClassical(data, signaturePair, keyPair, provider);

        } catch (Exception e) {
            throw new InvalidSignatureException("Classical signature verification failed", e);
        }
    }

    /**
     * Internal method to sign with classical algorithm.
     */
    private static byte[] signWithClassical(byte[] data, HybridKeyPair keyPair, Provider provider) 
            throws Exception {
        String algorithm = getClassicalSignatureAlgorithmName(keyPair);
        Signature sig = Signature.getInstance(algorithm, provider);
        sig.initSign(keyPair.getClassicalPrivateKey());
        sig.update(data);
        return sig.sign();
    }

    /**
     * Internal method to sign with the PQC algorithm (ML-DSA), delegating to {@link MLDSASigner}.
     */
    private static byte[] signWithPQC(byte[] data, HybridKeyPair keyPair, byte[] context) {
        return MLDSASigner.sign(data, keyPair.getPQCPrivateKey(),
                keyPair.getPQCPrivateKey().getAlgorithm(), context);
    }

    /**
     * Internal method to verify classical signature.
     */
    private static boolean verifyClassical(byte[] data, HybridSignaturePair signaturePair,
                                           HybridKeyPair keyPair, Provider provider) throws Exception {
        String algorithm = getClassicalSignatureAlgorithmName(keyPair);
        Signature sig = Signature.getInstance(algorithm, provider);
        sig.initVerify(keyPair.getClassicalPublicKey());
        sig.update(data);
        return sig.verify(signaturePair.getClassicalSignature());
    }

    /**
     * Internal method to verify the PQC signature (ML-DSA), delegating to {@link MLDSAVerifier}.
     */
    private static boolean verifyPQC(byte[] data, HybridSignaturePair signaturePair,
                                     HybridKeyPair keyPair, byte[] context) {
        // The parameter set is taken from the verification key, never from the signature blob
        // being checked: a caller-supplied HybridSignaturePair must not be able to steer which
        // algorithm verifies it. The name it carries stays informational metadata.
        return MLDSAVerifier.verify(data, signaturePair.getPQCSignature(),
                keyPair.getPQCPublicKey(), keyPair.getPQCPublicKey().getAlgorithm(), context);
    }

    /**
     * Resolves the classical signature algorithm from the key pair's own key material, so the
     * digest matches the key's strength (P-384 signs with SHA-384, not SHA-256). Signing and
     * verification both resolve from the public key, so the two sides always agree.
     */
    private static String getClassicalSignatureAlgorithmName(HybridKeyPair keyPair) {
        return ClassicalAlgorithm.getSignatureAlgorithmForKey(keyPair.getClassicalPublicKey());
    }

    /**
     * Hashes the data using SHA-256.
     */
    private static byte[] hashData(byte[] data) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256", "BC");
            return md.digest(data);
        } catch (Exception e) {
            throw new PQCHybridException("Failed to hash data", e);
        }
    }
}
