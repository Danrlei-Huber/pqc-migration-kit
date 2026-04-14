package com.pqc.hybrid.core.keygen;

import com.pqc.hybrid.core.config.CryptographicProviderFactory;
import com.pqc.hybrid.core.config.PQCAlgorithm;
import com.pqc.hybrid.core.exception.EncapsulationException;
import com.pqc.hybrid.core.exception.PQCHybridException;

import java.security.KeyPairGenerator;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.Provider;
import java.util.Objects;
import java.util.logging.Logger;

/**
 * Wrapper for ML-KEM (Key Encapsulation Mechanism) operations.
 * 
 * ML-KEM is a NIST-standardized key encapsulation mechanism based on lattice cryptography.
 * It provides:
 * - encapsulate(): Generates a shared secret and encapsulation from a public key
 * - decapsulate(): Recovers the shared secret from an encapsulation using the private key
 *
 * Used for secure key agreement in hybrid certificates for key establishment.
 *
 * @author PQC Hybrid Team
 * @version 1.0.0-BETA
 */
public final class KeyEncapsulationWrapper {

    private static final Logger logger = Logger.getLogger(KeyEncapsulationWrapper.class.getName());

    /**
     * Private constructor - use static factory methods.
     */
    private KeyEncapsulationWrapper() {
        throw new AssertionError("Cannot instantiate KeyEncapsulationWrapper");
    }

    /**
     * Generates an ML-KEM key pair.
     *
     * @param algorithm the ML-KEM algorithm variant
     * @return the generated KeyPair
     * @throws PQCHybridException if generation fails
     */
    public static KeyPair generateKeyPair(PQCAlgorithm algorithm) {
        Objects.requireNonNull(algorithm, "Algorithm cannot be null");
        
        if (algorithm.getCategory() != PQCAlgorithm.AlgorithmCategory.KEY_ENCAPSULATION) {
            throw new IllegalArgumentException("Algorithm must be a KEM algorithm: " + algorithm.getName());
        }

        try {
            CryptographicProviderFactory.initialize();
            Provider provider = CryptographicProviderFactory.getProvider();
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(algorithm.getName(), provider);
            
            KeyPair keyPair = kpg.generateKeyPair();
            logger.info("Generated ML-KEM key pair: " + algorithm.getName());
            return keyPair;

        } catch (Exception e) {
            throw new PQCHybridException("Failed to generate ML-KEM key pair for " + algorithm.getName(), e);
        }
    }

    /**
     * Encapsulates a shared secret using a public key.
     * 
     * The encapsulation can be transmitted insecurely; only the private key holder
     * can recover the shared secret with decapsulate().
     *
     * @param algorithm the ML-KEM algorithm variant
     * @param publicKey the recipient's public key
     * @return the encapsulation result containing the shared secret and ciphertext
     * @throws EncapsulationException if encapsulation fails
     */
    public static EncapsulationResult encapsulate(PQCAlgorithm algorithm, PublicKey publicKey) {
        Objects.requireNonNull(algorithm, "Algorithm cannot be null");
        Objects.requireNonNull(publicKey, "Public key cannot be null");

        try {
            CryptographicProviderFactory.initialize();
            Provider provider = CryptographicProviderFactory.getProvider();

            // This is a simplified representation. In production, would use actual KEM implementation
            // from BouncyCastle or OpenQuantumSafe
            
            logger.fine("Encapsulating with " + algorithm.getName());
            // Placeholder - actual implementation uses KEM provider from BC
            throw new EncapsulationException("KEM encapsulation not yet fully implemented");

        } catch (EncapsulationException e) {
            throw e;
        } catch (Exception e) {
            throw new EncapsulationException("Encapsulation failed for " + algorithm.getName(), e);
        }
    }

    /**
     * Decapsulates a ciphertext using a private key to recover the shared secret.
     *
     * @param algorithm the ML-KEM algorithm variant
     * @param privateKey the recipient's private key
     * @param ciphertext the encapsulation to decapsulate
     * @return the recovered shared secret
     * @throws EncapsulationException if decapsulation fails
     */
    public static byte[] decapsulate(PQCAlgorithm algorithm, PrivateKey privateKey, byte[] ciphertext) {
        Objects.requireNonNull(algorithm, "Algorithm cannot be null");
        Objects.requireNonNull(privateKey, "Private key cannot be null");
        Objects.requireNonNull(ciphertext, "Ciphertext cannot be null");

        try {
            CryptographicProviderFactory.initialize();
            Provider provider = CryptographicProviderFactory.getProvider();

            logger.fine("Decapsulating with " + algorithm.getName());
            // Placeholder - actual implementation uses KEM provider from BC
            throw new EncapsulationException("KEM decapsulation not yet fully implemented");

        } catch (EncapsulationException e) {
            throw e;
        } catch (Exception e) {
            throw new EncapsulationException("Decapsulation failed for " + algorithm.getName(), e);
        }
    }

    /**
     * Gets the expected size of the shared secret for an algorithm.
     *
     * @param algorithm the ML-KEM algorithm variant
     * @return the shared secret size in bytes
     */
    public static int getSharedSecretSize(PQCAlgorithm algorithm) {
        Objects.requireNonNull(algorithm, "Algorithm cannot be null");
        
        return switch (algorithm) {
            case ML_KEM_512 -> 32;   // 256 bits
            case ML_KEM_768 -> 32;   // 256 bits
            case ML_KEM_1024 -> 32;  // 256 bits
            default -> throw new IllegalArgumentException("Not a KEM algorithm: " + algorithm.getName());
        };
    }

    /**
     * Gets the expected size of the ciphertext for an algorithm.
     *
     * @param algorithm the ML-KEM algorithm variant
     * @return the ciphertext size in bytes (approximate)
     */
    public static int getCiphertextSize(PQCAlgorithm algorithm) {
        Objects.requireNonNull(algorithm, "Algorithm cannot be null");
        
        return switch (algorithm) {
            case ML_KEM_512 -> 800;
            case ML_KEM_768 -> 1088;
            case ML_KEM_1024 -> 1568;
            default -> throw new IllegalArgumentException("Not a KEM algorithm: " + algorithm.getName());
        };
    }
}
