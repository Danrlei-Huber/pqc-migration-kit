package com.pqc.hybrid.core.config;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import com.pqc.hybrid.core.exception.PQCHybridException;

import java.security.Provider;
import java.security.Security;
import java.util.Objects;
import java.util.logging.Logger;

/**
 * Factory for initializing and managing BouncyCastle as the default cryptographic provider.
 * 
 * This class ensures that BouncyCastle is properly installed and configured so that all
 * PQC algorithms (ML-KEM, ML-DSA, SLH-DSA, Falcon) are available for use with standard
 * Java cryptography APIs (Signature, KeyPairGenerator, etc.).
 *
 * BouncyCastle must be initialized before any cryptographic operations are performed.
 * This typically happens once at application startup.
 *
 * @author PQC Hybrid Team
 * @version 1.0.0-BETA
 */
public final class CryptographicProviderFactory {

    private static final Logger logger = Logger.getLogger(CryptographicProviderFactory.class.getName());
    private static final String BOUNCY_CASTLE_PROVIDER_NAME = "BC";
    private static volatile boolean initialized = false;

    /**
     * Private constructor to prevent instantiation.
     */
    private CryptographicProviderFactory() {
        throw new AssertionError("Cannot instantiate CryptographicProviderFactory");
    }

    /**
     * Initializes the BouncyCastle provider for PQC algorithms.
     * This method is idempotent - it can be called multiple times safely.
     *
     * This must be called at least once before performing any PQC operations.
     *
     * @throws PQCHybridException if BouncyCastle provider cannot be initialized
     */
    public static void initialize() {
        if (initialized) {
            logger.fine("BouncyCastle provider already initialized");
            return;
        }

        synchronized (CryptographicProviderFactory.class) {
            if (initialized) {
                return;  // Double-check locking
            }

            try {
                BouncyCastleProvider provider = new BouncyCastleProvider();
                Security.addProvider(provider);
                
                logger.info("BouncyCastle provider initialized");
                initialized = true;
            } catch (Exception e) {
                throw new PQCHybridException("Failed to initialize BouncyCastle provider", e);
            }
        }
    }

    /**
     * Gets the BouncyCastle provider instance.
     *
     * @return the BouncyCastle provider
     * @throws PQCHybridException if provider is not initialized
     */
    public static Provider getProvider() {
        ensureInitialized();
        Provider provider = Security.getProvider(BOUNCY_CASTLE_PROVIDER_NAME);
        if (provider == null) {
            throw new PQCHybridException("BouncyCastle provider not found in security provider list");
        }
        return provider;
    }

    /**
     * Checks if a specific algorithm is available.
     *
     * @param algorithm the algorithm name (e.g., "ML-DSA-65", "ML-KEM-512")
     * @return true if the algorithm is available
     */
    public static boolean isAlgorithmAvailable(String algorithm) {
        Objects.requireNonNull(algorithm, "Algorithm name cannot be null");
        ensureInitialized();
        
        // Use the provider's service to check if algorithm is available
        Provider provider = getProvider();
        return provider.getService("Signature", algorithm) != null
                || provider.getService("KeyPairGenerator", algorithm) != null
                || provider.getService("KeyGenerator", algorithm) != null;
    }

    /**
     * Validates that all required PQC algorithms are available.
     *
     * @throws PQCHybridException if any required algorithm is not available
     */
    public static void validateRequiredAlgorithms() {
        ensureInitialized();

        String[] requiredAlgorithms = {
                "ML-KEMKeyGen",
                "ML-KEMEncapsulate",
                "ML-KEMDecapsulate",
                "ML-DSA-44",
                "ML-DSA-65",
                "ML-DSA-87",
                "SLH-DSA-SHA2-128s",
                "SLH-DSA-SHA2-128f",
                "Falcon",
                "Falcon-512"
        };

        StringBuilder unavailable = new StringBuilder();
        for (String algo : requiredAlgorithms) {
            if (!isAlgorithmAvailable(algo)) {
                if (unavailable.length() > 0) {
                    unavailable.append(", ");
                }
                unavailable.append(algo);
            }
        }

        if (unavailable.length() > 0) {
            throw new PQCHybridException("Required PQC algorithms not available: " + unavailable);
        }

        logger.info("All required PQC algorithms are available");
    }

    /**
     * Gets the BouncyCastle provider version.
     *
     * @return the provider version string
     */
    public static String getProviderVersion() {
        ensureInitialized();
        Provider provider = getProvider();
        return String.valueOf(provider.getVersion());
    }

    /**
     * Ensures the provider is initialized.
     *
     * @throws PQCHybridException if initialization fails
     */
    private static void ensureInitialized() {
        if (!initialized) {
            initialize();
        }
    }

    /**
     * Reset the initialization state (primarily for testing).
     */
    static void reset() {
        synchronized (CryptographicProviderFactory.class) {
            initialized = false;
        }
    }
}
