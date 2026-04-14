package com.pqc.hybrid.core.util.printer;

import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.Objects;
import java.util.logging.Logger;

/**
 * Utility for printing and formatting cryptographic key information.
 * 
 * Extracts and displays details about public and private keys including:
 * - Key algorithm and parameters
 * - Key size (for RSA/ECDSA)
 * - Key format
 * - Encoded representation
 * 
 * Example Output:
 * ```
 * RSA Public Key (2048 bits)
 * ├── Algorithm: RSA
 * ├── Format: X.509
 * ├── Size: 2048 bits
 * └── Base64 (first 64 chars): MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCA...
 * ```
 * 
 * @author PQC Hybrid Team
 * @version 1.0.0
 * @since 2026-04-14
 */
public class KeyInfoPrinter {

    private static final Logger logger = Logger.getLogger(KeyInfoPrinter.class.getName());
    private static final int DISPLAY_LENGTH = 64;

    /**
     * Prints key information to console.
     * 
     * @param key the key to print
     */
    public void printKey(Key key) {
        Objects.requireNonNull(key, "Key cannot be null");
        System.out.println(formatKey(key));
    }

    /**
     * Formats key information as string.
     * 
     * @param key the key to format
     * @return formatted key information
     */
    public String formatKey(Key key) {
        Objects.requireNonNull(key, "Key cannot be null");
        
        StringBuilder sb = new StringBuilder();
        
        // Determine key type
        String keyType = key instanceof PrivateKey ? "Private" : "Public";
        String algo = key.getAlgorithm();
        
        // Get size if available
        int size = getKeySize(key);
        String sizeInfo = size > 0 ? " (" + size + " bits)" : "";
        
        sb.append(algo).append(" ").append(keyType).append(" Key").append(sizeInfo).append("\n");
        sb.append("├── Algorithm: ").append(algo).append("\n");
        sb.append("├── Type: ").append(keyType).append("\n");
        sb.append("├── Format: ").append(key.getFormat()).append("\n");
        
        if (size > 0) {
            sb.append("├── Size: ").append(size).append(" bits\n");
        }
        
        // Encoded representation (truncated)
        String encoded = Base64.getEncoder().encodeToString(key.getEncoded());
        String displayEncoded = encoded.length() > DISPLAY_LENGTH ? 
            encoded.substring(0, DISPLAY_LENGTH) + "..." : encoded;
        sb.append("└── Base64: ").append(displayEncoded);
        
        return sb.toString();
    }

    /**
     * Prints compact key summary to console.
     * 
     * @param key the key to print
     */
    public void printKeyCompact(Key key) {
        Objects.requireNonNull(key, "Key cannot be null");
        System.out.println(formatKeyCompact(key));
    }

    /**
     * Formats key as single-line summary.
     * 
     * @param key the key to format
     * @return single-line key summary
     */
    public String formatKeyCompact(Key key) {
        Objects.requireNonNull(key, "Key cannot be null");
        
        String keyType = key instanceof PrivateKey ? "Private" : "Public";
        String algo = key.getAlgorithm();
        int size = getKeySize(key);
        
        if (size > 0) {
            return String.format("%s %s Key [%s-%d]", algo, keyType, algo, size);
        } else {
            return String.format("%s %s Key", algo, keyType);
        }
    }

    /**
     * Prints public key information to console.
     * 
     * @param publicKey the public key to print
     */
    public void printPublicKey(PublicKey publicKey) {
        Objects.requireNonNull(publicKey, "Public key cannot be null");
        System.out.println(formatPublicKeyDetails(publicKey));
    }

    /**
     * Formats detailed public key information.
     * 
     * @param publicKey the public key
     * @return formatted public key details
     */
    public String formatPublicKeyDetails(PublicKey publicKey) {
        Objects.requireNonNull(publicKey, "Public key cannot be null");
        
        StringBuilder sb = new StringBuilder();
        sb.append(formatKey(publicKey)).append("\n");
        
        // Algorithm-specific details
        if (publicKey instanceof RSAPublicKey rsaKey) {
            sb.append("\nRSA Specific:\n");
            sb.append("  • Modulus bits: ").append(rsaKey.getModulus().bitLength()).append("\n");
            sb.append("  • Public exponent: ").append(rsaKey.getPublicExponent()).append("\n");
        } else if (publicKey instanceof ECPublicKey ecKey) {
            sb.append("\nElliptic Curve Specific:\n");
            sb.append("  • Curve field size: ").append(ecKey.getParams().getCurve().getField().getFieldSize()).append(" bits\n");
        }
        
        return sb.toString();
    }

    /**
     * Extracts key size in bits.
     * 
     * @param key the key to measure
     * @return key size in bits, or -1 if unknown
     */
    public int getKeySize(Key key) {
        Objects.requireNonNull(key, "Key cannot be null");
        
        try {
            if (key instanceof RSAPublicKey rsaKey) {
                return rsaKey.getModulus().bitLength();
            } else if (key instanceof ECPublicKey ecKey) {
                return ecKey.getParams().getCurve().getField().getFieldSize();
            }
            
            // Fallback: estimate from encoded form
            byte[] encoded = key.getEncoded();
            if (encoded != null) {
                return encoded.length * 8;
            }
        } catch (Exception e) {
            logger.fine("Could not determine key size: " + e.getMessage());
        }
        
        return -1;
    }

    /**
     * Compares two keys to check if they form a pair.
     * 
     * Note: This is a basic check based on algorithm and size matching.
     * Cryptographic validation should be done separately.
     * 
     * @param publicKey the public key
     * @param privateKey the private key
     * @return true if keys appear to be a matching pair
     */
    public boolean areKeysPair(PublicKey publicKey, PrivateKey privateKey) {
        Objects.requireNonNull(publicKey, "Public key cannot be null");
        Objects.requireNonNull(privateKey, "Private key cannot be null");
        
        // Check algorithm match
        if (!publicKey.getAlgorithm().equals(privateKey.getAlgorithm())) {
            return false;
        }
        
        // Check size match for RSA
        if (publicKey instanceof RSAPublicKey rsaPub && 
            privateKey instanceof java.security.interfaces.RSAPrivateKey rsaPriv) {
            return rsaPub.getModulus().equals(rsaPriv.getModulus());
        }
        
        // For other key types, we can't reliably check without cryptographic operations
        return true;
    }
}
