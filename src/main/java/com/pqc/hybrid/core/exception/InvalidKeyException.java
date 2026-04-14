package com.pqc.hybrid.core.exception;

/**
 * Thrown when an invalid key (format, size, or type) is detected.
 *
 * @author PQC Hybrid Team
 * @version 1.0.0-BETA
 */
public class InvalidKeyException extends PQCHybridException {
    
    private static final long serialVersionUID = 1L;

    /**
     * Creates a new InvalidKeyException.
     *
     * @param message the detail message
     */
    public InvalidKeyException(String message) {
        super(message);
    }

    /**
     * Creates a new InvalidKeyException with cause.
     *
     * @param message the detail message
     * @param cause the cause
     */
    public InvalidKeyException(String message, Throwable cause) {
        super(message, cause);
    }
}
