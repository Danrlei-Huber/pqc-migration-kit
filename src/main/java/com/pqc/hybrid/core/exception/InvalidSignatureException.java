package com.pqc.hybrid.core.exception;

/**
 * Thrown when a signature validation fails.
 *
 * @author PQC Hybrid Team
 * @version 1.0.0-BETA
 */
public class InvalidSignatureException extends PQCHybridException {
    
    private static final long serialVersionUID = 1L;

    /**
     * Creates a new InvalidSignatureException.
     *
     * @param message the detail message
     */
    public InvalidSignatureException(String message) {
        super(message);
    }

    /**
     * Creates a new InvalidSignatureException with cause.
     *
     * @param message the detail message
     * @param cause the cause
     */
    public InvalidSignatureException(String message, Throwable cause) {
        super(message, cause);
    }
}
