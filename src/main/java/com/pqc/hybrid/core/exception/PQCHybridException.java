package com.pqc.hybrid.core.exception;

/**
 * Base exception class for all PQC Hybrid Certificate Library exceptions.
 * All checked and unchecked exceptions in the library inherit from this class.
 *
 * @author PQC Hybrid Team
 * @version 1.0.0-BETA
 */
public class PQCHybridException extends RuntimeException {
    
    private static final long serialVersionUID = 1L;

    /**
     * Creates a new PQCHybridException with the specified detail message.
     *
     * @param message the detail message
     */
    public PQCHybridException(String message) {
        super(message);
    }

    /**
     * Creates a new PQCHybridException with the specified detail message and cause.
     *
     * @param message the detail message
     * @param cause the cause of this exception
     */
    public PQCHybridException(String message, Throwable cause) {
        super(message, cause);
    }

    /**
     * Creates a new PQCHybridException with the specified cause.
     *
     * @param cause the cause of this exception
     */
    public PQCHybridException(Throwable cause) {
        super(cause);
    }
}
