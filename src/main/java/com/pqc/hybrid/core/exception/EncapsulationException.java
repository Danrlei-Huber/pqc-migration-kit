package com.pqc.hybrid.core.exception;

/**
 * Thrown when key encapsulation (KEM) operations fail.
 *
 * @author PQC Hybrid Team
 * @version 1.0.0-BETA
 */
public class EncapsulationException extends PQCHybridException {
    
    private static final long serialVersionUID = 1L;

    /**
     * Creates a new EncapsulationException.
     *
     * @param message the detail message
     */
    public EncapsulationException(String message) {
        super(message);
    }

    /**
     * Creates a new EncapsulationException with cause.
     *
     * @param message the detail message
     * @param cause the cause
     */
    public EncapsulationException(String message, Throwable cause) {
        super(message, cause);
    }
}
