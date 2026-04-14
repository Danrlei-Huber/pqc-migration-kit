package com.pqc.hybrid.core.exception;

/**
 * Thrown when a certificate operation fails (generation, validation, parsing).
 *
 * @author PQC Hybrid Team
 * @version 1.0.0-BETA
 */
public class CertificateException extends PQCHybridException {
    
    private static final long serialVersionUID = 1L;

    /**
     * Creates a new CertificateException.
     *
     * @param message the detail message
     */
    public CertificateException(String message) {
        super(message);
    }

    /**
     * Creates a new CertificateException with cause.
     *
     * @param message the detail message
     * @param cause the cause
     */
    public CertificateException(String message, Throwable cause) {
        super(message, cause);
    }
}
