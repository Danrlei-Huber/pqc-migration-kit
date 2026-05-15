package com.pqc.hybrid.rfc;

/**
 * Exception thrown when an error occurs during RFC monitoring operations.
 * 
 * This exception encapsulates RFC-specific error conditions such as:
 * - Network failures when accessing IETF Datatracker API
 * - Invalid or unexpected API responses
 * - JSON parsing errors
 * - Cache-related issues
 * 
 * @author PQC Hybrid Team
 * @version 1.0.0-BETA
 */
public class RFCMonitoringException extends Exception {

    /** Error code for programmatic error handling */
    private final String errorCode;

    /** The RFC draft identifier related to the error (if applicable) */
    private final String draftIdentifier;

    /**
     * Constructs a new RFCMonitoringException with the specified detail message.
     * 
     * @param message The detail message
     */
    public RFCMonitoringException(String message) {
        this(message, null, null);
    }

    /**
     * Constructs a new RFCMonitoringException with the specified detail message and error code.
     * 
     * @param message The detail message
     * @param errorCode The error code for programmatic handling
     */
    public RFCMonitoringException(String message, String errorCode) {
        this(message, errorCode, null);
    }

    /**
     * Constructs a new RFCMonitoringException with the specified detail message, error code, and draft identifier.
     * 
     * @param message The detail message
     * @param errorCode The error code for programmatic handling
     * @param draftIdentifier The RFC draft identifier related to the error
     */
    public RFCMonitoringException(String message, String errorCode, String draftIdentifier) {
        super(message);
        this.errorCode = errorCode;
        this.draftIdentifier = draftIdentifier;
    }

    /**
     * Constructs a new RFCMonitoringException with the specified detail message and cause.
     * 
     * @param message The detail message
     * @param cause The cause of the exception
     */
    public RFCMonitoringException(String message, Throwable cause) {
        super(message, cause);
        this.errorCode = null;
        this.draftIdentifier = null;
    }

    /**
     * Gets the error code associated with this exception.
     * 
     * @return The error code, or null if none was specified
     */
    public String getErrorCode() {
        return errorCode;
    }

    /**
     * Gets the RFC draft identifier associated with this exception.
     * 
     * @return The draft identifier, or null if none was specified
     */
    public String getDraftIdentifier() {
        return draftIdentifier;
    }

    @Override
    public String toString() {
        return "RFCMonitoringException: " + getMessage() +
                (errorCode != null ? " [errorCode=" + errorCode + "]" : "") +
                (draftIdentifier != null ? " [draftIdentifier=" + draftIdentifier + "]" : "");
    }
}