package com.pqc.hybrid.migration;

/**
 * Exception thrown when an error occurs during the migration process from legacy to hybrid certificates.
 * 
 * This exception encapsulates migration-specific error conditions such as:
 * - Unsupported legacy certificate formats
 * - Invalid certificate data
 * - Unsupported algorithm combinations
 * - Migration process failures
 * 
 * @author PQC Hybrid Team
 * @version 1.0.0-BETA
 */
public class MigrationException extends Exception {

    /** Error code for programmatic error handling */
    private final String errorCode;

    /** Details about the migration step that failed */
    private final String migrationStep;

    /**
     * Constructs a new MigrationException with the specified detail message.
     * 
     * @param message The detail message
     */
    public MigrationException(String message) {
        this(message, null, null);
    }

    /**
     * Constructs a new MigrationException with the specified detail message and error code.
     * 
     * @param message The detail message
     * @param errorCode The error code for programmatic handling
     */
    public MigrationException(String message, String errorCode) {
        this(message, errorCode, null);
    }

    /**
     * Constructs a new MigrationException with the specified detail message, error code, and migration step.
     * 
     * @param message The detail message
     * @param errorCode The error code for programmatic handling
     * @param migrationStep The migration step where the error occurred
     */
    public MigrationException(String message, String errorCode, String migrationStep) {
        super(message);
        this.errorCode = errorCode;
        this.migrationStep = migrationStep;
    }

    /**
     * Constructs a new MigrationException with the specified detail message and cause.
     * 
     * @param message The detail message
     * @param cause The cause of the exception
     */
    public MigrationException(String message, Throwable cause) {
        super(message, cause);
        this.errorCode = null;
        this.migrationStep = null;
    }

    /**
     * Constructs a new MigrationException with the specified detail message, error code, migration step, and cause.
     * 
     * @param message The detail message
     * @param errorCode The error code for programmatic handling
     * @param migrationStep The migration step where the error occurred
     * @param cause The cause of the exception
     */
    public MigrationException(String message, String errorCode, String migrationStep, Throwable cause) {
        super(message, cause);
        this.errorCode = errorCode;
        this.migrationStep = migrationStep;
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
     * Gets the migration step where this error occurred.
     * 
     * @return The migration step, or null if none was specified
     */
    public String getMigrationStep() {
        return migrationStep;
    }

    @Override
    public String toString() {
        return "MigrationException: " + getMessage() +
                (errorCode != null ? " [errorCode=" + errorCode + "]" : "") +
                (migrationStep != null ? " [migrationStep=" + migrationStep + "]" : "");
    }
}