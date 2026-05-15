package com.pqc.hybrid.migration;

import java.util.List;

/**
 * Result object for the migration process from legacy to hybrid certificates.
 * 
 * This class encapsulates the outcome of a migration attempt, including
 * the generated hybrid certificate (if successful) or error information
 * (if unsuccessful).
 * 
 * @author PQC Hybrid Team
 * @version 1.0.0-BETA
 */
public class MigrationResult {

    /** Indicates whether the migration was successful */
    private boolean success;

    /** The generated hybrid certificate data (if successful) */
    private byte[] hybridCertificate;

    /** Warnings encountered during the migration process */
    private List<String> warnings;

    /** Errors encountered during the migration process */
    private List<String> errors;

    /** Metrics about the migration process */
    private MigrationMetrics metrics;

    /** Default constructor */
    public MigrationResult() {
        this.success = false;
    }

    // Getters and Setters
    public boolean isSuccess() {
        return success;
    }

    public void setSuccess(boolean success) {
        this.success = success;
    }

    public byte[] getHybridCertificate() {
        return hybridCertificate;
    }

    public void setHybridCertificate(byte[] hybridCertificate) {
        this.hybridCertificate = hybridCertificate;
    }

    public List<String> getWarnings() {
        return warnings;
    }

    public void setWarnings(List<String> warnings) {
        this.warnings = warnings;
    }

    public List<String> getErrors() {
        return errors;
    }

    public void setErrors(List<String> errors) {
        this.errors = errors;
    }

    public MigrationMetrics getMetrics() {
        return metrics;
    }

    public void setMetrics(MigrationMetrics metrics) {
        this.metrics = metrics;
    }

    /**
     * Convenience method to check if the migration resulted in a certificate.
     * 
     * @return true if successful and hybrid certificate is not null
     */
    public boolean hasCertificate() {
        return success && hybridCertificate != null && hybridCertificate.length > 0;
    }

    @Override
    public String toString() {
        return "MigrationResult{" +
                "success=" + success +
                ", hybridCertificateLength=" + (hybridCertificate != null ? hybridCertificate.length : 0) +
                ", warningsCount=" + (warnings != null ? warnings.size() : 0) +
                ", errorsCount=" + (errors != null ? errors.size() : 0) +
                ", metrics=" + metrics +
                '}';
    }
}