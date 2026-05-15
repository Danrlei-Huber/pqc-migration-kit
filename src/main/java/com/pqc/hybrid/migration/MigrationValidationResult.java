package com.pqc.hybrid.migration;

import java.util.List;

/**
 * Result object for validating a legacy certificate for migration to hybrid format.
 * 
 * This class provides detailed information about whether a legacy certificate
 * is suitable for migration to a hybrid PQC certificate format.
 * 
 * @author PQC Hybrid Team
 * @version 1.0.0-BETA
 */
public class MigrationValidationResult {

    /** Indicates whether the certificate is valid for migration */
    private boolean valid;

    /** List of issues that would prevent migration */
    private List<String> blockingIssues;

    /** List of warnings about the migration process */
    private List<String> warnings;

    /** Suggested migration configuration */
    private MigrationConfig suggestedConfig;

    /** Detected legacy certificate format */
    private String detectedFormat;

    /** Estimated time required for migration */
    private long estimatedMigrationTimeMs;

    // Getters and Setters
    public boolean isValid() {
        return valid;
    }

    public void setValid(boolean valid) {
        this.valid = valid;
    }

    public List<String> getBlockingIssues() {
        return blockingIssues;
    }

    public void setBlockingIssues(List<String> blockingIssues) {
        this.blockingIssues = blockingIssues;
    }

    public List<String> getWarnings() {
        return warnings;
    }

    public void setWarnings(List<String> warnings) {
        this.warnings = warnings;
    }

    public MigrationConfig getSuggestedConfig() {
        return suggestedConfig;
    }

    public void setSuggestedConfig(MigrationConfig suggestedConfig) {
        this.suggestedConfig = suggestedConfig;
    }

    public String getDetectedFormat() {
        return detectedFormat;
    }

    public void setDetectedFormat(String detectedFormat) {
        this.detectedFormat = detectedFormat;
    }

    public long getEstimatedMigrationTimeMs() {
        return estimatedMigrationTimeMs;
    }

    public void setEstimatedMigrationTimeMs(long estimatedMigrationTimeMs) {
        this.estimatedMigrationTimeMs = estimatedMigrationTimeMs;
    }

    @Override
    public String toString() {
        return "MigrationValidationResult{" +
                "valid=" + valid +
                ", blockingIssuesCount=" + (blockingIssues != null ? blockingIssues.size() : 0) +
                ", warningsCount=" + (warnings != null ? warnings.size() : 0) +
                ", suggestedConfig=" + suggestedConfig +
                ", detectedFormat='" + detectedFormat + '\'' +
                ", estimatedMigrationTimeMs=" + estimatedMigrationTimeMs +
                '}';
    }
}