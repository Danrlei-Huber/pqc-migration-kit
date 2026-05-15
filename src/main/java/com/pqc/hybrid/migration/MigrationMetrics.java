package com.pqc.hybrid.migration;

/**
 * Metrics object for the migration process.
 * 
 * This class holds various metrics about the migration process such as
 * time taken, memory used, etc.
 * 
 * @author PQC Hybrid Team
 * @version 1.0.0-BETA
 */
public class MigrationMetrics {

    /** Time taken for the migration process in milliseconds */
    private long migrationTimeMs;

    /** Memory used during the migration process in bytes */
    private long memoryUsedBytes;

    /** Number of legacy certificates processed */
    private int certificatesProcessed;

    /** Number of hybrid certificates generated */
    private int hybridCertificatesGenerated;

    /** Number of errors encountered */
    private int errorCount;

    /** Number of warnings encountered */
    private int warningCount;

    // Getters and Setters
    public long getMigrationTimeMs() {
        return migrationTimeMs;
    }

    public void setMigrationTimeMs(long migrationTimeMs) {
        this.migrationTimeMs = migrationTimeMs;
    }

    public long getMemoryUsedBytes() {
        return memoryUsedBytes;
    }

    public void setMemoryUsedBytes(long memoryUsedBytes) {
        this.memoryUsedBytes = memoryUsedBytes;
    }

    public int getCertificatesProcessed() {
        return certificatesProcessed;
    }

    public void setCertificatesProcessed(int certificatesProcessed) {
        this.certificatesProcessed = certificatesProcessed;
    }

    public int getHybridCertificatesGenerated() {
        return hybridCertificatesGenerated;
    }

    public void setHybridCertificatesGenerated(int hybridCertificatesGenerated) {
        this.hybridCertificatesGenerated = hybridCertificatesGenerated;
    }

    public int getErrorCount() {
        return errorCount;
    }

    public void setErrorCount(int errorCount) {
        this.errorCount = errorCount;
    }

    public int getWarningCount() {
        return warningCount;
    }

    public void setWarningCount(int warningCount) {
        this.warningCount = warningCount;
    }

    @Override
    public String toString() {
        return "MigrationMetrics{" +
                "migrationTimeMs=" + migrationTimeMs +
                ", memoryUsedBytes=" + memoryUsedBytes +
                ", certificatesProcessed=" + certificatesProcessed +
                ", hybridCertificatesGenerated=" + hybridCertificatesGenerated +
                ", errorCount=" + errorCount +
                ", warningCount=" + warningCount +
                '}';
    }
}