package com.pqc.hybrid.migration;

import com.pqc.hybrid.core.config.ClassicalAlgorithm;
import com.pqc.hybrid.core.config.PQCAlgorithm;

/**
 * Configuration class for the migration process from legacy to hybrid certificates.
 * 
 * This class holds all the necessary parameters to configure how a legacy certificate
 * should be converted to a hybrid PQC certificate.
 * 
 * @author PQC Hybrid Team
 * @version 1.0.0-BETA
 */
public class MigrationConfig {

    /** The PQC algorithm to be used in the hybrid certificate */
    private PQCAlgorithm pqcAlgorithm;

    /** The classical algorithm to be used in the hybrid certificate */
    private ClassicalAlgorithm classicalAlgorithm;

    /** Whether to preserve the original certificate chain during migration */
    private boolean preserveChain;

    /** The output format for the generated hybrid certificate */
    private String outputFormat;

    /** Whether to include additional metadata in the hybrid certificate */
    private boolean includeMetadata;

    /** The validity period (in days) for the migrated certificate */
    private int validityDays;

    /** Default constructor */
    public MigrationConfig() {
        // Default values
        this.pqcAlgorithm = PQCAlgorithm.ML_DSA_65; // Default to Dilithium (ML-DSA-65)
        this.classicalAlgorithm = ClassicalAlgorithm.RSA_2048; // Default to RSA 2048
        this.preserveChain = true;
        this.outputFormat = "PEM";
        this.includeMetadata = true;
        this.validityDays = 365; // One year by default
    }

    // Getters and Setters
    public PQCAlgorithm getPqcAlgorithm() {
        return pqcAlgorithm;
    }

    public void setPqcAlgorithm(PQCAlgorithm pqcAlgorithm) {
        this.pqcAlgorithm = pqcAlgorithm;
    }

    public ClassicalAlgorithm getClassicalAlgorithm() {
        return classicalAlgorithm;
    }

    public void setClassicalAlgorithm(ClassicalAlgorithm classicalAlgorithm) {
        this.classicalAlgorithm = classicalAlgorithm;
    }

    public boolean isPreserveChain() {
        return preserveChain;
    }

    public void setPreserveChain(boolean preserveChain) {
        this.preserveChain = preserveChain;
    }

    public String getOutputFormat() {
        return outputFormat;
    }

    public void setOutputFormat(String outputFormat) {
        this.outputFormat = outputFormat;
    }

    public boolean isIncludeMetadata() {
        return includeMetadata;
    }

    public void setIncludeMetadata(boolean includeMetadata) {
        this.includeMetadata = includeMetadata;
    }

    public int getValidityDays() {
        return validityDays;
    }

    public void setValidityDays(int validityDays) {
        this.validityDays = validityDays;
    }

    @Override
    public String toString() {
        return "MigrationConfig{" +
                "pqcAlgorithm=" + pqcAlgorithm +
                ", classicalAlgorithm=" + classicalAlgorithm +
                ", preserveChain=" + preserveChain +
                ", outputFormat='" + outputFormat + '\'' +
                ", includeMetadata=" + includeMetadata +
                ", validityDays=" + validityDays +
                '}';
    }
}