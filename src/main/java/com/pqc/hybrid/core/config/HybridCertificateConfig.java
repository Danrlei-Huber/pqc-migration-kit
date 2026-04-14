package com.pqc.hybrid.core.config;

import java.util.Objects;

/**
 * Configuration for creating hybrid PQC digital certificates.
 * This immutable configuration specifies all parameters needed to generate a hybrid certificate
 * with dual classical and PQC signatures.
 *
 * @author PQC Hybrid Team
 * @version 1.0.0-BETA
 */
public final class HybridCertificateConfig {

    private final HybridAlgorithmPair algorithmPair;
    private final String subjectDN;
    private final String issuerDN;
    private final long validityDays;
    private final int serialNumber;
    private final boolean includePrimarySignature;
    private final boolean includeAlternativeSignature;
    private final String version;

    /**
     * Private constructor - use the builder.
     */
    private HybridCertificateConfig(Builder builder) {
        this.algorithmPair = builder.algorithmPair;
        this.subjectDN = builder.subjectDN;
        this.issuerDN = builder.issuerDN;
        this.validityDays = builder.validityDays;
        this.serialNumber = builder.serialNumber;
        this.includePrimarySignature = builder.includePrimarySignature;
        this.includeAlternativeSignature = builder.includeAlternativeSignature;
        this.version = "1.0.0";
    }

    /**
     * Gets the hybrid algorithm pair.
     */
    public HybridAlgorithmPair getAlgorithmPair() {
        return algorithmPair;
    }

    /**
     * Gets the subject Distinguished Name.
     */
    public String getSubjectDN() {
        return subjectDN;
    }

    /**
     * Gets the issuer Distinguished Name.
     */
    public String getIssuerDN() {
        return issuerDN;
    }

    /**
     * Gets the certificate validity in days.
     */
    public long getValidityDays() {
        return validityDays;
    }

    /**
     * Gets the serial number.
     */
    public int getSerialNumber() {
        return serialNumber;
    }

    /**
     * Indicates whether to include the primary classical signature.
     */
    public boolean isIncludePrimarySignature() {
        return includePrimarySignature;
    }

    /**
     * Indicates whether to include the alternative PQC signature.
     */
    public boolean isIncludeAlternativeSignature() {
        return includeAlternativeSignature;
    }

    /**
     * Gets the configuration version.
     */
    public String getVersion() {
        return version;
    }

    /**
     * Builder for HybridCertificateConfig.
     */
    public static final class Builder {

        private HybridAlgorithmPair algorithmPair;
        private String subjectDN;
        private String issuerDN;
        private long validityDays = 365;  // default 1 year
        private int serialNumber = 1;
        private boolean includePrimarySignature = true;
        private boolean includeAlternativeSignature = true;

        /**
         * Creates a new builder.
         */
        public Builder() {
        }

        /**
         * Sets the hybrid algorithm pair.
         */
        public Builder withAlgorithmPair(HybridAlgorithmPair pair) {
            this.algorithmPair = Objects.requireNonNull(pair, "Algorithm pair cannot be null");
            return this;
        }

        /**
         * Sets the subject Distinguished Name.
         */
        public Builder withSubjectDN(String dn) {
            this.subjectDN = Objects.requireNonNull(dn, "Subject DN cannot be null");
            return this;
        }

        /**
         * Sets the issuer Distinguished Name.
         */
        public Builder withIssuerDN(String dn) {
            this.issuerDN = Objects.requireNonNull(dn, "Issuer DN cannot be null");
            return this;
        }

        /**
         * Sets the certificate validity period.
         */
        public Builder withValidityDays(long days) {
            this.validityDays = days;
            return this;
        }

        /**
         * Sets the serial number.
         */
        public Builder withSerialNumber(int serial) {
            this.serialNumber = serial;
            return this;
        }

        /**
         * Sets whether to include the primary signature.
         */
        public Builder withIncludePrimarySignature(boolean include) {
            this.includePrimarySignature = include;
            return this;
        }

        /**
         * Sets whether to include the alternative signature.
         */
        public Builder withIncludeAlternativeSignature(boolean include) {
            this.includeAlternativeSignature = include;
            return this;
        }

        /**
         * Builds the configuration.
         */
        public HybridCertificateConfig build() {
            Objects.requireNonNull(algorithmPair, "Algorithm pair is required");
            Objects.requireNonNull(subjectDN, "Subject DN is required");
            Objects.requireNonNull(issuerDN, "Issuer DN is required");

            if (!includePrimarySignature && !includeAlternativeSignature) {
                throw new IllegalStateException("At least one signature type must be included");
            }

            return new HybridCertificateConfig(this);
        }
    }

    /**
     * Gets a builder for a standard hybrid certificate config.
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Gets a builder pre-configured with a recommended algorithm pair.
     */
    public static Builder builderWithRecommendedAlgorithms(int securityLevel) {
        return new Builder()
                .withAlgorithmPair(HybridAlgorithmPair.recommended(securityLevel));
    }

    @Override
    public String toString() {
        return String.format("HybridCertificateConfig{" +
                        "algorithms=%s, subject=%s, issuer=%s, validity=%d days, " +
                        "primarySig=%b, altSig=%b}",
                algorithmPair.getDescription(), subjectDN, issuerDN, validityDays,
                includePrimarySignature, includeAlternativeSignature);
    }
}
