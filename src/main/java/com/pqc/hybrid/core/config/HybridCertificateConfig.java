package com.pqc.hybrid.core.config;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
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
    private final BigInteger serialNumber;
    private final boolean includePrimarySignature;
    private final boolean includeAlternativeSignature;
    private final List<String> subjectAltNames;
    private final boolean certificateAuthority;
    private final int pathLenConstraint;
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
        this.subjectAltNames = List.copyOf(builder.subjectAltNames);
        this.certificateAuthority = builder.certificateAuthority;
        this.pathLenConstraint = builder.pathLenConstraint;
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
    public BigInteger getSerialNumber() {
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
     * Gets the subject alternative names (DNS names and/or IP addresses). Never null.
     */
    public List<String> getSubjectAltNames() {
        return subjectAltNames;
    }

    /**
     * Indicates whether the certificate is a Certificate Authority (BasicConstraints CA:true).
     */
    public boolean isCertificateAuthority() {
        return certificateAuthority;
    }

    /**
     * Gets the BasicConstraints path length constraint, or {@code -1} if unconstrained.
     */
    public int getPathLenConstraint() {
        return pathLenConstraint;
    }

    /**
     * Builder for HybridCertificateConfig.
     */
    public static final class Builder {

        private HybridAlgorithmPair algorithmPair;
        private String subjectDN;
        private String issuerDN;
        private long validityDays = 365;  // default 1 year
        private BigInteger serialNumber;
        private boolean includePrimarySignature = true;
        private boolean includeAlternativeSignature = true;
        private List<String> subjectAltNames = new ArrayList<>();
        private boolean certificateAuthority = false;
        private int pathLenConstraint = -1;

        /**
         * Creates a new builder.
         */
        public Builder() {
        }

        /**
         * Sets the hybrid algorithm pair. This is optional descriptive metadata — it is not
         * required to build a certificate or CSR (the {@link com.pqc.hybrid.core.certificate.HybridSigner}
         * carries the actual signing algorithms). If supplied, it must not be {@code null}.
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
         * Sets the serial number. If not set, a random 160-bit value is generated.
         */
        public Builder withSerialNumber(BigInteger serial) {
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
         * Sets the subject alternative names (DNS names and/or IP addresses). The certificate
         * builder auto-detects IP addresses; everything else is treated as a DNS name.
         */
        public Builder withSubjectAltNames(List<String> names) {
            this.subjectAltNames = new ArrayList<>(Objects.requireNonNull(names, "names cannot be null"));
            return this;
        }

        /**
         * Marks the certificate as a Certificate Authority (BasicConstraints CA:true,
         * KeyUsage keyCertSign + cRLSign).
         */
        public Builder asCertificateAuthority(boolean isCA) {
            this.certificateAuthority = isCA;
            return this;
        }

        /**
         * Sets the BasicConstraints path length constraint (implies CA:true).
         */
        public Builder withPathLenConstraint(int pathLen) {
            this.pathLenConstraint = pathLen;
            this.certificateAuthority = true;
            return this;
        }

        /**
         * Builds the configuration.
         */
        public HybridCertificateConfig build() {
            // algorithmPair is optional descriptive metadata: the certificate/CSR builders never
            // read it (the signers carry their own AlgorithmIdentifier). It is therefore not
            // required, which keeps the Layer 1 (external-signer) flow free of unused setup.
            Objects.requireNonNull(subjectDN, "Subject DN is required");

            // issuerDN is optional: when absent the certificate is self-issued (issuer = subject).
            // For CA-issued certificates the issuer identity comes from the CA certificate.
            if (issuerDN == null) {
                issuerDN = subjectDN;
            }

            if (!includePrimarySignature && !includeAlternativeSignature) {
                throw new IllegalStateException("At least one signature type must be included");
            }

            if (serialNumber == null) {
                serialNumber = new BigInteger(160, new SecureRandom());
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
                (algorithmPair == null ? "n/a" : algorithmPair.getDescription()),
                subjectDN, issuerDN, validityDays,
                includePrimarySignature, includeAlternativeSignature);
    }
}
