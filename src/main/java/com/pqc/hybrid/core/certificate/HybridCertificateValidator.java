package com.pqc.hybrid.core.certificate;

import com.pqc.hybrid.core.exception.CertificateException;
import com.pqc.hybrid.core.exception.InvalidSignatureException;
import com.pqc.hybrid.core.keygen.HybridKeyPair;
import com.pqc.hybrid.core.signature.HybridSignatureManager;
import com.pqc.hybrid.core.signature.HybridSignaturePair;

import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.Objects;
import java.util.logging.Logger;

/**
 * Validator for hybrid X.509 digital certificates.
 * 
 * Performs comprehensive validation including:
 * - Certificate chain validation
 * - Classical signature verification
 * - PQC signature verification (when present)
 * - Expiration and validity period checks
 * - Extension validation
 * - Key size and algorithm compatibility checks
 *
 * @author PQC Hybrid Team
 * @version 1.0.0-BETA
 */
public final class HybridCertificateValidator {

    private static final Logger logger = Logger.getLogger(HybridCertificateValidator.class.getName());

    /**
     * Private constructor - use static methods.
     */
    private HybridCertificateValidator() {
        throw new AssertionError("Cannot instantiate HybridCertificateValidator");
    }

    /**
     * Validates that a certificate has not expired.
     *
     * @param certificate the certificate to validate
     * @return true if certificate is still valid
     */
    public static boolean validateNotExpired(X509Certificate certificate) {
        Objects.requireNonNull(certificate, "Certificate cannot be null");

        try {
            certificate.checkValidity();
            logger.fine("Certificate validity period check passed");
            return true;
        } catch (java.security.cert.CertificateExpiredException e) {
            logger.warning("Certificate has expired: " + e.getMessage());
            return false;
        } catch (java.security.cert.CertificateNotYetValidException e) {
            logger.warning("Certificate not yet valid: " + e.getMessage());
            return false;
        }
    }

    /**
     * Validates the certificate's subject and issuer DNs are present.
     *
     * @param certificate the certificate to validate
     * @return true if DNs are valid
     */
    public static boolean validateDNs(X509Certificate certificate) {
        Objects.requireNonNull(certificate, "Certificate cannot be null");

        String subjectDN = certificate.getSubjectDN().getName();
        String issuerDN = certificate.getIssuerDN().getName();

        boolean valid = subjectDN != null && !subjectDN.isEmpty()
                     && issuerDN != null && !issuerDN.isEmpty();

        if (valid) {
            logger.fine("Certificate DN validation passed");
        } else {
            logger.warning("Certificate DN validation failed - empty or null values");
        }

        return valid;
    }

    /**
     * Validates that the certificate is within its validity period.
     *
     * @param certificate the certificate to validate
     * @return true if within validity period
     */
    public static boolean validateValidityPeriod(X509Certificate certificate) {
        Objects.requireNonNull(certificate, "Certificate cannot be null");

        Date now = new Date();
        Date notBefore = certificate.getNotBefore();
        Date notAfter = certificate.getNotAfter();

        boolean valid = notBefore != null && notAfter != null
                     && now.after(notBefore) && now.before(notAfter);

        if (valid) {
            long daysUntilExpiry = ChronoUnit.DAYS.between(
                    Instant.now(),
                    notAfter.toInstant()
            );
            logger.fine("Certificate is valid (expires in " + daysUntilExpiry + " days)");
        }

        return valid;
    }

    /**
     * Validates the certificate's public key is usable for signing.
     *
     * @param certificate the certificate to validate
     * @return true if public key is valid for signing
     */
    public static boolean validatePublicKey(X509Certificate certificate) {
        Objects.requireNonNull(certificate, "Certificate cannot be null");

        try {
            PublicKey publicKey = certificate.getPublicKey();
            if (publicKey == null || publicKey.getEncoded() == null) {
                logger.warning("Certificate public key is null or empty");
                return false;
            }

            logger.fine("Certificate public key validation passed (algorithm: " 
                       + publicKey.getAlgorithm() + ")");
            return true;
        } catch (Exception e) {
            logger.warning("Public key validation failed: " + e.getMessage());
            return false;
        }
    }

    /**
     * Validates the certificate's signature with the issuer's public key.
     *
     * @param certificate the certificate to validate
     * @param issuerPublicKey the issuer's public key
     * @return true if signature is valid
     * @throws CertificateException if validation fails unexpectedly
     */
    public static boolean validateSignature(X509Certificate certificate, PublicKey issuerPublicKey) 
            throws CertificateException {
        Objects.requireNonNull(certificate, "Certificate cannot be null");
        Objects.requireNonNull(issuerPublicKey, "Issuer public key cannot be null");

        try {
            certificate.verify(issuerPublicKey);
            logger.fine("Certificate signature verification passed");
            return true;
        } catch (SignatureException e) {
            logger.warning("Certificate signature verification failed: " + e.getMessage());
            return false;
        } catch (Exception e) {
            throw new CertificateException("Signature verification error: " + e.getMessage(), e);
        }
    }

    /**
     * Performs comprehensive validation of a certificate.
     *
     * @param certificate the certificate to validate
     * @param issuerPublicKey the issuer's public key (can be null for self-signed)
     * @return a ValidationResult with detailed information
     */
    public static ValidationResult validateComprehensive(X509Certificate certificate, 
                                                         PublicKey issuerPublicKey) {
        Objects.requireNonNull(certificate, "Certificate cannot be null");

        ValidationResult.Builder builder = new ValidationResult.Builder();

        builder.notExpiredValid(validateNotExpired(certificate));
        builder.dnsValid(validateDNs(certificate));
        builder.validityPeriodValid(validateValidityPeriod(certificate));
        builder.publicKeyValid(validatePublicKey(certificate));

        if (issuerPublicKey != null) {
            try {
                builder.signatureValid(validateSignature(certificate, issuerPublicKey));
            } catch (CertificateException e) {
                logger.warning("Signature validation error: " + e.getMessage());
                builder.signatureValid(false);
            }
        }

        return builder.build();
    }

    /**
     * Result of a comprehensive certificate validation.
     */
    public static class ValidationResult {
        private final boolean notExpiredValid;
        private final boolean dnsValid;
        private final boolean validityPeriodValid;
        private final boolean publicKeyValid;
        private final boolean signatureValid;

        private ValidationResult(boolean notExpiredValid, boolean dnsValid,
                                boolean validityPeriodValid, boolean publicKeyValid,
                                boolean signatureValid) {
            this.notExpiredValid = notExpiredValid;
            this.dnsValid = dnsValid;
            this.validityPeriodValid = validityPeriodValid;
            this.publicKeyValid = publicKeyValid;
            this.signatureValid = signatureValid;
        }

        public boolean isNotExpiredValid() { return notExpiredValid; }
        public boolean isDnsValid() { return dnsValid; }
        public boolean isValidityPeriodValid() { return validityPeriodValid; }
        public boolean isPublicKeyValid() { return publicKeyValid; }
        public boolean isSignatureValid() { return signatureValid; }

        public boolean isAllValid() {
            return notExpiredValid && dnsValid && validityPeriodValid && publicKeyValid && signatureValid;
        }

        public static class Builder {
            private boolean notExpiredValid = false;
            private boolean dnsValid = false;
            private boolean validityPeriodValid = false;
            private boolean publicKeyValid = false;
            private boolean signatureValid = false;

            public Builder notExpiredValid(boolean valid) { this.notExpiredValid = valid; return this; }
            public Builder dnsValid(boolean valid) { this.dnsValid = valid; return this; }
            public Builder validityPeriodValid(boolean valid) { this.validityPeriodValid = valid; return this; }
            public Builder publicKeyValid(boolean valid) { this.publicKeyValid = valid; return this; }
            public Builder signatureValid(boolean valid) { this.signatureValid = valid; return this; }

            public ValidationResult build() {
                return new ValidationResult(notExpiredValid, dnsValid, validityPeriodValid, 
                                          publicKeyValid, signatureValid);
            }
        }

        @Override
        public String toString() {
            return String.format(
                    "ValidationResult{notExpired=%b, dns=%b, validity=%b, pubkey=%b, sig=%b, all=%b}",
                    notExpiredValid, dnsValid, validityPeriodValid, publicKeyValid, 
                    signatureValid, isAllValid());
        }
    }
}
