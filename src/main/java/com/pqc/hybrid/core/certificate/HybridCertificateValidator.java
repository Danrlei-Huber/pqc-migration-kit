package com.pqc.hybrid.core.certificate;

import com.pqc.hybrid.core.certificate.asn1.PQCExtensionsStructure;
import com.pqc.hybrid.core.common.oid.AlgorithmOIDRegistry;
import com.pqc.hybrid.core.config.CryptographicProviderFactory;
import com.pqc.hybrid.core.exception.CertificateException;
import com.pqc.hybrid.core.exception.InvalidSignatureException;
import com.pqc.hybrid.core.keygen.HybridKeyPair;
import com.pqc.hybrid.core.model.HybridCertificateInfo;
import com.pqc.hybrid.core.signature.HybridSignatureManager;
import com.pqc.hybrid.core.signature.HybridSignaturePair;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;

import java.io.IOException;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.logging.Logger;

public final class HybridCertificateValidator {

    private static final Logger logger = Logger.getLogger(HybridCertificateValidator.class.getName());

    private static final String OID_ALT_SIGNATURE_ALGORITHM = "2.5.29.62";
    private static final String OID_ALT_SIGNATURE_VALUE = "2.5.29.63";
    private static final String OID_SUBJECT_ALT_PUBKEY_INFO = "2.5.29.72";

    private HybridCertificateValidator() {
        throw new AssertionError("Cannot instantiate HybridCertificateValidator");
    }

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

    public static boolean validateDNs(X509Certificate certificate) {
        Objects.requireNonNull(certificate, "Certificate cannot be null");
        String subjectDN = certificate.getSubjectDN().getName();
        String issuerDN = certificate.getIssuerDN().getName();
        boolean valid = subjectDN != null && !subjectDN.isEmpty()
                     && issuerDN != null && !issuerDN.isEmpty();
        if (valid) {
            logger.fine("Certificate DN validation passed");
        } else {
            logger.warning("Certificate DN validation failed");
        }
        return valid;
    }

    public static boolean validateValidityPeriod(X509Certificate certificate) {
        Objects.requireNonNull(certificate, "Certificate cannot be null");
        Date now = new Date();
        Date notBefore = certificate.getNotBefore();
        Date notAfter = certificate.getNotAfter();
        boolean valid = notBefore != null && notAfter != null
                     && now.after(notBefore) && now.before(notAfter);
        if (valid) {
            long daysUntilExpiry = ChronoUnit.DAYS.between(Instant.now(), notAfter.toInstant());
            logger.fine("Certificate valid (expires in " + daysUntilExpiry + " days)");
        }
        return valid;
    }

    public static boolean validatePublicKey(X509Certificate certificate) {
        Objects.requireNonNull(certificate, "Certificate cannot be null");
        try {
            PublicKey publicKey = certificate.getPublicKey();
            if (publicKey == null || publicKey.getEncoded() == null) {
                logger.warning("Certificate public key is null or empty");
                return false;
            }
            logger.fine("Public key validation passed (algorithm: " + publicKey.getAlgorithm() + ")");
            return true;
        } catch (Exception e) {
            logger.warning("Public key validation failed: " + e.getMessage());
            return false;
        }
    }

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

    public static boolean validatePQCExtensions(X509Certificate certificate) {
        if (certificate == null) {
            logger.warning("Certificate is null");
            return false;
        }
        try {
            Map<String, Extension> pqcExtensions = extractPQCExtensions(certificate);

            boolean hasAlg = pqcExtensions.containsKey(OID_ALT_SIGNATURE_ALGORITHM);
            boolean hasSig = pqcExtensions.containsKey(OID_ALT_SIGNATURE_VALUE);
            boolean hasKey = pqcExtensions.containsKey(OID_SUBJECT_ALT_PUBKEY_INFO);

            boolean valid = hasAlg && hasSig && hasKey;
            logger.fine("PQC extensions present - alg=" + hasAlg + ", sig=" + hasSig + ", key=" + hasKey);
            return valid;
        } catch (Exception e) {
            logger.warning("PQC extension validation failed: " + e.getMessage());
            return false;
        }
    }

    public static Map<String, Extension> extractPQCExtensions(X509Certificate certificate) {
        Objects.requireNonNull(certificate, "Certificate cannot be null");
        Map<String, Extension> extensions = new HashMap<>();

        try {
            for (String oid : certificate.getCriticalExtensionOIDs()) {
                if (oid.equals(OID_ALT_SIGNATURE_ALGORITHM) ||
                    oid.equals(OID_ALT_SIGNATURE_VALUE) ||
                    oid.equals(OID_SUBJECT_ALT_PUBKEY_INFO)) {
                    byte[] extValue = certificate.getExtensionValue(oid);
                    if (extValue != null) {
                        Extension ext = new Extension(
                                new ASN1ObjectIdentifier(oid),
                                true,
                                extValue
                        );
                        extensions.put(oid, ext);
                    }
                }
            }

            for (String oid : certificate.getNonCriticalExtensionOIDs()) {
                if (oid.equals(OID_ALT_SIGNATURE_ALGORITHM) ||
                    oid.equals(OID_ALT_SIGNATURE_VALUE) ||
                    oid.equals(OID_SUBJECT_ALT_PUBKEY_INFO)) {
                    if (!extensions.containsKey(oid)) {
                        byte[] extValue = certificate.getExtensionValue(oid);
                        if (extValue != null) {
                            Extension ext = new Extension(
                                    new ASN1ObjectIdentifier(oid),
                                    false,
                                    extValue
                            );
                            extensions.put(oid, ext);
                        }
                    }
                }
            }
        } catch (Exception e) {
            logger.warning("Error extracting PQC extensions: " + e.getMessage());
        }

        return extensions;
    }

    public static String extractPQCAlgorithmOID(X509Certificate certificate) {
        Objects.requireNonNull(certificate, "Certificate cannot be null");
        try {
            byte[] extValue = certificate.getExtensionValue(OID_ALT_SIGNATURE_ALGORITHM);
            if (extValue == null) {
                return null;
            }
            org.bouncycastle.asn1.ASN1OctetString octetStr = 
                org.bouncycastle.asn1.ASN1OctetString.getInstance(extValue);
            org.bouncycastle.asn1.x509.AlgorithmIdentifier algId = 
                org.bouncycastle.asn1.x509.AlgorithmIdentifier.getInstance(octetStr.getOctets());
            return algId.getAlgorithm().getId();
        } catch (Exception e) {
            logger.warning("Failed to extract PQC algorithm OID: " + e.getMessage());
            return null;
        }
    }

    public static byte[] extractPQCSignature(X509Certificate certificate) {
        Objects.requireNonNull(certificate, "Certificate cannot be null");
        try {
            byte[] extValue = certificate.getExtensionValue(OID_ALT_SIGNATURE_VALUE);
            if (extValue == null) {
                return null;
            }
            org.bouncycastle.asn1.ASN1OctetString octetStr = 
                org.bouncycastle.asn1.ASN1OctetString.getInstance(extValue);
            org.bouncycastle.asn1.ASN1BitString bitString = 
                org.bouncycastle.asn1.DERBitString.getInstance(octetStr.getOctets());
            return bitString.getOctets();
        } catch (Exception e) {
            logger.warning("Failed to extract PQC signature: " + e.getMessage());
            return null;
        }
    }

    public static byte[] extractPQCPublicKey(X509Certificate certificate) {
        Objects.requireNonNull(certificate, "Certificate cannot be null");
        try {
            byte[] extValue = certificate.getExtensionValue(OID_SUBJECT_ALT_PUBKEY_INFO);
            if (extValue == null) {
                return null;
            }
            org.bouncycastle.asn1.ASN1OctetString octetStr = 
                org.bouncycastle.asn1.ASN1OctetString.getInstance(extValue);
            SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(octetStr.getOctets());
            return spki.getPublicKeyData().getBytes();
        } catch (Exception e) {
            logger.warning("Failed to extract PQC public key: " + e.getMessage());
            return null;
        }
    }

    public static boolean validatePQCSignature(X509Certificate certificate, HybridKeyPair keyPair)
            throws InvalidSignatureException {
        Objects.requireNonNull(certificate, "Certificate cannot be null");
        Objects.requireNonNull(keyPair, "Key pair cannot be null");

        try {
            byte[] tbsCertificate = certificate.getTBSCertificate();
            byte[] pqcSignature = extractPQCSignature(certificate);

            if (pqcSignature == null) {
                logger.warning("PQC signature not found in certificate extensions");
                return false;
            }

            String algorithm = keyPair.getPQCAlgorithm();
            CryptographicProviderFactory.initialize();
            Provider provider = CryptographicProviderFactory.getProvider();

            Signature sig = Signature.getInstance(algorithm, provider);
            sig.initVerify(keyPair.getPQCPublicKey());
            sig.update(tbsCertificate);
            boolean valid = sig.verify(pqcSignature);

            logger.fine("PQC signature verification result: " + valid);
            return valid;

        } catch (InvalidSignatureException e) {
            throw e;
        } catch (Exception e) {
            throw new InvalidSignatureException("PQC signature verification failed", e);
        }
    }

    public static HybridCertificateInfo extractCertificateInfo(X509Certificate certificate,
                                                                HybridKeyPair keyPair) {
        Objects.requireNonNull(certificate, "Certificate cannot be null");

        HybridCertificateInfo.Builder builder = HybridCertificateInfo.builder()
                .withCertificate(certificate)
                .withClassicalAlgorithm(keyPair != null ? keyPair.getClassicalAlgorithm() : null)
                .withPQCAlgorithm(keyPair != null ? keyPair.getPQCAlgorithm() : null);

        if (keyPair != null) {
            try {
                builder.withPQCPublicKeyBytes(keyPair.getPQCPublicKey().getEncoded());
            } catch (Exception e) {
                logger.warning("Failed to get PQC public key bytes: " + e.getMessage());
            }
        }

        String pqcOID = extractPQCAlgorithmOID(certificate);
        if (pqcOID != null) {
            builder.withPQCAlgorithmOID(pqcOID);
        }

        byte[] pqcSig = extractPQCSignature(certificate);
        if (pqcSig != null) {
            builder.withPQCSignature(pqcSig);
        }

        try {
            Map<String, Extension> exts = extractPQCExtensions(certificate);
            if (exts.size() == 3) {
                builder.withPQCExtensions(buildPQCExtensionsFromExtMap(exts));
            }
        } catch (Exception e) {
            logger.warning("Failed to build PQC extensions structure: " + e.getMessage());
        }

        return builder.build();
    }

    private static PQCExtensionsStructure buildPQCExtensionsFromExtMap(Map<String, Extension> exts)
            throws IOException {
        Extension altAlg = exts.get(OID_ALT_SIGNATURE_ALGORITHM);
        Extension altSig = exts.get(OID_ALT_SIGNATURE_VALUE);
        Extension altKey = exts.get(OID_SUBJECT_ALT_PUBKEY_INFO);

        if (altAlg == null || altSig == null || altKey == null) {
            return null;
        }

        org.bouncycastle.asn1.x509.AlgorithmIdentifier algId =
                org.bouncycastle.asn1.x509.AlgorithmIdentifier.getInstance(altAlg.getParsedValue());

        byte[] sigBytes = ((org.bouncycastle.asn1.DERBitString) altSig.getParsedValue()).getOctets();

        byte[] spkiBytes = ASN1OctetString.getInstance(altKey.getParsedValue()).getOctets();
        SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(spkiBytes);

        return new PQCExtensionsStructure(algId, sigBytes, spki);
    }

    public static ValidationResult validateComprehensive(X509Certificate certificate,
                                                         PublicKey issuerPublicKey) {
        return validateComprehensive(certificate, issuerPublicKey, null);
    }

    public static ValidationResult validateComprehensive(X509Certificate certificate,
                                                         PublicKey issuerPublicKey,
                                                         HybridKeyPair hybridKeyPair) {
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
        } else {
            builder.signatureValid(true);
        }

        boolean hasPQCExts = validatePQCExtensions(certificate);
        builder.pqcExtensionsValid(hasPQCExts);

        if (hasPQCExts && hybridKeyPair != null) {
            try {
                boolean pqcSigValid = validatePQCSignature(certificate, hybridKeyPair);
                builder.pqcSignatureValid(pqcSigValid);
            } catch (InvalidSignatureException e) {
                logger.warning("PQC signature validation error: " + e.getMessage());
                builder.pqcSignatureValid(false);
            }
        } else {
            builder.pqcSignatureValid(true);
        }

        return builder.build();
    }

    public static class ValidationResult {
        private final boolean notExpiredValid;
        private final boolean dnsValid;
        private final boolean validityPeriodValid;
        private final boolean publicKeyValid;
        private final boolean signatureValid;
        private final boolean pqcExtensionsValid;
        private final boolean pqcSignatureValid;

        private ValidationResult(boolean notExpiredValid, boolean dnsValid,
                                boolean validityPeriodValid, boolean publicKeyValid,
                                boolean signatureValid, boolean pqcExtensionsValid,
                                boolean pqcSignatureValid) {
            this.notExpiredValid = notExpiredValid;
            this.dnsValid = dnsValid;
            this.validityPeriodValid = validityPeriodValid;
            this.publicKeyValid = publicKeyValid;
            this.signatureValid = signatureValid;
            this.pqcExtensionsValid = pqcExtensionsValid;
            this.pqcSignatureValid = pqcSignatureValid;
        }

        public boolean isNotExpiredValid() { return notExpiredValid; }
        public boolean isDnsValid() { return dnsValid; }
        public boolean isValidityPeriodValid() { return validityPeriodValid; }
        public boolean isPublicKeyValid() { return publicKeyValid; }
        public boolean isSignatureValid() { return signatureValid; }
        public boolean isPqcExtensionsValid() { return pqcExtensionsValid; }
        public boolean isPqcSignatureValid() { return pqcSignatureValid; }

        public boolean isAllValid() {
            return notExpiredValid && dnsValid && validityPeriodValid
                && publicKeyValid && signatureValid && pqcExtensionsValid && pqcSignatureValid;
        }

        public boolean isHybridFullyValid() {
            return pqcExtensionsValid && pqcSignatureValid;
        }

        public static class Builder {
            private boolean notExpiredValid = false;
            private boolean dnsValid = false;
            private boolean validityPeriodValid = false;
            private boolean publicKeyValid = false;
            private boolean signatureValid = false;
            private boolean pqcExtensionsValid = false;
            private boolean pqcSignatureValid = false;

            public Builder notExpiredValid(boolean valid) { this.notExpiredValid = valid; return this; }
            public Builder dnsValid(boolean valid) { this.dnsValid = valid; return this; }
            public Builder validityPeriodValid(boolean valid) { this.validityPeriodValid = valid; return this; }
            public Builder publicKeyValid(boolean valid) { this.publicKeyValid = valid; return this; }
            public Builder signatureValid(boolean valid) { this.signatureValid = valid; return this; }
            public Builder pqcExtensionsValid(boolean valid) { this.pqcExtensionsValid = valid; return this; }
            public Builder pqcSignatureValid(boolean valid) { this.pqcSignatureValid = valid; return this; }

            public ValidationResult build() {
                return new ValidationResult(notExpiredValid, dnsValid, validityPeriodValid,
                        publicKeyValid, signatureValid, pqcExtensionsValid, pqcSignatureValid);
            }
        }

        @Override
        public String toString() {
            return String.format(
                    "ValidationResult{notExpired=%b, dns=%b, validity=%b, pubkey=%b, sig=%b, pqcExt=%b, pqcSig=%b, all=%b}",
                    notExpiredValid, dnsValid, validityPeriodValid, publicKeyValid,
                    signatureValid, pqcExtensionsValid, pqcSignatureValid, isAllValid());
        }
    }
}