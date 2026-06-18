package com.pqc.hybrid.core.certificate;

import com.pqc.hybrid.core.certificate.asn1.PQCExtensionsStructure;
import com.pqc.hybrid.core.common.oid.AlgorithmOIDRegistry;
import com.pqc.hybrid.core.config.CryptographicProviderFactory;
import com.pqc.hybrid.core.exception.CertificateException;
import com.pqc.hybrid.core.exception.InvalidSignatureException;
import com.pqc.hybrid.core.keygen.HybridKeyPair;
import com.pqc.hybrid.core.model.HybridCertificateInfo;
import com.pqc.hybrid.core.signature.ml_dsa.MLDSAVerifier;

import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.TBSCertificate;
import org.bouncycastle.asn1.x509.V3TBSCertificateGenerator;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

import java.io.IOException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXCertPathChecker;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.logging.Logger;

public final class HybridCertificateValidator {

    private static final Logger logger = Logger.getLogger(HybridCertificateValidator.class.getName());

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
        String subjectDN = certificate.getSubjectX500Principal().getName();
        String issuerDN = certificate.getIssuerX500Principal().getName();
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

            boolean hasAlg = pqcExtensions.containsKey(AlgorithmOIDRegistry.OID_ALT_SIGNATURE_ALGORITHM);
            boolean hasSig = pqcExtensions.containsKey(AlgorithmOIDRegistry.OID_ALT_SIGNATURE_VALUE);
            boolean hasKey = pqcExtensions.containsKey(AlgorithmOIDRegistry.OID_SUBJECT_ALT_PUBLIC_KEY_INFO);

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
            collectPQCExtensions(certificate, certificate.getCriticalExtensionOIDs(), true, extensions);
            collectPQCExtensions(certificate, certificate.getNonCriticalExtensionOIDs(), false, extensions);
        } catch (Exception e) {
            logger.warning("Error extracting PQC extensions: " + e.getMessage());
        }

        return extensions;
    }

    /**
     * Collects the Catalyst alternative-signature extensions found in {@code oids} into
     * {@code target}, tagging each with the given criticality. Extensions already present in
     * {@code target} are left untouched, so a critical entry takes precedence over a
     * non-critical one with the same OID.
     */
    private static void collectPQCExtensions(X509Certificate certificate, Set<String> oids,
                                             boolean critical, Map<String, Extension> target) {
        if (oids == null) {
            return;
        }
        for (String oid : oids) {
            if (!isPQCExtensionOid(oid) || target.containsKey(oid)) {
                continue;
            }
            byte[] extValue = certificate.getExtensionValue(oid);
            if (extValue != null) {
                target.put(oid, new Extension(new ASN1ObjectIdentifier(oid), critical, extValue));
            }
        }
    }

    /** @return true if {@code oid} is one of the three Catalyst alternative-signature extension OIDs. */
    private static boolean isPQCExtensionOid(String oid) {
        return AlgorithmOIDRegistry.OID_ALT_SIGNATURE_ALGORITHM.equals(oid)
                || AlgorithmOIDRegistry.OID_ALT_SIGNATURE_VALUE.equals(oid)
                || AlgorithmOIDRegistry.OID_SUBJECT_ALT_PUBLIC_KEY_INFO.equals(oid);
    }

    public static String extractPQCAlgorithmOID(X509Certificate certificate) {
        Objects.requireNonNull(certificate, "Certificate cannot be null");
        try {
            byte[] extValue = certificate.getExtensionValue(AlgorithmOIDRegistry.OID_ALT_SIGNATURE_ALGORITHM);
            if (extValue == null) {
                return null;
            }
            ASN1OctetString octetStr = ASN1OctetString.getInstance(extValue);
            AlgorithmIdentifier algId = AlgorithmIdentifier.getInstance(octetStr.getOctets());
            return algId.getAlgorithm().getId();
        } catch (Exception e) {
            logger.warning("Failed to extract PQC algorithm OID: " + e.getMessage());
            return null;
        }
    }

    public static byte[] extractPQCSignature(X509Certificate certificate) {
        Objects.requireNonNull(certificate, "Certificate cannot be null");
        try {
            byte[] extValue = certificate.getExtensionValue(AlgorithmOIDRegistry.OID_ALT_SIGNATURE_VALUE);
            if (extValue == null) {
                return null;
            }
            ASN1OctetString octetStr = ASN1OctetString.getInstance(extValue);
            ASN1BitString bitString = DERBitString.getInstance(octetStr.getOctets());
            return bitString.getOctets();
        } catch (Exception e) {
            logger.warning("Failed to extract PQC signature: " + e.getMessage());
            return null;
        }
    }

    public static byte[] extractPQCPublicKey(X509Certificate certificate) {
        Objects.requireNonNull(certificate, "Certificate cannot be null");
        try {
            byte[] extValue = certificate.getExtensionValue(AlgorithmOIDRegistry.OID_SUBJECT_ALT_PUBLIC_KEY_INFO);
            if (extValue == null) {
                return null;
            }
            ASN1OctetString octetStr = ASN1OctetString.getInstance(extValue);
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
        // For a self-signed certificate the alternative signature is verified against the
        // subject's own PQC public key.
        return verifyAltSignature(certificate, keyPair.getPQCPublicKey());
    }

    /**
     * Verifies a certificate's alternative (PQC) signature against the issuer's alternative
     * public key. The signature is checked over the reconstructed pre-TBS (see
     * {@link #reconstructPreTBS(X509Certificate)}), using the algorithm declared in the
     * certificate's {@code altSignatureAlgorithm} (2.5.29.73) extension.
     *
     * @param certificate        the certificate whose alternative signature is verified
     * @param issuerAltPublicKey the issuer's alternative (PQC) public key (the subject's own
     *                           key for a self-signed certificate)
     * @return true if the alternative signature is valid
     */
    public static boolean verifyAltSignature(X509Certificate certificate, PublicKey issuerAltPublicKey)
            throws InvalidSignatureException {
        Objects.requireNonNull(certificate, "Certificate cannot be null");
        Objects.requireNonNull(issuerAltPublicKey, "Issuer alternative public key cannot be null");

        try {
            byte[] pqcSignature = extractPQCSignature(certificate);
            if (pqcSignature == null) {
                logger.warning("PQC signature not found in certificate extensions");
                return false;
            }

            String oid = extractPQCAlgorithmOID(certificate);
            String algorithm = AlgorithmOIDRegistry.getAlgorithmName(oid);
            if (algorithm == null) {
                algorithm = oid; // fall back to the raw OID
            }

            byte[] preTbs = reconstructPreTBS(certificate);

            boolean valid = MLDSAVerifier.verify(preTbs, pqcSignature, issuerAltPublicKey, algorithm);

            logger.fine("PQC alternative signature verification result: " + valid);
            return valid;

        } catch (InvalidSignatureException e) {
            throw e;
        } catch (Exception e) {
            throw new InvalidSignatureException("PQC alternative signature verification failed", e);
        }
    }

    /**
     * Extracts the alternative (PQC) public key from a certificate's
     * {@code subjectAltPublicKeyInfo} (2.5.29.72) extension as a usable {@link PublicKey}.
     *
     * @return the decoded public key, or {@code null} if the extension is absent or invalid
     */
    public static PublicKey extractAltPublicKey(X509Certificate certificate) {
        Objects.requireNonNull(certificate, "Certificate cannot be null");
        try {
            byte[] extValue = certificate.getExtensionValue(AlgorithmOIDRegistry.OID_SUBJECT_ALT_PUBLIC_KEY_INFO);
            if (extValue == null) {
                return null;
            }
            ASN1OctetString octetStr = ASN1OctetString.getInstance(extValue);
            SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(octetStr.getOctets());
            CryptographicProviderFactory.initialize();
            return new JcaPEMKeyConverter().setProvider("BC").getPublicKey(spki);
        } catch (Exception e) {
            logger.warning("Failed to extract alternative public key: " + e.getMessage());
            return null;
        }
    }

    /**
     * Reconstructs the pre-TBS certificate over which the alternative (PQC) signature is
     * computed in the ITU-T X.509 (2019) model. This is the TBSCertificate with the
     * {@code signature} AlgorithmIdentifier field omitted and the {@code altSignatureValue}
     * (2.5.29.74) extension removed — exactly what BouncyCastle's native
     * {@code build(primary, true, altSigner)} signs via
     * {@link V3TBSCertificateGenerator#generatePreTBSCertificate()}.
     */
    private static byte[] reconstructPreTBS(X509Certificate certificate) throws Exception {
        TBSCertificate tbs = TBSCertificate.getInstance(certificate.getTBSCertificate());

        ExtensionsGenerator extGen = new ExtensionsGenerator();
        extGen.addExtensions(tbs.getExtensions());
        extGen.removeExtension(Extension.altSignatureValue);
        Extensions preExtensions = extGen.generate();

        V3TBSCertificateGenerator tbsGen = new V3TBSCertificateGenerator();
        // NOTE: the signature field is intentionally NOT set — generatePreTBSCertificate()
        // omits it (and rejects the structure if it is present).
        tbsGen.setSerialNumber(tbs.getSerialNumber());
        tbsGen.setIssuer(tbs.getIssuer());
        tbsGen.setStartDate(tbs.getStartDate());
        tbsGen.setEndDate(tbs.getEndDate());
        tbsGen.setSubject(tbs.getSubject());
        tbsGen.setSubjectPublicKeyInfo(tbs.getSubjectPublicKeyInfo());

        ASN1BitString issuerUniqueId = tbs.getIssuerUniqueId();
        if (issuerUniqueId != null) {
            tbsGen.setIssuerUniqueID(new DERBitString(issuerUniqueId.getBytes(), issuerUniqueId.getPadBits()));
        }
        ASN1BitString subjectUniqueId = tbs.getSubjectUniqueId();
        if (subjectUniqueId != null) {
            tbsGen.setSubjectUniqueID(new DERBitString(subjectUniqueId.getBytes(), subjectUniqueId.getPadBits()));
        }

        tbsGen.setExtensions(preExtensions);

        return tbsGen.generatePreTBSCertificate().getEncoded(ASN1Encoding.DER);
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
        Extension altAlg = exts.get(AlgorithmOIDRegistry.OID_ALT_SIGNATURE_ALGORITHM);
        Extension altSig = exts.get(AlgorithmOIDRegistry.OID_ALT_SIGNATURE_VALUE);
        Extension altKey = exts.get(AlgorithmOIDRegistry.OID_SUBJECT_ALT_PUBLIC_KEY_INFO);

        if (altAlg == null || altSig == null || altKey == null) {
            return null;
        }

        AlgorithmIdentifier algId = AlgorithmIdentifier.getInstance(altAlg.getParsedValue());

        byte[] sigBytes = ((DERBitString) altSig.getParsedValue()).getOctets();

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
        } else if (hasPQCExts) {
            builder.pqcSignatureValid(false);
        } else {
            builder.pqcSignatureValid(true);
        }

        return builder.build();
    }

    /**
     * Validates a full hybrid certificate chain in both dimensions.
     *
     * <p>The chain must be ordered leaf → … → root, where the last element is the
     * (self-signed) trust anchor. The classical dimension is validated with the JDK's PKIX
     * {@link CertPathValidator}; the post-quantum dimension is validated by walking each link
     * and verifying its alternative signature against the issuer's alternative public key.
     *
     * @param chain the ordered certificate chain (leaf first, root last)
     * @return a {@link HybridChainValidationResult} with both dimensions' outcomes
     */
    public static HybridChainValidationResult validateHybridChain(List<X509Certificate> chain) {
        Objects.requireNonNull(chain, "Chain cannot be null");
        if (chain.isEmpty()) {
            throw new IllegalArgumentException("Certificate chain cannot be empty");
        }
        boolean classicalValid = validateClassicalChain(chain);
        boolean pqcValid = validateAltSignatureChain(chain);
        logger.fine("Hybrid chain validation: classical=" + classicalValid + ", pqc=" + pqcValid);
        return new HybridChainValidationResult(classicalValid, pqcValid);
    }

    private static boolean validateClassicalChain(List<X509Certificate> chain) {
        try {
            CryptographicProviderFactory.initialize();
            X509Certificate root = chain.get(chain.size() - 1);

            // The PKIX CertPath excludes the trust anchor (root).
            List<X509Certificate> path = new ArrayList<>(chain.subList(0, chain.size() - 1));
            if (path.isEmpty()) {
                // Single self-signed certificate: verify its classical signature directly.
                root.verify(root.getPublicKey(), "BC");
                return true;
            }

            CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
            CertPath certPath = cf.generateCertPath(path);

            PKIXParameters params = new PKIXParameters(Set.of(new TrustAnchor(root, null)));
            params.setRevocationEnabled(false);
            // The Catalyst alt-signature extensions are marked critical; tell PKIX they are handled.
            params.addCertPathChecker(new HybridExtensionChecker());

            CertPathValidator validator = CertPathValidator.getInstance("PKIX", "BC");
            validator.validate(certPath, params);
            return true;
        } catch (Exception e) {
            logger.warning("Classical chain validation failed: " + e.getMessage());
            return false;
        }
    }

    private static boolean validateAltSignatureChain(List<X509Certificate> chain) {
        try {
            for (int i = 0; i < chain.size(); i++) {
                X509Certificate cert = chain.get(i);
                X509Certificate issuer = (i + 1 < chain.size()) ? chain.get(i + 1) : cert; // root self-issues
                PublicKey issuerAltKey = extractAltPublicKey(issuer);
                if (issuerAltKey == null) {
                    logger.warning("Missing alternative public key for issuer at chain index " + i);
                    return false;
                }
                if (!verifyAltSignature(cert, issuerAltKey)) {
                    logger.warning("Alternative (PQC) signature invalid at chain index " + i);
                    return false;
                }
            }
            return true;
        } catch (Exception e) {
            logger.warning("PQC chain validation failed: " + e.getMessage());
            return false;
        }
    }

    /**
     * Outcome of a hybrid chain validation: classical (PKIX) and post-quantum dimensions.
     */
    public record HybridChainValidationResult(boolean classicalValid, boolean pqcValid) {
        /** @return true only if both the classical and the PQC dimensions are valid. */
        public boolean isValid() {
            return classicalValid && pqcValid;
        }
    }

    /**
     * PKIX extension checker that marks the Catalyst alternative-signature extensions
     * (altSignatureAlgorithm/altSignatureValue) as handled, so PKIX does not reject them as
     * unrecognised critical extensions.
     */
    private static final class HybridExtensionChecker extends PKIXCertPathChecker {
        private static final Set<String> SUPPORTED = Set.of(
                AlgorithmOIDRegistry.OID_ALT_SIGNATURE_ALGORITHM,
                AlgorithmOIDRegistry.OID_ALT_SIGNATURE_VALUE,
                AlgorithmOIDRegistry.OID_SUBJECT_ALT_PUBLIC_KEY_INFO);

        @Override
        public void init(boolean forward) {
            // stateless
        }

        @Override
        public boolean isForwardCheckingSupported() {
            return true;
        }

        @Override
        public Set<String> getSupportedExtensions() {
            return SUPPORTED;
        }

        @Override
        public void check(Certificate cert, Collection<String> unresolvedCritExts) {
            if (unresolvedCritExts != null) {
                unresolvedCritExts.removeAll(SUPPORTED);
            }
        }
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