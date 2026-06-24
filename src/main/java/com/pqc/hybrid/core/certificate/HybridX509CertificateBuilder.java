package com.pqc.hybrid.core.certificate;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import com.pqc.hybrid.core.config.ClassicalAlgorithm;
import com.pqc.hybrid.core.config.CryptographicProviderFactory;
import com.pqc.hybrid.core.config.HybridCertificateConfig;
import com.pqc.hybrid.core.keygen.HybridKeyPair;
import com.pqc.hybrid.core.exception.CertificateException;

import java.math.BigInteger;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Objects;
import java.util.logging.Logger;

/**
 * Builds hybrid X.509v3 certificates following the ITU-T X.509 (2019)
 * "alternative signature" (Catalyst) model: a classical primary signature plus a
 * post-quantum alternative signature carried in the {@code subjectAltPublicKeyInfo}
 * ({@code 2.5.29.72}), {@code altSignatureAlgorithm} ({@code 2.5.29.73}) and
 * {@code altSignatureValue} ({@code 2.5.29.74}) extensions.
 *
 * <p><b>Two ways to sign:</b>
 * <ul>
 *   <li><b>Layer 1 (signer-agnostic):</b> the static
 *       {@link #build(HybridCertificateConfig, PublicKey, PublicKey, HybridSigner, X509Certificate)}
 *       takes the subject's public keys plus a {@link HybridSigner} (two
 *       {@link ContentSigner}s). The private keys never need to be in memory — the signers may be
 *       HSM/token-backed (e.g. CZERTAINLY {@code TokenContentSigner}), KMS-backed, or local.</li>
 *   <li><b>Layer 2 (convenience):</b> the instance API
 *       ({@code new HybridX509CertificateBuilder(config, keyPair).build()}) builds in-memory
 *       {@link ContentSigner}s from a {@link HybridKeyPair} and delegates to Layer 1.</li>
 * </ul>
 *
 * <p>By default the certificate is self-signed. Call
 * {@link #withIssuer(HybridKeyPair, X509Certificate)} (Layer 2) or pass an issuer certificate
 * (Layer 1) to issue a certificate signed by a (hybrid) Certificate Authority: the primary
 * signature is produced with the issuer's classical signer and the alternative signature with the
 * issuer's PQC signer, while the subject's own public keys go into the certificate.
 */
public final class HybridX509CertificateBuilder {

    private static final Logger logger = Logger.getLogger(HybridX509CertificateBuilder.class.getName());

    private final HybridCertificateConfig config;
    private final HybridKeyPair keyPair;
    private boolean includePQCExtensions = true;
    private X509ExtensionManager extensionManager;

    private HybridKeyPair issuerKeyPair;        // null => self-signed (signed with subject's keys)
    private X509Certificate issuerCertificate;  // null => self-signed (issuer DN from config)

    public HybridX509CertificateBuilder(HybridCertificateConfig config, HybridKeyPair keyPair) {
        this.config = Objects.requireNonNull(config, "Config cannot be null");
        this.keyPair = Objects.requireNonNull(keyPair, "Key pair cannot be null");
        this.extensionManager = new X509ExtensionManager();
    }

    public HybridX509CertificateBuilder withExtensionManager(X509ExtensionManager manager) {
        this.extensionManager = Objects.requireNonNull(manager, "Extension manager cannot be null");
        return this;
    }

    public HybridX509CertificateBuilder withPQCExtensions(boolean include) {
        this.includePQCExtensions = include;
        return this;
    }

    /**
     * Signs the certificate with a (hybrid) issuer instead of self-signing.
     *
     * @param issuerKeyPair    the CA's hybrid key pair (classical + PQC private keys sign)
     * @param issuerCertificate the CA's certificate (provides the issuer DN and AKI)
     */
    public HybridX509CertificateBuilder withIssuer(HybridKeyPair issuerKeyPair, X509Certificate issuerCertificate) {
        this.issuerKeyPair = Objects.requireNonNull(issuerKeyPair, "Issuer key pair cannot be null");
        this.issuerCertificate = Objects.requireNonNull(issuerCertificate, "Issuer certificate cannot be null");
        return this;
    }

    /**
     * Layer 2 entry point: builds the certificate using in-memory {@link ContentSigner}s derived
     * from the configured {@link HybridKeyPair} (the issuer's when {@link #withIssuer} was called,
     * otherwise the subject's for a self-signed certificate), then delegates to the Layer 1 core.
     */
    public X509Certificate build() throws CertificateException {
        HybridKeyPair signingKeyPair = (issuerKeyPair != null) ? issuerKeyPair : keyPair;

        ContentSigner classicalSigner;
        ContentSigner altSigner = null;
        try {
            CryptographicProviderFactory.initialize();
            classicalSigner = new JcaContentSignerBuilder(getClassicalSignatureAlgorithmName(signingKeyPair))
                    .setProvider("BC")
                    .build(signingKeyPair.getClassicalPrivateKey());
            if (includePQCExtensions) {
                altSigner = new JcaContentSignerBuilder(getPQCSignatureAlgorithmName(signingKeyPair))
                        .setProvider("BC")
                        .build(signingKeyPair.getPQCPrivateKey());
            }
        } catch (Exception e) {
            throw new CertificateException("Failed to build hybrid X509 certificate", e);
        }

        return build(
                config,
                keyPair.getClassicalPublicKey(),
                includePQCExtensions ? keyPair.getPQCPublicKey() : null,
                new HybridSigner(classicalSigner, altSigner),
                issuerCertificate);
    }

    /**
     * Layer 1 core: builds a hybrid X.509v3 certificate from the subject's public keys and an
     * externally-supplied {@link HybridSigner}. No private keys are required — the signers carry
     * their own keys and {@code AlgorithmIdentifier}s, so they may be backed by an HSM, a token, a
     * KMS, or in-memory keys.
     *
     * <p>The alternative signature is produced over the pre-TBS by BouncyCastle's
     * {@code build(primarySigner, isCritical, altSigner)}, which also emits the
     * {@code altSignatureAlgorithm} ({@code 2.5.29.73}) and {@code altSignatureValue}
     * ({@code 2.5.29.74}) extensions from the PQC signer's algorithm identifier and signature. Their
     * criticality is taken from {@link HybridCertificateConfig#isAltSignatureExtensionsCritical()}
     * and defaults to non-critical, so RFC 5280 legacy verifiers ignore them and still accept the
     * certificate by its classical signature.
     *
     * @param config                     certificate parameters (DNs, validity, serial, SANs, CA flags)
     * @param subjectClassicalPublicKey  the subject's classical public key (goes into the certificate)
     * @param subjectPqcPublicKey        the subject's PQC public key for {@code subjectAltPublicKeyInfo};
     *                                   may be {@code null} only when {@code issuerSigner} has no PQC signer
     * @param issuerSigner               the issuer's signer(s); when its PQC signer is {@code null} the
     *                                   certificate is built with the classical signature only
     * @param issuerCertificate          the issuer's certificate (issuer DN + AKI); {@code null} => self-signed
     * @return the generated {@link X509Certificate}
     * @throws CertificateException if certificate construction or signing fails
     */
    public static X509Certificate build(
            HybridCertificateConfig config,
            PublicKey subjectClassicalPublicKey,
            PublicKey subjectPqcPublicKey,
            HybridSigner issuerSigner,
            X509Certificate issuerCertificate) throws CertificateException {

        Objects.requireNonNull(config, "Config cannot be null");
        Objects.requireNonNull(subjectClassicalPublicKey, "Subject classical public key cannot be null");
        Objects.requireNonNull(issuerSigner, "Issuer signer cannot be null");

        boolean includePQCExtensions = issuerSigner.hasPqc();
        if (includePQCExtensions) {
            Objects.requireNonNull(subjectPqcPublicKey,
                    "Subject PQC public key cannot be null when a PQC signer is provided");
        }

        try {
            CryptographicProviderFactory.initialize();

            X500Name issuer = resolveIssuerName(config, issuerCertificate);
            X500Name subject = new X500Name(config.getSubjectDN());

            BigInteger serialNumber = config.getSerialNumber();
            Instant now = Instant.now();
            Date notBefore = Date.from(now);
            Date notAfter = Date.from(now.plus(config.getValidityDays(), ChronoUnit.DAYS));

            JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                    issuer, serialNumber, notBefore, notAfter, subject,
                    subjectClassicalPublicKey);

            addExtensions(certBuilder, config, subjectClassicalPublicKey, issuerCertificate);

            X509CertificateHolder holder;
            if (includePQCExtensions) {
                SubjectPublicKeyInfo pqcSPKI = SubjectPublicKeyInfo.getInstance(
                        subjectPqcPublicKey.getEncoded());
                certBuilder.addExtension(Extension.subjectAltPublicKeyInfo, false, pqcSPKI);

                // Criticality of altSignatureAlgorithm (2.5.29.73) / altSignatureValue (2.5.29.74)
                // is a migration-phase trade-off (RFC 5280 §4.2). Default is non-critical, so a
                // legacy verifier ignores the hybrid extensions and still accepts the certificate by
                // its classical signature (backward-compatible). See
                // HybridCertificateConfig#isAltSignatureExtensionsCritical().
                boolean altCritical = config.isAltSignatureExtensionsCritical();
                holder = certBuilder.build(issuerSigner.classical(), altCritical, issuerSigner.pqc());
                logger.info("Issued hybrid certificate for " + config.getSubjectDN()
                        + " (issuer: " + issuer + ")");
            } else {
                holder = certBuilder.build(issuerSigner.classical());
            }

            return new JcaX509CertificateConverter()
                    .setProvider("BC")
                    .getCertificate(holder);

        } catch (CertificateException e) {
            throw e;
        } catch (Exception e) {
            throw new CertificateException("Failed to build hybrid X509 certificate", e);
        }
    }

    private static X500Name resolveIssuerName(HybridCertificateConfig config, X509Certificate issuerCertificate) {
        if (issuerCertificate != null) {
            return X500Name.getInstance(issuerCertificate.getSubjectX500Principal().getEncoded());
        }
        return new X500Name(config.getIssuerDN());
    }

    private static void addExtensions(X509v3CertificateBuilder certBuilder,
                                      HybridCertificateConfig config,
                                      PublicKey subjectClassicalPublicKey,
                                      X509Certificate issuerCertificate) throws Exception {
        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();

        // Subject Key Identifier (from the subject's classical public key).
        certBuilder.addExtension(Extension.subjectKeyIdentifier, false,
                extUtils.createSubjectKeyIdentifier(subjectClassicalPublicKey));

        // Authority Key Identifier (issuer's, or self when self-signed).
        if (issuerCertificate != null) {
            certBuilder.addExtension(Extension.authorityKeyIdentifier, false,
                    extUtils.createAuthorityKeyIdentifier(issuerCertificate));
        } else {
            certBuilder.addExtension(Extension.authorityKeyIdentifier, false,
                    extUtils.createAuthorityKeyIdentifier(subjectClassicalPublicKey));
        }

        boolean isCA = config.isCertificateAuthority();

        // Key Usage.
        int keyUsageBits = isCA
                ? (KeyUsage.digitalSignature | KeyUsage.keyCertSign | KeyUsage.cRLSign)
                : (KeyUsage.digitalSignature | KeyUsage.nonRepudiation);
        certBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(keyUsageBits));

        // Basic Constraints.
        BasicConstraints basicConstraints;
        if (isCA) {
            basicConstraints = (config.getPathLenConstraint() >= 0)
                    ? new BasicConstraints(config.getPathLenConstraint())
                    : new BasicConstraints(true);
        } else {
            basicConstraints = new BasicConstraints(false);
        }
        certBuilder.addExtension(Extension.basicConstraints, true, basicConstraints);

        // Extended Key Usage only for end-entity (leaf) certificates.
        if (!isCA) {
            certBuilder.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(new KeyPurposeId[] {
                    KeyPurposeId.id_kp_serverAuth,
                    KeyPurposeId.id_kp_clientAuth
            }));
        }

        // Subject Alternative Name (DNS names and IP addresses).
        List<String> sans = config.getSubjectAltNames();
        if (sans != null && !sans.isEmpty()) {
            List<GeneralName> names = new ArrayList<>(sans.size());
            for (String san : sans) {
                int tag = looksLikeIpAddress(san) ? GeneralName.iPAddress : GeneralName.dNSName;
                names.add(new GeneralName(tag, san));
            }
            certBuilder.addExtension(Extension.subjectAlternativeName, false,
                    new GeneralNames(names.toArray(new GeneralName[0])));
        }

        logger.fine("Added X.509v3 extensions (CA=" + isCA + ", SANs=" + (sans == null ? 0 : sans.size()) + ")");
    }

    private static boolean looksLikeIpAddress(String value) {
        // IPv4 dotted-quad or anything containing ':' (IPv6).
        return value.matches("^\\d{1,3}(\\.\\d{1,3}){3}$") || value.contains(":");
    }

    private String getClassicalSignatureAlgorithmName(HybridKeyPair signing) {
        return ClassicalAlgorithm.getSignatureAlgorithmForName(signing.getClassicalAlgorithm());
    }

    /**
     * Resolves the JCA signature algorithm name for the signing key pair's PQC algorithm.
     * Within the current scope the certificate path uses ML-DSA; legacy Dilithium names are
     * normalised to their ML-DSA equivalents.
     */
    private String getPQCSignatureAlgorithmName(HybridKeyPair signing) {
        String algorithmName = signing.getPQCAlgorithm();
        return switch (algorithmName) {
            case "ML-DSA-44", "Dilithium2" -> "ML-DSA-44";
            case "ML-DSA-65", "Dilithium3" -> "ML-DSA-65";
            case "ML-DSA-87", "Dilithium5" -> "ML-DSA-87";
            default -> algorithmName;
        };
    }

    public static HybridX509CertificateBuilder builder(HybridCertificateConfig config, HybridKeyPair keyPair) {
        return new HybridX509CertificateBuilder(config, keyPair);
    }
}
