package com.pqc.hybrid.core.certificate;

import com.pqc.hybrid.core.config.HybridCertificateConfig;
import com.pqc.hybrid.core.exception.CertificateException;
import com.pqc.hybrid.core.keygen.HybridKeyPair;

import java.security.cert.X509Certificate;
import java.util.Objects;

/**
 * A hybrid Certificate Authority following the ITU-T X.509 (2019) "alternative signature"
 * (Catalyst) model. Wraps the CA's hybrid key pair and its certificate, and issues
 * subordinate (sub-CA or end-entity) certificates signed with <em>both</em> the CA's
 * classical key (primary signature) and the CA's PQC key (alternative signature).
 *
 * <p>Typical usage:
 * <pre>{@code
 * var root  = HybridCertificateAuthority.createRoot(rootConfig, rootKeys);   // self-signed CA
 * var inter = new HybridCertificateAuthority(interKeys,
 *                 root.issueCertificate(interConfig, interKeys));            // sub-CA
 * X509Certificate leaf = inter.issueCertificate(leafConfig, leafKeys);       // end-entity
 * }</pre>
 */
public final class HybridCertificateAuthority {

    private final HybridKeyPair caKeyPair;
    private final X509Certificate caCertificate;

    /**
     * Wraps an existing CA key pair and certificate.
     *
     * @param caKeyPair     the CA's hybrid key pair (its private keys sign issued certificates)
     * @param caCertificate the CA's certificate (provides the issuer DN and AKI)
     */
    public HybridCertificateAuthority(HybridKeyPair caKeyPair, X509Certificate caCertificate) {
        this.caKeyPair = Objects.requireNonNull(caKeyPair, "CA key pair cannot be null");
        this.caCertificate = Objects.requireNonNull(caCertificate, "CA certificate cannot be null");
    }

    /**
     * Bootstraps a self-signed root CA. The given configuration should be marked as a CA
     * (see {@link HybridCertificateConfig.Builder#asCertificateAuthority(boolean)}).
     *
     * @param caConfig the root CA certificate configuration
     * @param caKeyPair the root CA's hybrid key pair
     * @return a ready-to-use {@code HybridCertificateAuthority}
     * @throws CertificateException if the root certificate cannot be built
     */
    public static HybridCertificateAuthority createRoot(HybridCertificateConfig caConfig,
                                                        HybridKeyPair caKeyPair) throws CertificateException {
        Objects.requireNonNull(caConfig, "CA config cannot be null");
        Objects.requireNonNull(caKeyPair, "CA key pair cannot be null");

        X509Certificate rootCertificate =
                new HybridX509CertificateBuilder(caConfig, caKeyPair).build();
        return new HybridCertificateAuthority(caKeyPair, rootCertificate);
    }

    /**
     * Issues a certificate for a subject, signed by this CA's classical and PQC keys.
     * Only the subject's <em>public</em> keys are used.
     *
     * @param subjectConfig  the subject certificate configuration (CA flag, SANs, validity, ...)
     * @param subjectKeyPair the subject's hybrid key pair (public keys are placed in the cert)
     * @return the issued X.509 certificate
     * @throws CertificateException if the certificate cannot be built
     */
    public X509Certificate issueCertificate(HybridCertificateConfig subjectConfig,
                                            HybridKeyPair subjectKeyPair) throws CertificateException {
        Objects.requireNonNull(subjectConfig, "Subject config cannot be null");
        Objects.requireNonNull(subjectKeyPair, "Subject key pair cannot be null");

        return new HybridX509CertificateBuilder(subjectConfig, subjectKeyPair)
                .withIssuer(caKeyPair, caCertificate)
                .build();
    }

    /**
     * @return this CA's certificate
     */
    public X509Certificate getCertificate() {
        return caCertificate;
    }

    /**
     * @return this CA's hybrid key pair
     */
    public HybridKeyPair getKeyPair() {
        return caKeyPair;
    }
}
