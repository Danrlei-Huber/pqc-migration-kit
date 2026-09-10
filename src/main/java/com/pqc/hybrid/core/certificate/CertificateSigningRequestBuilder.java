package com.pqc.hybrid.core.certificate;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import com.pqc.hybrid.core.config.ClassicalAlgorithm;
import com.pqc.hybrid.core.config.CryptographicProviderFactory;
import com.pqc.hybrid.core.keygen.HybridKeyPair;
import com.pqc.hybrid.core.exception.CertificateException;

import java.security.PublicKey;
import java.util.Objects;
import java.util.logging.Logger;

/**
 * Builds hybrid PKCS#10 Certificate Signing Requests (CSRs).
 *
 * <p>The CSR carries the classical subject public key signed with the classical key, plus
 * an alternative (PQC) subject public key and an alternative signature, produced natively
 * by BouncyCastle via
 * {@link org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder#build(ContentSigner, SubjectPublicKeyInfo, ContentSigner)}.
 * A CA can therefore issue a hybrid certificate from this single request.
 *
 * <p><b>Two ways to sign</b>, mirroring {@link HybridX509CertificateBuilder}:
 * <ul>
 *   <li><b>Layer 1 (signer-agnostic):</b> the static
 *       {@link #build(String, PublicKey, PublicKey, HybridSigner)} takes the subject's public keys
 *       plus a {@link HybridSigner}; the private keys never need to be in memory (HSM/token/KMS).</li>
 *   <li><b>Layer 2 (convenience):</b> the instance API builds in-memory {@link ContentSigner}s from
 *       a {@link HybridKeyPair} and delegates to Layer 1.</li>
 * </ul>
 */
public final class CertificateSigningRequestBuilder {

    private static final Logger logger = Logger.getLogger(CertificateSigningRequestBuilder.class.getName());

    private final String subjectDN;
    private final HybridKeyPair keyPair;
    private X509ExtensionManager extensionManager;

    public CertificateSigningRequestBuilder(String subjectDN, HybridKeyPair keyPair) {
        this.subjectDN = Objects.requireNonNull(subjectDN, "Subject DN cannot be null");
        this.keyPair = Objects.requireNonNull(keyPair, "Key pair cannot be null");
        this.extensionManager = new X509ExtensionManager();
    }

    /**
     * Sets a custom extension manager.
     */
    public CertificateSigningRequestBuilder withExtensionManager(X509ExtensionManager manager) {
        this.extensionManager = Objects.requireNonNull(manager, "Extension manager cannot be null");
        return this;
    }

    /**
     * Layer 2 entry point: builds the hybrid CSR using in-memory {@link ContentSigner}s derived from
     * the configured {@link HybridKeyPair}, then delegates to the Layer 1 core.
     *
     * @return the PKCS10CertificationRequest
     * @throws CertificateException if CSR generation fails
     */
    public PKCS10CertificationRequest build() throws CertificateException {
        ContentSigner classicalSigner;
        ContentSigner altSigner;
        try {
            CryptographicProviderFactory.initialize();
            classicalSigner = new JcaContentSignerBuilder(getClassicalSignatureAlgorithmName())
                    .setProvider("BC")
                    .build(keyPair.getClassicalPrivateKey());
            altSigner = new JcaContentSignerBuilder(getPQCSignatureAlgorithmName())
                    .setProvider("BC")
                    .build(keyPair.getPQCPrivateKey());
        } catch (Exception e) {
            throw new CertificateException("Failed to build hybrid PKCS#10 CSR", e);
        }

        return build(subjectDN, keyPair.getClassicalPublicKey(), keyPair.getPQCPublicKey(),
                new HybridSigner(classicalSigner, altSigner));
    }

    /**
     * Layer 1 core: builds a hybrid PKCS#10 CSR from the subject's public keys and an
     * externally-supplied {@link HybridSigner}. No private keys are required — the signers may be
     * backed by an HSM, a token, a KMS, or in-memory keys.
     *
     * <p>When {@code signer.pqc()} is {@code null}, a classical-only CSR is produced.
     *
     * @param subjectDN                  the subject Distinguished Name
     * @param subjectClassicalPublicKey  the subject's classical public key
     * @param subjectPqcPublicKey        the subject's PQC public key (alternative); may be {@code null}
     *                                   only when {@code signer} has no PQC signer
     * @param signer                     the subject's signer(s)
     * @return the PKCS10CertificationRequest
     * @throws CertificateException if CSR generation fails
     */
    public static PKCS10CertificationRequest build(
            String subjectDN,
            PublicKey subjectClassicalPublicKey,
            PublicKey subjectPqcPublicKey,
            HybridSigner signer) throws CertificateException {

        Objects.requireNonNull(subjectDN, "Subject DN cannot be null");
        Objects.requireNonNull(subjectClassicalPublicKey, "Subject classical public key cannot be null");
        Objects.requireNonNull(signer, "Signer cannot be null");

        boolean includePQC = signer.hasPqc();
        if (includePQC) {
            Objects.requireNonNull(subjectPqcPublicKey,
                    "Subject PQC public key cannot be null when a PQC signer is provided");
        }

        try {
            CryptographicProviderFactory.initialize();

            X500Name subject = new X500Name(subjectDN);
            JcaPKCS10CertificationRequestBuilder csrBuilder =
                    new JcaPKCS10CertificationRequestBuilder(subject, subjectClassicalPublicKey);

            PKCS10CertificationRequest csr;
            if (includePQC) {
                SubjectPublicKeyInfo pqcSPKI = SubjectPublicKeyInfo.getInstance(
                        subjectPqcPublicKey.getEncoded());
                csr = csrBuilder.build(signer.classical(), pqcSPKI, signer.pqc());
                logger.info("Generated hybrid PKCS#10 CSR (classical + PQC) for subject: " + subjectDN);
            } else {
                csr = csrBuilder.build(signer.classical());
                logger.info("Generated classical-only PKCS#10 CSR for subject: " + subjectDN);
            }

            return csr;

        } catch (CertificateException e) {
            throw e;
        } catch (Exception e) {
            throw new CertificateException("Failed to build hybrid PKCS#10 CSR", e);
        }
    }

    /**
     * Resolves the classical signature algorithm from the requester's key itself, so the digest
     * matches the key's strength (P-384 signs with SHA-384, not SHA-256).
     */
    private String getClassicalSignatureAlgorithmName() {
        return ClassicalAlgorithm.getSignatureAlgorithmForKey(keyPair.getClassicalPublicKey());
    }

    private String getPQCSignatureAlgorithmName() {
        String algorithmName = keyPair.getPQCAlgorithm();
        return switch (algorithmName) {
            case "ML-DSA-44", "Dilithium2" -> "ML-DSA-44";
            case "ML-DSA-65", "Dilithium3" -> "ML-DSA-65";
            case "ML-DSA-87", "Dilithium5" -> "ML-DSA-87";
            default -> algorithmName;
        };
    }

    /**
     * Creates a builder for a CSR.
     */
    public static CertificateSigningRequestBuilder builder(String subjectDN, HybridKeyPair keyPair) {
        return new CertificateSigningRequestBuilder(subjectDN, keyPair);
    }
}
