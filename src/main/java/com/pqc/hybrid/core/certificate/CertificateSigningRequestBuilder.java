package com.pqc.hybrid.core.certificate;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import com.pqc.hybrid.core.config.CryptographicProviderFactory;
import com.pqc.hybrid.core.keygen.HybridKeyPair;
import com.pqc.hybrid.core.exception.CertificateException;

import java.security.PublicKey;
import java.util.Arrays;
import java.util.Objects;
import java.util.logging.Logger;

/**
 * Builder for hybrid PKCS#10 Certificate Signing Requests (CSRs).
 * 
 * Creates CSRs that request both classical and PQC signatures in the resulting certificate.
 * The CSR contains hybrid subject key material and metadata for certificate issuance.
 *
 * @author PQC Hybrid Team
 * @version 1.0.0-BETA
 */
public final class CertificateSigningRequestBuilder {

    private static final Logger logger = Logger.getLogger(CertificateSigningRequestBuilder.class.getName());

    private final String subjectDN;
    private final HybridKeyPair keyPair;
    private X509ExtensionManager extensionManager;

    /**
     * Creates a new CSR builder.
     *
     * @param subjectDN the subject Distinguished Name
     * @param keyPair the hybrid key pair
     */
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
     * Builds the hybrid PKCS#10 CSR.
     *
     * @return the PKCS10CertificationRequest
     * @throws CertificateException if CSR generation fails
     */
    public PKCS10CertificationRequest build() throws CertificateException {
        try {
            CryptographicProviderFactory.initialize();

            X500Name subject = new X500Name(subjectDN);
            PublicKey subjectPublicKey = keyPair.getClassicalPublicKey();

            // Create the CSR builder with classical public key
            PKCS10CertificationRequestBuilder csrBuilder = 
                    new JcaPKCS10CertificationRequestBuilder(subject, subjectPublicKey);

            // Sign with classical private key
            String signatureAlgorithm = getClassicalSignatureAlgorithmName();
            ContentSigner signer = new JcaContentSignerBuilder(signatureAlgorithm)
                    .setProvider(CryptographicProviderFactory.getProvider())
                    .build(keyPair.getClassicalPrivateKey());

            PKCS10CertificationRequest csr = csrBuilder.build(signer);
            logger.info("Generated hybrid PKCS#10 CSR for subject: " + subjectDN);

            return csr;

        } catch (CertificateException e) {
            throw e;
        } catch (Exception e) {
            throw new CertificateException("Failed to build hybrid PKCS#10 CSR", e);
        }
    }

    /**
     * Gets the signature algorithm name for the classical algorithm.
     */
    private String getClassicalSignatureAlgorithmName() {
        String algo = keyPair.getClassicalAlgorithm();
        if (algo.contains("RSA")) {
            return "SHA256withRSA";
        } else if (algo.contains("ECDSA")) {
            return "SHA256withECDSA";
        }
        throw new IllegalArgumentException("Unknown classical algorithm: " + algo);
    }

    /**
     * Creates a builder for a CSR.
     */
    public static CertificateSigningRequestBuilder builder(String subjectDN, HybridKeyPair keyPair) {
        return new CertificateSigningRequestBuilder(subjectDN, keyPair);
    }
}
