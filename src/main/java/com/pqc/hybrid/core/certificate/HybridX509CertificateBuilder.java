package com.pqc.hybrid.core.certificate;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;

import com.pqc.hybrid.core.config.CryptographicProviderFactory;
import com.pqc.hybrid.core.config.HybridCertificateConfig;
import com.pqc.hybrid.core.keygen.HybridKeyPair;
import com.pqc.hybrid.core.model.HybridCertificateInfo;
import com.pqc.hybrid.core.exception.CertificateException;
import com.pqc.hybrid.core.exception.PQCHybridException;
import com.pqc.hybrid.core.common.oid.AlgorithmOIDRegistry;

import java.io.IOException;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.Objects;
import java.util.logging.Logger;

public final class HybridX509CertificateBuilder {

    private static final Logger logger = Logger.getLogger(HybridX509CertificateBuilder.class.getName());

    private static final String OID_ALT_SIGNATURE_ALGORITHM = "2.5.29.62";
    private static final String OID_ALT_SIGNATURE_VALUE = "2.5.29.63";
    private static final String OID_SUBJECT_ALT_PUBKEY_INFO = "2.5.29.72";

    private final HybridCertificateConfig config;
    private final HybridKeyPair keyPair;
    private boolean includePQCExtensions = true;
    private X509ExtensionManager extensionManager;

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

    public X509Certificate build() throws CertificateException {
        try {
            CryptographicProviderFactory.initialize();
            logger.info("Building hybrid X509 certificate with PQC extensions: " + includePQCExtensions);

            X509Certificate baseCertificate = buildBaseCertificate();
            logger.info("Generated base X509 certificate with classical signature");

            if (includePQCExtensions) {
                X509Certificate hybridCertificate = addPQCExtensions(baseCertificate);
                logger.info("Added PQC extensions and alternative signatures to certificate");
                return hybridCertificate;
            }

            return baseCertificate;

        } catch (CertificateException e) {
            throw e;
        } catch (Exception e) {
            throw new CertificateException("Failed to build hybrid X509 certificate", e);
        }
    }

    private X509Certificate buildBaseCertificate() throws Exception {
        X500Name subject = new X500Name(config.getSubjectDN());
        X500Name issuer = new X500Name(config.getIssuerDN());

        BigInteger serialNumber = BigInteger.valueOf(config.getSerialNumber());
        Instant now = Instant.now();
        Date notBefore = Date.from(now);
        Date notAfter = Date.from(now.plus(config.getValidityDays(), ChronoUnit.DAYS));

        PublicKey subjectPublicKey = keyPair.getClassicalPublicKey();

        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                issuer, serialNumber, notBefore, notAfter, subject, subjectPublicKey);

        addBasicExtensions(certBuilder);

        String signatureAlgorithm = getClassicalSignatureAlgorithmName();
        ContentSigner signer = new JcaContentSignerBuilder(signatureAlgorithm)
                .setProvider(CryptographicProviderFactory.getProvider())
                .build(keyPair.getClassicalPrivateKey());

        return new JcaX509CertificateConverter()
                .setProvider(CryptographicProviderFactory.getProvider())
                .getCertificate(certBuilder.build(signer));
    }

    private void addBasicExtensions(X509v3CertificateBuilder certBuilder) throws Exception {
        SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(
                keyPair.getClassicalPublicKey().getEncoded()
        );
        byte[] publicKeyBytes = spki.getPublicKeyData().getBytes();
        certBuilder.addExtension(
                org.bouncycastle.asn1.x509.Extension.subjectKeyIdentifier,
                false,
                new org.bouncycastle.asn1.x509.SubjectKeyIdentifier(publicKeyBytes)
        );

        certBuilder.addExtension(
                org.bouncycastle.asn1.x509.Extension.keyUsage,
                true,
                new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment)
        );

        KeyPurposeId[] purposes = new KeyPurposeId[] {
            KeyPurposeId.id_kp_serverAuth,
            KeyPurposeId.id_kp_clientAuth
        };
        certBuilder.addExtension(
                org.bouncycastle.asn1.x509.Extension.extendedKeyUsage,
                false,
                new ExtendedKeyUsage(purposes)
        );

        certBuilder.addExtension(
                org.bouncycastle.asn1.x509.Extension.basicConstraints,
                true,
                new BasicConstraints(false)
        );

        logger.fine("Added basic X.509v3 extensions");
    }

    private X509Certificate addPQCExtensions(X509Certificate baseCertificate) throws Exception {
        logger.info("Adding PQC extensions to certificate");

        byte[] tbsCertificate = baseCertificate.getTBSCertificate();
        String pqcAlgorithmName = keyPair.getPQCAlgorithm();
        String pqcOID = getPQCAlgorithmOID(pqcAlgorithmName);

        byte[] pqcSignature = signTBSWithPQC(tbsCertificate);

        byte[] pqcPublicKeyBytes = keyPair.getPQCPublicKey().getEncoded();
        SubjectPublicKeyInfo pqcSPKI = SubjectPublicKeyInfo.getInstance(pqcPublicKeyBytes);

        AlgorithmIdentifier pqcAlgorithmId = new AlgorithmIdentifier(new ASN1ObjectIdentifier(pqcOID));

        X509v3CertificateBuilder newCertBuilder = new JcaX509v3CertificateBuilder(
                baseCertificate.getIssuerX500Principal(),
                baseCertificate.getSerialNumber(),
                baseCertificate.getNotBefore(),
                baseCertificate.getNotAfter(),
                baseCertificate.getSubjectX500Principal(),
                baseCertificate.getPublicKey()
        );

        addBasicExtensions(newCertBuilder);

        byte[] altSigAlgEncoded = pqcAlgorithmId.getEncoded();
        newCertBuilder.addExtension(
                new ASN1ObjectIdentifier(OID_ALT_SIGNATURE_ALGORITHM),
                false,
                altSigAlgEncoded
        );

        newCertBuilder.addExtension(
                new ASN1ObjectIdentifier(OID_ALT_SIGNATURE_VALUE),
                false,
                new DERBitString(pqcSignature)
        );

        byte[] altPubKeyEncoded = pqcSPKI.getEncoded();
        newCertBuilder.addExtension(
                new ASN1ObjectIdentifier(OID_SUBJECT_ALT_PUBKEY_INFO),
                false,
                new DEROctetString(altPubKeyEncoded)
        );

        String signatureAlgorithm = getClassicalSignatureAlgorithmName();
        ContentSigner signer = new JcaContentSignerBuilder(signatureAlgorithm)
                .setProvider(CryptographicProviderFactory.getProvider())
                .build(keyPair.getClassicalPrivateKey());

        X509CertificateHolder certHolder = newCertBuilder.build(signer);

        return new JcaX509CertificateConverter()
                .setProvider(CryptographicProviderFactory.getProvider())
                .getCertificate(certHolder);
    }

    private String getPQCAlgorithmNameForSignature(String algorithmName) {
        return switch (algorithmName) {
            case "ML-DSA-44", "Dilithium2" -> "ML-DSA-44";
            case "ML-DSA-65", "Dilithium3" -> "ML-DSA-65";
            case "ML-DSA-87", "Dilithium5" -> "ML-DSA-87";
            default -> algorithmName;
        };
    }

    private byte[] signTBSWithPQC(byte[] tbsCertificate) throws Exception {
        String algorithmName = getPQCAlgorithmNameForSignature(keyPair.getPQCAlgorithm());
        Provider provider = CryptographicProviderFactory.getProvider();

        Signature sig = Signature.getInstance(algorithmName, provider);
        sig.initSign(keyPair.getPQCPrivateKey());
        sig.update(tbsCertificate);
        return sig.sign();
    }

    private String getPQCAlgorithmOID(String algorithmName) {
        if (algorithmName == null) {
            throw new IllegalArgumentException("PQC algorithm name cannot be null");
        }

        return switch (algorithmName) {
            case "ML-DSA-44", "Dilithium2" -> AlgorithmOIDRegistry.OID_ML_DSA_44;
            case "ML-DSA-65", "Dilithium3" -> AlgorithmOIDRegistry.OID_ML_DSA_65;
            case "ML-DSA-87", "Dilithium5" -> AlgorithmOIDRegistry.OID_ML_DSA_87;
            case "SLH-DSA-SHA2-128s" -> AlgorithmOIDRegistry.OID_SLH_DSA_SHA2_128S;
            case "SLH-DSA-SHA2-128f" -> AlgorithmOIDRegistry.OID_SLH_DSA_SHA2_128F;
            case "SLH-DSA-SHA2-192s" -> AlgorithmOIDRegistry.OID_SLH_DSA_SHA2_192S;
            case "SLH-DSA-SHA2-192f" -> AlgorithmOIDRegistry.OID_SLH_DSA_SHA2_192F;
            case "SLH-DSA-SHA2-256s" -> AlgorithmOIDRegistry.OID_SLH_DSA_SHA2_256S;
            case "SLH-DSA-SHA2-256f" -> AlgorithmOIDRegistry.OID_SLH_DSA_SHA2_256F;
            case "Falcon-512" -> AlgorithmOIDRegistry.OID_FALCON_512;
            case "Falcon-1024" -> AlgorithmOIDRegistry.OID_FALCON_1024;
            default -> throw new IllegalArgumentException("Unknown PQC algorithm: " + algorithmName);
        };
    }

    private String getClassicalSignatureAlgorithmName() {
        String algo = keyPair.getClassicalAlgorithm();
        if (algo.contains("RSA")) {
            return "SHA256withRSA";
        } else if (algo.contains("ECDSA")) {
            return "SHA256withECDSA";
        }
        throw new IllegalArgumentException("Unknown classical algorithm: " + algo);
    }

    public static HybridX509CertificateBuilder builder(HybridCertificateConfig config, HybridKeyPair keyPair) {
        return new HybridX509CertificateBuilder(config, keyPair);
    }
}