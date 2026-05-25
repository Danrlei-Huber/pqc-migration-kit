package com.pqc.hybrid.core.signature;

import com.pqc.hybrid.core.api.HybridSignatureStrategy;
import com.pqc.hybrid.core.certificate.HybridCertificateValidator;
import com.pqc.hybrid.core.certificate.HybridX509CertificateBuilder;
import com.pqc.hybrid.core.config.CompositeAlgorithm;
import com.pqc.hybrid.core.config.HybridAlgorithmPair;
import com.pqc.hybrid.core.config.HybridCertificateConfig;
import com.pqc.hybrid.core.config.ClassicalAlgorithm;
import com.pqc.hybrid.core.config.PQCAlgorithm;
import com.pqc.hybrid.core.exception.CertificateException;
import com.pqc.hybrid.core.exception.InvalidSignatureException;
import com.pqc.hybrid.core.exception.PQCHybridException;
import com.pqc.hybrid.core.keygen.CompositeKeyGenerator;
import com.pqc.hybrid.core.keygen.HybridKeyPair;

import java.security.PublicKey;
import java.security.cert.X509Certificate;

/**
 * <b>EXPERIMENTAL.</b> {@link HybridSignatureStrategy} implementing the composite
 * signature path ({@code draft-ietf-lamps-pq-composite-sigs}).
 *
 * <p>This strategy is <b>not</b> the one used by
 * {@link com.pqc.hybrid.core.api.PQCHybridCertificateAPI}, which wires in the
 * Catalyst / dual-signature {@link DualSignatureStrategy}. Kept as future work;
 * APIs here may change without notice.
 */
public class CompositeSignatureStrategy implements HybridSignatureStrategy {

    private final CompositeAlgorithm algorithm;

    public CompositeSignatureStrategy(CompositeAlgorithm algorithm) {
        this.algorithm = algorithm;
    }

    public CompositeAlgorithm getCompositeAlgorithm() {
        return algorithm;
    }

    @Override
    public String getStrategyName() {
        return "COMPOSITE_" + algorithm.name();
    }

    @Override
    public HybridKeyPair generateKeyPair(int securityLevel) {
        return CompositeKeyGenerator.generate(algorithm);
    }

    @Override
    public HybridKeyPair generateKeyPair(HybridKeyPair keyPair) {
        return keyPair;
    }

    @Override
    public byte[] signData(byte[] data, HybridKeyPair keyPair) throws PQCHybridException {
        return CompositeSigner.sign(data, keyPair);
    }

    @Override
    public byte[] signData(byte[] data, HybridKeyPair keyPair, byte[] ctx) throws PQCHybridException {
        return CompositeSigner.sign(data, keyPair, ctx);
    }

    @Override
    public boolean verifySignature(byte[] data, byte[] signature, HybridKeyPair keyPair) throws InvalidSignatureException {
        return CompositeVerifier.verify(data, signature, keyPair);
    }

    @Override
    public boolean verifySignature(byte[] data, byte[] signature, HybridKeyPair keyPair, byte[] ctx) throws InvalidSignatureException {
        return CompositeVerifier.verify(data, signature, keyPair, ctx);
    }

    @Override
    public X509Certificate buildCertificate(HybridCertificateConfig config, HybridKeyPair keyPair) throws CertificateException {
        HybridAlgorithmPair pair = mapToHybridPair();
        HybridCertificateConfig adaptedConfig = HybridCertificateConfig.builder()
                .withAlgorithmPair(pair)
                .withSubjectDN(config.getSubjectDN())
                .withIssuerDN(config.getIssuerDN())
                .withValidityDays(config.getValidityDays())
                .withSerialNumber(config.getSerialNumber())
                .build();
        return new HybridX509CertificateBuilder(adaptedConfig, keyPair).build();
    }

    @Override
    public Object validateCertificate(X509Certificate certificate, PublicKey issuerPublicKey, HybridKeyPair keyPair) {
        return HybridCertificateValidator.validateComprehensive(certificate, issuerPublicKey, keyPair);
    }

    private HybridAlgorithmPair mapToHybridPair() {
        PQCAlgorithm pqc = algorithm.getPQCAlgorithm();
        ClassicalAlgorithm classical = switch (algorithm.getTradAlgorithmName()) {
            case "RSA" -> switch (algorithm.getTradKeySize()) {
                case 2048 -> ClassicalAlgorithm.RSA_2048;
                case 3072 -> ClassicalAlgorithm.RSA_3072;
                case 4096 -> ClassicalAlgorithm.RSA_4096;
                default -> ClassicalAlgorithm.RSA_2048;
            };
            case "ECDSA" -> switch (algorithm.getTradKeySize()) {
                case 256 -> ClassicalAlgorithm.ECDSA_P256;
                case 384 -> ClassicalAlgorithm.ECDSA_P384;
                case 521 -> ClassicalAlgorithm.ECDSA_P521;
                default -> ClassicalAlgorithm.ECDSA_P256;
            };
            default -> ClassicalAlgorithm.ECDSA_P256;
        };
        return new HybridAlgorithmPair(classical, pqc);
    }
}
