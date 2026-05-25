package com.pqc.hybrid.core.signature;

import com.pqc.hybrid.core.api.HybridSignatureStrategy;
import com.pqc.hybrid.core.certificate.HybridCertificateValidator;
import com.pqc.hybrid.core.certificate.HybridX509CertificateBuilder;
import com.pqc.hybrid.core.config.HybridAlgorithmPair;
import com.pqc.hybrid.core.config.HybridCertificateConfig;
import com.pqc.hybrid.core.exception.CertificateException;
import com.pqc.hybrid.core.exception.InvalidSignatureException;
import com.pqc.hybrid.core.exception.PQCHybridException;
import com.pqc.hybrid.core.keygen.HybridKeyGenerator;
import com.pqc.hybrid.core.keygen.HybridKeyPair;

import java.nio.ByteBuffer;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

public class DualSignatureStrategy implements HybridSignatureStrategy {

    @Override
    public String getStrategyName() {
        return "DUAL_AND";
    }

    @Override
    public HybridKeyPair generateKeyPair(int securityLevel) {
        HybridAlgorithmPair pair = HybridAlgorithmPair.recommended(securityLevel);
        return HybridKeyGenerator.generate(pair);
    }

    @Override
    public HybridKeyPair generateKeyPair(HybridKeyPair keyPair) {
        return keyPair;
    }

    @Override
    public byte[] signData(byte[] data, HybridKeyPair keyPair) throws PQCHybridException {
        return signData(data, keyPair, new byte[0]);
    }

    @Override
    public byte[] signData(byte[] data, HybridKeyPair keyPair, byte[] ctx) throws PQCHybridException {
        HybridSignaturePair sig = HybridSignatureManager.sign(data, keyPair);
        byte[] classical = sig.getClassicalSignature();
        byte[] pqc = sig.getPQCSignature();

        // Length-prefixed encoding: [4-byte BE classical length][classical][pqc].
        // The classical (e.g. ECDSA) signature is variable-length, so a fixed split
        // (such as length/2) cannot recover the two components.
        byte[] result = new byte[Integer.BYTES + classical.length + pqc.length];
        ByteBuffer.wrap(result)
                .putInt(classical.length)
                .put(classical)
                .put(pqc);
        return result;
    }

    @Override
    public boolean verifySignature(byte[] data, byte[] signature, HybridKeyPair keyPair) throws InvalidSignatureException {
        return verifySignature(data, signature, keyPair, new byte[0]);
    }

    @Override
    public boolean verifySignature(byte[] data, byte[] signature, HybridKeyPair keyPair, byte[] ctx) throws InvalidSignatureException {
        if (signature == null || signature.length < Integer.BYTES) {
            throw new InvalidSignatureException("Invalid hybrid signature encoding: too short");
        }

        ByteBuffer buffer = ByteBuffer.wrap(signature);
        int classicalLen = buffer.getInt();
        if (classicalLen < 0 || classicalLen > signature.length - Integer.BYTES) {
            throw new InvalidSignatureException("Invalid hybrid signature encoding: bad classical length");
        }

        byte[] classicalSig = new byte[classicalLen];
        buffer.get(classicalSig);
        byte[] pqcSig = new byte[signature.length - Integer.BYTES - classicalLen];
        buffer.get(pqcSig);

        HybridSignaturePair sigPair = new HybridSignaturePair(
                classicalSig, pqcSig,
                keyPair.getClassicalAlgorithm(),
                keyPair.getPQCAlgorithm(),
                null);
        return HybridSignatureManager.verify(data, sigPair, keyPair);
    }

    @Override
    public X509Certificate buildCertificate(HybridCertificateConfig config, HybridKeyPair keyPair) throws CertificateException {
        return new HybridX509CertificateBuilder(config, keyPair).build();
    }

    @Override
    public Object validateCertificate(X509Certificate certificate, PublicKey issuerPublicKey, HybridKeyPair keyPair) {
        return HybridCertificateValidator.validateComprehensive(certificate, issuerPublicKey, keyPair);
    }
}
