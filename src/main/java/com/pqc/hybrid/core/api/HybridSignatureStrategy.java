package com.pqc.hybrid.core.api;

import com.pqc.hybrid.core.config.HybridCertificateConfig;
import com.pqc.hybrid.core.exception.CertificateException;
import com.pqc.hybrid.core.exception.InvalidSignatureException;
import com.pqc.hybrid.core.exception.PQCHybridException;
import com.pqc.hybrid.core.keygen.HybridKeyPair;

import java.security.PublicKey;
import java.security.cert.X509Certificate;

public interface HybridSignatureStrategy {

    String getStrategyName();

    HybridKeyPair generateKeyPair(int securityLevel);

    HybridKeyPair generateKeyPair(HybridKeyPair keyPair);

    byte[] signData(byte[] data, HybridKeyPair keyPair) throws PQCHybridException;

    byte[] signData(byte[] data, HybridKeyPair keyPair, byte[] ctx) throws PQCHybridException;

    boolean verifySignature(byte[] data, byte[] signature, HybridKeyPair keyPair) throws InvalidSignatureException;

    boolean verifySignature(byte[] data, byte[] signature, HybridKeyPair keyPair, byte[] ctx) throws InvalidSignatureException;

    X509Certificate buildCertificate(HybridCertificateConfig config, HybridKeyPair keyPair) throws CertificateException;

    Object validateCertificate(X509Certificate certificate, PublicKey issuerPublicKey, HybridKeyPair keyPair);
}
