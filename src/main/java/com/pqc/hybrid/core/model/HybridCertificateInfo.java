package com.pqc.hybrid.core.model;

import com.pqc.hybrid.core.certificate.asn1.PQCExtensionsStructure;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Objects;

public final class HybridCertificateInfo {

    private final X509Certificate certificate;
    private final String classicalAlgorithm;
    private final String pqcAlgorithm;
    private final String pqcOID;
    private final byte[] classicalSignature;
    private final byte[] pqcSignature;
    private final byte[] classicalPublicKeyBytes;
    private final byte[] pqcPublicKeyBytes;
    private final PQCExtensionsStructure pqcExtensions;
    private final long generationTime;

    private HybridCertificateInfo(Builder builder) {
        this.certificate = builder.certificate;
        this.classicalAlgorithm = builder.classicalAlgorithm;
        this.pqcAlgorithm = builder.pqcAlgorithm;
        this.pqcOID = builder.pqcOID;
        this.classicalSignature = builder.classicalSignature != null ? builder.classicalSignature.clone() : null;
        this.pqcSignature = builder.pqcSignature != null ? builder.pqcSignature.clone() : null;
        this.classicalPublicKeyBytes = builder.classicalPublicKeyBytes != null ? builder.classicalPublicKeyBytes.clone() : null;
        this.pqcPublicKeyBytes = builder.pqcPublicKeyBytes != null ? builder.pqcPublicKeyBytes.clone() : null;
        this.pqcExtensions = builder.pqcExtensions;
        this.generationTime = System.currentTimeMillis();
    }

    public X509Certificate getCertificate() {
        return certificate;
    }

    public String getClassicalAlgorithm() {
        return classicalAlgorithm;
    }

    public String getPQCAlgorithm() {
        return pqcAlgorithm;
    }

    public String getPQCAlgorithmOID() {
        return pqcOID;
    }

    public byte[] getClassicalSignature() {
        return classicalSignature != null ? classicalSignature.clone() : null;
    }

    public byte[] getPQCSignature() {
        return pqcSignature != null ? pqcSignature.clone() : null;
    }

    public byte[] getClassicalPublicKeyBytes() {
        return classicalPublicKeyBytes != null ? classicalPublicKeyBytes.clone() : null;
    }

    public byte[] getPQCPublicKeyBytes() {
        return pqcPublicKeyBytes != null ? pqcPublicKeyBytes.clone() : null;
    }

    public PQCExtensionsStructure getPQCExtensions() {
        return pqcExtensions;
    }

    public long getGenerationTime() {
        return generationTime;
    }

    public Instant getGenerationInstant() {
        return Instant.ofEpochMilli(generationTime);
    }

    public boolean hasPQCExtensions() {
        return pqcExtensions != null;
    }

    public boolean hasPQCSignature() {
        return pqcSignature != null && pqcSignature.length > 0;
    }

    public int getClassicalSignatureSize() {
        return classicalSignature != null ? classicalSignature.length : 0;
    }

    public int getPQCSignatureSize() {
        return pqcSignature != null ? pqcSignature.length : 0;
    }

    public int getClassicalPublicKeySize() {
        return classicalPublicKeyBytes != null ? classicalPublicKeyBytes.length : 0;
    }

    public int getPQCPublicKeySize() {
        return pqcPublicKeyBytes != null ? pqcPublicKeyBytes.length : 0;
    }

    public String getSubjectDN() {
        return certificate != null ? certificate.getSubjectX500Principal().getName() : null;
    }

    public String getIssuerDN() {
        return certificate != null ? certificate.getIssuerX500Principal().getName() : null;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private X509Certificate certificate;
        private String classicalAlgorithm;
        private String pqcAlgorithm;
        private String pqcOID;
        private byte[] classicalSignature;
        private byte[] pqcSignature;
        private byte[] classicalPublicKeyBytes;
        private byte[] pqcPublicKeyBytes;
        private PQCExtensionsStructure pqcExtensions;

        public Builder withCertificate(X509Certificate certificate) {
            this.certificate = certificate;
            return this;
        }

        public Builder withClassicalAlgorithm(String algorithm) {
            this.classicalAlgorithm = algorithm;
            return this;
        }

        public Builder withPQCAlgorithm(String algorithm) {
            this.pqcAlgorithm = algorithm;
            return this;
        }

        public Builder withPQCAlgorithmOID(String oid) {
            this.pqcOID = oid;
            return this;
        }

        public Builder withClassicalSignature(byte[] signature) {
            this.classicalSignature = signature.clone();
            return this;
        }

        public Builder withPQCSignature(byte[] signature) {
            this.pqcSignature = signature.clone();
            return this;
        }

        public Builder withClassicalPublicKeyBytes(byte[] publicKeyBytes) {
            this.classicalPublicKeyBytes = publicKeyBytes.clone();
            return this;
        }

        public Builder withPQCPublicKeyBytes(byte[] publicKeyBytes) {
            this.pqcPublicKeyBytes = publicKeyBytes.clone();
            return this;
        }

        public Builder withPQCExtensions(PQCExtensionsStructure extensions) {
            this.pqcExtensions = extensions;
            return this;
        }

        public HybridCertificateInfo build() {
            Objects.requireNonNull(certificate, "Certificate is required");
            return new HybridCertificateInfo(this);
        }
    }

    @Override
    public String toString() {
        return "HybridCertificateInfo{" +
                "classicalAlgorithm=" + classicalAlgorithm +
                ", pqcAlgorithm=" + pqcAlgorithm +
                ", pqcOID=" + pqcOID +
                ", hasPQCExtensions=" + hasPQCExtensions() +
                ", hasPQCSignature=" + hasPQCSignature() +
                ", subject=" + getSubjectDN() +
                '}';
    }
}