package com.pqc.hybrid.core.certificate.asn1;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;

import java.io.IOException;

public class PQCExtensionsStructure extends ASN1Object {

    public static final String OID_ALT_SIGNATURE_ALGORITHM = "2.5.29.62";
    public static final String OID_ALT_SIGNATURE_VALUE = "2.5.29.63";
    public static final String OID_SUBJECT_ALT_PUBLIC_KEY_INFO = "2.5.29.72";

    private final AlgorithmIdentifier altSignatureAlgorithm;
    private final byte[] altSignatureValue;
    private final SubjectPublicKeyInfo subjectAltPublicKeyInfo;

    public PQCExtensionsStructure(AlgorithmIdentifier altSignatureAlgorithm,
                                  byte[] altSignatureValue,
                                  SubjectPublicKeyInfo subjectAltPublicKeyInfo) {
        this.altSignatureAlgorithm = altSignatureAlgorithm;
        this.altSignatureValue = altSignatureValue.clone();
        this.subjectAltPublicKeyInfo = subjectAltPublicKeyInfo;
    }

    public static PQCExtensionsStructure getInstance(Object obj) {
        if (obj instanceof PQCExtensionsStructure) {
            return (PQCExtensionsStructure) obj;
        }
        if (obj != null) {
            return new PQCExtensionsStructure(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    private PQCExtensionsStructure(ASN1Sequence sequence) {
        if (sequence.size() != 3) {
            throw new IllegalArgumentException("Sequence size must be exactly 3");
        }

        this.altSignatureAlgorithm = AlgorithmIdentifier.getInstance(sequence.getObjectAt(0));
        this.altSignatureValue = DERBitString.getInstance(sequence.getObjectAt(1)).getOctets();
        this.subjectAltPublicKeyInfo = SubjectPublicKeyInfo.getInstance(sequence.getObjectAt(2));
    }

    public AlgorithmIdentifier getAltSignatureAlgorithm() {
        return altSignatureAlgorithm;
    }

    public byte[] getAltSignatureValue() {
        return altSignatureValue.clone();
    }

    public SubjectPublicKeyInfo getSubjectAltPublicKeyInfo() {
        return subjectAltPublicKeyInfo;
    }

    public String getAltSignatureAlgorithmOID() {
        return altSignatureAlgorithm.getAlgorithm().getId();
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(3);
        v.add(altSignatureAlgorithm);
        v.add(new DERBitString(altSignatureValue));
        v.add(subjectAltPublicKeyInfo);
        return new DERSequence(v);
    }

    public byte[] getEncoded() throws IOException {
        return toASN1Primitive().getEncoded(ASN1Encoding.DER);
    }

    public byte[] getEncodedDER() throws IOException {
        return toASN1Primitive().getEncoded(ASN1Encoding.DER);
    }

    public static PQCExtensionsStructure parse(byte[] encoded) throws IOException {
        return getInstance(ASN1Primitive.fromByteArray(encoded));
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private AlgorithmIdentifier altSignatureAlgorithm;
        private byte[] altSignatureValue;
        private SubjectPublicKeyInfo subjectAltPublicKeyInfo;

        public Builder withAltSignatureAlgorithm(AlgorithmIdentifier algorithm) {
            this.altSignatureAlgorithm = algorithm;
            return this;
        }

        public Builder withAltSignatureAlgorithmOID(String oid) {
            this.altSignatureAlgorithm = new AlgorithmIdentifier(new ASN1ObjectIdentifier(oid));
            return this;
        }

        public Builder withAltSignatureValue(byte[] signature) {
            this.altSignatureValue = signature.clone();
            return this;
        }

        public Builder withSubjectAltPublicKeyInfo(SubjectPublicKeyInfo spki) {
            this.subjectAltPublicKeyInfo = spki;
            return this;
        }

        public Builder withPQCPublicKeyBytes(byte[] publicKeyBytes, String algorithmOID) {
            SubjectPublicKeyInfo spki = new SubjectPublicKeyInfo(
                    new AlgorithmIdentifier(new ASN1ObjectIdentifier(algorithmOID)),
                    publicKeyBytes
            );
            this.subjectAltPublicKeyInfo = spki;
            return this;
        }

        public PQCExtensionsStructure build() {
            if (altSignatureAlgorithm == null) {
                throw new IllegalStateException("altSignatureAlgorithm is required");
            }
            if (altSignatureValue == null) {
                throw new IllegalStateException("altSignatureValue is required");
            }
            if (subjectAltPublicKeyInfo == null) {
                throw new IllegalStateException("subjectAltPublicKeyInfo is required");
            }
            return new PQCExtensionsStructure(altSignatureAlgorithm, altSignatureValue, subjectAltPublicKeyInfo);
        }
    }

    @Override
    public String toString() {
        return "PQCExtensionsStructure{" +
                "altSignatureAlgorithm=" + altSignatureAlgorithm.getAlgorithm().getId() +
                ", altSignatureValue=" + altSignatureValue.length + " bytes" +
                ", subjectAltPublicKeyInfo=" + subjectAltPublicKeyInfo.getAlgorithm().getAlgorithm().getId() +
                '}';
    }
}