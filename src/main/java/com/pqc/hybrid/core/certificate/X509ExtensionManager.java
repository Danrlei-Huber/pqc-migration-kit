package com.pqc.hybrid.core.certificate;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;

import com.pqc.hybrid.core.certificate.asn1.PQCExtensionsStructure;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

public final class X509ExtensionManager {

    private static final String ALT_SIGNATURE_ALGORITHM_OID = "2.5.29.62";
    private static final String ALT_SIGNATURE_VALUE_OID = "2.5.29.63";
    private static final String SUBJECT_ALT_PUBKEY_INFO_OID = "2.5.29.72";

    private final Map<String, Extension> extensions = new HashMap<>();

    /**
     * Gets the Alternative Signature Algorithm extension OID.
     */
    public static String getAltSignatureAlgorithmOID() {
        return ALT_SIGNATURE_ALGORITHM_OID;
    }

    /**
     * Gets the Alternative Signature Value extension OID.
     */
    public static String getAltSignatureValueOID() {
        return ALT_SIGNATURE_VALUE_OID;
    }

    /**
     * Gets the Subject Alternative Public Key Info extension OID.
     */
    public static String getSubjectAltPubKeyInfoOID() {
        return SUBJECT_ALT_PUBKEY_INFO_OID;
    }

    /**
     * Adds the alternative signature algorithm extension.
     *
     * @param algorithmOID the OID of the alternative signature algorithm
     * @param critical whether the extension is critical
     */
    public void addAltSignatureAlgorithmExtension(String algorithmOID, boolean critical) {
        Objects.requireNonNull(algorithmOID, "Algorithm OID cannot be null");
        try {
            AlgorithmIdentifier algId = new AlgorithmIdentifier(new ASN1ObjectIdentifier(algorithmOID));
            Extension ext = new Extension(
                    new ASN1ObjectIdentifier(ALT_SIGNATURE_ALGORITHM_OID),
                    critical,
                    algId.getEncoded()
            );
            extensions.put(ALT_SIGNATURE_ALGORITHM_OID, ext);
        } catch (IOException e) {
            throw new RuntimeException("Failed to create alternative signature algorithm extension", e);
        }
    }

    public void addPQCExtensions(AlgorithmIdentifier pqcAlgorithm, byte[] pqcSignature, 
                                  byte[] pqcPublicKeyBytes, boolean critical) {
        Objects.requireNonNull(pqcAlgorithm, "PQC AlgorithmIdentifier cannot be null");
        Objects.requireNonNull(pqcSignature, "PQC signature bytes cannot be null");
        Objects.requireNonNull(pqcPublicKeyBytes, "PQC public key bytes cannot be null");

        try {
            byte[] algEncoded = pqcAlgorithm.getEncoded();
            Extension altSigAlgExt = new Extension(
                    new ASN1ObjectIdentifier(ALT_SIGNATURE_ALGORITHM_OID),
                    critical,
                    algEncoded
            );
            extensions.put(ALT_SIGNATURE_ALGORITHM_OID, altSigAlgExt);

            byte[] signatureEncoded = new org.bouncycastle.asn1.DERBitString(pqcSignature).getEncoded();
            Extension altSigValExt = new Extension(
                    new ASN1ObjectIdentifier(ALT_SIGNATURE_VALUE_OID),
                    critical,
                    signatureEncoded
            );
            extensions.put(ALT_SIGNATURE_VALUE_OID, altSigValExt);

            SubjectPublicKeyInfo spki = new SubjectPublicKeyInfo(pqcAlgorithm, pqcPublicKeyBytes);
            byte[] spkiEncoded = spki.getEncoded();
            Extension altPubKeyExt = new Extension(
                    new ASN1ObjectIdentifier(SUBJECT_ALT_PUBKEY_INFO_OID),
                    critical,
                    new DEROctetString(spkiEncoded)
            );
            extensions.put(SUBJECT_ALT_PUBKEY_INFO_OID, altPubKeyExt);

        } catch (IOException e) {
            throw new RuntimeException("Failed to create PQC extensions", e);
        }
    }

    public PQCExtensionsStructure buildPQCExtensionsStructure() throws IOException {
        Extension altSigAlg = extensions.get(ALT_SIGNATURE_ALGORITHM_OID);
        Extension altSigVal = extensions.get(ALT_SIGNATURE_VALUE_OID);
        Extension altPubKey = extensions.get(SUBJECT_ALT_PUBKEY_INFO_OID);

        if (altSigAlg == null || altSigVal == null || altPubKey == null) {
            return null;
        }

        AlgorithmIdentifier algId = AlgorithmIdentifier.getInstance(
                ASN1Sequence.getInstance(altSigAlg.getParsedValue())
        );
        byte[] sigBytes = ((org.bouncycastle.asn1.DERBitString) altSigVal.getParsedValue()).getOctets();
        SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(
                ASN1OctetString.getInstance(altPubKey.getParsedValue()).getOctets()
        );

        return new PQCExtensionsStructure(algId, sigBytes, spki);
    }

    /**
     * Adds the alternative signature value extension.
     *
     * @param signatureBytes the PQC signature bytes
     * @param critical whether the extension is critical
     */
    public void addAltSignatureValueExtension(byte[] signatureBytes, boolean critical) {
        Objects.requireNonNull(signatureBytes, "Signature bytes cannot be null");
        Extension ext = new Extension(
                new ASN1ObjectIdentifier(ALT_SIGNATURE_VALUE_OID),
                critical,
                new DEROctetString(signatureBytes)
        );
        extensions.put(ALT_SIGNATURE_VALUE_OID, ext);
    }

    /**
     * Adds the subject alternative public key info extension.
     *
     * @param publicKeyBytes the PQC public key bytes
     * @param critical whether the extension is critical
     */
    public void addSubjectAltPublicKeyInfoExtension(byte[] publicKeyBytes, boolean critical) {
        Objects.requireNonNull(publicKeyBytes, "Public key bytes cannot be null");
        Extension ext = new Extension(
                new ASN1ObjectIdentifier(SUBJECT_ALT_PUBKEY_INFO_OID),
                critical,
                new DEROctetString(publicKeyBytes)
        );
        extensions.put(SUBJECT_ALT_PUBKEY_INFO_OID, ext);
    }

    /**
     * Gets an extension by OID.
     */
    public Extension getExtension(String oid) {
        return extensions.get(oid);
    }

    /**
     * Gets all managed extensions.
     */
    public Map<String, Extension> getAllExtensions() {
        return new HashMap<>(extensions);
    }

    /**
     * Checks if a specific extension is present.
     */
    public boolean hasExtension(String oid) {
        return extensions.containsKey(oid);
    }

    /**
     * Removes an extension.
     */
    public void removeExtension(String oid) {
        extensions.remove(oid);
    }

    /**
     * Clears all extensions.
     */
    public void clearAllExtensions() {
        extensions.clear();
    }

    /**
     * Gets the number of managed extensions.
     */
    public int getExtensionCount() {
        return extensions.size();
    }
}
