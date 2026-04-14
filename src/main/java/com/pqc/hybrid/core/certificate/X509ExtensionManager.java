package com.pqc.hybrid.core.certificate;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.Extension;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Manager for custom X.509 extensions used in hybrid PQC certificates.
 * 
 * Manages creation and serialization of hybrid certificate extensions:
 * - Alternative Signature Algorithm (OID 2.5.29.62)
 * - Alternative Signature Value (OID 2.5.29.63)
 * - Subject Alternative Public Key Info (OID 2.5.29.72)
 *
 * @author PQC Hybrid Team
 * @version 1.0.0-BETA
 */
public final class X509ExtensionManager {

    // OIDs for hybrid certificate extensions
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
            // Create extension with OID value
            Extension ext = new Extension(
                    new ASN1ObjectIdentifier(ALT_SIGNATURE_ALGORITHM_OID),
                    critical,
                    new DEROctetString(new ASN1ObjectIdentifier(algorithmOID).getEncoded())
            );
            extensions.put(ALT_SIGNATURE_ALGORITHM_OID, ext);
        } catch (IOException e) {
            throw new RuntimeException("Failed to create alternative signature algorithm extension", e);
        }
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
