package com.pqc.hybrid.core.certificate;

import com.pqc.hybrid.core.common.oid.AlgorithmOIDRegistry;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("X509ExtensionManager Tests")
class X509ExtensionManagerTest {

    private static final AlgorithmIdentifier PQC_ALG =
            new AlgorithmIdentifier(new ASN1ObjectIdentifier(AlgorithmOIDRegistry.OID_ML_DSA_65));

    @Test
    @DisplayName("static OID getters should mirror the registry")
    void test_static_oids() {
        assertThat(X509ExtensionManager.getAltSignatureAlgorithmOID())
                .isEqualTo(AlgorithmOIDRegistry.OID_ALT_SIGNATURE_ALGORITHM);
        assertThat(X509ExtensionManager.getAltSignatureValueOID())
                .isEqualTo(AlgorithmOIDRegistry.OID_ALT_SIGNATURE_VALUE);
        assertThat(X509ExtensionManager.getSubjectAltPubKeyInfoOID())
                .isEqualTo(AlgorithmOIDRegistry.OID_SUBJECT_ALT_PUBLIC_KEY_INFO);
    }

    @Test
    @DisplayName("individual extensions can be added, queried, removed and cleared")
    void test_individual_extension_management() {
        X509ExtensionManager mgr = new X509ExtensionManager();
        assertThat(mgr.getExtensionCount()).isZero();

        mgr.addAltSignatureValueExtension(new byte[]{1, 2, 3}, false);
        mgr.addSubjectAltPublicKeyInfoExtension(new byte[]{4, 5}, false);
        mgr.addAltSignatureAlgorithmExtension(AlgorithmOIDRegistry.OID_ML_DSA_65, false);

        assertThat(mgr.getExtensionCount()).isEqualTo(3);
        assertThat(mgr.hasExtension(X509ExtensionManager.getAltSignatureValueOID())).isTrue();
        assertThat(mgr.getExtension(X509ExtensionManager.getAltSignatureValueOID())).isNotNull();
        assertThat(mgr.getAllExtensions()).hasSize(3);

        mgr.removeExtension(X509ExtensionManager.getAltSignatureValueOID());
        assertThat(mgr.hasExtension(X509ExtensionManager.getAltSignatureValueOID())).isFalse();
        assertThat(mgr.getExtensionCount()).isEqualTo(2);

        mgr.clearAllExtensions();
        assertThat(mgr.getExtensionCount()).isZero();
    }

    @Test
    @DisplayName("addPQCExtensions should populate the three Catalyst extensions")
    void test_add_pqc_extensions() {
        X509ExtensionManager mgr = new X509ExtensionManager();
        byte[] signature = new byte[]{10, 11, 12, 13};
        byte[] publicKey = new byte[]{20, 21, 22};

        mgr.addPQCExtensions(PQC_ALG, signature, publicKey, false);

        assertThat(mgr.getExtensionCount()).isEqualTo(3);
        assertThat(mgr.hasExtension(X509ExtensionManager.getAltSignatureAlgorithmOID())).isTrue();
        assertThat(mgr.hasExtension(X509ExtensionManager.getAltSignatureValueOID())).isTrue();
        assertThat(mgr.hasExtension(X509ExtensionManager.getSubjectAltPubKeyInfoOID())).isTrue();
    }

    @Test
    @DisplayName("buildPQCExtensionsStructure should return null when extensions are incomplete")
    void test_incomplete_structure_is_null() throws Exception {
        X509ExtensionManager mgr = new X509ExtensionManager();
        mgr.addAltSignatureValueExtension(new byte[]{1}, false);
        assertThat(mgr.buildPQCExtensionsStructure()).isNull();
    }

    @Test
    @DisplayName("add methods should reject null arguments")
    void test_null_checks() {
        X509ExtensionManager mgr = new X509ExtensionManager();
        assertThatThrownBy(() -> mgr.addAltSignatureAlgorithmExtension(null, false))
                .isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> mgr.addAltSignatureValueExtension(null, false))
                .isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> mgr.addSubjectAltPublicKeyInfoExtension(null, false))
                .isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> mgr.addPQCExtensions(null, new byte[1], new byte[1], false))
                .isInstanceOf(NullPointerException.class);
    }
}
