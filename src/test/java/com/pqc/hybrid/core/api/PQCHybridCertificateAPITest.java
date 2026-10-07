package com.pqc.hybrid.core.api;

import com.pqc.hybrid.core.TestFixtures;
import com.pqc.hybrid.core.certificate.HybridCertificateAuthority;
import com.pqc.hybrid.core.certificate.HybridCertificateValidator;
import com.pqc.hybrid.core.config.HybridAlgorithmPair;
import com.pqc.hybrid.core.config.HybridCertificateConfig;
import com.pqc.hybrid.core.keygen.HybridKeyPair;
import com.pqc.hybrid.core.signature.DualSignatureStrategy;
import com.pqc.hybrid.core.signature.HybridSignatureManager;
import com.pqc.hybrid.core.signature.HybridSignaturePair;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.cert.X509Certificate;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("PQCHybridCertificateAPI Tests")
class PQCHybridCertificateAPITest {

    private static PQCHybridCertificateAPI api;
    private static HybridKeyPair keyPair;

    @BeforeAll
    static void setUpAll() throws Exception {
        api = new PQCHybridCertificateAPI();
        api.initialize();
        keyPair = api.generateHybridKeyPair(128);
    }

    // ---- lifecycle / metadata -------------------------------------------------

    @Test
    @DisplayName("initialize should be idempotent and flip isInitialized")
    void test_initialize() throws Exception {
        PQCHybridCertificateAPI fresh = new PQCHybridCertificateAPI();
        assertThat(fresh.isInitialized()).isFalse();
        fresh.initialize();
        fresh.initialize(); // idempotent
        assertThat(fresh.isInitialized()).isTrue();
        assertThat(fresh.getVersion()).isEqualTo("1.0.0-BETA");
    }

    @Test
    @DisplayName("operations before initialize should fail fast")
    void test_requires_initialization() {
        PQCHybridCertificateAPI fresh = new PQCHybridCertificateAPI();
        assertThatThrownBy(() -> fresh.generateHybridKeyPair(128))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    @DisplayName("static metadata helpers should be populated")
    void test_static_metadata() {
        assertThat(PQCHybridCertificateAPI.getLibraryInfo()).contains("1.0.0-BETA");
        assertThat(api.toString()).contains("initialized=true");
    }

    @Test
    @DisplayName("signature strategy should be configurable")
    void test_strategy_accessors() {
        PQCHybridCertificateAPI local = new PQCHybridCertificateAPI();
        assertThat(local.getSignatureStrategy()).isInstanceOf(DualSignatureStrategy.class);

        DualSignatureStrategy other = new DualSignatureStrategy();
        local.setSignatureStrategy(other);
        assertThat(local.getSignatureStrategy()).isSameAs(other);

        assertThat(new PQCHybridCertificateAPI(other).getSignatureStrategy()).isSameAs(other);
        assertThatThrownBy(() -> new PQCHybridCertificateAPI(null))
                .isInstanceOf(NullPointerException.class);
    }

    // ---- key generation -------------------------------------------------------

    @Test
    @DisplayName("key generation overloads should all produce complete pairs")
    void test_key_generation() throws Exception {
        assertThat(api.generateHybridKeyPair(128)).isNotNull();
        assertThat(api.generateHybridKeyPair(
                HybridAlgorithmPair.recommended(128))).isNotNull();
        assertThat(api.generateHybridKeyPairWithStrategy(128)).isNotNull();
        assertThatThrownBy(() -> api.generateHybridKeyPair((HybridAlgorithmPair) null))
                .isInstanceOf(NullPointerException.class);
    }

    // ---- signing / verification ----------------------------------------------

    @Test
    @DisplayName("sign / verify should round-trip with and without context")
    void test_sign_verify() throws Exception {
        byte[] data = "api payload".getBytes();

        byte[] sig = api.signData(data, keyPair);
        assertThat(api.verifySignature(data, sig, keyPair)).isTrue();
        assertThat(api.verifySignature("tampered".getBytes(), sig, keyPair)).isFalse();

        byte[] ctxSig = api.signData(data, keyPair, new byte[0]);
        assertThat(api.verifySignature(data, ctxSig, keyPair, new byte[0])).isTrue();
    }

    @Test
    @DisplayName("sign should reject null arguments")
    void test_sign_null_checks() {
        assertThatThrownBy(() -> api.signData(null, keyPair)).isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> api.signData("x".getBytes(), null)).isInstanceOf(NullPointerException.class);
    }

    @Test
    @DisplayName("deprecated verify and structural validation should work on a HybridSignaturePair")
    void test_legacy_verify_and_structure() throws Exception {
        byte[] data = "legacy payload".getBytes();
        HybridSignaturePair pair = HybridSignatureManager.sign(data, keyPair);

        assertThat(api.verifySignature(data, pair, keyPair)).isTrue();
        assertThat(api.validateSignatureStructure(pair)).isNotNull();
    }

    // ---- certificates ---------------------------------------------------------

    @Test
    @DisplayName("certificate generation, inspection and validation should round-trip")
    void test_certificate_lifecycle() throws Exception {
        HybridCertificateConfig config = TestFixtures.createTestCertificateConfig();

        X509Certificate cert = api.generateHybridCertificate(config, keyPair);
        assertThat(cert).isNotNull();
        assertThat(cert.getSubjectX500Principal().getName()).contains("test.example.com");

        X509Certificate certWithExt = api.generateHybridCertificateWithPQCExtensions(config, keyPair, true);
        assertThat(certWithExt).isNotNull();

        assertThat(api.getCertificateInfo(cert, keyPair)).isNotNull();
        assertThat(api.validatePQCExtensions(cert)).isTrue();
        assertThat(api.validatePQCSignature(cert, keyPair)).isTrue();

        HybridCertificateValidator.ValidationResult result = api.validateCertificate(cert, null);
        assertThat(result).isNotNull();
    }

    @Test
    @DisplayName("complete end-to-end workflow should produce a certificate")
    void test_complete_workflow() throws Exception {
        X509Certificate cert = api.generateCompleteHybridCertificate(
                128, "CN=complete.example.com", "CN=complete.example.com", 365);
        assertThat(cert).isNotNull();
        assertThat(cert.getSubjectX500Principal().getName()).contains("complete.example.com");
    }

    @Test
    @DisplayName("CSR generation should produce a PKCS#10 request")
    void test_csr() throws Exception {
        assertThat(api.generateCertificateSigningRequest("CN=csr.example.com", keyPair)).isNotNull();
    }

    // ---- CA / chain -----------------------------------------------------------

    @Test
    @DisplayName("root CA issuance and chain validation should succeed in both dimensions")
    void test_ca_and_chain() throws Exception {
        HybridKeyPair caKeyPair = api.generateHybridKeyPair(192);
        HybridKeyPair leafKeyPair = api.generateHybridKeyPair(192);

        HybridCertificateConfig caConfig = HybridCertificateConfig.builder()
                .withAlgorithmPair(HybridAlgorithmPair.recommended(192))
                .withSubjectDN("CN=API Root CA,O=TCC,C=BR")
                .asCertificateAuthority(true)
                .withValidityDays(3650)
                .build();
        HybridCertificateConfig leafConfig = HybridCertificateConfig.builder()
                .withAlgorithmPair(HybridAlgorithmPair.recommended(192))
                .withSubjectDN("CN=api-leaf.example.com,O=TCC,C=BR")
                .withValidityDays(365)
                .build();

        HybridCertificateAuthority ca = api.createRootCA(caConfig, caKeyPair);
        assertThat(ca).isNotNull();

        X509Certificate leaf = api.issueCertificate(ca, leafConfig, leafKeyPair);
        assertThat(leaf.getIssuerX500Principal()).isEqualTo(ca.getCertificate().getSubjectX500Principal());

        HybridCertificateValidator.HybridChainValidationResult chain =
                api.validateCertificateChain(List.of(leaf, ca.getCertificate()));
        assertThat(chain.isValid()).isTrue();
    }
}
