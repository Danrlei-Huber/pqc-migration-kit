package com.pqc.hybrid.core.certificate;

import com.pqc.hybrid.core.BaseTest;
import com.pqc.hybrid.core.config.CryptographicProviderFactory;
import com.pqc.hybrid.core.config.HybridAlgorithmPair;
import com.pqc.hybrid.core.config.HybridCertificateConfig;
import com.pqc.hybrid.core.keygen.HybridKeyPair;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Collection;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("Hybrid CA / chain / SAN Tests")
class HybridCertificateAuthorityTest extends BaseTest {

    @BeforeAll
    static void setUpAll() {
        CryptographicProviderFactory.initialize();
    }

    private HybridKeyPair newKeyPair() throws Exception {
        KeyPairGenerator pqcGen = KeyPairGenerator.getInstance("ML-DSA-65", "BC");
        KeyPairGenerator ecGen = KeyPairGenerator.getInstance("EC", "BC");
        ecGen.initialize(new ECGenParameterSpec("secp384r1"));
        KeyPair pqcKp = pqcGen.generateKeyPair();
        KeyPair ecKp = ecGen.generateKeyPair();
        return new HybridKeyPair(
                ecKp.getPublic(), ecKp.getPrivate(),
                pqcKp.getPublic(), pqcKp.getPrivate(),
                "ECDSA", "ML-DSA-65");
    }

    private HybridCertificateConfig caConfig(String dn) {
        return HybridCertificateConfig.builder()
                .withAlgorithmPair(HybridAlgorithmPair.recommended(192))
                .withSubjectDN(dn)
                .asCertificateAuthority(true)
                .withValidityDays(3650)
                .build();
    }

    private HybridCertificateConfig leafConfig(String dn, List<String> sans) {
        return HybridCertificateConfig.builder()
                .withAlgorithmPair(HybridAlgorithmPair.recommended(192))
                .withSubjectDN(dn)
                .withSubjectAltNames(sans)
                .withValidityDays(365)
                .build();
    }

    @Test
    @DisplayName("should build a 3-level hierarchy and validate the full hybrid chain")
    void shouldBuildAndValidateChain() throws Exception {
        HybridKeyPair rootKp = newKeyPair();
        HybridKeyPair interKp = newKeyPair();
        HybridKeyPair leafKp = newKeyPair();

        HybridCertificateAuthority root =
                HybridCertificateAuthority.createRoot(caConfig("CN=Root CA,O=TCC,C=BR"), rootKp);
        X509Certificate interCert =
                root.issueCertificate(caConfig("CN=Intermediate CA,O=TCC,C=BR"), interKp);
        HybridCertificateAuthority inter = new HybridCertificateAuthority(interKp, interCert);
        X509Certificate leaf =
                inter.issueCertificate(leafConfig("CN=leaf.example.com,O=TCC,C=BR",
                        List.of("leaf.example.com", "10.0.0.1")), leafKp);

        // Basic constraints: CAs are CA, leaf is not.
        assertThat(root.getCertificate().getBasicConstraints()).isGreaterThanOrEqualTo(0);
        assertThat(interCert.getBasicConstraints()).isGreaterThanOrEqualTo(0);
        assertThat(leaf.getBasicConstraints()).isEqualTo(-1);

        // Root has keyCertSign (KeyUsage bit 5).
        assertThat(root.getCertificate().getKeyUsage()[5]).isTrue();

        // Issuer chaining + AKI present on issued certs.
        assertThat(interCert.getIssuerX500Principal()).isEqualTo(root.getCertificate().getSubjectX500Principal());
        assertThat(leaf.getIssuerX500Principal()).isEqualTo(interCert.getSubjectX500Principal());
        assertThat(leaf.getExtensionValue("2.5.29.35")).isNotNull(); // authorityKeyIdentifier

        // Full hybrid chain validates in both dimensions.
        HybridCertificateValidator.HybridChainValidationResult result =
                HybridCertificateValidator.validateHybridChain(List.of(leaf, interCert, root.getCertificate()));
        assertThat(result.classicalValid()).isTrue();
        assertThat(result.pqcValid()).isTrue();
        assertThat(result.isValid()).isTrue();
    }

    @Test
    @DisplayName("should expose SAN with DNS and IP entries on the leaf")
    void shouldExposeSanDnsAndIp() throws Exception {
        HybridKeyPair rootKp = newKeyPair();
        HybridKeyPair leafKp = newKeyPair();

        HybridCertificateAuthority root =
                HybridCertificateAuthority.createRoot(caConfig("CN=Root CA"), rootKp);
        X509Certificate leaf = root.issueCertificate(
                leafConfig("CN=svc.example.com", List.of("svc.example.com", "192.168.0.10")), leafKp);

        Collection<List<?>> sans = leaf.getSubjectAlternativeNames();
        assertThat(sans).isNotNull();
        boolean hasDns = sans.stream().anyMatch(e -> (Integer) e.get(0) == 2 && "svc.example.com".equals(e.get(1)));
        boolean hasIp = sans.stream().anyMatch(e -> (Integer) e.get(0) == 7 && "192.168.0.10".equals(e.get(1)));
        assertThat(hasDns).isTrue();
        assertThat(hasIp).isTrue();
    }

    @Test
    @DisplayName("should verify alt signature against the correct issuer and reject the wrong one")
    void shouldVerifyAltSignatureAgainstIssuer() throws Exception {
        HybridKeyPair rootKp = newKeyPair();
        HybridKeyPair leafKp = newKeyPair();

        HybridCertificateAuthority root =
                HybridCertificateAuthority.createRoot(caConfig("CN=Root CA"), rootKp);
        X509Certificate leaf = root.issueCertificate(
                leafConfig("CN=leaf.example.com", List.of("leaf.example.com")), leafKp);

        PublicKey rootAltKey = HybridCertificateValidator.extractAltPublicKey(root.getCertificate());
        PublicKey leafAltKey = HybridCertificateValidator.extractAltPublicKey(leaf);
        assertThat(rootAltKey).isNotNull();
        assertThat(leafAltKey).isNotNull();

        // Leaf's alt signature was made by the root's PQC key -> verifies with root, not with leaf's own.
        assertThat(HybridCertificateValidator.verifyAltSignature(leaf, rootAltKey)).isTrue();
        assertThat(HybridCertificateValidator.verifyAltSignature(leaf, leafAltKey)).isFalse();
    }

    @Test
    @DisplayName("should reject a chain whose leaf was issued by a different CA")
    void shouldRejectChainFromDifferentCA() throws Exception {
        HybridKeyPair rootKp = newKeyPair();
        HybridKeyPair otherRootKp = newKeyPair();
        HybridKeyPair leafKp = newKeyPair();

        HybridCertificateAuthority root =
                HybridCertificateAuthority.createRoot(caConfig("CN=Root CA"), rootKp);
        HybridCertificateAuthority otherRoot =
                HybridCertificateAuthority.createRoot(caConfig("CN=Other Root CA"), otherRootKp);

        // Leaf actually issued by 'otherRoot', but presented under 'root' -> chain must fail.
        X509Certificate rogueLeaf = otherRoot.issueCertificate(
                leafConfig("CN=rogue.example.com", List.of("rogue.example.com")), leafKp);

        HybridCertificateValidator.HybridChainValidationResult result =
                HybridCertificateValidator.validateHybridChain(List.of(rogueLeaf, root.getCertificate()));
        assertThat(result.isValid()).isFalse();
    }
}
