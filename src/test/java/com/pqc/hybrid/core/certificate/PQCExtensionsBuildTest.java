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
import java.security.cert.X509Certificate;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("PQC Certificate Extensions Build Tests")
class PQCExtensionsBuildTest extends BaseTest {

    private static final String PQC_ALGORITHM = "ML-DSA-65";
    private static final String CLASSICAL_ALGORITHM = "ECDSA";

    @BeforeAll
    static void setUpAll() {
        CryptographicProviderFactory.initialize();
    }

    private KeyPair generateMLDSAKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(PQC_ALGORITHM, "BC");
        return kpg.generateKeyPair();
    }

    private KeyPair generateECKeyPair(String curve) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", "BC");
        java.security.spec.ECGenParameterSpec ecSpec = 
            new java.security.spec.ECGenParameterSpec(curve);
        kpg.initialize(ecSpec);
        return kpg.generateKeyPair();
    }

    @Test
    @DisplayName("Should build certificate with PQC extensions")
    void shouldBuildCertificateWithPQCExtensions() throws Exception {
        KeyPair pqcKp = generateMLDSAKeyPair();
        KeyPair ecKp = generateECKeyPair("secp384r1");

        HybridKeyPair keyPair = new HybridKeyPair(
                ecKp.getPublic(), ecKp.getPrivate(),
                pqcKp.getPublic(), pqcKp.getPrivate(),
                CLASSICAL_ALGORITHM, PQC_ALGORITHM
        );

        HybridCertificateConfig config = HybridCertificateConfig.builder()
                .withSubjectDN("CN=test.example.com,O=Test,C=US")
                .withIssuerDN("CN=Test CA,O=Test,C=US")
                .withValidityDays(365)
                .withSerialNumber(java.math.BigInteger.ONE)
                .withAlgorithmPair(HybridAlgorithmPair.recommended(192))
                .build();

        X509Certificate certificate = HybridX509CertificateBuilder.builder(config, keyPair)
                .withPQCExtensions(true)
                .build();

        assertThat(certificate).isNotNull();
        
        boolean valid = HybridCertificateValidator.validatePQCExtensions(certificate);
        assertThat(valid).isTrue();
    }

    @Test
    @DisplayName("Should validate PQC extensions structure")
    void shouldValidatePQCExtensionsStructure() throws Exception {
        KeyPair pqcKp = generateMLDSAKeyPair();
        KeyPair ecKp = generateECKeyPair("secp384r1");

        HybridKeyPair keyPair = new HybridKeyPair(
                ecKp.getPublic(), ecKp.getPrivate(),
                pqcKp.getPublic(), pqcKp.getPrivate(),
                CLASSICAL_ALGORITHM, PQC_ALGORITHM
        );

        HybridCertificateConfig config = HybridCertificateConfig.builder()
                .withSubjectDN("CN=test.example.com")
                .withIssuerDN("CN=Test CA")
                .withValidityDays(365)
                .withSerialNumber(java.math.BigInteger.TWO)
                .withAlgorithmPair(HybridAlgorithmPair.recommended(192))
                .build();

        X509Certificate certificate = HybridX509CertificateBuilder.builder(config, keyPair)
                .withPQCExtensions(true)
                .build();

        boolean valid = HybridCertificateValidator.validatePQCExtensions(certificate);
        assertThat(valid).isTrue();
        
        byte[] algExt = certificate.getExtensionValue("2.5.29.73");
        byte[] sigExt = certificate.getExtensionValue("2.5.29.74");
        byte[] keyExt = certificate.getExtensionValue("2.5.29.72");

        assertThat(algExt).isNotNull();
        assertThat(sigExt).isNotNull();
        assertThat(keyExt).isNotNull();

        // The legacy (non-standard) OIDs must no longer be present.
        assertThat(certificate.getExtensionValue("2.5.29.62")).isNull();
        assertThat(certificate.getExtensionValue("2.5.29.63")).isNull();
    }

    @Test
    @DisplayName("Should extract PQC algorithm OID")
    void shouldExtractPQCAlgorithmOID() throws Exception {
        KeyPair pqcKp = generateMLDSAKeyPair();
        KeyPair ecKp = generateECKeyPair("secp256r1");

        HybridKeyPair keyPair = new HybridKeyPair(
                ecKp.getPublic(), ecKp.getPrivate(),
                pqcKp.getPublic(), pqcKp.getPrivate(),
                CLASSICAL_ALGORITHM, PQC_ALGORITHM
        );

        HybridCertificateConfig config = HybridCertificateConfig.builder()
                .withSubjectDN("CN=test.example.com")
                .withIssuerDN("CN=Test CA")
                .withValidityDays(365)
                .withSerialNumber(java.math.BigInteger.valueOf(3))
                .withAlgorithmPair(HybridAlgorithmPair.recommended(128))
                .build();

        X509Certificate certificate = HybridX509CertificateBuilder.builder(config, keyPair)
                .withPQCExtensions(true)
                .build();

        String pqcOID = HybridCertificateValidator.extractPQCAlgorithmOID(certificate);
        assertThat(pqcOID).isNotNull();
        assertThat(pqcOID).isEqualTo("2.16.840.1.101.3.4.3.18");
    }

    @Test
    @DisplayName("Should build without PQC extensions when disabled")
    void shouldBuildWithoutPQCExtensionsWhenDisabled() throws Exception {
        KeyPair pqcKp = generateMLDSAKeyPair();
        KeyPair ecKp = generateECKeyPair("secp384r1");

        HybridKeyPair keyPair = new HybridKeyPair(
                ecKp.getPublic(), ecKp.getPrivate(),
                pqcKp.getPublic(), pqcKp.getPrivate(),
                CLASSICAL_ALGORITHM, PQC_ALGORITHM
        );

        HybridCertificateConfig config = HybridCertificateConfig.builder()
                .withSubjectDN("CN=test.example.com")
                .withIssuerDN("CN=Test CA")
                .withValidityDays(365)
                .withSerialNumber(java.math.BigInteger.valueOf(4))
                .withAlgorithmPair(HybridAlgorithmPair.recommended(192))
                .build();

        X509Certificate certificate = HybridX509CertificateBuilder.builder(config, keyPair)
                .withPQCExtensions(false)
                .build();

        assertThat(certificate).isNotNull();
        
        boolean hasPQCExts = HybridCertificateValidator.validatePQCExtensions(certificate);
        assertThat(hasPQCExts).isFalse();
    }

    @Test
    @DisplayName("Should perform comprehensive validation")
    void shouldPerformComprehensiveValidation() throws Exception {
        KeyPair pqcKp = generateMLDSAKeyPair();
        KeyPair ecKp = generateECKeyPair("secp256r1");

        HybridKeyPair keyPair = new HybridKeyPair(
                ecKp.getPublic(), ecKp.getPrivate(),
                pqcKp.getPublic(), pqcKp.getPrivate(),
                CLASSICAL_ALGORITHM, PQC_ALGORITHM
        );

        HybridCertificateConfig config = HybridCertificateConfig.builder()
                .withSubjectDN("CN=test.example.com")
                .withIssuerDN("CN=Test CA")
                .withValidityDays(365)
                .withSerialNumber(java.math.BigInteger.valueOf(5))
                .withAlgorithmPair(HybridAlgorithmPair.recommended(128))
                .build();

        X509Certificate certificate = HybridX509CertificateBuilder.builder(config, keyPair)
                .withPQCExtensions(true)
                .build();

        HybridCertificateValidator.ValidationResult result =
                HybridCertificateValidator.validateComprehensive(certificate, null, keyPair);

        assertThat(result.isPqcExtensionsValid()).isTrue();
        assertThat(result.isPublicKeyValid()).isTrue();
        assertThat(result.isDnsValid()).isTrue();
        // The PQC alternative signature must verify over the reconstructed pre-TBS.
        assertThat(result.isPqcSignatureValid()).isTrue();
    }

    @Test
    @DisplayName("Should reject null certificate")
    void shouldRejectNullCertificate() {
        assertThat(HybridCertificateValidator.validatePQCExtensions(null)).isFalse();
    }

    @Test
    @DisplayName("Should reject malformed PQC extension (decode error)")
    void shouldRejectMalformedPQCExtension() throws Exception {
        // Gera certificado válido
        KeyPair pqcKp = generateMLDSAKeyPair();
        KeyPair ecKp = generateECKeyPair("secp256r1");
        HybridKeyPair keyPair = new HybridKeyPair(
                ecKp.getPublic(), ecKp.getPrivate(),
                pqcKp.getPublic(), pqcKp.getPrivate(),
                CLASSICAL_ALGORITHM, PQC_ALGORITHM
        );
        HybridCertificateConfig config = HybridCertificateConfig.builder()
                .withSubjectDN("CN=fuzzed.example.com")
                .withIssuerDN("CN=fuzzed-CA")
                .withValidityDays(365)
                .withSerialNumber(java.math.BigInteger.valueOf(66))
                .withAlgorithmPair(HybridAlgorithmPair.recommended(128)).build();
        X509Certificate certificate = HybridX509CertificateBuilder.builder(config, keyPair)
                .withPQCExtensions(true)
                .build();

        // Corrompe a extensão: pega o valor da OID altSignatureValue e altera um byte
        byte[] sigExt = certificate.getExtensionValue("2.5.29.74");
        assertThat(sigExt).isNotNull();
        // Simula corrupção (exclui primeiro byte do valor DER, tornando ASN.1 inválido)
        byte[] malformed = new byte[sigExt.length - 1];
        System.arraycopy(sigExt, 1, malformed, 0, malformed.length);

        // Tenta decodificar como PQCExtensionsStructure (deve lançar exceção)
        org.assertj.core.api.Assertions.assertThatThrownBy(() ->
                com.pqc.hybrid.core.certificate.asn1.PQCExtensionsStructure.parse(malformed)
        ).isInstanceOf(Exception.class);
    }

    @Test
    @DisplayName("Should reject PQC alternative signature verified with the wrong key")
    void shouldRejectPQCSignatureWithWrongKey() throws Exception {
        KeyPair pqcKp = generateMLDSAKeyPair();
        KeyPair ecKp = generateECKeyPair("secp256r1");

        HybridKeyPair keyPair = new HybridKeyPair(
                ecKp.getPublic(), ecKp.getPrivate(),
                pqcKp.getPublic(), pqcKp.getPrivate(),
                CLASSICAL_ALGORITHM, PQC_ALGORITHM
        );

        HybridCertificateConfig config = HybridCertificateConfig.builder()
                .withSubjectDN("CN=wrongkey.example.com")
                .withIssuerDN("CN=wrongkey.example.com")
                .withValidityDays(365)
                .withSerialNumber(java.math.BigInteger.valueOf(77))
                .withAlgorithmPair(HybridAlgorithmPair.recommended(128))
                .build();

        X509Certificate certificate = HybridX509CertificateBuilder.builder(config, keyPair)
                .withPQCExtensions(true)
                .build();

        // A different alternative (PQC) key of the same algorithm must NOT verify the
        // alternative signature — proving it is cryptographically checked, not just present.
        KeyPair otherPqc = generateMLDSAKeyPair();
        HybridKeyPair wrongKeyPair = new HybridKeyPair(
                ecKp.getPublic(), ecKp.getPrivate(),
                otherPqc.getPublic(), otherPqc.getPrivate(),
                CLASSICAL_ALGORITHM, PQC_ALGORITHM
        );

        boolean valid = HybridCertificateValidator.validatePQCSignature(certificate, wrongKeyPair);
        assertThat(valid).isFalse();
    }

    @Test
    @DisplayName("Should verify certificate self-signature")
    void shouldVerifyCertificateSelfSignature() throws Exception {
        KeyPair pqcKp = generateMLDSAKeyPair();
        KeyPair ecKp = generateECKeyPair("secp256r1");

        HybridKeyPair keyPair = new HybridKeyPair(
                ecKp.getPublic(), ecKp.getPrivate(),
                pqcKp.getPublic(), pqcKp.getPrivate(),
                CLASSICAL_ALGORITHM, PQC_ALGORITHM
        );

        HybridCertificateConfig config = HybridCertificateConfig.builder()
                .withSubjectDN("CN=self.signed.example.com")
                .withIssuerDN("CN=self.signed.example.com")
                .withValidityDays(365)
                .withSerialNumber(java.math.BigInteger.valueOf(6))
                .withAlgorithmPair(HybridAlgorithmPair.recommended(128))
                .build();

        X509Certificate certificate = HybridX509CertificateBuilder.builder(config, keyPair)
                .withPQCExtensions(true)
                .build();

        boolean sigValid = HybridCertificateValidator.validateSignature(
                certificate, certificate.getPublicKey());
        assertThat(sigValid).isTrue();
    }
}
