package com.pqc.hybrid.core.model;

import com.pqc.hybrid.core.TestFixtures;
import com.pqc.hybrid.core.certificate.HybridX509CertificateBuilder;
import com.pqc.hybrid.core.keygen.HybridKeyGenerator;
import com.pqc.hybrid.core.keygen.HybridKeyPair;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.cert.X509Certificate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("HybridCertificateInfo Tests")
class HybridCertificateInfoTest {

    private static X509Certificate certificate;

    @BeforeAll
    static void buildCertificate() throws Exception {
        HybridKeyPair keyPair = HybridKeyGenerator.generate(TestFixtures.createRecommendedAlgorithmPair());
        certificate = new HybridX509CertificateBuilder(
                TestFixtures.createTestCertificateConfig(), keyPair).build();
    }

    private static HybridCertificateInfo fullInfo() {
        return HybridCertificateInfo.builder()
                .withCertificate(certificate)
                .withClassicalAlgorithm("RSA")
                .withPQCAlgorithm("ML-DSA-65")
                .withPQCAlgorithmOID("2.16.840.1.101.3.4.3.18")
                .withClassicalSignature(new byte[]{1, 2, 3})
                .withPQCSignature(new byte[]{4, 5, 6, 7})
                .withClassicalPublicKeyBytes(new byte[]{8, 9})
                .withPQCPublicKeyBytes(new byte[]{10, 11, 12})
                .build();
    }

    @Test
    @DisplayName("should expose all builder-provided fields")
    void test_getters() {
        HybridCertificateInfo info = fullInfo();
        assertThat(info.getClassicalAlgorithm()).isEqualTo("RSA");
        assertThat(info.getPQCAlgorithm()).isEqualTo("ML-DSA-65");
        assertThat(info.getPQCAlgorithmOID()).isEqualTo("2.16.840.1.101.3.4.3.18");
        assertThat(info.getClassicalSignatureSize()).isEqualTo(3);
        assertThat(info.getPQCSignatureSize()).isEqualTo(4);
        assertThat(info.getClassicalPublicKeySize()).isEqualTo(2);
        assertThat(info.getPQCPublicKeySize()).isEqualTo(3);
        assertThat(info.getCertificate()).isSameAs(certificate);
        assertThat(info.getSubjectDN()).contains("test.example.com");
        assertThat(info.getIssuerDN()).isNotBlank();
        assertThat(info.getGenerationTime()).isPositive();
        assertThat(info.getGenerationInstant().toEpochMilli()).isEqualTo(info.getGenerationTime());
    }

    @Test
    @DisplayName("hasPQCSignature / hasPQCExtensions should reflect presence")
    void test_presence_flags() {
        HybridCertificateInfo info = fullInfo();
        assertThat(info.hasPQCSignature()).isTrue();
        assertThat(info.hasPQCExtensions()).isFalse();
        assertThat(info.getPQCExtensions()).isNull();
    }

    @Test
    @DisplayName("byte-array getters should return defensive copies")
    void test_defensive_copies() {
        HybridCertificateInfo info = fullInfo();
        byte[] sig = info.getClassicalSignature();
        sig[0] = 99;
        assertThat(info.getClassicalSignature()).containsExactly(1, 2, 3);

        byte[] pqcSig = info.getPQCSignature();
        pqcSig[0] = 99;
        assertThat(info.getPQCSignature()).containsExactly(4, 5, 6, 7);
    }

    @Test
    @DisplayName("toString should include the algorithm summary")
    void test_to_string() {
        assertThat(fullInfo().toString())
                .contains("classicalAlgorithm=RSA")
                .contains("pqcAlgorithm=ML-DSA-65");
    }

    @Test
    @DisplayName("build should require a certificate")
    void test_build_requires_certificate() {
        assertThatThrownBy(() -> HybridCertificateInfo.builder().build())
                .isInstanceOf(NullPointerException.class);
    }
}
