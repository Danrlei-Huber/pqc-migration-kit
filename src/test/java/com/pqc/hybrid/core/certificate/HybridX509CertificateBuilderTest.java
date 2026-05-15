package com.pqc.hybrid.core.certificate;

import com.pqc.hybrid.core.config.ClassicalAlgorithm;
import com.pqc.hybrid.core.config.HybridAlgorithmPair;
import com.pqc.hybrid.core.config.HybridCertificateConfig;
import com.pqc.hybrid.core.config.PQCAlgorithm;
import com.pqc.hybrid.core.keygen.HybridKeyGenerator;
import com.pqc.hybrid.core.keygen.HybridKeyPair;
import com.pqc.hybrid.core.BaseTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;

import java.security.cert.X509Certificate;

import static org.assertj.core.api.Assertions.*;

@DisplayName("HybridX509CertificateBuilder Tests")
class HybridX509CertificateBuilderTest extends BaseTest {

    @Test
    @DisplayName("should build certificate with PQC extensions enabled")
    void test_build_with_pqc_extensions() {
        // Arrange
        HybridKeyPair keyPair = HybridKeyGenerator.generate(
                new com.pqc.hybrid.core.config.HybridAlgorithmPair(
                        ClassicalAlgorithm.RSA_2048, PQCAlgorithm.ML_DSA_65));
        HybridCertificateConfig config = HybridCertificateConfig.builder()
                .withSubjectDN("CN=Test Certificate")
                .withIssuerDN("CN=Test Certificate")
                .withValidityDays(365)
                .withSerialNumber(1)
                .withAlgorithmPair(new HybridAlgorithmPair(ClassicalAlgorithm.RSA_2048, PQCAlgorithm.ML_DSA_65))
                .build();

        // Act
        X509Certificate certificate = HybridX509CertificateBuilder.builder(config, keyPair)
                .build();

        // Assert
        assertThat(certificate).isNotNull();
        assertThat(certificate.getSubjectX500Principal().getName()).contains("CN=Test Certificate");
    }

    @Test
    @DisplayName("should build certificate with PQC extensions disabled")
    void test_build_without_pqc_extensions() {
        // Arrange
        HybridKeyPair keyPair = HybridKeyGenerator.generate(
                new com.pqc.hybrid.core.config.HybridAlgorithmPair(
                        ClassicalAlgorithm.ECDSA_P256, PQCAlgorithm.FALCON_512));
        HybridCertificateConfig config = HybridCertificateConfig.builder()
                .withSubjectDN("CN=Test Certificate No PQC")
                .withIssuerDN("CN=Test Certificate No PQC")
                .withValidityDays(365)
                .withSerialNumber(1)
                .withAlgorithmPair(new HybridAlgorithmPair(ClassicalAlgorithm.ECDSA_P256, PQCAlgorithm.FALCON_512))
                .build();

        // Act
        X509Certificate certificate = HybridX509CertificateBuilder.builder(config, keyPair)
                .withPQCExtensions(false)
                .build();

        // Assert
        assertThat(certificate).isNotNull();
        assertThat(certificate.getSubjectX500Principal().getName()).contains("CN=Test Certificate No PQC");
    }

    @Test
    @DisplayName("should throw exception when building with null key pair")
    void test_build_with_null_key_pair_throws_exception() {
        // Arrange
        HybridCertificateConfig config = HybridCertificateConfig.builder()
                .withSubjectDN("CN=Test Certificate")
                .withIssuerDN("CN=Test Certificate")
                .withValidityDays(365)
                .withSerialNumber(1)
                .withAlgorithmPair(new HybridAlgorithmPair(ClassicalAlgorithm.RSA_2048, PQCAlgorithm.ML_DSA_65))
                .build();

        // Act & Assert
        assertThatThrownBy(() -> HybridX509CertificateBuilder.builder(config, null))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("Key pair cannot be null");
    }

    @Test
    @DisplayName("should throw exception when creating config with null subject DN")
    void test_create_config_with_null_subject_throws_exception() {
        // Act & Assert
        assertThatThrownBy(() -> HybridCertificateConfig.builder()
                .withSubjectDN(null)
                .withIssuerDN("CN=Test Certificate")
                .withValidityDays(365)
                .withSerialNumber(1)
                .withAlgorithmPair(new HybridAlgorithmPair(ClassicalAlgorithm.RSA_2048, PQCAlgorithm.ML_DSA_65))
                .build())
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("Subject DN cannot be null");
    }
}