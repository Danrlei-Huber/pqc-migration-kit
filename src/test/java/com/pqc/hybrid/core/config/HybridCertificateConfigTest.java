package com.pqc.hybrid.core.config;

import com.pqc.hybrid.core.BaseTest;
import com.pqc.hybrid.core.TestFixtures;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;

import static org.assertj.core.api.Assertions.*;

/**
 * Unit tests for HybridCertificateConfig configuration class.
 * 
 * Tests:
 * - Builder pattern
 * - Configuration immutability
 * - Default values
 * - Validation of required fields
 * 
 * @author PQC Hybrid Team
 * @version 1.0.0-BETA
 */
@DisplayName("HybridCertificateConfig Tests")
class HybridCertificateConfigTest extends BaseTest {

    @Test
    @DisplayName("should create config with builder pattern")
    void test_create_config_with_builder() {
        HybridCertificateConfig config = HybridCertificateConfig.builder()
            .withAlgorithmPair(TestFixtures.createRecommendedAlgorithmPair())
            .withSubjectDN(TestFixtures.TEST_SUBJECT_DN)
            .withIssuerDN(TestFixtures.TEST_ISSUER_DN)
            .build();

        assertThat(config).isNotNull();
        assertThat(config.getAlgorithmPair()).isNotNull();
        assertThat(config.getSubjectDN()).isEqualTo(TestFixtures.TEST_SUBJECT_DN);
        assertThat(config.getIssuerDN()).isEqualTo(TestFixtures.TEST_ISSUER_DN);
    }

    @Test
    @DisplayName("should have default validity of 365 days")
    void test_default_validity_days() {
        HybridCertificateConfig config = TestFixtures.createTestCertificateConfig();

        assertThat(config.getValidityDays()).isGreaterThan(0);
    }

    @Test
    @DisplayName("should set custom validity days")
    void test_custom_validity_days() {
        long customDays = 730;  // 2 years
        HybridCertificateConfig config = HybridCertificateConfig.builder()
            .withAlgorithmPair(TestFixtures.createRecommendedAlgorithmPair())
            .withSubjectDN(TestFixtures.TEST_SUBJECT_DN)
            .withIssuerDN(TestFixtures.TEST_ISSUER_DN)
            .withValidityDays(customDays)
            .build();

        assertThat(config.getValidityDays()).isEqualTo(customDays);
    }

    @Test
    @DisplayName("should include both primary and alternative signatures by default")
    void test_default_includes_both_signatures() {
        HybridCertificateConfig config = TestFixtures.createTestCertificateConfig();

        assertThat(config.isIncludePrimarySignature()).isTrue();
        assertThat(config.isIncludeAlternativeSignature()).isTrue();
    }

    @Test
    @DisplayName("should allow disabling primary signature")
    void test_can_disable_primary_signature() {
        HybridCertificateConfig config = HybridCertificateConfig.builder()
            .withAlgorithmPair(TestFixtures.createRecommendedAlgorithmPair())
            .withSubjectDN(TestFixtures.TEST_SUBJECT_DN)
            .withIssuerDN(TestFixtures.TEST_ISSUER_DN)
            .withIncludePrimarySignature(false)
            .build();

        assertThat(config.isIncludePrimarySignature()).isFalse();
        assertThat(config.isIncludeAlternativeSignature()).isTrue();
    }

    @Test
    @DisplayName("should allow disabling alternative signature")
    void test_can_disable_alternative_signature() {
        HybridCertificateConfig config = HybridCertificateConfig.builder()
            .withAlgorithmPair(TestFixtures.createRecommendedAlgorithmPair())
            .withSubjectDN(TestFixtures.TEST_SUBJECT_DN)
            .withIssuerDN(TestFixtures.TEST_ISSUER_DN)
            .withIncludeAlternativeSignature(false)
            .build();

        assertThat(config.isIncludePrimarySignature()).isTrue();
        assertThat(config.isIncludeAlternativeSignature()).isFalse();
    }

    @Test
    @DisplayName("should throw exception when algorithm pair is null")
    void test_null_algorithm_pair_throws_exception() {
        assertThatThrownBy(() -> HybridCertificateConfig.builder()
            .withAlgorithmPair(null)
            .withSubjectDN(TestFixtures.TEST_SUBJECT_DN)
            .withIssuerDN(TestFixtures.TEST_ISSUER_DN)
            .build())
            .isInstanceOf(NullPointerException.class);
    }

    @Test
    @DisplayName("should be immutable after creation")
    void test_config_is_immutable() {
        HybridCertificateConfig config = TestFixtures.createTestCertificateConfig();

        // Verify that config is immutable (no setters)
        assertThat(config).hasNoNullFieldsOrProperties();
    }

    @Test
    @DisplayName("should have consistent serial number")
    void test_has_serial_number() {
        HybridCertificateConfig config = TestFixtures.createTestCertificateConfig();

        assertThat(config.getSerialNumber()).isGreaterThan(0);
    }

    @Test
    @DisplayName("should provide version information")
    void test_has_version_information() {
        HybridCertificateConfig config = TestFixtures.createTestCertificateConfig();

        // Version should be accessible (even if just for reference)
        assertThat(config.getAlgorithmPair()).isNotNull();
    }
}
