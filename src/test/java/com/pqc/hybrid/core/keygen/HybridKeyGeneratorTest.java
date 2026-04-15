package com.pqc.hybrid.core.keygen;

import com.pqc.hybrid.core.BaseTest;
import com.pqc.hybrid.core.config.ClassicalAlgorithm;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Disabled;

import java.security.KeyPair;

import static org.assertj.core.api.Assertions.*;

/**
 * Integration tests for HybridKeyGenerator.
 * 
 * Note: Tests requiring PQC algorithms are disabled in this environment.
 * Full PQC testing requires BouncyCast castle with PQC extensions enabled.
 * 
 * @author PQC Hybrid Team
 * @version 1.0.0-BETA
 */
@DisplayName("HybridKeyGenerator Tests")
class HybridKeyGeneratorTest extends BaseTest {

    @Test
    @DisplayName("should generate valid RSA-2048 classical key pair")
    void test_generate_classical_key_pair_rsa_2048() {
        KeyPair keyPair = HybridKeyGenerator.generateClassicalKeyPair(
            ClassicalAlgorithm.RSA_2048);

        assertThat(keyPair).isNotNull();
        assertThat(keyPair.getPublic()).isNotNull();
        assertThat(keyPair.getPrivate()).isNotNull();
        assertThat(keyPair.getPublic().getAlgorithm()).contains("RSA");
    }

    @Test
    @DisplayName("should generate valid RSA-3072 classical key pair")
    void test_generate_classical_key_pair_rsa_3072() {
        KeyPair keyPair = HybridKeyGenerator.generateClassicalKeyPair(
            ClassicalAlgorithm.RSA_3072);

        assertThat(keyPair).isNotNull();
        assertThat(keyPair.getPublic()).isNotNull();
        assertThat(keyPair.getPrivate()).isNotNull();
    }

    @Test
    @DisplayName("should generate valid RSA-4096 classical key pair")
    void test_generate_classical_key_pair_rsa_4096() {
        KeyPair keyPair = HybridKeyGenerator.generateClassicalKeyPair(
            ClassicalAlgorithm.RSA_4096);

        assertThat(keyPair).isNotNull();
    }

    @Test
    @DisplayName("should generate valid ECDSA-P256 classical key pair")
    void test_generate_classical_key_pair_ecdsa_p256() {
        KeyPair keyPair = HybridKeyGenerator.generateClassicalKeyPair(
            ClassicalAlgorithm.ECDSA_P256);

        assertThat(keyPair).isNotNull();
        assertThat(keyPair.getPublic()).isNotNull();
        assertThat(keyPair.getPrivate()).isNotNull();
        assertThat(keyPair.getPublic().getAlgorithm()).contains("EC");
    }

    @Test
    @DisplayName("should generate valid ECDSA-P384 classical key pair")
    void test_generate_classical_key_pair_ecdsa_p384() {
        KeyPair keyPair = HybridKeyGenerator.generateClassicalKeyPair(
            ClassicalAlgorithm.ECDSA_P384);

        assertThat(keyPair).isNotNull();
    }

    @Test
    @DisplayName("should generate valid ECDSA-P521 classical key pair")
    void test_generate_classical_key_pair_ecdsa_p521() {
        KeyPair keyPair = HybridKeyGenerator.generateClassicalKeyPair(
            ClassicalAlgorithm.ECDSA_P521);

        assertThat(keyPair).isNotNull();
    }

    @Test
    @DisplayName("should throw exception when algorithm pair is null")
    void test_null_algorithm_pair_throws_exception() {
        assertThatThrownBy(() -> HybridKeyGenerator.generate(null))
            .isInstanceOf(NullPointerException.class);
    }

    @Test
    @Disabled("PQC algorithms not available in test environment")
    @DisplayName("RFC 8610: Hybrid key pair generation (NIST L1)")
    void test_hybrid_key_pair_nist_level1() {
        // Requires BouncyCastle PQC support (ML-DSA, etc.)
    }

    @Test
    @Disabled("PQC algorithms not available in test environment")
    @DisplayName("RFC 8610: Hybrid key pair generation (NIST L3)")
    void test_hybrid_key_pair_nist_level3() {
        // Requires BouncyCastle PQC support
    }

    @Test
    @Disabled("PQC algorithms not available in test environment")
    @DisplayName("RFC 8610: Hybrid key pair generation (NIST L5)")
    void test_hybrid_key_pair_nist_level5() {
        // Requires BouncyCastle PQC support
    }
}
