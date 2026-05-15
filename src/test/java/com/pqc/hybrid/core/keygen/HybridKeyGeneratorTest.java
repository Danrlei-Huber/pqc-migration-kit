package com.pqc.hybrid.core.keygen;

import com.pqc.hybrid.core.config.ClassicalAlgorithm;
import com.pqc.hybrid.core.config.PQCAlgorithm;
import com.pqc.hybrid.core.keygen.HybridKeyPair;
import com.pqc.hybrid.core.BaseTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;

import java.security.KeyPair;

import static org.assertj.core.api.Assertions.*;

@DisplayName("HybridKeyGenerator Tests")
class HybridKeyGeneratorTest {

    @Test
    @DisplayName("should generate valid RSA-2048 classical key pair")
    void test_generate_classical_key_pair_rsa_2048() {
        KeyPair keyPair = HybridKeyGenerator.generateClassicalKeyPair(ClassicalAlgorithm.RSA_2048);

        assertThat(keyPair).isNotNull();
        assertThat(keyPair.getPrivate()).isNotNull();
        assertThat(keyPair.getPublic()).isNotNull();
        assertThat(keyPair.getPrivate().getAlgorithm()).isEqualTo("RSA");
        assertThat(keyPair.getPublic().getAlgorithm()).isEqualTo("RSA");
    }

    @Test
    @DisplayName("should generate valid ECDSA-P256 classical key pair")
    void test_generate_classical_key_pair_ecdsa_p256() {
        KeyPair keyPair = HybridKeyGenerator.generateClassicalKeyPair(ClassicalAlgorithm.ECDSA_P256);

        assertThat(keyPair).isNotNull();
        assertThat(keyPair.getPrivate()).isNotNull();
        assertThat(keyPair.getPublic()).isNotNull();
        assertThat(keyPair.getPrivate().getAlgorithm()).isEqualTo("ECDSA");
        assertThat(keyPair.getPublic().getAlgorithm()).isEqualTo("ECDSA");
    }

    @Test
    @DisplayName("should generate valid ML-DSA-65 PQC key pair")
    void test_generate_pqc_key_pair_ml_dsa_65() {
        KeyPair keyPair = HybridKeyGenerator.generatePQCKeyPair(PQCAlgorithm.ML_DSA_65);

        assertThat(keyPair).isNotNull();
        assertThat(keyPair.getPrivate()).isNotNull();
        assertThat(keyPair.getPublic()).isNotNull();
        assertThat(keyPair.getPrivate().getAlgorithm()).startsWith("ML-DSA");
        assertThat(keyPair.getPublic().getAlgorithm()).startsWith("ML-DSA");
    }

    @Test
    @DisplayName("should generate valid FALCON-1024 PQC key pair")
    void test_generate_pqc_key_pair_falcon_1024() {
        KeyPair keyPair = HybridKeyGenerator.generatePQCKeyPair(PQCAlgorithm.FALCON_1024);

        assertThat(keyPair).isNotNull();
        assertThat(keyPair.getPrivate()).isNotNull();
        assertThat(keyPair.getPublic()).isNotNull();
        assertThat(keyPair.getPrivate().getAlgorithm()).startsWith("FALCON");
        assertThat(keyPair.getPublic().getAlgorithm()).startsWith("FALCON");
    }

    @Test
    @DisplayName("should generate hybrid key pair")
    void test_generate_hybrid_key_pair() {
        HybridKeyPair hybridKeyPair = HybridKeyGenerator.generate(
                new com.pqc.hybrid.core.config.HybridAlgorithmPair(
                        ClassicalAlgorithm.RSA_2048, PQCAlgorithm.ML_DSA_65));

        assertThat(hybridKeyPair).isNotNull();
        assertThat(hybridKeyPair.getClassicalPrivateKey()).isNotNull();
        assertThat(hybridKeyPair.getClassicalPublicKey()).isNotNull();
        assertThat(hybridKeyPair.getPQCPrivateKey()).isNotNull();
        assertThat(hybridKeyPair.getPQCPublicKey()).isNotNull();
    }

    @Test
    @DisplayName("should throw exception when generating key pair with null algorithm")
    void test_generate_classical_key_pair_null_algorithm() {
        assertThatThrownBy(() -> HybridKeyGenerator.generateClassicalKeyPair(null))
                .isInstanceOf(NullPointerException.class);
    }

    @Test
    @DisplayName("should throw exception when generating PQC key pair with null algorithm")
    void test_generate_pqc_key_pair_null_algorithm() {
        assertThatThrownBy(() -> HybridKeyGenerator.generatePQCKeyPair(null))
                .isInstanceOf(NullPointerException.class);
    }
}