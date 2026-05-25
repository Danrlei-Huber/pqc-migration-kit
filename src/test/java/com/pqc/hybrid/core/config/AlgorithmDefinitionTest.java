package com.pqc.hybrid.core.config;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("AlgorithmDefinition Tests")
class AlgorithmDefinitionTest {

    @Test
    @DisplayName("classical definition should mirror its enum and report classical")
    void test_classical_definition() {
        ClassicalAlgorithm enumValue = ClassicalAlgorithm.RSA_2048;
        ClassicalAlgorithmDefinition def = new ClassicalAlgorithmDefinition(enumValue);

        assertThat(def.getName()).isEqualTo(enumValue.getAlgorithmName());
        assertThat(def.getOid()).isEqualTo(enumValue.getOid());
        assertThat(def.getSecurityLevel()).isEqualTo(enumValue.getSecurityLevel());
        assertThat(def.getKeySize()).isEqualTo(enumValue.getKeySize());
        assertThat(def.getSignatureAlgorithm()).isEqualTo(enumValue.getSignatureAlgorithm());
        assertThat(def.getAlgorithm()).isEqualTo(enumValue);
        assertThat(def.isClassical()).isTrue();
        assertThat(def.isPQC()).isFalse();
        assertThat(def.toString()).contains(enumValue.getAlgorithmName());
    }

    @Test
    @DisplayName("PQC signature definition should mirror its enum and report PQC signature")
    void test_pqc_signature_definition() {
        PQCAlgorithm enumValue = PQCAlgorithm.ML_DSA_65;
        PQCAlgorithmDefinition def = new PQCAlgorithmDefinition(enumValue);

        assertThat(def.getName()).isEqualTo(enumValue.getName());
        assertThat(def.getOid()).isEqualTo(enumValue.getOid());
        assertThat(def.getPublicKeySize()).isEqualTo(enumValue.getPublicKeySize());
        assertThat(def.getCategory()).isEqualTo(enumValue.getCategory());
        assertThat(def.getAlgorithm()).isEqualTo(enumValue);
        assertThat(def.isPQC()).isTrue();
        assertThat(def.isClassical()).isFalse();
        assertThat(def.isSignatureAlgorithm()).isTrue();
        assertThat(def.isKeyEncapsulation()).isFalse();
        assertThat(def.toString()).contains(enumValue.getName());
    }
}
