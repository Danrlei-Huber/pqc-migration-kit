package com.pqc.hybrid.core.config;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("CompositeAlgorithm Tests")
class CompositeAlgorithmTest {

    @ParameterizedTest
    @EnumSource(CompositeAlgorithm.class)
    @DisplayName("every entry should expose consistent, non-empty metadata")
    void test_metadata_is_consistent(CompositeAlgorithm algo) {
        assertThat(algo.getLabel()).isNotBlank();
        assertThat(algo.getOid()).isNotBlank();
        assertThat(algo.getPQCAlgorithm()).isNotNull();
        assertThat(algo.getTradAlgorithmName()).isNotBlank();
        assertThat(algo.getTradKeyAlgorithm()).isNotBlank();
        assertThat(algo.getTradSignatureAlgorithm()).isNotBlank();
        assertThat(algo.getPreHashAlgorithm()).isNotBlank();
        assertThat(algo.getSecurityLevel()).isIn(128, 192, 256);
        assertThat(algo.getMldsaSeedSize()).isPositive();
        assertThat(algo.getMldsaPublicKeySize()).isPositive();
        assertThat(algo.getMldsaSignatureSize()).isPositive();
        assertThat(algo.getCompositePublicKeySize()).isGreaterThan(algo.getMldsaPublicKeySize());
        assertThat(algo.getCompositeSignatureSize()).isGreaterThan(algo.getMldsaSignatureSize());
    }

    @ParameterizedTest
    @EnumSource(CompositeAlgorithm.class)
    @DisplayName("fromOid / fromLabel should round-trip every entry")
    void test_lookup_round_trips(CompositeAlgorithm algo) {
        assertThat(CompositeAlgorithm.fromOid(algo.getOid())).isEqualTo(algo);
        assertThat(CompositeAlgorithm.fromLabel(algo.getLabel())).isEqualTo(algo);
    }

    @Test
    @DisplayName("fromOid / fromLabel should return null for unknown values")
    void test_lookup_unknown_returns_null() {
        assertThat(CompositeAlgorithm.fromOid("0.0.0.0")).isNull();
        assertThat(CompositeAlgorithm.fromLabel("does-not-exist")).isNull();
    }

    @Test
    @DisplayName("recommended should map each security level")
    void test_recommended() {
        assertThat(CompositeAlgorithm.recommended(128)).isEqualTo(CompositeAlgorithm.MLDSA44_ECDSA_P256_SHA256);
        assertThat(CompositeAlgorithm.recommended(192)).isEqualTo(CompositeAlgorithm.MLDSA65_ECDSA_P256_SHA512);
        assertThat(CompositeAlgorithm.recommended(256)).isEqualTo(CompositeAlgorithm.MLDSA87_ECDSA_P521_SHA512);
    }

    @Test
    @DisplayName("recommended should reject unsupported security levels")
    void test_recommended_invalid() {
        assertThatThrownBy(() -> CompositeAlgorithm.recommended(64))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("isECDSABased should reflect the traditional algorithm")
    void test_is_ecdsa_based() {
        assertThat(CompositeAlgorithm.MLDSA44_ECDSA_P256_SHA256.isECDSABased()).isTrue();
        assertThat(CompositeAlgorithm.MLDSA44_RSA2048_PSS_SHA256.isECDSABased()).isFalse();
        assertThat(CompositeAlgorithm.MLDSA44_ED25519_SHA512.isECDSABased()).isFalse();
    }
}
