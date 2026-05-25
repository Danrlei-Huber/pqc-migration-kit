package com.pqc.hybrid.core.config;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("PreHashFunction Tests")
class PreHashFunctionTest {

    @BeforeAll
    static void initProvider() {
        CryptographicProviderFactory.initialize();
    }

    @Test
    @DisplayName("should expose algorithm name and output length")
    void test_metadata() {
        assertThat(PreHashFunction.SHA256.getAlgorithmName()).isEqualTo("SHA-256");
        assertThat(PreHashFunction.SHA256.getOutputLength()).isEqualTo(32);
        assertThat(PreHashFunction.SHA512.getAlgorithmName()).isEqualTo("SHA-512");
        assertThat(PreHashFunction.SHA512.getOutputLength()).isEqualTo(64);
        assertThat(PreHashFunction.SHAKE256.getAlgorithmName()).isEqualTo("SHAKE256");
    }

    @Test
    @DisplayName("should hash to the SHA-2 digest length")
    void test_hash_sha2_lengths() {
        byte[] data = "message".getBytes();
        assertThat(PreHashFunction.SHA256.hash(data)).hasSize(32);
        assertThat(PreHashFunction.SHA512.hash(data)).hasSize(64);
    }

    @Test
    @DisplayName("should hash deterministically")
    void test_hash_is_deterministic() {
        byte[] data = "deterministic".getBytes();
        assertThat(PreHashFunction.SHA256.hash(data))
                .isEqualTo(PreHashFunction.SHA256.hash(data));
    }

    @Test
    @DisplayName("should produce a non-empty SHAKE256 digest")
    void test_hash_shake256() {
        assertThat(PreHashFunction.SHAKE256.hash("x".getBytes())).isNotEmpty();
    }

    @Test
    @DisplayName("fromName should match case-insensitively and default to SHA256")
    void test_from_name() {
        assertThat(PreHashFunction.fromName("sha-512")).isEqualTo(PreHashFunction.SHA512);
        assertThat(PreHashFunction.fromName("SHA-256")).isEqualTo(PreHashFunction.SHA256);
        assertThat(PreHashFunction.fromName("unknown")).isEqualTo(PreHashFunction.SHA256);
    }
}
