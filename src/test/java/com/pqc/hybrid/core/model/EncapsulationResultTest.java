package com.pqc.hybrid.core.model;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("EncapsulationResult Tests")
class EncapsulationResultTest {

    private static EncapsulationResult sample() {
        return new EncapsulationResult(new byte[]{1, 2, 3, 4}, new byte[]{9, 8, 7});
    }

    @Test
    @DisplayName("should expose ciphertext, shared secret and their sizes")
    void test_accessors() {
        EncapsulationResult result = sample();
        assertThat(result.ciphertext()).containsExactly(1, 2, 3, 4);
        assertThat(result.sharedSecret()).containsExactly(9, 8, 7);
        assertThat(result.ciphertextSize()).isEqualTo(4);
        assertThat(result.sharedSecretSize()).isEqualTo(3);
    }

    @Test
    @DisplayName("withZeroedSecret should keep ciphertext and zero the secret")
    void test_with_zeroed_secret() {
        EncapsulationResult zeroed = sample().withZeroedSecret();
        assertThat(zeroed.ciphertext()).containsExactly(1, 2, 3, 4);
        assertThat(zeroed.sharedSecret()).containsOnly(0);
        assertThat(zeroed.sharedSecretSize()).isEqualTo(3);
    }

    @Test
    @DisplayName("clearSharedSecret should zero the secret in place")
    void test_clear_shared_secret() {
        EncapsulationResult result = sample();
        result.clearSharedSecret();
        assertThat(result.sharedSecret()).containsOnly(0);
    }

    @Test
    @DisplayName("toString should report sizes without leaking values")
    void test_to_string() {
        assertThat(sample().toString())
                .contains("ciphertextSize=4")
                .contains("sharedSecretSize=3")
                .doesNotContain("[9, 8, 7]");
    }

    @Test
    @DisplayName("constructor should reject null or empty components")
    void test_constructor_validation() {
        assertThatThrownBy(() -> new EncapsulationResult(null, new byte[]{1}))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new EncapsulationResult(new byte[]{1}, null))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new EncapsulationResult(new byte[0], new byte[]{1}))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new EncapsulationResult(new byte[]{1}, new byte[0]))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
