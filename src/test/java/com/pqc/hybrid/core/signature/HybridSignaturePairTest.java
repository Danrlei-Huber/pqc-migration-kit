package com.pqc.hybrid.core.signature;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("HybridSignaturePair Tests")
class HybridSignaturePairTest {

    private static HybridSignaturePair sample() {
        return new HybridSignaturePair(
                new byte[]{1, 2, 3}, new byte[]{4, 5, 6, 7},
                "RSA", "ML-DSA-65", new byte[]{8, 9});
    }

    @Test
    @DisplayName("should expose signatures, sizes, label and algorithms")
    void test_accessors() {
        HybridSignaturePair pair = sample();
        assertThat(pair.getClassicalSignature()).containsExactly(1, 2, 3);
        assertThat(pair.getPQCSignature()).containsExactly(4, 5, 6, 7);
        assertThat(pair.getClassicalAlgorithm()).isEqualTo("RSA");
        assertThat(pair.getPQCAlgorithm()).isEqualTo("ML-DSA-65");
        assertThat(pair.getMessageHash()).containsExactly(8, 9);
        assertThat(pair.getClassicalSignatureSize()).isEqualTo(3);
        assertThat(pair.getPQCSignatureSize()).isEqualTo(4);
        assertThat(pair.getTotalSize()).isEqualTo(7);
        assertThat(pair.getLabel()).isEqualTo("RSA + ML-DSA-65");
        assertThat(pair.getSignatureTime()).isPositive();
    }

    @Test
    @DisplayName("getters should return defensive copies")
    void test_defensive_copies() {
        HybridSignaturePair pair = sample();
        pair.getClassicalSignature()[0] = 99;
        pair.getPQCSignature()[0] = 99;
        pair.getMessageHash()[0] = 99;
        assertThat(pair.getClassicalSignature()).containsExactly(1, 2, 3);
        assertThat(pair.getPQCSignature()).containsExactly(4, 5, 6, 7);
        assertThat(pair.getMessageHash()).containsExactly(8, 9);
    }

    @Test
    @DisplayName("should tolerate a null message hash")
    void test_null_message_hash() {
        HybridSignaturePair pair = new HybridSignaturePair(
                new byte[]{1}, new byte[]{2}, "RSA", "ML-DSA-65", null);
        assertThat(pair.getMessageHash()).isNull();
    }

    @Test
    @DisplayName("wipeSignatures should not throw")
    void test_wipe() {
        HybridSignaturePair pair = sample();
        pair.wipeSignatures();
        // internal arrays are wiped; public getters still return (now zeroed) copies
        assertThat(pair.getClassicalSignature()).containsOnly(0);
    }

    @Test
    @DisplayName("toString should mention both algorithms and sizes")
    void test_to_string() {
        assertThat(sample().toString()).contains("RSA").contains("ML-DSA-65").contains("bytes");
    }

    @Test
    @DisplayName("constructor should reject null required components")
    void test_constructor_null_checks() {
        assertThatThrownBy(() -> new HybridSignaturePair(null, new byte[]{1}, "RSA", "ML-DSA", null))
                .isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> new HybridSignaturePair(new byte[]{1}, null, "RSA", "ML-DSA", null))
                .isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> new HybridSignaturePair(new byte[]{1}, new byte[]{1}, null, "ML-DSA", null))
                .isInstanceOf(NullPointerException.class);
    }
}
