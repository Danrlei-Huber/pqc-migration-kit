package com.pqc.hybrid.core.keygen;

import com.pqc.hybrid.core.config.ClassicalAlgorithm;
import com.pqc.hybrid.core.config.HybridAlgorithmPair;
import com.pqc.hybrid.core.config.PQCAlgorithm;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.catchThrowable;

@DisplayName("HybridKeyPair Tests")
class HybridKeyPairTest {

    private static HybridKeyPair newPair() {
        return HybridKeyGenerator.generate(
                new HybridAlgorithmPair(ClassicalAlgorithm.RSA_2048, PQCAlgorithm.ML_DSA_65));
    }

    @Test
    @DisplayName("should expose both key pairs, algorithm names and a label")
    void test_accessors() {
        HybridKeyPair pair = newPair();
        assertThat(pair.getClassicalPublicKey()).isNotNull();
        assertThat(pair.getClassicalPrivateKey()).isNotNull();
        assertThat(pair.getPQCPublicKey()).isNotNull();
        assertThat(pair.getPQCPrivateKey()).isNotNull();
        assertThat(pair.getClassicalAlgorithm()).isEqualTo("RSA");
        assertThat(pair.getPQCAlgorithm()).startsWith("ML-DSA");
        assertThat(pair.getLabel()).isEqualTo("RSA + " + pair.getPQCAlgorithm());
        assertThat(pair.getGenerationTime()).isPositive();
    }

    @Test
    @DisplayName("equals/hashCode should be reflexive and distinguish distinct pairs")
    void test_equals_hashcode() {
        HybridKeyPair a = newPair();
        HybridKeyPair b = newPair();

        assertThat(a).isEqualTo(a);
        assertThat(a.hashCode()).isEqualTo(a.hashCode());
        assertThat(a).isNotEqualTo(b);          // different generated public keys
        assertThat(a).isNotEqualTo(null);
        assertThat(a).isNotEqualTo("not a key pair");
    }

    @Test
    @DisplayName("toString should mention both algorithms")
    void test_to_string() {
        assertThat(newPair().toString()).contains("RSA").contains("ML-DSA");
    }

    @Test
    @DisplayName("destroy should be a best-effort no-throw operation")
    void test_destroy_does_not_throw() {
        assertThat(catchThrowable(() -> newPair().destroy())).doesNotThrowAnyException();
    }

    @Test
    @DisplayName("constructor should reject null components")
    void test_constructor_null_checks() {
        HybridKeyPair valid = newPair();
        assertThatThrownBy(() -> new HybridKeyPair(
                null, valid.getClassicalPrivateKey(), valid.getPQCPublicKey(),
                valid.getPQCPrivateKey(), "RSA", "ML-DSA-65"))
                .isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> new HybridKeyPair(
                valid.getClassicalPublicKey(), valid.getClassicalPrivateKey(),
                valid.getPQCPublicKey(), valid.getPQCPrivateKey(), "RSA", null))
                .isInstanceOf(NullPointerException.class);
    }
}
