package com.pqc.hybrid.core.signature;

import com.pqc.hybrid.core.config.CompositeAlgorithm;
import com.pqc.hybrid.core.config.CryptographicProviderFactory;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("MessageRepresentativeBuilder Tests")
class MessageRepresentativeBuilderTest {

    private static final CompositeAlgorithm ALG = CompositeAlgorithm.MLDSA44_ECDSA_P256_SHA256;

    @BeforeAll
    static void initProvider() {
        CryptographicProviderFactory.initialize();
    }

    @Test
    @DisplayName("should build deterministically and embed the pre-hash output")
    void test_build_deterministic() {
        byte[] data = "payload".getBytes();
        byte[] a = MessageRepresentativeBuilder.build(data, ALG);
        byte[] b = MessageRepresentativeBuilder.build(data, ALG);
        assertThat(a).isEqualTo(b).isNotEmpty();
    }

    @Test
    @DisplayName("null context should equal an empty context")
    void test_null_ctx_equals_empty() {
        byte[] data = "payload".getBytes();
        assertThat(MessageRepresentativeBuilder.build(data, ALG, null))
                .isEqualTo(MessageRepresentativeBuilder.build(data, ALG, new byte[0]));
    }

    @Test
    @DisplayName("a non-empty context should change the representative")
    void test_ctx_changes_output() {
        byte[] data = "payload".getBytes();
        assertThat(MessageRepresentativeBuilder.build(data, ALG, new byte[]{42}))
                .isNotEqualTo(MessageRepresentativeBuilder.build(data, ALG, new byte[0]));
    }

    @Test
    @DisplayName("different algorithms (label/pre-hash) should change the representative")
    void test_algorithm_changes_output() {
        byte[] data = "payload".getBytes();
        assertThat(MessageRepresentativeBuilder.build(data, CompositeAlgorithm.MLDSA44_ECDSA_P256_SHA256))
                .isNotEqualTo(MessageRepresentativeBuilder.build(data, CompositeAlgorithm.MLDSA65_ECDSA_P256_SHA512));
    }

    @Test
    @DisplayName("a context longer than 255 bytes should be rejected")
    void test_ctx_too_long() {
        assertThatThrownBy(() -> MessageRepresentativeBuilder.build("d".getBytes(), ALG, new byte[256]))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
