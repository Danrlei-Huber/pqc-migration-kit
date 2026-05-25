package com.pqc.hybrid.core.signature;

import com.pqc.hybrid.core.config.CompositeAlgorithm;
import com.pqc.hybrid.core.keygen.HybridKeyPair;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("CompositeSignatureStrategy Tests")
class CompositeSignatureStrategyTest {

    private static final CompositeAlgorithm ALG = CompositeAlgorithm.MLDSA44_ECDSA_P256_SHA256;
    private final CompositeSignatureStrategy strategy = new CompositeSignatureStrategy(ALG);

    @Test
    @DisplayName("should expose its name and composite algorithm")
    void test_metadata() {
        assertThat(strategy.getCompositeAlgorithm()).isEqualTo(ALG);
        assertThat(strategy.getStrategyName()).isEqualTo("COMPOSITE_" + ALG.name());
    }

    @Test
    @DisplayName("generateKeyPair should produce a composite key pair; passthrough overload returns input")
    void test_generate_key_pair() {
        HybridKeyPair generated = strategy.generateKeyPair(128);
        assertThat(generated).isNotNull();
        assertThat(strategy.generateKeyPair(generated)).isSameAs(generated);
    }

    @Test
    @DisplayName("should round-trip sign and verify")
    void test_sign_verify_round_trip() throws Exception {
        HybridKeyPair keyPair = strategy.generateKeyPair(128);
        byte[] data = "strategy payload".getBytes();

        byte[] signature = strategy.signData(data, keyPair);

        assertThat(strategy.verifySignature(data, signature, keyPair)).isTrue();
        assertThat(strategy.verifySignature("other".getBytes(), signature, keyPair)).isFalse();
    }

    @Test
    @DisplayName("should round-trip with an explicit context")
    void test_sign_verify_with_ctx() throws Exception {
        HybridKeyPair keyPair = strategy.generateKeyPair(128);
        byte[] data = "ctx payload".getBytes();
        byte[] ctx = "bind".getBytes();

        byte[] signature = strategy.signData(data, keyPair, ctx);

        assertThat(strategy.verifySignature(data, signature, keyPair, ctx)).isTrue();
    }
}
