package com.pqc.hybrid.core.signature;

import com.pqc.hybrid.core.config.CompositeAlgorithm;
import com.pqc.hybrid.core.config.ClassicalAlgorithm;
import com.pqc.hybrid.core.config.HybridAlgorithmPair;
import com.pqc.hybrid.core.config.PQCAlgorithm;
import com.pqc.hybrid.core.keygen.CompositeKeyGenerator;
import com.pqc.hybrid.core.keygen.HybridKeyGenerator;
import com.pqc.hybrid.core.keygen.HybridKeyPair;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("CompositeSigner / CompositeVerifier Tests")
class CompositeSignerVerifierTest {

    @Test
    @DisplayName("ECDSA composite should round-trip sign and verify")
    void test_round_trip_ecdsa() {
        HybridKeyPair keyPair = CompositeKeyGenerator.generate(CompositeAlgorithm.MLDSA44_ECDSA_P256_SHA256);
        byte[] data = "composite payload".getBytes();

        byte[] signature = CompositeSigner.sign(data, keyPair);

        assertThat(signature).isNotEmpty();
        assertThat(CompositeVerifier.verify(data, signature, keyPair)).isTrue();
    }

    @Test
    @DisplayName("Ed25519 composite should round-trip sign and verify")
    void test_round_trip_ed25519() {
        HybridKeyPair keyPair = CompositeKeyGenerator.generate(CompositeAlgorithm.MLDSA44_ED25519_SHA512);
        byte[] data = "composite payload ed".getBytes();

        byte[] signature = CompositeSigner.sign(data, keyPair);

        assertThat(CompositeVerifier.verify(data, signature, keyPair)).isTrue();
    }

    @Test
    @DisplayName("a matching context should round-trip")
    void test_round_trip_with_ctx() {
        HybridKeyPair keyPair = CompositeKeyGenerator.generate(CompositeAlgorithm.MLDSA44_ECDSA_P256_SHA256);
        byte[] data = "ctx payload".getBytes();
        byte[] ctx = "binding".getBytes();

        byte[] signature = CompositeSigner.sign(data, keyPair, ctx);

        assertThat(CompositeVerifier.verify(data, signature, keyPair, ctx)).isTrue();
    }

    @Test
    @DisplayName("verification should fail for tampered data")
    void test_tampered_data() {
        HybridKeyPair keyPair = CompositeKeyGenerator.generate(CompositeAlgorithm.MLDSA44_ECDSA_P256_SHA256);
        byte[] signature = CompositeSigner.sign("original".getBytes(), keyPair);

        assertThat(CompositeVerifier.verify("tampered".getBytes(), signature, keyPair)).isFalse();
    }

    @Test
    @DisplayName("verification should fail for a mismatched context")
    void test_mismatched_ctx() {
        HybridKeyPair keyPair = CompositeKeyGenerator.generate(CompositeAlgorithm.MLDSA44_ECDSA_P256_SHA256);
        byte[] data = "data".getBytes();
        byte[] signature = CompositeSigner.sign(data, keyPair, "ctxA".getBytes());

        assertThat(CompositeVerifier.verify(data, signature, keyPair, "ctxB".getBytes())).isFalse();
    }

    @Test
    @DisplayName("signing/verifying with a non-composite key pair should fail")
    void test_non_composite_key_pair() {
        HybridKeyPair plain = HybridKeyGenerator.generate(
                new HybridAlgorithmPair(ClassicalAlgorithm.RSA_2048, PQCAlgorithm.ML_DSA_44));

        assertThatThrownBy(() -> CompositeSigner.sign("d".getBytes(), plain))
                .isInstanceOf(RuntimeException.class);
        assertThatThrownBy(() -> CompositeVerifier.verify("d".getBytes(), new byte[3000], plain))
                .isInstanceOf(RuntimeException.class);
    }
}
