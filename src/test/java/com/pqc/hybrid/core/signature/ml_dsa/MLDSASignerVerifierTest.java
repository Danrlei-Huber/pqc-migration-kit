package com.pqc.hybrid.core.signature.ml_dsa;

import com.pqc.hybrid.core.BaseTest;
import com.pqc.hybrid.core.config.ClassicalAlgorithm;
import com.pqc.hybrid.core.config.HybridAlgorithmPair;
import com.pqc.hybrid.core.config.PQCAlgorithm;
import com.pqc.hybrid.core.exception.PQCHybridException;
import com.pqc.hybrid.core.keygen.HybridKeyGenerator;
import com.pqc.hybrid.core.keygen.HybridKeyPair;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.PrivateKey;
import java.security.PublicKey;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("MLDSASigner / MLDSAVerifier Tests")
class MLDSASignerVerifierTest extends BaseTest {

    private static HybridKeyPair keyPair;
    private static String algorithm;

    @BeforeAll
    static void generateKeys() {
        keyPair = HybridKeyGenerator.generate(
                new HybridAlgorithmPair(ClassicalAlgorithm.ECDSA_P256, PQCAlgorithm.ML_DSA_44));
        algorithm = keyPair.getPQCAlgorithm();
    }

    @Test
    @DisplayName("should sign and verify a valid ML-DSA signature round-trip")
    void sign_then_verify_roundtrip_is_valid() {
        byte[] data = "hybrid certificate payload".getBytes();

        byte[] signature = MLDSASigner.sign(data, keyPair.getPQCPrivateKey(), algorithm);

        assertNotEmptyBytes(signature, "ML-DSA signature");
        assertThat(MLDSAVerifier.verify(data, signature, keyPair.getPQCPublicKey(), algorithm)).isTrue();
    }

    @Test
    @DisplayName("should reject a signature when the data does not match")
    void verify_with_different_data_is_false() {
        byte[] signature = MLDSASigner.sign("original".getBytes(), keyPair.getPQCPrivateKey(), algorithm);

        assertThat(MLDSAVerifier.verify("tampered".getBytes(), signature,
                keyPair.getPQCPublicKey(), algorithm)).isFalse();
    }

    @Test
    @DisplayName("should reject null arguments when signing")
    void sign_with_null_arguments_throws() {
        byte[] data = "x".getBytes();
        PrivateKey key = keyPair.getPQCPrivateKey();

        assertThatThrownBy(() -> MLDSASigner.sign(null, key, algorithm))
                .isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> MLDSASigner.sign(data, null, algorithm))
                .isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> MLDSASigner.sign(data, key, null))
                .isInstanceOf(NullPointerException.class);
    }

    @Test
    @DisplayName("should reject null arguments when verifying")
    void verify_with_null_arguments_throws() {
        byte[] data = "x".getBytes();
        byte[] sig = "y".getBytes();
        PublicKey key = keyPair.getPQCPublicKey();

        assertThatThrownBy(() -> MLDSAVerifier.verify(null, sig, key, algorithm))
                .isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> MLDSAVerifier.verify(data, null, key, algorithm))
                .isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> MLDSAVerifier.verify(data, sig, null, algorithm))
                .isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> MLDSAVerifier.verify(data, sig, key, null))
                .isInstanceOf(NullPointerException.class);
    }

    @Test
    @DisplayName("should raise PQCHybridException for an unknown algorithm")
    void unknown_algorithm_raises_pqc_exception() {
        byte[] data = "x".getBytes();

        assertThatThrownBy(() -> MLDSASigner.sign(data, keyPair.getPQCPrivateKey(), "ML-DSA-NOPE"))
                .isInstanceOf(PQCHybridException.class);

        byte[] sig = MLDSASigner.sign(data, keyPair.getPQCPrivateKey(), algorithm);
        assertThatThrownBy(() -> MLDSAVerifier.verify(data, sig, keyPair.getPQCPublicKey(), "ML-DSA-NOPE"))
                .isInstanceOf(PQCHybridException.class);
    }

    @Test
    @DisplayName("should validate ML-DSA keys and reject non-ML-DSA keys")
    void key_validation_helpers() {
        assertThat(MLDSASigner.isValidPrivateKey(keyPair.getPQCPrivateKey())).isTrue();
        assertThat(MLDSAVerifier.isValidPublicKey(keyPair.getPQCPublicKey())).isTrue();

        assertThat(MLDSASigner.isValidPrivateKey(null)).isFalse();
        assertThat(MLDSAVerifier.isValidPublicKey(null)).isFalse();

        // A classical (ECDSA) key is not an ML-DSA key.
        assertThat(MLDSASigner.isValidPrivateKey(keyPair.getClassicalPrivateKey())).isFalse();
        assertThat(MLDSAVerifier.isValidPublicKey(keyPair.getClassicalPublicKey())).isFalse();
    }
}
