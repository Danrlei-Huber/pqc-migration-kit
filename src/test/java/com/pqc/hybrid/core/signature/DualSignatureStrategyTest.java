package com.pqc.hybrid.core.signature;

import com.pqc.hybrid.core.BaseTest;
import com.pqc.hybrid.core.config.HybridAlgorithmPair;
import com.pqc.hybrid.core.exception.InvalidSignatureException;
import com.pqc.hybrid.core.keygen.HybridKeyGenerator;
import com.pqc.hybrid.core.keygen.HybridKeyPair;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("DualSignatureStrategy Tests")
class DualSignatureStrategyTest extends BaseTest {

    private final DualSignatureStrategy strategy = new DualSignatureStrategy();

    @Test
    @DisplayName("should round-trip sign and verify with a variable-length ECDSA component")
    void shouldRoundTripWithEcdsa() throws Exception {
        // 128-bit level => ECDSA-P256 + ML-DSA-44; ECDSA signatures are variable-length,
        // which the previous length/2 split could not recover.
        HybridKeyPair keyPair = HybridKeyGenerator.generate(HybridAlgorithmPair.recommended(128));
        byte[] data = "hybrid dual signature payload".getBytes();

        byte[] signature = strategy.signData(data, keyPair);

        assertThat(strategy.verifySignature(data, signature, keyPair)).isTrue();
    }

    @Test
    @DisplayName("should reject verification of tampered data")
    void shouldRejectTamperedData() throws Exception {
        HybridKeyPair keyPair = HybridKeyGenerator.generate(HybridAlgorithmPair.recommended(128));
        byte[] signature = strategy.signData("original message".getBytes(), keyPair);

        assertThat(strategy.verifySignature("tampered message".getBytes(), signature, keyPair)).isFalse();
    }

    @Test
    @DisplayName("should reject a malformed signature encoding")
    void shouldRejectMalformedEncoding() throws Exception {
        HybridKeyPair keyPair = HybridKeyGenerator.generate(HybridAlgorithmPair.recommended(128));

        assertThatThrownBy(() -> strategy.verifySignature("msg".getBytes(), new byte[]{1, 2}, keyPair))
                .isInstanceOf(InvalidSignatureException.class);
    }
}
