package com.pqc.hybrid.core.keygen;

import com.pqc.hybrid.core.config.CompositeAlgorithm;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("CompositeKeyGenerator Tests")
class CompositeKeyGeneratorTest {

    /**
     * One representative algorithm per traditional key type to exercise the
     * RSA / EC / Ed25519 branches of the generator.
     */
    @ParameterizedTest
    @EnumSource(value = CompositeAlgorithm.class, names = {
            "MLDSA44_RSA2048_PSS_SHA256",
            "MLDSA44_ECDSA_P256_SHA256",
            "MLDSA44_ED25519_SHA512"
    })
    @DisplayName("should generate a composite hybrid key pair for each traditional type")
    void test_generate(CompositeAlgorithm algorithm) {
        HybridKeyPair pair = CompositeKeyGenerator.generate(algorithm);

        assertThat(pair).isNotNull();
        assertThat(pair.getClassicalPublicKey()).isInstanceOf(CompositePublicKey.class);
        assertThat(pair.getClassicalPrivateKey()).isInstanceOf(CompositePrivateKey.class);
        // generate() wires the composite keys into both slots
        assertThat(pair.getPQCPublicKey()).isSameAs(pair.getClassicalPublicKey());
        assertThat(pair.getPQCPrivateKey()).isSameAs(pair.getClassicalPrivateKey());
        assertThat(pair.getClassicalAlgorithm()).isEqualTo(algorithm.getTradAlgorithmName());
        assertThat(pair.getPQCAlgorithm()).isEqualTo(algorithm.getPQCAlgorithm().getName());

        CompositePublicKey pub = (CompositePublicKey) pair.getClassicalPublicKey();
        assertThat(pub.getCompositeAlgorithm()).isEqualTo(algorithm);
        assertThat(pub.getEncoded()).isNotEmpty();
    }
}
