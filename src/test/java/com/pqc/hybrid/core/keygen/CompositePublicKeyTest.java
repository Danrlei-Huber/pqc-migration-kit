package com.pqc.hybrid.core.keygen;

import com.pqc.hybrid.core.config.ClassicalAlgorithm;
import com.pqc.hybrid.core.config.CompositeAlgorithm;
import com.pqc.hybrid.core.config.PQCAlgorithm;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.PublicKey;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("CompositePublicKey Tests")
class CompositePublicKeyTest {

    private static PublicKey mldsa;
    private static PublicKey trad;

    @BeforeAll
    static void keys() {
        mldsa = HybridKeyGenerator.generatePQCKeyPair(PQCAlgorithm.ML_DSA_44).getPublic();
        trad = HybridKeyGenerator.generateClassicalKeyPair(ClassicalAlgorithm.ECDSA_P256).getPublic();
    }

    private static CompositePublicKey newKey() {
        return new CompositePublicKey(mldsa, trad, CompositeAlgorithm.MLDSA44_ECDSA_P256_SHA256);
    }

    @Test
    @DisplayName("should report composite algorithm, RAW format and component keys")
    void test_accessors() {
        CompositePublicKey key = newKey();
        assertThat(key.getAlgorithm()).isEqualTo("Composite-ML-DSA");
        assertThat(key.getFormat()).isEqualTo("RAW");
        assertThat(key.getMldsaPublicKey()).isSameAs(mldsa);
        assertThat(key.getTradPublicKey()).isSameAs(trad);
        assertThat(key.getCompositeAlgorithm()).isEqualTo(CompositeAlgorithm.MLDSA44_ECDSA_P256_SHA256);
    }

    @Test
    @DisplayName("encoded form should concatenate components and be a defensive copy")
    void test_encoded() {
        CompositePublicKey key = newKey();
        byte[] expectedLen = new byte[mldsa.getEncoded().length + trad.getEncoded().length];
        assertThat(key.getEncoded()).hasSize(expectedLen.length);

        byte[] encoded = key.getEncoded();
        encoded[0] = (byte) (encoded[0] + 1);
        assertThat(key.getEncoded()).isNotEqualTo(encoded); // mutation did not leak
    }

    @Test
    @DisplayName("equals/hashCode should be based on encoded bytes")
    void test_equals_hashcode() {
        CompositePublicKey a = newKey();
        CompositePublicKey b = newKey();
        assertThat(a).isEqualTo(b).isEqualTo(a);
        assertThat(a.hashCode()).isEqualTo(b.hashCode());
        assertThat(a).isNotEqualTo(null);
        assertThat(a).isNotEqualTo("x");
    }
}
