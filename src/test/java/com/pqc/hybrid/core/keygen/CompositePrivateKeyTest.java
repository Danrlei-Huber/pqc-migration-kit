package com.pqc.hybrid.core.keygen;

import com.pqc.hybrid.core.config.ClassicalAlgorithm;
import com.pqc.hybrid.core.config.CompositeAlgorithm;
import com.pqc.hybrid.core.config.PQCAlgorithm;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.PrivateKey;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("CompositePrivateKey Tests")
class CompositePrivateKeyTest {

    private static final CompositeAlgorithm ALG = CompositeAlgorithm.MLDSA44_ECDSA_P256_SHA256;
    private static PrivateKey mldsa;
    private static PrivateKey trad;

    @BeforeAll
    static void keys() {
        mldsa = HybridKeyGenerator.generatePQCKeyPair(PQCAlgorithm.ML_DSA_44).getPrivate();
        trad = HybridKeyGenerator.generateClassicalKeyPair(ClassicalAlgorithm.ECDSA_P256).getPrivate();
    }

    private static CompositePrivateKey newKey() {
        return new CompositePrivateKey(mldsa, trad, new byte[ALG.getMldsaSeedSize()], ALG);
    }

    @Test
    @DisplayName("should report composite algorithm, RAW format and component keys")
    void test_accessors() {
        CompositePrivateKey key = newKey();
        assertThat(key.getAlgorithm()).isEqualTo("Composite-ML-DSA");
        assertThat(key.getFormat()).isEqualTo("RAW");
        assertThat(key.getMldsaPrivateKey()).isSameAs(mldsa);
        assertThat(key.getTradPrivateKey()).isSameAs(trad);
        assertThat(key.getCompositeAlgorithm()).isEqualTo(ALG);
        assertThat(key.isDestroyed()).isFalse();
        assertThat(key.getEncoded()).isNotEmpty();
    }

    @Test
    @DisplayName("destroy should be idempotent and flip isDestroyed")
    void test_destroy() {
        CompositePrivateKey key = newKey();
        key.destroy();
        assertThat(key.isDestroyed()).isTrue();
        key.destroy(); // idempotent, must not throw
        assertThat(key.isDestroyed()).isTrue();
        // algorithm metadata is still readable after destruction
        assertThat(key.getCompositeAlgorithm()).isEqualTo(ALG);
    }

    @Test
    @DisplayName("accessing key material after destroy should fail")
    void test_access_after_destroy() {
        CompositePrivateKey key = newKey();
        key.destroy();
        assertThatThrownBy(key::getEncoded).isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(key::getMldsaPrivateKey).isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(key::getTradPrivateKey).isInstanceOf(IllegalStateException.class);
    }
}
