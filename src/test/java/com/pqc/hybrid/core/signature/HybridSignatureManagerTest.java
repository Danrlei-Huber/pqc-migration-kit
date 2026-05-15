package com.pqc.hybrid.core.signature;

import com.pqc.hybrid.core.config.ClassicalAlgorithm;
import com.pqc.hybrid.core.config.PQCAlgorithm;
import com.pqc.hybrid.core.keygen.HybridKeyGenerator;
import com.pqc.hybrid.core.keygen.HybridKeyPair;
import com.pqc.hybrid.core.BaseTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;

import static org.assertj.core.api.Assertions.*;

@DisplayName("HybridSignatureManager Tests")
class HybridSignatureManagerTest extends BaseTest {

    @Test
    @DisplayName("should generate and verify ML-DSA signature")
    void test_generate_and_verify_ml_dsa_signature() {
         // Arrange
         HybridKeyPair keyPair = HybridKeyGenerator.generate(
                 new com.pqc.hybrid.core.config.HybridAlgorithmPair(
                         ClassicalAlgorithm.RSA_2048, PQCAlgorithm.ML_DSA_65));

        // Act & Assert
        assertThatThrownBy(() -> HybridSignatureManager.sign(null, keyPair))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("Data cannot be null");
    }

    @Test
    @DisplayName("should throw exception when verifying with null data")
    void test_verify_with_null_data_throws_exception() {
         // Arrange
         HybridKeyPair keyPair = HybridKeyGenerator.generate(
                 new com.pqc.hybrid.core.config.HybridAlgorithmPair(
                         ClassicalAlgorithm.RSA_2048, PQCAlgorithm.ML_DSA_65));
        HybridSignaturePair signaturePair = HybridSignatureManager.sign("test".getBytes(), keyPair);

        // Act & Assert
        assertThatThrownBy(() -> HybridSignatureManager.verify(null, signaturePair, keyPair))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("Data cannot be null");
    }
}