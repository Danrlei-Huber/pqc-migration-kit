package com.pqc.hybrid.core.signature;

import com.pqc.hybrid.core.config.ClassicalAlgorithm;
import com.pqc.hybrid.core.config.PQCAlgorithm;
import com.pqc.hybrid.core.keygen.HybridKeyGenerator;
import com.pqc.hybrid.core.keygen.HybridKeyPair;
import com.pqc.hybrid.core.BaseTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;

import static org.assertj.core.api.Assertions.*;

@DisplayName("DualSignatureValidator Tests")
class DualSignatureValidatorTest extends BaseTest {

    @Test
    @DisplayName("should validate presence of both signatures")
    void test_validate_presence() {
        // Arrange
        HybridKeyPair keyPair = HybridKeyGenerator.generate(
                new com.pqc.hybrid.core.config.HybridAlgorithmPair(
                        ClassicalAlgorithm.RSA_2048, PQCAlgorithm.ML_DSA_65));
        byte[] data = "Test message for signature".getBytes();
        HybridSignaturePair signaturePair = HybridSignatureManager.sign(data, keyPair);

        // Act
        boolean hasPresence = DualSignatureValidator.validatePresence(signaturePair);

        // Assert
        assertThat(hasPresence).isTrue();
    }

    @Test
    @DisplayName("should validate signature sizes are reasonable")
    void test_validate_sizes() {
        // Arrange
        HybridKeyPair keyPair = HybridKeyGenerator.generate(
                new com.pqc.hybrid.core.config.HybridAlgorithmPair(
                        ClassicalAlgorithm.RSA_2048, PQCAlgorithm.ML_DSA_65));
        byte[] data = "Test message for signature".getBytes();
        HybridSignaturePair signaturePair = HybridSignatureManager.sign(data, keyPair);

        // Act
        boolean sizesValid = DualSignatureValidator.validateSizes(signaturePair);

        // Assert
        assertThat(sizesValid).isTrue();
    }

    @Test
    @DisplayName("should validate message consistency when hash is present")
    void test_validate_message_consistency() {
        // Arrange
        HybridKeyPair keyPair = HybridKeyGenerator.generate(
                new com.pqc.hybrid.core.config.HybridAlgorithmPair(
                        ClassicalAlgorithm.RSA_2048, PQCAlgorithm.ML_DSA_65));
        byte[] data = "Test message for signature".getBytes();
        HybridSignaturePair signaturePair = HybridSignatureManager.sign(data, keyPair);

        // Act
        boolean consistent = DualSignatureValidator.validateMessageConsistency(signaturePair);

        // Assert
        assertThat(consistent).isTrue();
    }

    @Test
    @DisplayName("should validate algorithm compatibility")
    void test_validate_algorithm_compatibility() {
        // Arrange
        HybridKeyPair keyPair = HybridKeyGenerator.generate(
                new com.pqc.hybrid.core.config.HybridAlgorithmPair(
                        ClassicalAlgorithm.RSA_2048, PQCAlgorithm.ML_DSA_65));
        byte[] data = "Test message for signature".getBytes();
        HybridSignaturePair signaturePair = HybridSignatureManager.sign(data, keyPair);

        // Act
        boolean compatible = DualSignatureValidator.validateAlgorithmCompatibility(signaturePair);

        // Assert
        assertThat(compatible).isTrue();
    }

    @Test
    @DisplayName("should perform comprehensive validation")
    void test_validate_comprehensive() {
        // Arrange
        HybridKeyPair keyPair = HybridKeyGenerator.generate(
                new com.pqc.hybrid.core.config.HybridAlgorithmPair(
                        ClassicalAlgorithm.RSA_2048, PQCAlgorithm.ML_DSA_65));
        byte[] data = "Test message for signature".getBytes();
        HybridSignaturePair signaturePair = HybridSignatureManager.sign(data, keyPair);

        // Act
        com.pqc.hybrid.core.signature.DualSignatureValidator.ValidationResult result =
                DualSignatureValidator.validateComprehensive(signaturePair);

        // Assert
        assertThat(result.isAllValid()).isTrue();
        assertThat(result.isPresenceValid()).isTrue();
        assertThat(result.isSizeValid()).isTrue();
        assertThat(result.isMessageConsistentValid()).isTrue();
        assertThat(result.isAlgorithmCompatibleValid()).isTrue();
    }

    @Test
    @DisplayName("should return invalid result for null signature pair")
    void test_validate_comprehensive_null_signature() {
        // Act & Assert
        assertThatThrownBy(() -> DualSignatureValidator.validateComprehensive(null))
                .isInstanceOf(NullPointerException.class);
    }
}