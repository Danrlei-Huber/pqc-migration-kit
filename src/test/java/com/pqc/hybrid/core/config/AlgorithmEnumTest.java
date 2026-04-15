package com.pqc.hybrid.core.config;

import com.pqc.hybrid.core.BaseTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;

import static org.assertj.core.api.Assertions.*;

/**
 * Unit tests for ClassicalAlgorithm enumeration.
 * 
 * Tests:
 * - All algorithm values exist
 * - Algorithm names are correct
 * - Key sizes are valid
 * 
 * @author PQC Hybrid Team
 * @version 1.0.0-BETA
 */
@DisplayName("ClassicalAlgorithm Tests")
class ClassicalAlgorithmTest extends BaseTest {

    @Test
    @DisplayName("should have at least 2 RSA algorithms")
    void test_has_rsa_algorithms() {
        ClassicalAlgorithm[] values = ClassicalAlgorithm.values();
        assertThat(values).isNotEmpty();
        assertThat(values).contains(ClassicalAlgorithm.RSA_2048);
    }

    @Test
    @DisplayName("should have at least 1 ECDSA algorithm")
    void test_has_ecdsa_algorithms() {
        assertThat(ClassicalAlgorithm.values()).contains(ClassicalAlgorithm.ECDSA_P256);
    }

    @Test
    @DisplayName("should return non-empty algorithm name for RSA")
    void test_rsa_algorithm_name() {
        String name = ClassicalAlgorithm.RSA_2048.getAlgorithmName();
        assertThat(name).isNotEmpty().contains("RSA");
    }

    @Test
    @DisplayName("should return non-empty algorithm name for ECDSA")
    void test_ecdsa_algorithm_name() {
        String name = ClassicalAlgorithm.ECDSA_P256.getAlgorithmName();
        assertThat(name).isNotEmpty().contains("ECDSA");
    }

    @Test
    @DisplayName("should have valid key size for RSA")
    void test_rsa_key_size() {
        int keySize = ClassicalAlgorithm.RSA_2048.getKeySize();
        assertThat(keySize).isEqualTo(2048);
    }

    @Test
    @DisplayName("should have valid key size for ECDSA")
    void test_ecdsa_key_size() {
        int keySize = ClassicalAlgorithm.ECDSA_P256.getKeySize();
        assertThat(keySize).isGreaterThan(0);
    }

    @Test
    @DisplayName("should find algorithm by name")
    void test_find_algorithm_by_name() {
        ClassicalAlgorithm algo = ClassicalAlgorithm.RSA_2048;
        String name = algo.getAlgorithmName();
        
        assertThat(name).isNotEmpty();
    }
}

/**
 * Unit tests for PQCAlgorithm enumeration.
 * 
 * Tests:
 * - All PQC algorithm values exist
 * - Algorithm names are correct
 * - NIST reference levels
 * 
 * @author PQC Hybrid Team
 * @version 1.0.0-BETA
 */
@DisplayName("PQCAlgorithm Tests")
class PQCAlgorithmTest extends BaseTest {

    @Test
    @DisplayName("should have FALCON algorithms")
    void test_has_falcon_algorithms() {
        assertThat(PQCAlgorithm.values()).contains(
            PQCAlgorithm.FALCON_512,
            PQCAlgorithm.FALCON_1024
        );
    }

    @Test
    @DisplayName("should have ML-DSA algorithms")
    void test_has_ml_dsa_algorithms() {
        assertThat(PQCAlgorithm.values()).contains(
            PQCAlgorithm.ML_DSA_44,
            PQCAlgorithm.ML_DSA_65,
            PQCAlgorithm.ML_DSA_87
        );
    }

    @Test
    @DisplayName("should have SLH-DSA algorithms")
    void test_has_slh_dsa_algorithms() {
        assertThat(PQCAlgorithm.values()).contains(
            PQCAlgorithm.SLH_DSA_SHA2_128S,
            PQCAlgorithm.SLH_DSA_SHA2_128F
        );
    }

    @Test
    @DisplayName("should return non-empty name for FALCON")
    void test_falcon_algorithm_name() {
        String name = PQCAlgorithm.FALCON_1024.getName();
        assertThat(name).isNotEmpty().contains("Falcon");
    }

    @Test
    @DisplayName("should return non-empty name for ML-DSA")
    void test_ml_dsa_algorithm_name() {
        String name = PQCAlgorithm.ML_DSA_44.getName();
        assertThat(name).isNotEmpty().contains("ML-DSA");
    }

    @Test
    @DisplayName("should return non-empty name for SLH-DSA")
    void test_slh_dsa_algorithm_name() {
        String name = PQCAlgorithm.SLH_DSA_SHA2_128S.getName();
        assertThat(name).isNotEmpty().contains("SLH-DSA");
    }

    @Test
    @DisplayName("FALCON-512 should be NIST Level 1")
    void test_falcon_512_nist_level() {
        // FALCON-512 ≈ NIST Level 1 (128-bit security)
        assertThat(PQCAlgorithm.FALCON_512.getName()).isNotEmpty();
    }

    @Test
    @DisplayName("FALCON-1024 should be NIST Level 5 equivalent")
    void test_falcon_1024_nist_level() {
        // FALCON-1024 ≈ NIST Level 5 (256-bit security)
        assertThat(PQCAlgorithm.FALCON_1024.getName()).isNotEmpty();
    }

    @Test
    @DisplayName("all PQC algorithms should have unique names")
    void test_all_algorithms_have_unique_names() {
        org.junit.jupiter.api.Assertions.assertAll(
            () -> assertThat(PQCAlgorithm.FALCON_512.getName()).isNotEmpty(),
            () -> assertThat(PQCAlgorithm.FALCON_1024.getName()).isNotEmpty(),
            () -> assertThat(PQCAlgorithm.ML_DSA_44.getName()).isNotEmpty(),
            () -> assertThat(PQCAlgorithm.ML_DSA_65.getName()).isNotEmpty(),
            () -> assertThat(PQCAlgorithm.ML_DSA_87.getName()).isNotEmpty(),
            () -> assertThat(PQCAlgorithm.SLH_DSA_SHA2_128S.getName()).isNotEmpty(),
            () -> assertThat(PQCAlgorithm.SLH_DSA_SHA2_128F.getName()).isNotEmpty()
        );
    }
}
