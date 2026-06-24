package com.pqc.hybrid.core.common.oid;

import com.pqc.hybrid.core.common.oid.AlgorithmOIDRegistry.AlgorithmType;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("AlgorithmOIDRegistry Tests")
class AlgorithmOIDRegistryTest {

    @Test
    @DisplayName("name <-> OID lookups should round-trip for known algorithms")
    void test_name_oid_round_trip() {
        assertThat(AlgorithmOIDRegistry.getAlgorithmName(AlgorithmOIDRegistry.OID_ML_DSA_65))
                .isEqualTo("ML-DSA-65");
        assertThat(AlgorithmOIDRegistry.getOID("ML-DSA-65"))
                .isEqualTo(AlgorithmOIDRegistry.OID_ML_DSA_65);
        assertThat(AlgorithmOIDRegistry.getAlgorithmName("0.0.0.0")).isNull();
        assertThat(AlgorithmOIDRegistry.getOID("Nope")).isNull();
    }

    @Test
    @DisplayName("algorithm type classification should be correct")
    void test_algorithm_type() {
        assertThat(AlgorithmOIDRegistry.getAlgorithmType(AlgorithmOIDRegistry.OID_ML_DSA_44))
                .isEqualTo(AlgorithmType.PQC_SIGNATURE);
        assertThat(AlgorithmOIDRegistry.getAlgorithmType(AlgorithmOIDRegistry.OID_RSA))
                .isEqualTo(AlgorithmType.CLASSICAL);
        assertThat(AlgorithmOIDRegistry.getAlgorithmType("0.0.0.0")).isNull();
    }

    @Test
    @DisplayName("isPQC should be true only for PQC signature/KEM OIDs")
    void test_is_pqc() {
        assertThat(AlgorithmOIDRegistry.isPQC(AlgorithmOIDRegistry.OID_ML_DSA_87)).isTrue();
        assertThat(AlgorithmOIDRegistry.isPQC(AlgorithmOIDRegistry.OID_RSA)).isFalse();
        assertThat(AlgorithmOIDRegistry.isPQC("0.0.0.0")).isFalse();
    }

    @Test
    @DisplayName("isClassical should be true only for classical OIDs")
    void test_is_classical() {
        assertThat(AlgorithmOIDRegistry.isClassical(AlgorithmOIDRegistry.OID_RSA)).isTrue();
        assertThat(AlgorithmOIDRegistry.isClassical(AlgorithmOIDRegistry.OID_SHA256_WITH_RSA)).isTrue();
        assertThat(AlgorithmOIDRegistry.isClassical(AlgorithmOIDRegistry.OID_ML_DSA_44)).isFalse();
    }

    @Test
    @DisplayName("isHybridExtension should be true only for the alt-* extension OIDs")
    void test_is_hybrid_extension() {
        assertThat(AlgorithmOIDRegistry.isHybridExtension(AlgorithmOIDRegistry.OID_ALT_SIGNATURE_VALUE)).isTrue();
        assertThat(AlgorithmOIDRegistry.isHybridExtension(AlgorithmOIDRegistry.OID_SUBJECT_ALT_PUBLIC_KEY_INFO)).isTrue();
        assertThat(AlgorithmOIDRegistry.isHybridExtension(AlgorithmOIDRegistry.OID_RSA)).isFalse();
    }

    @Test
    @DisplayName("dumpRegistry should include ML-DSA, extension and composite entries")
    void test_dump_registry() {
        String dump = AlgorithmOIDRegistry.dumpRegistry();
        assertThat(dump)
                .contains("ML-DSA-44").contains(AlgorithmOIDRegistry.OID_ML_DSA_44)
                .contains("altSignatureValue")
                .contains("COMPSIG-");
    }
}
