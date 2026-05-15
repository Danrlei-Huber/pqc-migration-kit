package com.pqc.hybrid.migration;

import com.pqc.hybrid.core.config.ClassicalAlgorithm;
import com.pqc.hybrid.core.config.PQCAlgorithm;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;

import static org.assertj.core.api.Assertions.*;

@DisplayName("MigrationConfig Tests")
class MigrationConfigTest {

    @Test
    @DisplayName("should create default configuration with Dilithium and RSA 2048")
    void test_default_configuration() {
        MigrationConfig config = new MigrationConfig();

        assertThat(config.getPqcAlgorithm()).isEqualTo(PQCAlgorithm.ML_DSA_65);
        assertThat(config.getClassicalAlgorithm()).isEqualTo(ClassicalAlgorithm.RSA_2048);
        assertThat(config.isPreserveChain()).isTrue();
        assertThat(config.getOutputFormat()).isEqualTo("PEM");
        assertThat(config.isIncludeMetadata()).isTrue();
        assertThat(config.getValidityDays()).isEqualTo(365);
    }

    @Test
    @DisplayName("should allow configuration customization")
    void test_custom_configuration() {
        MigrationConfig config = new MigrationConfig();
        config.setPqcAlgorithm(PQCAlgorithm.FALCON_1024);
        config.setClassicalAlgorithm(ClassicalAlgorithm.ECDSA_P384);
        config.setPreserveChain(false);
        config.setOutputFormat("DER");
        config.setIncludeMetadata(false);
        config.setValidityDays(730);

        assertThat(config.getPqcAlgorithm()).isEqualTo(PQCAlgorithm.FALCON_1024);
        assertThat(config.getClassicalAlgorithm()).isEqualTo(ClassicalAlgorithm.ECDSA_P384);
        assertThat(config.isPreserveChain()).isFalse();
        assertThat(config.getOutputFormat()).isEqualTo("DER");
        assertThat(config.isIncludeMetadata()).isFalse();
        assertThat(config.getValidityDays()).isEqualTo(730);
    }

    @Test
    @DisplayName("should return correct string representation")
    void test_to_string() {
        MigrationConfig config = new MigrationConfig();
        String configString = config.toString();

        assertThat(configString).contains("pqcAlgorithm=ML_DSA_65");
        assertThat(configString).contains("classicalAlgorithm=RSA_2048");
        assertThat(configString).contains("preserveChain=true");
        assertThat(configString).contains("outputFormat='PEM'");
        assertThat(configString).contains("includeMetadata=true");
        assertThat(configString).contains("validityDays=365");
    }
}