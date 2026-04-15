package com.pqc.hybrid.core;

import com.pqc.hybrid.core.config.*;

/**
 * Provides test fixtures and common test data for the PQC Hybrid Library.
 * 
 * Contains:
 * - Algorithm pair fixtures
 * - Distinguished Names
 * - Test constants
 * - Factory methods for common test objects
 * 
 * @author PQC Hybrid Team
 * @version 1.0.0-BETA
 */
public class TestFixtures {

    // Test Distinguished Names
    public static final String TEST_SUBJECT_DN = "CN=test.example.com,O=Test Company,C=US";
    public static final String TEST_ISSUER_DN = "CN=Test Root CA,O=Test Company,C=US";
    public static final String TEST_SUBJECT_CN = "test.example.com";

    // Certificate parameters
    public static final int TEST_VALIDITY_DAYS = 365;
    public static final int TEST_SERIAL_NUMBER = 1001;

    // Cryptographic parameters
    public static final int SECURITY_LEVEL_128 = 128;  // 128-bit security (quantum-resistant)
    public static final int SECURITY_LEVEL_256 = 256;  // 256-bit security

    // Test data
    public static final String TEST_MESSAGE = "Test message for signing";
    public static final byte[] TEST_MESSAGE_BYTES = TEST_MESSAGE.getBytes();

    /**
     * Create a recommended hybrid algorithm pair for 128-bit security.
     */
    public static HybridAlgorithmPair createRecommendedAlgorithmPair() {
        return HybridAlgorithmPair.recommended(SECURITY_LEVEL_128);
    }

    /**
     * Create a hybrid algorithm pair with specific algorithms.
     */
    public static HybridAlgorithmPair createAlgorithmPair(
            ClassicalAlgorithm classical, PQCAlgorithm pqc) {
        return new HybridAlgorithmPair(classical, pqc);
    }

    /**
     * Create a test certificate configuration.
     */
    public static HybridCertificateConfig createTestCertificateConfig() {
        return HybridCertificateConfig.builder()
            .withAlgorithmPair(createRecommendedAlgorithmPair())
            .withSubjectDN(TEST_SUBJECT_DN)
            .withIssuerDN(TEST_ISSUER_DN)
            .build();
    }

    /**
     * Create a test certificate configuration with custom algorithm.
     */
    public static HybridCertificateConfig createTestCertificateConfig(
            ClassicalAlgorithm classical, PQCAlgorithm pqc) {
        return HybridCertificateConfig.builder()
            .withAlgorithmPair(new HybridAlgorithmPair(classical, pqc))
            .withSubjectDN(TEST_SUBJECT_DN)
            .withIssuerDN(TEST_ISSUER_DN)
            .build();
    }

    /**
     * Get all available classical algorithms for testing.
     */
    public static ClassicalAlgorithm[] getAllClassicalAlgorithms() {
        return ClassicalAlgorithm.values();
    }

    /**
     * Get all available PQC algorithms for testing.
     */
    public static PQCAlgorithm[] getAllPQCAlgorithms() {
        return PQCAlgorithm.values();
    }

    /**
     * Create random test data of specified length.
     */
    public static byte[] createRandomTestData(int length) {
        byte[] data = new byte[length];
        org.bouncycastle.crypto.util.Pack.intToBigEndian((int) System.currentTimeMillis(), data, 0);
        for (int i = 4; i < length; i++) {
            data[i] = (byte) ((data[i - 1] + i) & 0xFF);
        }
        return data;
    }
}
