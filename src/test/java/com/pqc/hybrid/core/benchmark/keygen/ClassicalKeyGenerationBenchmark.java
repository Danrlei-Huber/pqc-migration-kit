package com.pqc.hybrid.core.benchmark.keygen;

import com.pqc.hybrid.core.benchmark.BaseBenchmark;
import com.pqc.hybrid.core.config.ClassicalAlgorithm;
import com.pqc.hybrid.core.keygen.HybridKeyGenerator;
import org.openjdk.jmh.annotations.*;

import java.security.KeyPair;

/**
 * Performance benchmarks for classical key generation (RSA, ECDSA).
 * 
 * Measures:
 * - RSA-2048/3072/4096 key generation time
 * - ECDSA-P256/P384/P521 key generation time
 * - Relative performance between algorithms
 * 
 * Results are in milliseconds (average time per operation).
 * 
 * Typical Results (local machine):
 * - RSA-2048:    ~50-100ms
 * - RSA-3072:    ~150-250ms
 * - RSA-4096:    ~250-400ms
 * - ECDSA-P256:  ~5-15ms
 * - ECDSA-P384:  ~10-20ms
 * - ECDSA-P521:  ~15-30ms
 * 
 * @author PQC Hybrid Team
 * @version 1.0.0-BETA
 */
@State(Scope.Thread)
public class ClassicalKeyGenerationBenchmark extends BaseBenchmark {

    /**
     * Benchmark RSA-2048 key generation.
     * Typical security: 112-bit equivalent
     */
    @Benchmark
    public KeyPair benchmarkRSA2048Generation() {
        return HybridKeyGenerator.generateClassicalKeyPair(ClassicalAlgorithm.RSA_2048);
    }

    /**
     * Benchmark RSA-3072 key generation.
     * Typical security: 128-bit equivalent
     */
    @Benchmark
    public KeyPair benchmarkRSA3072Generation() {
        return HybridKeyGenerator.generateClassicalKeyPair(ClassicalAlgorithm.RSA_3072);
    }

    /**
     * Benchmark RSA-4096 key generation.
     * Typical security: 152-bit equivalent
     */
    @Benchmark
    public KeyPair benchmarkRSA4096Generation() {
        return HybridKeyGenerator.generateClassicalKeyPair(ClassicalAlgorithm.RSA_4096);
    }

    /**
     * Benchmark ECDSA-P256 key generation.
     * NIST Level 1 (128-bit security)
     */
    @Benchmark
    public KeyPair benchmarkECDSAP256Generation() {
        return HybridKeyGenerator.generateClassicalKeyPair(ClassicalAlgorithm.ECDSA_P256);
    }

    /**
     * Benchmark ECDSA-P384 key generation.
     * NIST Level 3 (192-bit security)
     */
    @Benchmark
    public KeyPair benchmarkECDSAP384Generation() {
        return HybridKeyGenerator.generateClassicalKeyPair(ClassicalAlgorithm.ECDSA_P384);
    }

    /**
     * Benchmark ECDSA-P521 key generation.
     * NIST Level 5 (256-bit security)
     */
    @Benchmark
    public KeyPair benchmarkECDSAP521Generation() {
        return HybridKeyGenerator.generateClassicalKeyPair(ClassicalAlgorithm.ECDSA_P521);
    }

    /**
     * Benchmark comparison: RSA vs ECDSA for equivalent security.
     * RSA-3072 ~= ECDSA-P256 (128-bit equivalent)
     * Expected: ECDSA is 10-20x faster
     */
    @Benchmark
    @Group("RSAvsECDSA")
    @GroupThreads(1)
    public KeyPair benchmarkRSA3072Comparison() {
        return HybridKeyGenerator.generateClassicalKeyPair(ClassicalAlgorithm.RSA_3072);
    }

    /**
     * Equivalent security comparison for ECDSA.
     */
    @Benchmark
    @Group("RSAvsECDSA")
    @GroupThreads(1)
    public KeyPair benchmarkECDSAP256Comparison() {
        return HybridKeyGenerator.generateClassicalKeyPair(ClassicalAlgorithm.ECDSA_P256);
    }
}
