package com.pqc.hybrid.core.benchmark;

import org.openjdk.jmh.annotations.*;

import java.util.concurrent.TimeUnit;

/**
 * Base class for JMH benchmarks in the PQC Hybrid Library.
 * 
 * Provides common JMH configuration and utilities for performance testing.
 * Benchmark results are comparable across runs with this consistent setup.
 * 
 * Configuration:
 * - Warmup: 3 iterations (1 second each)
 * - Measurement: 5 iterations (1 second each)
 * - Fork: 2 separate JVM processes
 * - TimeUnit: Milliseconds
 * - Threads: Single-threaded (unless overridden)
 * 
 * Usage:
 * ```bash
 * mvn clean verify -Pbenchmark
 * java -jar target/benchmarks.jar
 * ```
 * 
 * @author PQC Hybrid Team
 * @version 1.0.0-BETA
 */
@State(Scope.Thread)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
@Warmup(iterations = 3, time = 1)
@Measurement(iterations = 5, time = 1)
@Fork(value = 2, jvmArgs = {"-Xms512m", "-Xmx1024m"})
public abstract class BaseBenchmark {

    /**
     * Setup method called before each benchmark iteration.
     * Override in subclasses for benchmark-specific initialization.
     */
    @Setup(Level.Trial)
    public void setup() {
        // Initialize cryptographic provider
        com.pqc.hybrid.core.config.CryptographicProviderFactory.initialize();
    }

    /**
     * Teardown method called after each benchmark iteration.
     * Override in subclasses for cleanup.
     */
    @TearDown(Level.Trial)
    public void teardown() {
        // Cleanup resources
    }

    /**
     * Gets benchmark metadata for reporting.
     */
    public static class BenchmarkMetadata {
        public String name;
        public String algorithm;
        public int keySize;
        public int iterations;
        public TimeUnit timeUnit;

        public BenchmarkMetadata(String name, String algorithm, int keySize) {
            this.name = name;
            this.algorithm = algorithm;
            this.keySize = keySize;
            this.iterations = 5;
            this.timeUnit = TimeUnit.MILLISECONDS;
        }
    }
}
