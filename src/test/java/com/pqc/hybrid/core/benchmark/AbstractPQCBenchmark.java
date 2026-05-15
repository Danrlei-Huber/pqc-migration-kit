package com.pqc.hybrid.core.benchmark;

import org.openjdk.jmh.annotations.*;

import java.security.SecureRandom;
import java.util.concurrent.TimeUnit;

/**
 * Abstract base class for PQC algorithm benchmarks.
 * Extends BaseBenchmark with PQC-specific configuration and utilities.
 * 
 * Provides common setup for PQC algorithm benchmarks including:
 * - Consistent JMH configuration for fair comparisons
 * - Test data generation utilities
 * - Common teardown logic
 * 
 * @author PQC Hybrid Team
 * @version 1.0.0-BETA
 */
@State(Scope.Thread)
@BenchmarkMode({Mode.AverageTime, Mode.Throughput, Mode.SampleTime})
@OutputTimeUnit(TimeUnit.MILLISECONDS)
@Warmup(iterations = 3, time = 1, timeUnit = TimeUnit.SECONDS)
@Measurement(iterations = 5, time = 1, timeUnit = TimeUnit.SECONDS)
@Fork(value = 2, jvmArgs = {"-Xms512m", "-Xmx1024m"})
@Timeout(time = 10, timeUnit = TimeUnit.MINUTES)
public abstract class AbstractPQCBenchmark extends BaseBenchmark {

    /** Secure random for test data generation */
    protected final SecureRandom secureRandom = new SecureRandom();

    /**
     * Generates random test data of specified size.
     * 
     * @param size Size of test data in bytes
     * @return Random test data
     */
    protected byte[] generateTestData(int size) {
        byte[] data = new byte[size];
        secureRandom.nextBytes(data);
        return data;
    }

    /**
     * Generates a simple string-based test data.
     * 
     * @param prefix Prefix for the test string
     * @param index Index to make each data unique
     * @return Test data bytes
     */
    protected byte[] generateStringTestData(String prefix, int index) {
        return (prefix + "-" + index + "-test-data-" + 
                System.currentTimeMillis()).getBytes();
    }

    /**
     * Abstract method to be implemented by subclasses to run the actual PQC operation.
     * 
     * @param input Input data for the operation
     * @return Result of the PQC operation
     */
    protected abstract Object runPQCOperation(byte[] input);

    /**
     * Gets the name of the PQC algorithm being benchmarked.
     * 
     * @return Algorithm name
     */
    protected abstract String getAlgorithmName();

    /**
     * Gets benchmark metadata for reporting and analysis.
     * 
     * @param keySize Size of the key used in the algorithm (if applicable)
     * @return Benchmark metadata
     */
    public BenchmarkMetadata getBenchmarkMetadata(int keySize) {
        BenchmarkMetadata metadata = new BenchmarkMetadata(
                getAlgorithmName(), 
                getAlgorithmName(), 
                keySize
        );
        metadata.iterations = 5;
        metadata.timeUnit = TimeUnit.MILLISECONDS;
        return metadata;
    }
}