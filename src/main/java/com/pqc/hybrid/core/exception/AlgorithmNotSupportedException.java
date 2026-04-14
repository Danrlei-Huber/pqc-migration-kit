package com.pqc.hybrid.core.exception;

/**
 * Thrown when a requested algorithm is not supported by the library.
 *
 * @author PQC Hybrid Team
 * @version 1.0.0-BETA
 */
public class AlgorithmNotSupportedException extends PQCHybridException {
    
    private static final long serialVersionUID = 1L;
    
    private final String algorithmName;

    /**
     * Creates a new AlgorithmNotSupportedException.
     *
     * @param algorithmName the name of the unsupported algorithm
     */
    public AlgorithmNotSupportedException(String algorithmName) {
        super("Algorithm not supported: " + algorithmName);
        this.algorithmName = algorithmName;
    }

    /**
     * Creates a new AlgorithmNotSupportedException with detailed message.
     *
     * @param algorithmName the name of the unsupported algorithm
     * @param message detailed message
     */
    public AlgorithmNotSupportedException(String algorithmName, String message) {
        super("Algorithm not supported: " + algorithmName + " - " + message);
        this.algorithmName = algorithmName;
    }

    /**
     * Gets the name of the unsupported algorithm.
     *
     * @return the algorithm name
     */
    public String getAlgorithmName() {
        return algorithmName;
    }
}
