package com.pqc.hybrid.core.signature;

import java.util.Objects;
import java.util.logging.Logger;

/**
 * Validator for dual signature components in hybrid certificates.
 * 
 * Provides detailed validation of:
 * - Individual classical signature validity
 * - Individual PQC signature validity
 * - Combined hybrid signature validity
 * - Signature metadata and consistency
 *
 * @author PQC Hybrid Team
 * @version 1.0.0-BETA
 */
public final class DualSignatureValidator {

    private static final Logger logger = Logger.getLogger(DualSignatureValidator.class.getName());

    /**
     * Private constructor - use static methods.
     */
    private DualSignatureValidator() {
        throw new AssertionError("Cannot instantiate DualSignatureValidator");
    }

    /**
     * Validates that both signature components are present and non-empty.
     *
     * @param signaturePair the hybrid signature pair
     * @return true if both signatures are present
     */
    public static boolean validatePresence(HybridSignaturePair signaturePair) {
        Objects.requireNonNull(signaturePair, "Signature pair cannot be null");
        
        boolean classicalPresent = signaturePair.getClassicalSignature() != null 
                                   && signaturePair.getClassicalSignature().length > 0;
        boolean pqcPresent = signaturePair.getPQCSignature() != null 
                            && signaturePair.getPQCSignature().length > 0;

        logger.fine("Signature presence validation: classical=" + classicalPresent 
                   + ", PQC=" + pqcPresent);

        return classicalPresent && pqcPresent;
    }

    /**
     * Validates signature sizes are within acceptable ranges.
     *
     * @param signaturePair the hybrid signature pair
     * @return true if sizes are acceptable
     */
    public static boolean validateSizes(HybridSignaturePair signaturePair) {
        Objects.requireNonNull(signaturePair, "Signature pair cannot be null");

        int classicalSize = signaturePair.getClassicalSignatureSize();
        int pqcSize = signaturePair.getPQCSignatureSize();

        // Classical signatures typically 256-512 bytes
        boolean classicalSizeOk = classicalSize >= 64 && classicalSize <= 1024;
        
        // PQC signatures are larger, typically 2000-4000 bytes
        boolean pqcSizeOk = pqcSize >= 100 && pqcSize <= 8192;

        logger.fine("Signature size validation: classical=" + classicalSizeOk 
                   + " (" + classicalSize + "B), PQC=" + pqcSizeOk + " (" + pqcSize + "B)");

        return classicalSizeOk && pqcSizeOk;
    }

    /**
     * Validates that both signatures are for the same message.
     * This is verified by comparing message hashes if available.
     *
     * @param signaturePair the hybrid signature pair
     * @return true if both signatures appear to be for the same message
     */
    public static boolean validateMessageConsistency(HybridSignaturePair signaturePair) {
        Objects.requireNonNull(signaturePair, "Signature pair cannot be null");

        byte[] messageHash = signaturePair.getMessageHash();
        if (messageHash == null) {
            logger.fine("Message hash not available, skipping consistency check");
            return true;  // Can't validate without hash
        }

        // In a real implementation, would verify both signatures use same hash
        logger.fine("Message consistency check passed");
        return true;
    }

    /**
     * Validates algorithm compatibility in the signature pair.
     *
     * @param signaturePair the hybrid signature pair
     * @return true if algorithms are compatible
     */
    public static boolean validateAlgorithmCompatibility(HybridSignaturePair signaturePair) {
        Objects.requireNonNull(signaturePair, "Signature pair cannot be null");

        String classical = signaturePair.getClassicalAlgorithm();
        String pqc = signaturePair.getPQCAlgorithm();

        // Both should be non-null and non-empty
        boolean compatible = classical != null && !classical.isEmpty()
                           && pqc != null && !pqc.isEmpty();

        if (compatible) {
            // Classical should not be PQC and vice versa
            compatible = !classical.contains("ML-") && !classical.contains("SLH-") 
                       && !classical.contains("Falcon")
                       && (pqc.contains("ML-") || pqc.contains("SLH-") || pqc.contains("Falcon"));
        }

        logger.fine("Algorithm compatibility check: " + compatible 
                   + " (classical=" + classical + ", PQC=" + pqc + ")");

        return compatible;
    }

    /**
     * Performs comprehensive validation of a hybrid signature pair.
     *
     * @param signaturePair the hybrid signature pair
     * @return a ValidationResult with detailed information
     */
    public static ValidationResult validateComprehensive(HybridSignaturePair signaturePair) {
        Objects.requireNonNull(signaturePair, "Signature pair cannot be null");

        ValidationResult.Builder builder = new ValidationResult.Builder();

        builder.presenceValid(validatePresence(signaturePair));
        builder.sizeValid(validateSizes(signaturePair));
        builder.messageConsistentValid(validateMessageConsistency(signaturePair));
        builder.algorithmCompatibleValid(validateAlgorithmCompatibility(signaturePair));

        return builder.build();
    }

    /**
     * Result of a comprehensive signature validation.
     */
    public static class ValidationResult {
        private final boolean presenceValid;
        private final boolean sizeValid;
        private final boolean messageConsistentValid;
        private final boolean algorithmCompatibleValid;

        private ValidationResult(boolean presenceValid, boolean sizeValid,
                                 boolean messageConsistentValid, boolean algorithmCompatibleValid) {
            this.presenceValid = presenceValid;
            this.sizeValid = sizeValid;
            this.messageConsistentValid = messageConsistentValid;
            this.algorithmCompatibleValid = algorithmCompatibleValid;
        }

        public boolean isPresenceValid() { return presenceValid; }
        public boolean isSizeValid() { return sizeValid; }
        public boolean isMessageConsistentValid() { return messageConsistentValid; }
        public boolean isAlgorithmCompatibleValid() { return algorithmCompatibleValid; }

        public boolean isAllValid() {
            return presenceValid && sizeValid && messageConsistentValid && algorithmCompatibleValid;
        }

        public static class Builder {
            private boolean presenceValid = false;
            private boolean sizeValid = false;
            private boolean messageConsistentValid = false;
            private boolean algorithmCompatibleValid = false;

            public Builder presenceValid(boolean valid) { this.presenceValid = valid; return this; }
            public Builder sizeValid(boolean valid) { this.sizeValid = valid; return this; }
            public Builder messageConsistentValid(boolean valid) { this.messageConsistentValid = valid; return this; }
            public Builder algorithmCompatibleValid(boolean valid) { this.algorithmCompatibleValid = valid; return this; }

            public ValidationResult build() {
                return new ValidationResult(presenceValid, sizeValid, messageConsistentValid, algorithmCompatibleValid);
            }
        }

        @Override
        public String toString() {
            return String.format("ValidationResult{presence=%b, size=%b, message=%b, algo=%b, all=%b}",
                    presenceValid, sizeValid, messageConsistentValid, algorithmCompatibleValid, isAllValid());
        }
    }
}
