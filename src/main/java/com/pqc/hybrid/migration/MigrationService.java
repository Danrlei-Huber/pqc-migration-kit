package com.pqc.hybrid.migration;

import java.util.List;

/**
 * Service interface for migrating legacy certificates to hybrid PQC certificates.
 * 
 * This service provides the core functionality for converting traditional 
 * certificates (X.509 with classical cryptography) to hybrid certificates 
 * that contain both classical and post-quantum cryptographic elements.
 * 
 * @author PQC Hybrid Team
 * @version 1.0.0-BETA
 */
public interface MigrationService {

    /**
     * Converts a legacy certificate to a hybrid PQC certificate.
     * 
     * @param legacyCertificate The legacy certificate data in PEM, DER, or PKCS#12 format
     * @param migrationConfig Configuration for the migration process including 
     *                        target algorithms and preservation options
     * @return Result of the migration containing the hybrid certificate or error information
     * @throws MigrationException if the migration process fails due to invalid input,
     *                           unsupported algorithms, or other migration-specific issues
     */
    MigrationResult migrateToHybrid(byte[] legacyCertificate, MigrationConfig migrationConfig) 
        throws MigrationException;

    /**
     * Validates whether a legacy certificate can be successfully migrated to hybrid format.
     * 
     * @param legacyCertificate The legacy certificate data to validate
     * @param migrationConfig Configuration for the migration process
     * @return Validation result indicating suitability for migration
     * @throws MigrationException if validation process encounters unexpected errors
     */
    MigrationValidationResult validateForMigration(byte[] legacyCertificate, MigrationConfig migrationConfig) 
        throws MigrationException;

    /**
     * Gets the list of supported legacy certificate formats for migration.
     * 
     * @return List of supported format identifiers (e.g., "PEM", "DER", "PKCS12")
     */
    List<String> getSupportedLegacyFormats();

    /**
     * Gets the list of supported hybrid certificate configurations.
     * 
     * @return List of supported configuration descriptors
     */
    List<String> getSupportedHybridConfigurations();
}