package com.pqc.hybrid.core;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayNameGeneration;
import org.junit.jupiter.api.DisplayNameGenerator;

/**
 * Base class for all unit tests in the PQC Hybrid Library.
 * 
 * Provides common setup, utilities, and conventions:
 * - Test display name generation
 * - Common initialization before each test
 * - Shared test utilities and helpers
 * 
 * @author PQC Hybrid Team
 * @version 1.0.0-BETA
 */
@DisplayNameGeneration(DisplayNameGenerator.ReplaceUnderscores.class)
public abstract class BaseTest {

    /**
     * Setup method called before each test.
     * Override in subclasses to customize initialization.
     */
    @BeforeEach
    public void setUp() {
        // Override in subclasses
    }

    /**
     * Helper method to assert text is not empty.
     */
    protected void assertNotEmpty(String text, String message) {
        if (text == null || text.trim().isEmpty()) {
            throw new AssertionError(message + ": expected non-empty string but was: " + text);
        }
    }

    /**
     * Helper method to assert bytes are not null or empty.
     */
    protected void assertNotEmptyBytes(byte[] bytes, String message) {
        if (bytes == null || bytes.length == 0) {
            throw new AssertionError(message + ": expected non-empty bytes but was: " + 
                (bytes == null ? "null" : "empty"));
        }
    }

    /**
     * Helper to get test display name with package context.
     */
    protected String getTestContext() {
        return this.getClass().getSimpleName();
    }
}
