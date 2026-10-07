package com.pqc.hybrid.core.certificate;

import com.pqc.hybrid.core.config.PQCAlgorithm;

import java.util.Collections;
import java.util.EnumSet;
import java.util.Objects;
import java.util.Set;

/**
 * The relying party's decision rule for a hybrid (Catalyst) certificate: which of the two
 * signature dimensions must hold for the certificate to be accepted, and which post-quantum
 * algorithms may produce the alternative signature.
 *
 * <p>Validation always computes both dimensions as diagnostics; the policy only decides which of
 * them determines {@code accepted()}. Under {@link Mode#REQUIRE_BOTH} a certificate whose
 * alternative signature is absent, invalid or produced by an algorithm outside
 * {@link #allowedAltAlgorithms()} is rejected even when its classical path is valid — the case in
 * which legacy verifiers accept a hybrid certificate on its classical half alone.
 *
 * <p>A {@code PQC_ONLY} mode is deliberately not offered: it would need its own definition of
 * which structural PKIX checks (validity, {@code basicConstraints}, {@code keyUsage}) remain
 * mandatory once the classical path is ignored.
 *
 * @param mode                 which dimensions decide the verdict
 * @param allowedAltAlgorithms the PQC algorithms accepted for alternative signatures along the
 *                             path; consulted only when the PQC dimension decides the verdict
 */
public record ValidationPolicy(Mode mode, Set<PQCAlgorithm> allowedAltAlgorithms) {

    /** Which signature dimensions decide whether a certificate is accepted. */
    public enum Mode {
        /** Both the classical path and every alternative signature must be valid. */
        REQUIRE_BOTH,
        /**
         * Only the classical path decides; the post-quantum outcome is reported but ignored.
         * Models a relying party early in the migration, before it enforces the PQC half.
         */
        CLASSICAL_ONLY
    }

    private static final ValidationPolicy STRICT =
            new ValidationPolicy(Mode.REQUIRE_BOTH, EnumSet.allOf(PQCAlgorithm.class));

    private static final ValidationPolicy CLASSICAL_ONLY =
            new ValidationPolicy(Mode.CLASSICAL_ONLY, EnumSet.allOf(PQCAlgorithm.class));

    public ValidationPolicy {
        Objects.requireNonNull(mode, "Mode cannot be null");
        Objects.requireNonNull(allowedAltAlgorithms, "Allowed algorithms cannot be null");
        if (mode == Mode.REQUIRE_BOTH && allowedAltAlgorithms.isEmpty()) {
            throw new IllegalArgumentException(
                    "REQUIRE_BOTH with no allowed alternative algorithm would reject every certificate");
        }
        allowedAltAlgorithms = allowedAltAlgorithms.isEmpty()
                ? Collections.emptySet()
                : Collections.unmodifiableSet(EnumSet.copyOf(allowedAltAlgorithms));
    }

    /** Both dimensions required; every ML-DSA parameter set accepted. The library default. */
    public static ValidationPolicy strict() {
        return STRICT;
    }

    /** Both dimensions required; alternative signatures restricted to {@code allowed}. */
    public static ValidationPolicy requireBoth(Set<PQCAlgorithm> allowed) {
        return new ValidationPolicy(Mode.REQUIRE_BOTH, allowed);
    }

    /** Only the classical path decides the verdict. */
    public static ValidationPolicy classicalOnly() {
        return CLASSICAL_ONLY;
    }

    /** @return true if the post-quantum dimension takes part in the verdict */
    public boolean requiresPqc() {
        return mode == Mode.REQUIRE_BOTH;
    }

    /** @return true if {@code algorithm} may produce an alternative signature under this policy */
    public boolean allowsAltAlgorithm(PQCAlgorithm algorithm) {
        return algorithm != null && allowedAltAlgorithms.contains(algorithm);
    }
}
