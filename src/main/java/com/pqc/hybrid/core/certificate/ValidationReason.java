package com.pqc.hybrid.core.certificate;

import java.util.Objects;

/**
 * One reason a certificate was rejected under a {@link ValidationPolicy}.
 *
 * @param code       what failed, stable enough to assert on and to tabulate
 * @param chainIndex the position of the offending certificate (0 = leaf); 0 for a single
 *                   certificate validated against its issuer, -1 when the failure cannot be
 *                   attributed to one certificate
 * @param detail     free-form diagnostic text; not part of the contract
 */
public record ValidationReason(Code code, int chainIndex, String detail) {

    /** The failure categories a validation can report. */
    public enum Code {
        /** The classical (PKIX) path or one of its checks — signature, validity, constraints — failed. */
        CLASSICAL_PATH_INVALID,
        /** The certificate lacks one or more of the Catalyst extensions 2.5.29.72/73/74. */
        ALT_EXTENSIONS_MISSING,
        /** The alternative signature does not verify under the issuer's alternative public key. */
        ALT_SIGNATURE_INVALID,
        /** The alternative signature algorithm is unknown or outside the policy's allow-list. */
        ALT_ALGORITHM_NOT_ALLOWED,
        /** The issuer's certificate carries no usable {@code subjectAltPublicKeyInfo}. */
        ISSUER_ALT_KEY_MISSING,
        /** The certificate's issuer name does not chain to the issuer certificate's subject name. */
        ISSUER_NAME_MISMATCH
    }

    public ValidationReason {
        Objects.requireNonNull(code, "Code cannot be null");
        detail = (detail == null) ? "" : detail;
    }

    @Override
    public String toString() {
        return code + "@" + chainIndex + (detail.isEmpty() ? "" : " (" + detail + ")");
    }
}
