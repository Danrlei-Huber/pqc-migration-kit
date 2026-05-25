package com.pqc.hybrid.core.certificate;

import org.bouncycastle.operator.ContentSigner;

import java.util.Objects;

/**
 * Holder for the two {@link ContentSigner}s that produce a hybrid (dual) signature:
 * a {@code classical} signer for the primary signature and an optional {@code pqc}
 * signer for the alternative (post-quantum) signature.
 *
 * <p>Because the library depends only on the {@link ContentSigner} abstraction, the
 * underlying private keys may live anywhere the caller chooses — in-memory (via
 * {@link org.bouncycastle.operator.jcajce.JcaContentSignerBuilder}), in an HSM/token, or
 * behind a remote signing service. In CZERTAINLY-Core, for instance, both signers would be
 * {@code TokenContentSigner} instances delegating to an external cryptographic connector.
 *
 * <p>When {@code pqc} is {@code null} the certificate/CSR is built with the classical
 * signature only (no alternative-signature extensions / attributes).
 *
 * @param classical the primary (classical) content signer; must not be {@code null}
 * @param pqc       the alternative (post-quantum) content signer, or {@code null} for classical-only
 */
public record HybridSigner(ContentSigner classical, ContentSigner pqc) {

    public HybridSigner {
        Objects.requireNonNull(classical, "Classical ContentSigner cannot be null");
    }

    /**
     * Creates a hybrid signer with both a classical and a PQC signer.
     */
    public static HybridSigner of(ContentSigner classical, ContentSigner pqc) {
        return new HybridSigner(classical, pqc);
    }

    /**
     * Creates a classical-only signer (no alternative PQC signature).
     */
    public static HybridSigner classicalOnly(ContentSigner classical) {
        return new HybridSigner(classical, null);
    }

    /**
     * @return {@code true} if a PQC signer is present (hybrid), {@code false} for classical-only.
     */
    public boolean hasPqc() {
        return pqc != null;
    }
}
