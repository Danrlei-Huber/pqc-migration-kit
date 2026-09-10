package com.pqc.hybrid.core.signature;

import com.pqc.hybrid.core.BaseTest;
import com.pqc.hybrid.core.api.PQCHybridCertificateAPI;
import com.pqc.hybrid.core.config.ClassicalAlgorithm;
import com.pqc.hybrid.core.config.CryptographicProviderFactory;
import com.pqc.hybrid.core.config.HybridAlgorithmPair;
import com.pqc.hybrid.core.config.PQCAlgorithm;
import com.pqc.hybrid.core.exception.PQCHybridException;
import com.pqc.hybrid.core.keygen.HybridKeyPair;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.*;

/**
 * Regression tests for the FIPS 204 context string and for which algorithm drives verification.
 *
 * <p>Two defects are covered. The {@code ctx} parameter of {@code signData}/{@code verifySignature}
 * was accepted and then silently discarded, so callers asking for domain separation got none.
 * And {@code verifyPQC} chose its parameter set from the {@link HybridSignaturePair} being
 * verified rather than from the verification key, letting a caller-supplied signature blob steer
 * how it was checked.
 *
 * @author PQC Hybrid Team
 * @version 1.0.0-BETA
 */
@DisplayName("Signature context and algorithm selection")
class SignatureContextTest extends BaseTest {

    private static final byte[] DATA = "a document worth signing".getBytes(StandardCharsets.UTF_8);
    private static final byte[] CTX_BILLING = "billing".getBytes(StandardCharsets.UTF_8);
    private static final byte[] CTX_AUDIT = "audit".getBytes(StandardCharsets.UTF_8);

    private PQCHybridCertificateAPI api;
    private HybridKeyPair keyPair;

    @BeforeAll
    static void setUpAll() {
        CryptographicProviderFactory.initialize();
    }

    @BeforeEach
    public void setUp() {
        api = new PQCHybridCertificateAPI();
        api.initialize();
        keyPair = api.generateHybridKeyPair(HybridAlgorithmPair.recommended(192));
    }

    // ---------------------------------------------------------------- context

    @Test
    @DisplayName("a signature made under one context does not verify under another")
    void contextSeparatesDomains() throws Exception {
        byte[] signature = api.signData(DATA, keyPair, CTX_BILLING);

        assertThat(api.verifySignature(DATA, signature, keyPair, CTX_BILLING))
                .as("same context must verify")
                .isTrue();
        assertThat(api.verifySignature(DATA, signature, keyPair, CTX_AUDIT))
                .as("a different context must not verify")
                .isFalse();
        assertThat(api.verifySignature(DATA, signature, keyPair))
                .as("no context must not verify a signature bound to one")
                .isFalse();
    }

    @Test
    @DisplayName("a signature made without a context does not verify under one")
    void contextlessSignatureRejectsAContext() throws Exception {
        byte[] signature = api.signData(DATA, keyPair);

        assertThat(api.verifySignature(DATA, signature, keyPair)).isTrue();
        assertThat(api.verifySignature(DATA, signature, keyPair, CTX_BILLING)).isFalse();
    }

    @Test
    @DisplayName("null and empty contexts are the FIPS 204 default and interoperate")
    void emptyContextEqualsNoContext() throws Exception {
        byte[] signedWithNull = api.signData(DATA, keyPair, null);
        byte[] signedWithEmpty = api.signData(DATA, keyPair, new byte[0]);

        assertThat(api.verifySignature(DATA, signedWithNull, keyPair, new byte[0])).isTrue();
        assertThat(api.verifySignature(DATA, signedWithEmpty, keyPair, null)).isTrue();
        assertThat(api.verifySignature(DATA, signedWithEmpty, keyPair)).isTrue();
    }

    @Test
    @DisplayName("the context is still bound when the data changes are what break it")
    void tamperedDataStillFailsUnderTheRightContext() throws Exception {
        byte[] signature = api.signData(DATA, keyPair, CTX_BILLING);
        byte[] tampered = DATA.clone();
        tampered[0] ^= 0x01;

        assertThat(api.verifySignature(tampered, signature, keyPair, CTX_BILLING)).isFalse();
    }

    @Test
    @DisplayName("a context longer than the FIPS 204 limit of 255 bytes is rejected")
    void oversizedContextIsRejected() {
        assertThatThrownBy(() -> api.signData(DATA, keyPair, new byte[256]))
                .isInstanceOf(PQCHybridException.class);

        assertThatCode(() -> api.signData(DATA, keyPair, new byte[255]))
                .doesNotThrowAnyException();
    }

    @Test
    @DisplayName("context separation holds across every recommended security level")
    void contextSeparationHoldsAtEveryLevel() throws Exception {
        for (int level : new int[]{128, 192, 256}) {
            HybridKeyPair kp = api.generateHybridKeyPair(HybridAlgorithmPair.recommended(level));
            byte[] signature = api.signData(DATA, kp, CTX_BILLING);

            assertThat(api.verifySignature(DATA, signature, kp, CTX_BILLING))
                    .as("level %d, same context", level).isTrue();
            assertThat(api.verifySignature(DATA, signature, kp, CTX_AUDIT))
                    .as("level %d, different context", level).isFalse();
        }
    }

    // ---------------------------------------------------------------- algorithm selection

    @Test
    @DisplayName("the parameter set declared in the signature pair does not steer verification")
    void declaredAlgorithmDoesNotSteerVerification() throws Exception {
        HybridSignaturePair honest = HybridSignatureManager.sign(DATA, keyPair);

        // Same signature bytes, but the pair lies about which parameter set produced them.
        HybridSignaturePair mislabelled = new HybridSignaturePair(
                honest.getClassicalSignature(),
                honest.getPQCSignature(),
                keyPair.getClassicalAlgorithm(),
                PQCAlgorithm.ML_DSA_44.getName(),
                null);

        assertThat(HybridSignatureManager.verify(DATA, honest, keyPair)).isTrue();
        assertThat(HybridSignatureManager.verify(DATA, mislabelled, keyPair))
                .as("verification follows the key's parameter set, so the label is irrelevant")
                .isTrue();
    }

    @Test
    @DisplayName("a mislabelled pair still cannot make an invalid signature verify")
    void mislabellingCannotForgeAValidResult() throws Exception {
        HybridSignaturePair honest = HybridSignatureManager.sign(DATA, keyPair);
        byte[] corrupted = honest.getPQCSignature().clone();
        corrupted[0] ^= 0x01;

        HybridSignaturePair forged = new HybridSignaturePair(
                honest.getClassicalSignature(), corrupted,
                keyPair.getClassicalAlgorithm(), PQCAlgorithm.ML_DSA_44.getName(), null);

        assertThat(HybridSignatureManager.verify(DATA, forged, keyPair)).isFalse();
    }

    // ---------------------------------------------------------------- RSA security levels

    @Test
    @DisplayName("classical security levels follow NIST SP 800-57")
    void classicalSecurityLevelsAreFactual() {
        assertThat(ClassicalAlgorithm.RSA_2048.getSecurityLevel()).isEqualTo(112);
        assertThat(ClassicalAlgorithm.RSA_3072.getSecurityLevel()).isEqualTo(128);
        assertThat(ClassicalAlgorithm.RSA_4096.getSecurityLevel()).isEqualTo(152);
        assertThat(ClassicalAlgorithm.ECDSA_P256.getSecurityLevel()).isEqualTo(128);
        assertThat(ClassicalAlgorithm.ECDSA_P384.getSecurityLevel()).isEqualTo(192);
        assertThat(ClassicalAlgorithm.ECDSA_P521.getSecurityLevel()).isEqualTo(256);
    }

    @Test
    @DisplayName("RSA-4096 paired with ML-DSA-87 is reported as unbalanced, not balanced")
    void rsa4096WithMlDsa87IsNotBalanced() {
        HybridAlgorithmPair pair =
                new HybridAlgorithmPair(ClassicalAlgorithm.RSA_4096, PQCAlgorithm.ML_DSA_87);

        assertThat(pair.isSecurityBalanced())
                .as("RSA-4096 gives ~152 bits and cannot match ML-DSA-87's 256")
                .isFalse();
    }

    @Test
    @DisplayName("every pair returned by recommended() is balanced")
    void everyRecommendedPairIsBalanced() {
        for (int level : new int[]{128, 192, 256}) {
            assertThat(HybridAlgorithmPair.recommended(level).isSecurityBalanced())
                    .as("recommended(%d)", level)
                    .isTrue();
        }
    }
}
