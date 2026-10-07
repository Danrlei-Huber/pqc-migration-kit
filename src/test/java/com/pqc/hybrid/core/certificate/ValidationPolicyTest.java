package com.pqc.hybrid.core.certificate;

import com.pqc.hybrid.core.api.PQCHybridCertificateAPI;
import com.pqc.hybrid.core.certificate.HybridCertificateValidator.HybridChainValidationResult;
import com.pqc.hybrid.core.certificate.HybridCertificateValidator.ValidationResult;
import com.pqc.hybrid.core.config.ClassicalAlgorithm;
import com.pqc.hybrid.core.config.HybridAlgorithmPair;
import com.pqc.hybrid.core.config.HybridCertificateConfig;
import com.pqc.hybrid.core.config.PQCAlgorithm;
import com.pqc.hybrid.core.keygen.HybridKeyPair;

import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.tuple;

/**
 * Relying-party policy: the post-quantum half of a hybrid certificate decides the verdict
 * only when the policy says so, and every rejection names its reason.
 *
 * <p>The adversarial certificates below are all signed with the CA's <em>real</em> classical
 * key — the position of an attacker who has broken (or stolen) the classical half. A legacy
 * verifier accepts every one of them; {@link ValidationPolicy#strict()} must not.
 */
@DisplayName("ValidationPolicy")
class ValidationPolicyTest {

    private static final String DN_CA = "CN=Policy Root CA,O=TCC,C=BR";
    private static final String DN_LEAF = "CN=policy.leaf.example,O=TCC,C=BR";

    private static PQCHybridCertificateAPI api;
    private static HybridKeyPair caKeys;
    private static X509Certificate caCert;
    private static HybridKeyPair leafKeys;

    @BeforeAll
    static void setUp() throws Exception {
        api = new PQCHybridCertificateAPI();
        api.initialize();
        HybridAlgorithmPair pair = HybridAlgorithmPair.recommended(192); // ML-DSA-65
        caKeys = api.generateHybridKeyPair(pair);
        caCert = rootCertificate(pair, caKeys, DN_CA);
        leafKeys = api.generateHybridKeyPair(pair);
    }

    // ------------------------------------------------------------------ fixtures

    private static X509Certificate rootCertificate(HybridAlgorithmPair pair, HybridKeyPair keys,
                                                   String dn) throws Exception {
        return HybridCertificateAuthority.createRoot(caConfig(pair, dn), keys).getCertificate();
    }

    private static HybridCertificateConfig caConfig(HybridAlgorithmPair pair, String dn) {
        return HybridCertificateConfig.builder()
                .withAlgorithmPair(pair)
                .withSubjectDN(dn)
                .withIssuerDN(dn)
                .withValidityDays(365)
                .asCertificateAuthority(true)
                .build();
    }

    private static HybridCertificateConfig leafConfig() {
        return HybridCertificateConfig.builder()
                .withAlgorithmPair(HybridAlgorithmPair.recommended(192))
                .withSubjectDN(DN_LEAF)
                .withIssuerDN(DN_CA)
                .withValidityDays(365)
                .build();
    }

    private static ContentSigner classicalSigner(HybridKeyPair keys) throws Exception {
        return signer(ClassicalAlgorithm.getSignatureAlgorithmForKey(keys.getClassicalPublicKey()),
                keys.getClassicalPrivateKey());
    }

    private static ContentSigner pqcSigner(HybridKeyPair keys) throws Exception {
        return signer(keys.getPQCAlgorithm(), keys.getPQCPrivateKey());
    }

    private static ContentSigner signer(String algorithm, PrivateKey key) throws Exception {
        return new JcaContentSignerBuilder(algorithm).setProvider("BC").build(key);
    }

    private static X509Certificate leaf(HybridSigner signer, X509Certificate issuer) throws Exception {
        PublicKey pqc = signer.hasPqc() ? leafKeys.getPQCPublicKey() : null;
        return HybridX509CertificateBuilder.build(leafConfig(), leafKeys.getClassicalPublicKey(), pqc,
                signer, issuer);
    }

    /** Intact hybrid leaf issued by the CA. */
    private static X509Certificate intactLeaf() throws Exception {
        return leaf(HybridSigner.of(classicalSigner(caKeys), pqcSigner(caKeys)), caCert);
    }

    /** Classical signature by the real CA key, alternative signature by an attacker's ML-DSA key. */
    private static X509Certificate mixedSignerLeaf() throws Exception {
        HybridKeyPair attacker = api.generateHybridKeyPair(HybridAlgorithmPair.recommended(192));
        return leaf(HybridSigner.of(classicalSigner(caKeys), pqcSigner(attacker)), caCert);
    }

    /** Stripping: a classical-only certificate signed by the real CA key. */
    private static X509Certificate strippedLeaf() throws Exception {
        return leaf(HybridSigner.classicalOnly(classicalSigner(caKeys)), caCert);
    }

    // ------------------------------------------------------------------ the policy object

    @Nested
    @DisplayName("construction")
    class Construction {

        @Test
        @DisplayName("strict() requires both dimensions and accepts every ML-DSA level")
        void strictDefaults() {
            ValidationPolicy strict = ValidationPolicy.strict();
            assertThat(strict.mode()).isEqualTo(ValidationPolicy.Mode.REQUIRE_BOTH);
            assertThat(strict.allowedAltAlgorithms()).containsExactlyInAnyOrder(PQCAlgorithm.values());
        }

        @Test
        @DisplayName("the allow-list is copied and unmodifiable")
        void allowListIsDefensive() {
            Set<PQCAlgorithm> allowed = EnumSet.of(PQCAlgorithm.ML_DSA_65);
            ValidationPolicy policy = ValidationPolicy.requireBoth(allowed);
            allowed.add(PQCAlgorithm.ML_DSA_44);
            assertThat(policy.allowedAltAlgorithms()).containsExactly(PQCAlgorithm.ML_DSA_65);
            assertThatThrownBy(() -> policy.allowedAltAlgorithms().add(PQCAlgorithm.ML_DSA_87))
                    .isInstanceOf(UnsupportedOperationException.class);
        }

        @Test
        @DisplayName("REQUIRE_BOTH with an empty allow-list would reject everything and is refused")
        void emptyAllowListRefused() {
            assertThatThrownBy(() -> ValidationPolicy.requireBoth(Set.of()))
                    .isInstanceOf(IllegalArgumentException.class);
        }

        @Test
        @DisplayName("null arguments are refused")
        void nullsRefused() {
            assertThatThrownBy(() -> new ValidationPolicy(null, Set.of(PQCAlgorithm.ML_DSA_65)))
                    .isInstanceOf(NullPointerException.class);
            assertThatThrownBy(() -> new ValidationPolicy(ValidationPolicy.Mode.REQUIRE_BOTH, null))
                    .isInstanceOf(NullPointerException.class);
        }
    }

    // ------------------------------------------------------------------ chain validation

    @Nested
    @DisplayName("validateHybridChain")
    class Chain {

        @Test
        @DisplayName("an intact chain is accepted under both policies, with no reasons")
        void intact() throws Exception {
            List<X509Certificate> chain = List.of(intactLeaf(), caCert);

            HybridChainValidationResult strict = HybridCertificateValidator.validateHybridChain(chain);
            assertThat(strict.accepted()).isTrue();
            assertThat(strict.reasons()).isEmpty();
            assertThat(strict.policy()).isEqualTo(ValidationPolicy.strict());

            assertThat(HybridCertificateValidator
                    .validateHybridChain(chain, ValidationPolicy.classicalOnly()).accepted()).isTrue();
        }

        @Test
        @DisplayName("mixed signers: classical path valid, alternative signature invalid → rejected")
        void mixedSigners() throws Exception {
            List<X509Certificate> chain = List.of(mixedSignerLeaf(), caCert);

            HybridChainValidationResult strict = HybridCertificateValidator.validateHybridChain(chain);
            assertThat(strict.classicalValid()).isTrue();
            assertThat(strict.pqcValid()).isFalse();
            assertThat(strict.accepted()).isFalse();
            assertThat(strict.reasons()).extracting(ValidationReason::code, ValidationReason::chainIndex)
                    .containsExactly(tuple(ValidationReason.Code.ALT_SIGNATURE_INVALID, 0));

            HybridChainValidationResult control =
                    HybridCertificateValidator.validateHybridChain(chain, ValidationPolicy.classicalOnly());
            assertThat(control.accepted()).isTrue();
            assertThat(control.reasons()).isEmpty();
            assertThat(control.pqcValid()).as("PQC outcome is still reported as a diagnostic").isFalse();
        }

        @Test
        @DisplayName("stripping: classical-only leaf signed by the CA → rejected for missing extensions")
        void stripping() throws Exception {
            List<X509Certificate> chain = List.of(strippedLeaf(), caCert);

            HybridChainValidationResult strict = HybridCertificateValidator.validateHybridChain(chain);
            assertThat(strict.classicalValid()).isTrue();
            assertThat(strict.accepted()).isFalse();
            assertThat(strict.reasons()).extracting(ValidationReason::code, ValidationReason::chainIndex)
                    .containsExactly(tuple(ValidationReason.Code.ALT_EXTENSIONS_MISSING, 0));

            assertThat(HybridCertificateValidator
                    .validateHybridChain(chain, ValidationPolicy.classicalOnly()).accepted()).isTrue();
        }

        @Test
        @DisplayName("an alternative algorithm outside the allow-list is rejected even though it verifies")
        void algorithmNotAllowed() throws Exception {
            HybridAlgorithmPair level128 = HybridAlgorithmPair.recommended(128); // ML-DSA-44
            HybridKeyPair keys44 = api.generateHybridKeyPair(level128);
            X509Certificate root44 = rootCertificate(level128, keys44, DN_CA);
            X509Certificate leaf44 = leaf(HybridSigner.of(classicalSigner(keys44), pqcSigner(keys44)), root44);
            List<X509Certificate> chain = List.of(leaf44, root44);

            ValidationPolicy only65and87 =
                    ValidationPolicy.requireBoth(EnumSet.of(PQCAlgorithm.ML_DSA_65, PQCAlgorithm.ML_DSA_87));
            HybridChainValidationResult restricted =
                    HybridCertificateValidator.validateHybridChain(chain, only65and87);
            assertThat(restricted.classicalValid()).isTrue();
            assertThat(restricted.pqcValid()).as("the signatures themselves are valid").isTrue();
            assertThat(restricted.accepted()).isFalse();
            assertThat(restricted.reasons()).extracting(ValidationReason::code).containsOnly(
                    ValidationReason.Code.ALT_ALGORITHM_NOT_ALLOWED);
            assertThat(restricted.reasons()).extracting(ValidationReason::chainIndex).containsExactly(0, 1);

            assertThat(HybridCertificateValidator.validateHybridChain(chain).accepted())
                    .as("strict() admits ML-DSA-44").isTrue();
            assertThat(HybridCertificateValidator
                    .validateHybridChain(chain, ValidationPolicy.classicalOnly()).accepted()).isTrue();
        }

        @Test
        @DisplayName("a chain to an unrelated root fails the classical path under every policy")
        void wrongRoot() throws Exception {
            HybridAlgorithmPair pair = HybridAlgorithmPair.recommended(192);
            X509Certificate otherRoot = rootCertificate(pair, api.generateHybridKeyPair(pair),
                    "CN=Other Root,O=TCC,C=BR");
            List<X509Certificate> chain = List.of(intactLeaf(), otherRoot);

            for (ValidationPolicy policy : List.of(ValidationPolicy.strict(), ValidationPolicy.classicalOnly())) {
                HybridChainValidationResult result = HybridCertificateValidator.validateHybridChain(chain, policy);
                assertThat(result.accepted()).isFalse();
                assertThat(result.reasons()).extracting(ValidationReason::code)
                        .contains(ValidationReason.Code.CLASSICAL_PATH_INVALID);
            }
        }
    }

    // ------------------------------------------------------------------ single-link validation

    @Nested
    @DisplayName("validateAgainstIssuer")
    class AgainstIssuer {

        @Test
        @DisplayName("an intact leaf is accepted with no reasons")
        void intact() throws Exception {
            ValidationResult result = HybridCertificateValidator.validateAgainstIssuer(intactLeaf(), caCert);
            assertThat(result.isAccepted()).isTrue();
            assertThat(result.getReasons()).isEmpty();
        }

        @Test
        @DisplayName("mixed signers are rejected under strict and accepted under CLASSICAL_ONLY")
        void mixedSigners() throws Exception {
            X509Certificate leaf = mixedSignerLeaf();

            ValidationResult strict = HybridCertificateValidator.validateAgainstIssuer(leaf, caCert);
            assertThat(strict.isSignatureValid()).isTrue();
            assertThat(strict.isAccepted()).isFalse();
            assertThat(strict.getReasons()).extracting(ValidationReason::code, ValidationReason::chainIndex)
                    .containsExactly(tuple(ValidationReason.Code.ALT_SIGNATURE_INVALID, 0));

            assertThat(HybridCertificateValidator.validateAgainstIssuer(leaf, caCert,
                    ValidationPolicy.classicalOnly()).isAccepted()).isTrue();
        }

        @Test
        @DisplayName("an issuer without an alternative key cannot vouch for an alternative signature")
        void issuerWithoutAltKey() throws Exception {
            HybridAlgorithmPair pair = HybridAlgorithmPair.recommended(192);
            X509Certificate classicalCa = HybridX509CertificateBuilder
                    .builder(caConfig(pair, DN_CA), caKeys).withPQCExtensions(false).build();
            X509Certificate leaf = leaf(HybridSigner.of(classicalSigner(caKeys), pqcSigner(caKeys)), classicalCa);

            ValidationResult result = HybridCertificateValidator.validateAgainstIssuer(leaf, classicalCa);
            assertThat(result.isSignatureValid()).isTrue();
            assertThat(result.isAccepted()).isFalse();
            assertThat(result.getReasons()).extracting(ValidationReason::code, ValidationReason::chainIndex)
                    .containsExactly(tuple(ValidationReason.Code.ISSUER_ALT_KEY_MISSING, 0));
        }

        @Test
        @DisplayName("an unrelated issuer is reported as a name mismatch and a classical failure")
        void unrelatedIssuer() throws Exception {
            HybridAlgorithmPair pair = HybridAlgorithmPair.recommended(192);
            X509Certificate otherRoot = rootCertificate(pair, api.generateHybridKeyPair(pair),
                    "CN=Other Root,O=TCC,C=BR");

            ValidationResult result = HybridCertificateValidator.validateAgainstIssuer(intactLeaf(), otherRoot);
            assertThat(result.isAccepted()).isFalse();
            assertThat(result.getReasons()).extracting(ValidationReason::code).contains(
                    ValidationReason.Code.ISSUER_NAME_MISMATCH,
                    ValidationReason.Code.CLASSICAL_PATH_INVALID,
                    ValidationReason.Code.ALT_SIGNATURE_INVALID);
        }
    }

    // ------------------------------------------------------------------ facade

    @Test
    @DisplayName("the facade exposes the policy overloads")
    void facadeOverloads() throws Exception {
        X509Certificate leaf = mixedSignerLeaf();
        assertThat(api.validateCertificateChain(List.of(leaf, caCert)).accepted()).isFalse();
        assertThat(api.validateCertificateChain(List.of(leaf, caCert), ValidationPolicy.classicalOnly())
                .accepted()).isTrue();
        assertThat(api.validateCertificateAgainstIssuer(leaf, caCert).isAccepted()).isFalse();
        assertThat(api.validateCertificateAgainstIssuer(leaf, caCert, ValidationPolicy.classicalOnly())
                .isAccepted()).isTrue();
    }
}
