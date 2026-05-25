package com.pqc.hybrid.core.certificate;

import com.pqc.hybrid.core.BaseTest;
import com.pqc.hybrid.core.api.PQCHybridCertificateAPI;
import com.pqc.hybrid.core.config.CryptographicProviderFactory;
import com.pqc.hybrid.core.config.HybridCertificateConfig;
import com.pqc.hybrid.core.keygen.HybridKeyPair;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.OutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Tests for the Layer 1 (signer-agnostic) certificate/CSR API and the parity between Layer 1
 * (external {@link ContentSigner}s) and Layer 2 (in-memory {@link HybridKeyPair}).
 *
 * <p>The {@link CountingContentSigner} stands in for an external/HSM-backed signer: the builders
 * never construct it, they only invoke the {@link ContentSigner} abstraction handed to them. This
 * is exactly how CZERTAINLY-Core would plug its {@code TokenContentSigner}.
 */
@DisplayName("Layer 1 external-signer (HSM-agnostic) Tests")
class Layer1ExternalSignerTest extends BaseTest {

    private static final String SUBJECT_DN = "CN=layer1.example.com,O=Test,C=US";
    private static final String CLASSICAL_SIG_ALG = "SHA256withECDSA";
    private static final String PQC_SIG_ALG = "ML-DSA-44";

    @BeforeAll
    static void setUpAll() {
        CryptographicProviderFactory.initialize();
    }

    // --- helpers -----------------------------------------------------------------

    private static HybridKeyPair newHybridKeyPair() throws Exception {
        KeyPairGenerator ecGen = KeyPairGenerator.getInstance("EC", "BC");
        ecGen.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPairGenerator pqcGen = KeyPairGenerator.getInstance(PQC_SIG_ALG, "BC");
        KeyPair ecKp = ecGen.generateKeyPair();
        KeyPair pqcKp = pqcGen.generateKeyPair();
        return new HybridKeyPair(
                ecKp.getPublic(), ecKp.getPrivate(),
                pqcKp.getPublic(), pqcKp.getPrivate(),
                "ECDSA", PQC_SIG_ALG);
    }

    private static ContentSigner signer(String jcaAlg, PrivateKey key) throws Exception {
        return new JcaContentSignerBuilder(jcaAlg).setProvider("BC").build(key);
    }

    private static HybridConfigSerial config() {
        BigInteger serial = BigInteger.valueOf(42);
        // Layer 1 needs no algorithm metadata: the HybridSigner carries the signing algorithms.
        HybridCertificateConfig cfg = HybridCertificateConfig.builder()
                .withSubjectDN(SUBJECT_DN)
                .withIssuerDN(SUBJECT_DN)
                .withValidityDays(365)
                .withSerialNumber(serial)
                .build();
        return new HybridConfigSerial(cfg, serial);
    }

    private record HybridConfigSerial(HybridCertificateConfig config, BigInteger serial) {}

    /** External-signer stand-in: delegates to a real ContentSigner but counts signature requests. */
    static final class CountingContentSigner implements ContentSigner {
        private final ContentSigner delegate;
        int signCalls = 0;

        CountingContentSigner(ContentSigner delegate) {
            this.delegate = delegate;
        }

        @Override public AlgorithmIdentifier getAlgorithmIdentifier() { return delegate.getAlgorithmIdentifier(); }
        @Override public OutputStream getOutputStream() { return delegate.getOutputStream(); }
        @Override public byte[] getSignature() { signCalls++; return delegate.getSignature(); }
    }

    // --- certificate tests -------------------------------------------------------

    @Test
    @DisplayName("Layer 1 self-signed cert with external signers is structurally equivalent to Layer 2")
    void layer1_parity_with_layer2() throws Exception {
        HybridKeyPair kp = newHybridKeyPair();
        HybridConfigSerial c = config();

        // Layer 2: in-memory keyPair
        X509Certificate l2 = new HybridX509CertificateBuilder(c.config(), kp).build();

        // Layer 1: external signers built from the same keys
        HybridSigner externalSigner = new HybridSigner(
                signer(CLASSICAL_SIG_ALG, kp.getClassicalPrivateKey()),
                signer(PQC_SIG_ALG, kp.getPQCPrivateKey()));
        X509Certificate l1 = HybridX509CertificateBuilder.build(
                c.config(), kp.getClassicalPublicKey(), kp.getPQCPublicKey(), externalSigner, null);

        assertThat(l1.getSubjectX500Principal()).isEqualTo(l2.getSubjectX500Principal());
        assertThat(l1.getIssuerX500Principal()).isEqualTo(l2.getIssuerX500Principal());
        assertThat(l1.getSerialNumber()).isEqualTo(c.serial()).isEqualTo(l2.getSerialNumber());
        assertThat(l1.getPublicKey().getEncoded()).isEqualTo(l2.getPublicKey().getEncoded());

        // both carry the three hybrid extensions
        assertThat(HybridCertificateValidator.validatePQCExtensions(l1)).isTrue();
        assertThat(HybridCertificateValidator.validatePQCExtensions(l2)).isTrue();

        // the alternative public key carried by Layer 1 matches the subject's PQC key
        assertThat(HybridCertificateValidator.extractAltPublicKey(l1).getEncoded())
                .isEqualTo(kp.getPQCPublicKey().getEncoded());
    }

    @Test
    @DisplayName("Layer 1 cert built with external (HSM-like) signers verifies classical + PQC signatures")
    void layer1_external_signer_certificate_verifies() throws Exception {
        HybridKeyPair kp = newHybridKeyPair();
        HybridConfigSerial c = config();

        CountingContentSigner classical = new CountingContentSigner(signer(CLASSICAL_SIG_ALG, kp.getClassicalPrivateKey()));
        CountingContentSigner pqc = new CountingContentSigner(signer(PQC_SIG_ALG, kp.getPQCPrivateKey()));

        X509Certificate cert = HybridX509CertificateBuilder.build(
                c.config(), kp.getClassicalPublicKey(), kp.getPQCPublicKey(),
                new HybridSigner(classical, pqc), null);

        // the external signers were actually exercised by the builder
        assertThat(classical.signCalls).isEqualTo(1);
        assertThat(pqc.signCalls).isEqualTo(1);

        // 2.5.29.72 / 73 / 74 present
        assertThat(cert.getExtensionValue("2.5.29.72")).isNotNull();
        assertThat(cert.getExtensionValue("2.5.29.73")).isNotNull();
        assertThat(cert.getExtensionValue("2.5.29.74")).isNotNull();

        // classical (self-signed) and PQC alternative signatures both validate
        assertThat(HybridCertificateValidator.validateSignature(cert, kp.getClassicalPublicKey())).isTrue();
        assertThat(HybridCertificateValidator.verifyAltSignature(cert, kp.getPQCPublicKey())).isTrue();
    }

    @Test
    @DisplayName("Layer 1 classical-only signer produces a cert without PQC extensions")
    void layer1_classical_only() throws Exception {
        HybridKeyPair kp = newHybridKeyPair();
        HybridConfigSerial c = config();

        HybridSigner classicalOnly = HybridSigner.classicalOnly(signer(CLASSICAL_SIG_ALG, kp.getClassicalPrivateKey()));
        assertThat(classicalOnly.hasPqc()).isFalse();

        X509Certificate cert = HybridX509CertificateBuilder.build(
                c.config(), kp.getClassicalPublicKey(), null, classicalOnly, null);

        assertThat(cert.getExtensionValue("2.5.29.72")).isNull();
        assertThat(HybridCertificateValidator.validatePQCExtensions(cert)).isFalse();
        assertThat(HybridCertificateValidator.validateSignature(cert, kp.getClassicalPublicKey())).isTrue();
    }

    // --- CSR tests ---------------------------------------------------------------

    @Test
    @DisplayName("Layer 1 CSR built with external signers has a valid classical signature and PQC attributes")
    void layer1_external_signer_csr() throws Exception {
        HybridKeyPair kp = newHybridKeyPair();

        CountingContentSigner classical = new CountingContentSigner(signer(CLASSICAL_SIG_ALG, kp.getClassicalPrivateKey()));
        CountingContentSigner pqc = new CountingContentSigner(signer(PQC_SIG_ALG, kp.getPQCPrivateKey()));

        PKCS10CertificationRequest csr = CertificateSigningRequestBuilder.build(
                SUBJECT_DN, kp.getClassicalPublicKey(), kp.getPQCPublicKey(),
                new HybridSigner(classical, pqc));

        assertThat(classical.signCalls).isEqualTo(1);
        assertThat(pqc.signCalls).isEqualTo(1);

        boolean classicalValid = csr.isSignatureValid(
                new JcaContentVerifierProviderBuilder().setProvider("BC").build(kp.getClassicalPublicKey()));
        assertThat(classicalValid).isTrue();
        assertThat(csr.getAttributes()).isNotEmpty();
    }

    @Test
    @DisplayName("Layer 1 classical-only CSR builds and validates")
    void layer1_classical_only_csr() throws Exception {
        HybridKeyPair kp = newHybridKeyPair();

        PKCS10CertificationRequest csr = CertificateSigningRequestBuilder.build(
                SUBJECT_DN, kp.getClassicalPublicKey(), null,
                HybridSigner.classicalOnly(signer(CLASSICAL_SIG_ALG, kp.getClassicalPrivateKey())));

        assertThat(csr.isSignatureValid(
                new JcaContentVerifierProviderBuilder().setProvider("BC").build(kp.getClassicalPublicKey()))).isTrue();
    }

    // --- facade overloads --------------------------------------------------------

    @Test
    @DisplayName("Facade Layer 1 overloads issue a verifiable hybrid cert and CSR")
    void facade_layer1_overloads() throws Exception {
        HybridKeyPair kp = newHybridKeyPair();
        HybridConfigSerial c = config();

        PQCHybridCertificateAPI api = new PQCHybridCertificateAPI();
        api.initialize();

        HybridSigner signer = new HybridSigner(
                signer(CLASSICAL_SIG_ALG, kp.getClassicalPrivateKey()),
                signer(PQC_SIG_ALG, kp.getPQCPrivateKey()));

        X509Certificate cert = api.generateHybridCertificate(
                c.config(), kp.getClassicalPublicKey(), kp.getPQCPublicKey(), signer, null);
        assertThat(HybridCertificateValidator.validatePQCExtensions(cert)).isTrue();
        assertThat(HybridCertificateValidator.verifyAltSignature(cert, kp.getPQCPublicKey())).isTrue();

        // a fresh signer instance for the CSR (signers are single-use per signature)
        HybridSigner csrSigner = new HybridSigner(
                signer(CLASSICAL_SIG_ALG, kp.getClassicalPrivateKey()),
                signer(PQC_SIG_ALG, kp.getPQCPrivateKey()));
        PKCS10CertificationRequest csr = api.generateCertificateSigningRequest(
                SUBJECT_DN, kp.getClassicalPublicKey(), kp.getPQCPublicKey(), csrSigner);
        assertThat(csr).isNotNull();
        assertThat(csr.getAttributes()).isNotEmpty();
    }

    // --- HybridSigner record -----------------------------------------------------

    @Test
    @DisplayName("HybridSigner rejects a null classical signer and reports PQC presence")
    void hybridSigner_validation() throws Exception {
        HybridKeyPair kp = newHybridKeyPair();
        ContentSigner cs = signer(CLASSICAL_SIG_ALG, kp.getClassicalPrivateKey());

        assertThatThrownBy(() -> new HybridSigner(null, null))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("Classical ContentSigner cannot be null");

        assertThat(HybridSigner.of(cs, null).hasPqc()).isFalse();
        assertThat(HybridSigner.classicalOnly(cs).hasPqc()).isFalse();
    }
}
