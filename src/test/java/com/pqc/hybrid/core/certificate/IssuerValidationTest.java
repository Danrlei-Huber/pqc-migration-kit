package com.pqc.hybrid.core.certificate;

import com.pqc.hybrid.core.BaseTest;
import com.pqc.hybrid.core.api.PQCHybridCertificateAPI;
import com.pqc.hybrid.core.config.CryptographicProviderFactory;
import com.pqc.hybrid.core.config.HybridAlgorithmPair;
import com.pqc.hybrid.core.config.HybridCertificateConfig;
import com.pqc.hybrid.core.keygen.HybridKeyPair;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.cert.X509Certificate;

import static org.assertj.core.api.Assertions.*;

/**
 * Regression tests for validating a certificate against the authority that issued it.
 *
 * <p>Two defects are covered. First, a fail-open: {@code validateComprehensive} used to report
 * {@code signatureValid == true} whenever no issuer public key was supplied, so a CA-issued
 * certificate whose signature was never checked came back as valid. Second,
 * {@code validateDNs} only checked that the distinguished names were non-empty, while the library
 * claimed to verify subject/issuer consistency — a certificate could name any issuer at all and
 * still pass.
 *
 * @author PQC Hybrid Team
 * @version 1.0.0-BETA
 */
@DisplayName("Issuer validation")
class IssuerValidationTest extends BaseTest {

    private static final HybridAlgorithmPair PAIR = HybridAlgorithmPair.recommended(192);

    private PQCHybridCertificateAPI api;
    private HybridKeyPair caKeyPair;
    private X509Certificate caCertificate;
    private HybridKeyPair leafKeyPair;
    private X509Certificate leafCertificate;

    @BeforeAll
    static void setUpAll() {
        CryptographicProviderFactory.initialize();
    }

    @BeforeEach
    public void setUp() {
        api = new PQCHybridCertificateAPI();
        api.initialize();

        caKeyPair = api.generateHybridKeyPair(PAIR);
        caCertificate = selfSignedCA(caKeyPair, "CN=Root CA,O=TCC");

        leafKeyPair = api.generateHybridKeyPair(PAIR);
        leafCertificate = issuedBy(caKeyPair, caCertificate, leafKeyPair,
                "CN=leaf.example.com,O=TCC");
    }

    private X509Certificate selfSignedCA(HybridKeyPair keyPair, String dn) {
        HybridCertificateConfig config = HybridCertificateConfig.builder()
                .withAlgorithmPair(PAIR)
                .withSubjectDN(dn)
                .withIssuerDN(dn)
                .withValidityDays(3650)
                .asCertificateAuthority(true)
                .build();
        return HybridX509CertificateBuilder.builder(config, keyPair).build();
    }

    private X509Certificate issuedBy(HybridKeyPair issuerKeyPair, X509Certificate issuerCertificate,
                                     HybridKeyPair subjectKeyPair, String subjectDN) {
        HybridCertificateConfig config = HybridCertificateConfig.builder()
                .withAlgorithmPair(PAIR)
                .withSubjectDN(subjectDN)
                .withIssuerDN(issuerCertificate.getSubjectX500Principal().getName())
                .withValidityDays(365)
                .build();
        return HybridX509CertificateBuilder.builder(config, subjectKeyPair)
                .withIssuer(issuerKeyPair, issuerCertificate)
                .build();
    }

    // ---------------------------------------------------------------- fail-open

    @Test
    @DisplayName("a CA-issued certificate is not reported valid when no issuer key is supplied")
    void caIssuedCertificateIsNotWavedThroughWithoutIssuerKey() {
        var result = api.validateCertificate(leafCertificate, null);

        assertThat(result.isSignatureValid())
                .as("no signature was verified, so none may be reported as valid")
                .isFalse();
        assertThat(result.isAllValid()).isFalse();
    }

    @Test
    @DisplayName("a self-signed certificate still validates with no issuer key")
    void selfSignedCertificateValidatesWithoutIssuerKey() {
        var result = api.validateCertificate(caCertificate, null);

        assertThat(result.isSignatureValid()).isTrue();
    }

    @Test
    @DisplayName("the wrong issuer public key is rejected")
    void wrongIssuerPublicKeyIsRejected() {
        HybridKeyPair strangerKeyPair = api.generateHybridKeyPair(PAIR);

        var result = api.validateCertificate(leafCertificate,
                strangerKeyPair.getClassicalPublicKey());

        assertThat(result.isSignatureValid()).isFalse();
    }

    // ---------------------------------------------------------------- name chaining

    @Test
    @DisplayName("issuer name chaining accepts the real issuer and rejects any other")
    void issuerLinkageDistinguishesTheRealIssuer() {
        HybridKeyPair otherKeyPair = api.generateHybridKeyPair(PAIR);
        X509Certificate otherCA = selfSignedCA(otherKeyPair, "CN=Another CA,O=TCC");

        assertThat(HybridCertificateValidator.validateIssuerLinkage(leafCertificate, caCertificate))
                .isTrue();
        assertThat(HybridCertificateValidator.validateIssuerLinkage(leafCertificate, otherCA))
                .isFalse();
        // A self-signed root chains to itself.
        assertThat(HybridCertificateValidator.validateIssuerLinkage(caCertificate, caCertificate))
                .isTrue();
    }

    @Test
    @DisplayName("structural DN check still requires both names to be present")
    void structuralDnCheckPasses() {
        assertThat(HybridCertificateValidator.validateDNs(leafCertificate)).isTrue();
        assertThat(HybridCertificateValidator.validateDNs(caCertificate)).isTrue();
    }

    // ---------------------------------------------------------------- validateAgainstIssuer

    @Test
    @DisplayName("a genuine issuer/subject link validates in both dimensions")
    void genuineLinkValidates() {
        var result = api.validateCertificateAgainstIssuer(leafCertificate, caCertificate);

        assertThat(result.isSignatureValid()).isTrue();
        assertThat(result.isPqcSignatureValid()).isTrue();
        assertThat(result.isPqcExtensionsValid()).isTrue();
        assertThat(result.isDnsValid()).isTrue();
        assertThat(result.isAllValid()).isTrue();
    }

    @Test
    @DisplayName("a self-signed root validates against itself")
    void selfSignedRootValidatesAgainstItself() {
        var result = api.validateCertificateAgainstIssuer(caCertificate, caCertificate);

        assertThat(result.isAllValid()).isTrue();
    }

    @Test
    @DisplayName("an unrelated CA fails on names, classical signature and alternative signature")
    void unrelatedIssuerIsRejectedOnEveryDimension() {
        HybridKeyPair otherKeyPair = api.generateHybridKeyPair(PAIR);
        X509Certificate otherCA = selfSignedCA(otherKeyPair, "CN=Another CA,O=TCC");

        var result = api.validateCertificateAgainstIssuer(leafCertificate, otherCA);

        assertThat(result.isDnsValid()).isFalse();
        assertThat(result.isSignatureValid()).isFalse();
        assertThat(result.isPqcSignatureValid()).isFalse();
        assertThat(result.isAllValid()).isFalse();
    }

    @Test
    @DisplayName("an issuer publishing no alternative key cannot vouch for an alternative signature")
    void issuerWithoutAlternativeKeyCannotVerifyAltSignature() {
        // The CA signs with its PQC key but its own certificate omits subjectAltPublicKeyInfo,
        // so the alternative signature is unverifiable — which must read as invalid, not valid.
        HybridCertificateConfig caConfig = HybridCertificateConfig.builder()
                .withAlgorithmPair(PAIR)
                .withSubjectDN("CN=Classical CA,O=TCC")
                .withIssuerDN("CN=Classical CA,O=TCC")
                .withValidityDays(3650)
                .asCertificateAuthority(true)
                .build();
        X509Certificate classicalOnlyCA = HybridX509CertificateBuilder.builder(caConfig, caKeyPair)
                .withPQCExtensions(false)
                .build();

        X509Certificate leaf = issuedBy(caKeyPair, classicalOnlyCA, leafKeyPair,
                "CN=leaf2.example.com,O=TCC");

        assertThat(HybridCertificateValidator.extractAltPublicKey(classicalOnlyCA)).isNull();

        var result = api.validateCertificateAgainstIssuer(leaf, classicalOnlyCA);

        assertThat(result.isSignatureValid()).isTrue();
        assertThat(result.isPqcExtensionsValid()).isTrue();
        assertThat(result.isPqcSignatureValid())
                .as("nothing was verified, so nothing may be reported as valid")
                .isFalse();
        assertThat(result.isAllValid()).isFalse();
    }

    @Test
    @DisplayName("null arguments are rejected")
    void nullArgumentsRejected() {
        assertThatThrownBy(() -> api.validateCertificateAgainstIssuer(leafCertificate, null))
                .isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> api.validateCertificateAgainstIssuer(null, caCertificate))
                .isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> HybridCertificateValidator.validateIssuerLinkage(leafCertificate, null))
                .isInstanceOf(NullPointerException.class);
    }
}
