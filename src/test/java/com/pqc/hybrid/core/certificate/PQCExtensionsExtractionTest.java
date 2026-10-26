package com.pqc.hybrid.core.certificate;

import com.pqc.hybrid.core.BaseTest;
import com.pqc.hybrid.core.api.PQCHybridCertificateAPI;
import com.pqc.hybrid.core.certificate.asn1.PQCExtensionsStructure;
import com.pqc.hybrid.core.common.oid.AlgorithmOIDRegistry;
import com.pqc.hybrid.core.config.CryptographicProviderFactory;
import com.pqc.hybrid.core.config.HybridAlgorithmPair;
import com.pqc.hybrid.core.config.HybridCertificateConfig;
import com.pqc.hybrid.core.keygen.HybridKeyPair;
import com.pqc.hybrid.core.model.HybridCertificateInfo;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.x509.Extension;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.security.cert.X509Certificate;
import java.util.Map;

import static org.assertj.core.api.Assertions.*;

/**
 * Regression tests for reading the Catalyst alternative-signature extensions back out of an
 * issued certificate.
 *
 * <p>{@code X509Certificate.getExtensionValue()} returns the extension value already wrapped in a
 * DER OCTET STRING, while {@code Extension(oid, critical, byte[])} wraps whatever it is handed.
 * Passing the raw bytes straight through therefore double-wraps the value: {@code getParsedValue()}
 * yields a {@code DEROctetString} instead of the real content, and building the
 * {@link PQCExtensionsStructure} fails with "unknown object in getInstance", leaving
 * {@code getPQCExtensions()} silently {@code null}.
 *
 * @author PQC Hybrid Team
 * @version 1.0.0-BETA
 */
@DisplayName("Catalyst extension extraction")
class PQCExtensionsExtractionTest extends BaseTest {

    private static final String[] CATALYST_OIDS = {
            AlgorithmOIDRegistry.OID_SUBJECT_ALT_PUBLIC_KEY_INFO,  // 2.5.29.72
            AlgorithmOIDRegistry.OID_ALT_SIGNATURE_ALGORITHM,      // 2.5.29.73
            AlgorithmOIDRegistry.OID_ALT_SIGNATURE_VALUE           // 2.5.29.74
    };

    @BeforeAll
    static void setUpAll() {
        CryptographicProviderFactory.initialize();
    }

    private static X509Certificate selfSigned(HybridKeyPair keyPair, HybridAlgorithmPair pair,
                                              boolean altCritical) throws Exception {
        HybridCertificateConfig config = HybridCertificateConfig.builder()
                .withAlgorithmPair(pair)
                .withSubjectDN("CN=extraction.example.com")
                .withIssuerDN("CN=extraction.example.com")
                .withValidityDays(365)
                .withAltSignatureExtensionsCritical(altCritical)
                .build();
        return HybridX509CertificateBuilder.builder(config, keyPair)
                .withPQCExtensions(true)
                .build();
    }

    @ParameterizedTest(name = "{0}-bit pair exposes a parsed PQCExtensionsStructure")
    @CsvSource({
            // security level, expected ML-DSA OID (FIPS 204), canonical signature size in bytes
            "128, 2.16.840.1.101.3.4.3.17, 2420",
            "192, 2.16.840.1.101.3.4.3.18, 3309",
            "256, 2.16.840.1.101.3.4.3.19, 4627"
    })
    @DisplayName("getPQCExtensions() returns a populated structure, not null")
    void pqcExtensionsStructureIsParsed(int securityLevel, String expectedOid, int expectedSigSize)
            throws Exception {
        PQCHybridCertificateAPI api = new PQCHybridCertificateAPI();
        api.initialize();

        HybridAlgorithmPair pair = HybridAlgorithmPair.recommended(securityLevel);
        HybridKeyPair keyPair = api.generateHybridKeyPair(pair);
        X509Certificate certificate = selfSigned(keyPair, pair, false);

        HybridCertificateInfo info = api.getCertificateInfo(certificate, keyPair);
        PQCExtensionsStructure structure = info.getPQCExtensions();

        assertThat(structure)
                .as("getPQCExtensions() must not be null once the extensions are present")
                .isNotNull();
        assertThat(structure.getAltSignatureAlgorithm().getAlgorithm().getId())
                .isEqualTo(expectedOid);
        assertThat(structure.getSubjectAltPublicKeyInfo().getAlgorithm().getAlgorithm().getId())
                .isEqualTo(expectedOid);
        assertThat(structure.getAltSignatureValue())
                .as("ML-DSA signature size defined by FIPS 204")
                .hasSize(expectedSigSize);
    }

    @Test
    @DisplayName("parsed structure agrees with the standalone extractors")
    void structureAgreesWithStandaloneExtractors() throws Exception {
        PQCHybridCertificateAPI api = new PQCHybridCertificateAPI();
        api.initialize();

        HybridAlgorithmPair pair = HybridAlgorithmPair.recommended(192);
        HybridKeyPair keyPair = api.generateHybridKeyPair(pair);
        X509Certificate certificate = selfSigned(keyPair, pair, false);

        PQCExtensionsStructure structure =
                api.getCertificateInfo(certificate, keyPair).getPQCExtensions();

        assertThat(structure).isNotNull();
        assertThat(structure.getAltSignatureAlgorithm().getAlgorithm().getId())
                .isEqualTo(HybridCertificateValidator.extractPQCAlgorithmOID(certificate));
        assertThat(structure.getAltSignatureValue())
                .isEqualTo(HybridCertificateValidator.extractPQCSignature(certificate));
    }

    @ParameterizedTest(name = "criticality={0} round-trips through extraction")
    @CsvSource({"false", "true"})
    @DisplayName("extracted extensions re-encode byte-identically to the certificate")
    void extractedExtensionsReEncodeIdentically(boolean altCritical) throws Exception {
        PQCHybridCertificateAPI api = new PQCHybridCertificateAPI();
        api.initialize();

        HybridAlgorithmPair pair = HybridAlgorithmPair.recommended(192);
        HybridKeyPair keyPair = api.generateHybridKeyPair(pair);
        X509Certificate certificate = selfSigned(keyPair, pair, altCritical);

        Map<String, Extension> extracted =
                HybridCertificateValidator.extractPQCExtensions(certificate);

        assertThat(extracted).containsOnlyKeys(CATALYST_OIDS);

        for (String oid : CATALYST_OIDS) {
            Extension extension = extracted.get(oid);

            // The single most direct guard against double-wrapping: the Extension rebuilt from the
            // certificate must serialise back to exactly the bytes the certificate carries.
            assertThat(extension.getExtnValue().getEncoded(ASN1Encoding.DER))
                    .as("extnValue round trip for %s", oid)
                    .isEqualTo(certificate.getExtensionValue(oid));

            // getParsedValue() must yield the real content, never a nested OCTET STRING.
            assertThat(extension.getParsedValue())
                    .as("parsed value for %s must not be a nested OCTET STRING", oid)
                    .isNotInstanceOf(org.bouncycastle.asn1.ASN1OctetString.class);
        }

        // subjectAltPublicKeyInfo (2.5.29.72) stays non-critical regardless of the 73/74 setting.
        assertThat(extracted.get(AlgorithmOIDRegistry.OID_ALT_SIGNATURE_ALGORITHM).isCritical())
                .isEqualTo(altCritical);
        assertThat(extracted.get(AlgorithmOIDRegistry.OID_ALT_SIGNATURE_VALUE).isCritical())
                .isEqualTo(altCritical);
        assertThat(extracted.get(AlgorithmOIDRegistry.OID_SUBJECT_ALT_PUBLIC_KEY_INFO).isCritical())
                .isFalse();
    }

    @Test
    @DisplayName("a certificate without the Catalyst extensions yields an empty map and no structure")
    void certificateWithoutExtensionsYieldsNothing() throws Exception {
        PQCHybridCertificateAPI api = new PQCHybridCertificateAPI();
        api.initialize();

        HybridAlgorithmPair pair = HybridAlgorithmPair.recommended(192);
        HybridKeyPair keyPair = api.generateHybridKeyPair(pair);
        HybridCertificateConfig config = HybridCertificateConfig.builder()
                .withAlgorithmPair(pair)
                .withSubjectDN("CN=classical.example.com")
                .withIssuerDN("CN=classical.example.com")
                .withValidityDays(365)
                .build();

        X509Certificate classicalOnly = HybridX509CertificateBuilder.builder(config, keyPair)
                .withPQCExtensions(false)
                .build();

        assertThat(HybridCertificateValidator.extractPQCExtensions(classicalOnly)).isEmpty();
        assertThat(api.getCertificateInfo(classicalOnly, keyPair).getPQCExtensions()).isNull();
    }
}
