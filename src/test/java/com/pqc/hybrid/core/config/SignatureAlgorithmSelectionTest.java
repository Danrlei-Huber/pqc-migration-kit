package com.pqc.hybrid.core.config;

import com.pqc.hybrid.core.BaseTest;
import com.pqc.hybrid.core.api.PQCHybridCertificateAPI;
import com.pqc.hybrid.core.exception.AlgorithmNotSupportedException;
import com.pqc.hybrid.core.keygen.HybridKeyGenerator;
import com.pqc.hybrid.core.keygen.HybridKeyPair;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.security.KeyPair;
import java.security.cert.X509Certificate;

import static org.assertj.core.api.Assertions.*;

/**
 * Regression tests for the selection of the classical signature algorithm.
 *
 * <p>The digest must be chosen from the <em>key</em>, not from the bare algorithm name: a
 * name-only lookup returns the first declared variant, which silently signs every EC curve with
 * SHA-256. That downgrade breaks the security-level balance the recommended hybrid pairs are
 * built on — a "192-bit" pair whose classical half is capped at SHA-256 is not a 192-bit pair.
 *
 * @author PQC Hybrid Team
 * @version 1.0.0-BETA
 */
@DisplayName("Classical signature algorithm selection")
class SignatureAlgorithmSelectionTest extends BaseTest {

    @BeforeAll
    static void setUpAll() {
        CryptographicProviderFactory.initialize();
    }

    @ParameterizedTest(name = "{0} key signs with {1}")
    @CsvSource({
            "RSA_2048,   SHA256withRSA",
            "RSA_3072,   SHA256withRSA",
            "RSA_4096,   SHA512withRSA",
            "ECDSA_P256, SHA256withECDSA",
            "ECDSA_P384, SHA384withECDSA",
            "ECDSA_P521, SHA512withECDSA"
    })
    @DisplayName("resolves the signature algorithm from actual key material")
    void resolvesSignatureAlgorithmFromKey(ClassicalAlgorithm algorithm, String expectedSigAlg) {
        KeyPair keyPair = HybridKeyGenerator.generateClassicalKeyPair(algorithm);

        assertThat(ClassicalAlgorithm.getSignatureAlgorithmForKey(keyPair.getPublic()))
                .isEqualTo(expectedSigAlg);
        assertThat(ClassicalAlgorithm.getSignatureAlgorithmForKey(keyPair.getPrivate()))
                .isEqualTo(expectedSigAlg);
        assertThat(ClassicalAlgorithm.fromKey(keyPair.getPublic())).isEqualTo(algorithm);
        assertThat(ClassicalAlgorithm.fromKey(keyPair.getPrivate())).isEqualTo(algorithm);
    }

    @ParameterizedTest(name = "{0}-bit pair issues a certificate signed with {1}")
    @CsvSource({
            "128, SHA256WITHECDSA",
            "192, SHA384WITHECDSA",
            "256, SHA512WITHECDSA"
    })
    @DisplayName("issued certificate carries a digest matching the key strength")
    void certificateDigestMatchesKeyStrength(int securityLevel, String expectedSigAlgName)
            throws Exception {
        PQCHybridCertificateAPI api = new PQCHybridCertificateAPI();
        api.initialize();

        HybridAlgorithmPair pair = HybridAlgorithmPair.recommended(securityLevel);
        HybridKeyPair keyPair = api.generateHybridKeyPair(pair);
        HybridCertificateConfig config = HybridCertificateConfig.builder()
                .withAlgorithmPair(pair)
                .withSubjectDN("CN=level" + securityLevel + ".example.com")
                .withIssuerDN("CN=level" + securityLevel + ".example.com")
                .withValidityDays(365)
                .build();

        X509Certificate certificate = api.generateHybridCertificate(config, keyPair);

        assertThat(certificate.getSigAlgName()).isEqualToIgnoringCase(expectedSigAlgName);
        // The certificate must still verify under the digest it declares.
        assertThatCode(() -> certificate.verify(keyPair.getClassicalPublicKey()))
                .doesNotThrowAnyException();
    }

    @Test
    @DisplayName("a P-384 key is never signed with SHA-256")
    void p384IsNotDowngradedToSha256() {
        KeyPair keyPair = HybridKeyGenerator.generateClassicalKeyPair(ClassicalAlgorithm.ECDSA_P384);

        assertThat(ClassicalAlgorithm.getSignatureAlgorithmForKey(keyPair.getPublic()))
                .isNotEqualTo(ClassicalAlgorithm.ECDSA_P256.getSignatureAlgorithm())
                .isEqualTo("SHA384withECDSA");
    }

    @Test
    @DisplayName("standalone hybrid signatures round-trip on every classical variant")
    void hybridSignatureRoundTripsOnEveryVariant() throws Exception {
        PQCHybridCertificateAPI api = new PQCHybridCertificateAPI();
        api.initialize();
        byte[] data = "hybrid signature payload".getBytes();

        for (ClassicalAlgorithm algorithm : ClassicalAlgorithm.values()) {
            HybridKeyPair keyPair = api.generateHybridKeyPair(
                    new HybridAlgorithmPair(algorithm, PQCAlgorithm.ML_DSA_44));

            byte[] signature = api.signData(data, keyPair);

            assertThat(api.verifySignature(data, signature, keyPair))
                    .as("round trip for %s", algorithm)
                    .isTrue();
        }
    }

    @Test
    @DisplayName("rejects a key outside the supported RSA/ECDSA variants")
    void rejectsUnsupportedKey() throws Exception {
        // Ed25519 is a valid signing key, but not one of the six supported classical variants.
        KeyPair ed25519 = java.security.KeyPairGenerator
                .getInstance("Ed25519", CryptographicProviderFactory.getProvider())
                .generateKeyPair();

        assertThat(ClassicalAlgorithm.fromKey(ed25519.getPublic())).isNull();
        assertThatThrownBy(() -> ClassicalAlgorithm.getSignatureAlgorithmForKey(ed25519.getPublic()))
                .isInstanceOf(AlgorithmNotSupportedException.class)
                .hasMessageContaining("RSA-2048/3072/4096");
    }

    @Test
    @DisplayName("rejects an RSA key whose modulus is not a supported size")
    void rejectsUnsupportedRsaModulus() throws Exception {
        java.security.KeyPairGenerator kpg = java.security.KeyPairGenerator
                .getInstance("RSA", CryptographicProviderFactory.getProvider());
        kpg.initialize(1024);
        KeyPair weak = kpg.generateKeyPair();

        assertThat(ClassicalAlgorithm.fromKey(weak.getPublic())).isNull();
        assertThatThrownBy(() -> ClassicalAlgorithm.getSignatureAlgorithmForKey(weak.getPublic()))
                .isInstanceOf(AlgorithmNotSupportedException.class)
                .hasMessageContaining("RSA-1024");
    }
}
