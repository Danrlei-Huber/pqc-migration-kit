package com.pqc.hybrid.core.certificate;

import com.pqc.hybrid.core.BaseTest;
import com.pqc.hybrid.core.config.CryptographicProviderFactory;
import com.pqc.hybrid.core.config.HybridAlgorithmPair;
import com.pqc.hybrid.core.config.HybridCertificateConfig;
import com.pqc.hybrid.core.keygen.HybridKeyGenerator;
import com.pqc.hybrid.core.keygen.HybridKeyPair;
import com.pqc.hybrid.core.util.export.CertificateExporter;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.*;

/**
 * Verifies the claim the whole Catalyst migration strategy rests on: a hybrid certificate whose
 * alternative-signature extensions are non-critical is accepted by verifiers that know nothing
 * about post-quantum cryptography.
 *
 * <p>The evidence has to come from outside this library, so two independent verifiers are used,
 * neither of which understands the Catalyst extensions:
 *
 * <ul>
 *   <li>the JDK's own {@link CertPathValidator}, running plain PKIX with the default providers
 *       and <b>without</b> the {@code HybridExtensionChecker} that
 *       {@link HybridCertificateValidator} installs to tolerate those extensions;</li>
 *   <li>the {@code openssl verify} command line, when an OpenSSL binary is available.</li>
 * </ul>
 *
 * <p>Each acceptance test is paired with a negative control that issues the same certificates
 * with the extensions marked critical. RFC 5280 §4.2 requires a conforming verifier to reject a
 * certificate carrying an unrecognised critical extension, so the controls must fail — otherwise
 * the acceptance tests would pass for the wrong reason and prove nothing.
 *
 * @author PQC Hybrid Team
 * @version 1.0.0-BETA
 */
@DisplayName("Legacy verifier compatibility")
class LegacyVerifierCompatibilityTest extends BaseTest {

    private static final HybridAlgorithmPair PAIR = HybridAlgorithmPair.recommended(192);
    private static final String ROOT_DN = "CN=PQC Hybrid Root CA,O=TCC,C=BR";
    private static final String LEAF_DN = "CN=secure.example.com,O=TCC,C=BR";

    @TempDir
    Path workDir;

    private HybridKeyPair rootKeyPair;
    private HybridKeyPair leafKeyPair;

    @BeforeAll
    static void setUpAll() {
        CryptographicProviderFactory.initialize();
    }

    @BeforeEach
    public void setUp() {
        rootKeyPair = HybridKeyGenerator.generate(PAIR);
        leafKeyPair = HybridKeyGenerator.generate(PAIR);
    }

    // ---------------------------------------------------------------- fixtures

    /** Issues a self-signed hybrid root plus a leaf signed by it, with the given criticality. */
    private Chain issueChain(boolean altExtensionsCritical) {
        HybridCertificateConfig rootConfig = HybridCertificateConfig.builder()
                .withAlgorithmPair(PAIR)
                .withSubjectDN(ROOT_DN)
                .withIssuerDN(ROOT_DN)
                .withValidityDays(3650)
                .asCertificateAuthority(true)
                .withAltSignatureExtensionsCritical(altExtensionsCritical)
                .build();
        X509Certificate root = HybridX509CertificateBuilder.builder(rootConfig, rootKeyPair)
                .withPQCExtensions(true)
                .build();

        HybridCertificateConfig leafConfig = HybridCertificateConfig.builder()
                .withAlgorithmPair(PAIR)
                .withSubjectDN(LEAF_DN)
                .withIssuerDN(ROOT_DN)
                .withValidityDays(365)
                .withAltSignatureExtensionsCritical(altExtensionsCritical)
                .build();
        X509Certificate leaf = HybridX509CertificateBuilder.builder(leafConfig, leafKeyPair)
                .withIssuer(rootKeyPair, root)
                .withPQCExtensions(true)
                .build();

        return new Chain(root, leaf);
    }

    private record Chain(X509Certificate root, X509Certificate leaf) {
    }

    // ---------------------------------------------------------------- JDK PKIX

    /**
     * Runs plain PKIX with the JDK's default providers — no BouncyCastle, and no
     * {@code HybridExtensionChecker} to declare the Catalyst extensions handled.
     */
    private static void validateWithPlainJdkPkix(Chain chain) throws Exception {
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        CertPath path = factory.generateCertPath(List.of(chain.leaf()));

        PKIXParameters parameters = new PKIXParameters(Set.of(new TrustAnchor(chain.root(), null)));
        parameters.setRevocationEnabled(false);

        CertPathValidator.getInstance("PKIX").validate(path, parameters);
    }

    @Test
    @DisplayName("the JDK's plain PKIX validator accepts non-critical alt-signature extensions")
    void jdkPkixAcceptsNonCriticalExtensions() {
        Chain chain = issueChain(false);

        assertThatCode(() -> validateWithPlainJdkPkix(chain))
                .as("a purely classical verifier must ignore the Catalyst extensions "
                        + "and accept the certificate on its classical signature")
                .doesNotThrowAnyException();
    }

    @Test
    @DisplayName("negative control: the JDK's plain PKIX validator rejects them when critical")
    void jdkPkixRejectsCriticalExtensions() {
        Chain chain = issueChain(true);

        assertThatThrownBy(() -> validateWithPlainJdkPkix(chain))
                .as("RFC 5280 obliges a conforming verifier to reject unrecognised critical extensions")
                .isInstanceOf(CertPathValidatorException.class)
                .hasMessageContaining("critical extension");
    }

    // ---------------------------------------------------------------- OpenSSL

    @Test
    @DisplayName("openssl verify accepts a hybrid certificate with non-critical extensions")
    void opensslAcceptsNonCriticalExtensions() throws Exception {
        assumeOpensslAvailable();
        Chain chain = issueChain(false);
        Path rootPem = writePem(chain.root(), "root.pem");
        Path leafPem = writePem(chain.leaf(), "leaf.pem");

        ProcessResult result = run("openssl", "verify",
                "-CAfile", rootPem.toString(), leafPem.toString());

        assertThat(result.exitCode())
                .as("openssl rejected the certificate: %s", result.output())
                .isZero();
        assertThat(result.output()).contains("OK");
    }

    @Test
    @DisplayName("negative control: openssl verify rejects them when critical")
    void opensslRejectsCriticalExtensions() throws Exception {
        assumeOpensslAvailable();
        Chain chain = issueChain(true);
        Path rootPem = writePem(chain.root(), "root-critical.pem");
        Path leafPem = writePem(chain.leaf(), "leaf-critical.pem");

        ProcessResult result = run("openssl", "verify",
                "-CAfile", rootPem.toString(), leafPem.toString());

        assertThat(result.exitCode())
                .as("openssl accepted a certificate with unhandled critical extensions: %s",
                        result.output())
                .isNotZero();
        assertThat(result.output()).contains("unhandled critical extension");
    }

    @Test
    @DisplayName("openssl parses the certificate and sees the three Catalyst extensions as non-critical")
    void opensslReportsExtensionsAsNonCritical() throws Exception {
        assumeOpensslAvailable();
        Chain chain = issueChain(false);
        Path leafPem = writePem(chain.leaf(), "leaf-text.pem");

        ProcessResult result = run("openssl", "x509", "-in", leafPem.toString(), "-noout", "-text");

        assertThat(result.exitCode()).isZero();
        // Present, and none of them followed by the "critical" marker OpenSSL prints inline.
        assertThat(result.output()).contains("2.5.29.72", "2.5.29.73", "2.5.29.74");
        assertThat(result.output()).doesNotContain("2.5.29.72: critical",
                "2.5.29.73: critical", "2.5.29.74: critical");
    }

    // ---------------------------------------------------------------- helpers

    private Path writePem(X509Certificate certificate, String fileName) throws IOException {
        Path path = workDir.resolve(fileName);
        Files.writeString(path,
                new CertificateExporter().exportCertificateToPEMString(certificate),
                StandardCharsets.US_ASCII);
        return path;
    }

    private static void assumeOpensslAvailable() {
        boolean available;
        try {
            available = run("openssl", "version").exitCode() == 0;
        } catch (Exception e) {
            available = false;
        }
        Assumptions.assumeTrue(available,
                "openssl is not available on this machine; external-verifier check skipped");
    }

    private static ProcessResult run(String... command) throws IOException, InterruptedException {
        Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
        String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        if (!process.waitFor(60, TimeUnit.SECONDS)) {
            process.destroyForcibly();
            throw new IOException("Timed out running: " + String.join(" ", command));
        }
        return new ProcessResult(process.exitValue(), output);
    }

    private record ProcessResult(int exitCode, String output) {
    }
}
