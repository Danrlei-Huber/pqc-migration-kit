package com.pqc.hybrid.validation;

import com.pqc.hybrid.core.api.PQCHybridCertificateAPI;
import com.pqc.hybrid.core.certificate.HybridX509CertificateBuilder;
import com.pqc.hybrid.core.config.CryptographicProviderFactory;
import com.pqc.hybrid.core.config.HybridAlgorithmPair;
import com.pqc.hybrid.core.config.HybridCertificateConfig;
import com.pqc.hybrid.core.keygen.HybridKeyPair;
import com.pqc.hybrid.core.util.export.CertificateExporter;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayNameGeneration;
import org.junit.jupiter.api.DisplayNameGenerator;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.api.extension.TestInstancePostProcessor;

import java.security.cert.X509Certificate;

/**
 * Base class for the module validation campaign.
 *
 * <p>Every subclass is tagged {@code validacao}, which keeps it out of the default build: the
 * campaign writes into the versioned {@code evidencias/} directory, so running it on every
 * {@code mvn test} would dirty the working tree. Run it deliberately with
 * {@code mvn test -Pvalidacao}.
 *
 * <p>Subclasses both <b>assert</b> the behaviour described in the module functionality summary
 * and <b>record</b> the raw bytes that back the assertion. The assertion is what makes this a
 * validation rather than a report generator: a regression fails the run instead of quietly
 * producing wrong evidence.
 *
 * @author PQC Hybrid Team
 * @version 1.0.0-BETA
 */
@Tag("validacao")
@DisplayNameGeneration(DisplayNameGenerator.ReplaceUnderscores.class)
@ExtendWith(ValidationTestBase.EvidenceExtension.class)
public abstract class ValidationTestBase {

    /** Session-wide evidence recorder, injected before the test instance runs. */
    protected EvidenceRecorder evidencia;

    /** Facade under validation, initialised fresh for each test. */
    protected PQCHybridCertificateAPI api;

    /** Exports certificates to PEM/DER; the library's own supported output path. */
    protected final CertificateExporter exporter = new CertificateExporter();

    @BeforeEach
    void inicializaApi() {
        CryptographicProviderFactory.initialize();
        api = new PQCHybridCertificateAPI();
        api.initialize();
    }

    // ------------------------------------------------------------------ fixtures

    /** Issues a self-signed hybrid CA certificate for the given pair and DN. */
    protected X509Certificate raizAutoassinada(HybridAlgorithmPair par, HybridKeyPair chaves,
                                               String dn) {
        HybridCertificateConfig config = HybridCertificateConfig.builder()
                .withAlgorithmPair(par)
                .withSubjectDN(dn)
                .withIssuerDN(dn)
                .withValidityDays(3650)
                .asCertificateAuthority(true)
                .build();
        return HybridX509CertificateBuilder.builder(config, chaves).withPQCExtensions(true).build();
    }

    /** Issues an end-entity certificate signed by the given issuer. */
    protected X509Certificate folhaEmitidaPor(HybridAlgorithmPair par, HybridKeyPair chavesEmissor,
                                              X509Certificate certEmissor,
                                              HybridKeyPair chavesSujeito, String dn) {
        HybridCertificateConfig config = HybridCertificateConfig.builder()
                .withAlgorithmPair(par)
                .withSubjectDN(dn)
                .withIssuerDN(certEmissor.getSubjectX500Principal().getName())
                .withValidityDays(365)
                .build();
        return HybridX509CertificateBuilder.builder(config, chavesSujeito)
                .withIssuer(chavesEmissor, certEmissor)
                .withPQCExtensions(true)
                .build();
    }

    /** @return a hex rendering of {@code data}, wrapped for readability in a report. */
    protected static String hex(byte[] data, int bytesPorLinha) {
        StringBuilder sb = new StringBuilder(data.length * 3);
        for (int i = 0; i < data.length; i++) {
            sb.append(String.format("%02x", data[i]));
            if ((i + 1) % bytesPorLinha == 0) {
                sb.append('\n');
            } else if (i + 1 < data.length) {
                sb.append(' ');
            }
        }
        if (data.length % bytesPorLinha != 0) {
            sb.append('\n');
        }
        return sb.toString();
    }

    // ------------------------------------------------------------------ extension

    /**
     * Injects the session-wide {@link EvidenceRecorder} into each validation test instance.
     *
     * <p>Resolving it here, from the root {@link ExtensionContext}, is what registers the
     * recorder as a closeable session resource — the manifest is then flushed exactly once,
     * after the last class, instead of once per class as {@code @AfterAll} would do.
     */
    static final class EvidenceExtension implements TestInstancePostProcessor {

        @Override
        public void postProcessTestInstance(Object testInstance, ExtensionContext context) {
            if (testInstance instanceof ValidationTestBase base) {
                base.evidencia = EvidenceRecorder.forSession(context);
            }
        }
    }
}
