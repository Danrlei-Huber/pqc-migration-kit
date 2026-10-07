package com.pqc.hybrid.core.benchmark;

import com.pqc.hybrid.core.certificate.HybridCertificateAuthority;
import com.pqc.hybrid.core.certificate.HybridCertificateValidator;
import com.pqc.hybrid.core.certificate.HybridCertificateValidator.HybridChainValidationResult;
import com.pqc.hybrid.core.certificate.HybridX509CertificateBuilder;
import com.pqc.hybrid.core.certificate.ValidationPolicy;
import com.pqc.hybrid.core.config.ClassicalAlgorithm;
import com.pqc.hybrid.core.config.CryptographicProviderFactory;
import com.pqc.hybrid.core.config.HybridAlgorithmPair;
import com.pqc.hybrid.core.config.HybridCertificateConfig;
import com.pqc.hybrid.core.keygen.HybridKeyGenerator;
import com.pqc.hybrid.core.keygen.HybridKeyPair;

import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.Warmup;

import java.security.KeyPair;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * Cost of the hybrid operations against their classical-only baseline, for each recommended
 * security level (ECDSA P-256/P-384/P-521 paired with ML-DSA-44/65/87).
 *
 * <p>Each primitive is measured on its own (classical and ML-DSA key generation, signing and
 * verification over 1 KiB) and at certificate level: issuing a leaf from a CA and validating a
 * two-certificate chain, both with and without the Catalyst extensions. The classical-only
 * certificate rows are the baseline for the cost of hybridisation.
 *
 * <p>Run with {@code java -cp <test classpath> org.openjdk.jmh.Main HybridOperationsBenchmark}.
 */
@State(Scope.Benchmark)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MICROSECONDS)
@Warmup(iterations = 5, time = 1)
@Measurement(iterations = 5, time = 1)
@Fork(value = 3, jvmArgs = {"-Xms512m", "-Xmx1024m"})
public class HybridOperationsBenchmark {

    @Param({"128", "192", "256"})
    public int nivel;

    private static final byte[] DADOS = new byte[1024];

    private ClassicalAlgorithm classico;
    private String algoritmoAssinaturaClassica;
    private String algoritmoPqc;

    private KeyPair parClassico;
    private KeyPair parPqc;
    private byte[] assinaturaClassica;
    private byte[] assinaturaPqc;

    private HybridKeyPair chavesAc;
    private HybridKeyPair chavesFolha;
    private HybridCertificateAuthority acHibrida;
    private HybridCertificateAuthority acClassica;
    private HybridCertificateConfig configFolha;
    private List<X509Certificate> cadeiaHibrida;
    private List<X509Certificate> cadeiaClassica;

    @Setup(Level.Trial)
    public void preparar() throws Exception {
        CryptographicProviderFactory.initialize();
        java.util.logging.Logger.getLogger("com.pqc.hybrid").setLevel(java.util.logging.Level.WARNING);
        new java.util.Random(42).nextBytes(DADOS);

        HybridAlgorithmPair par = HybridAlgorithmPair.recommended(nivel);
        classico = par.classicalAlgorithm();
        algoritmoPqc = par.pqcAlgorithm().getName();

        parClassico = HybridKeyGenerator.generateClassicalKeyPair(classico);
        parPqc = HybridKeyGenerator.generatePQCKeyPair(par.pqcAlgorithm());
        algoritmoAssinaturaClassica = ClassicalAlgorithm.getSignatureAlgorithmForKey(parClassico.getPublic());
        assinaturaClassica = assinar(algoritmoAssinaturaClassica, parClassico, DADOS);
        assinaturaPqc = assinar(algoritmoPqc, parPqc, DADOS);

        chavesAc = HybridKeyGenerator.generate(par);
        chavesFolha = HybridKeyGenerator.generate(par);
        String dnAc = "CN=Benchmark Root CA,O=TCC,C=BR";
        HybridCertificateConfig configAc = HybridCertificateConfig.builder()
                .withAlgorithmPair(par).withSubjectDN(dnAc).withIssuerDN(dnAc)
                .withValidityDays(3650).asCertificateAuthority(true).build();
        configFolha = HybridCertificateConfig.builder()
                .withAlgorithmPair(par).withSubjectDN("CN=folha.benchmark,O=TCC,C=BR").withIssuerDN(dnAc)
                .withValidityDays(365).build();

        acHibrida = HybridCertificateAuthority.createRoot(configAc, chavesAc);
        X509Certificate raizClassica = HybridX509CertificateBuilder.builder(configAc, chavesAc)
                .withPQCExtensions(false).build();
        acClassica = new HybridCertificateAuthority(chavesAc, raizClassica);

        cadeiaHibrida = List.of(acHibrida.issueCertificate(configFolha, chavesFolha), acHibrida.getCertificate());
        cadeiaClassica = List.of(emitirClassico(), raizClassica);

        // Sanity: a benchmark that measures a failing path would be meaningless.
        check(HybridCertificateValidator.validateHybridChain(cadeiaHibrida).accepted(), "hybrid chain");
        check(HybridCertificateValidator.validateHybridChain(cadeiaClassica, ValidationPolicy.classicalOnly())
                .accepted(), "classical chain");
        check(verificar(algoritmoPqc, parPqc, DADOS, assinaturaPqc), "ML-DSA signature");
        check(verificar(algoritmoAssinaturaClassica, parClassico, DADOS, assinaturaClassica), "classical signature");
    }

    // ------------------------------------------------------------------ primitives

    @Benchmark
    public KeyPair geracaoChavesClassica() {
        return HybridKeyGenerator.generateClassicalKeyPair(classico);
    }

    @Benchmark
    public KeyPair geracaoChavesMlDsa() {
        return HybridKeyGenerator.generatePQCKeyPair(HybridAlgorithmPair.recommended(nivel).pqcAlgorithm());
    }

    @Benchmark
    public byte[] assinaturaClassica() throws Exception {
        return assinar(algoritmoAssinaturaClassica, parClassico, DADOS);
    }

    @Benchmark
    public byte[] assinaturaMlDsa() throws Exception {
        return assinar(algoritmoPqc, parPqc, DADOS);
    }

    @Benchmark
    public boolean verificacaoClassica() throws Exception {
        return verificar(algoritmoAssinaturaClassica, parClassico, DADOS, assinaturaClassica);
    }

    @Benchmark
    public boolean verificacaoMlDsa() throws Exception {
        return verificar(algoritmoPqc, parPqc, DADOS, assinaturaPqc);
    }

    // ------------------------------------------------------------------ certificates

    @Benchmark
    public X509Certificate emissaoHibrida() throws Exception {
        return acHibrida.issueCertificate(configFolha, chavesFolha);
    }

    @Benchmark
    public X509Certificate emissaoClassica() throws Exception {
        return emitirClassico();
    }

    @Benchmark
    public HybridChainValidationResult validacaoCadeiaHibrida() {
        return HybridCertificateValidator.validateHybridChain(cadeiaHibrida);
    }

    @Benchmark
    public HybridChainValidationResult validacaoCadeiaClassica() {
        return HybridCertificateValidator.validateHybridChain(cadeiaClassica, ValidationPolicy.classicalOnly());
    }

    // ------------------------------------------------------------------ helpers

    private X509Certificate emitirClassico() throws Exception {
        return HybridX509CertificateBuilder.builder(configFolha, chavesFolha)
                .withIssuer(chavesAc, acClassica.getCertificate())
                .withPQCExtensions(false)
                .build();
    }

    private static byte[] assinar(String algoritmo, KeyPair par, byte[] dados) throws Exception {
        Signature s = Signature.getInstance(algoritmo, "BC");
        s.initSign(par.getPrivate());
        s.update(dados);
        return s.sign();
    }

    private static boolean verificar(String algoritmo, KeyPair par, byte[] dados, byte[] assinatura)
            throws Exception {
        Signature s = Signature.getInstance(algoritmo, "BC");
        s.initVerify(par.getPublic());
        s.update(dados);
        return s.verify(assinatura);
    }

    private static void check(boolean condition, String what) {
        if (!condition) {
            throw new IllegalStateException("Benchmark setup invalid: " + what + " does not verify");
        }
    }
}
