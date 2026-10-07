package com.pqc.hybrid.validation;

import com.pqc.hybrid.core.certificate.HybridCertificateValidator;
import com.pqc.hybrid.core.certificate.HybridCertificateValidator.HybridChainValidationResult;
import com.pqc.hybrid.core.certificate.HybridSigner;
import com.pqc.hybrid.core.certificate.HybridX509CertificateBuilder;
import com.pqc.hybrid.core.certificate.ValidationPolicy;
import com.pqc.hybrid.core.certificate.ValidationReason;
import com.pqc.hybrid.core.config.ClassicalAlgorithm;
import com.pqc.hybrid.core.config.HybridAlgorithmPair;
import com.pqc.hybrid.core.config.HybridCertificateConfig;
import com.pqc.hybrid.core.config.PQCAlgorithm;
import com.pqc.hybrid.core.keygen.HybridKeyPair;

import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertPathValidator;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Área 9 — a política da parte confiante decide o veredito.
 *
 * <p>Reproduz, no ambiente deste trabalho, o achado de Kim et al.: um verificador legado aceita
 * um certificado híbrido pela parte clássica mesmo quando a parte pós-quântica está ausente,
 * inválida ou fora do que a parte confiante admite. Os certificados adversariais são assinados
 * com a chave clássica <em>verdadeira</em> da AC — a posição de um atacante que quebrou a
 * componente clássica.
 *
 * <p>Os veredictos do JDK e do OpenSSL são <b>medidos e registrados</b>, não presumidos; apenas
 * o comportamento da biblioteca é afirmado pelo teste.
 */
@DisplayName("Área 9 — política de validação")
class A9PoliticaValidacaoValidationTest extends ValidationTestBase {

    private static final String AREA = "09-politica-validacao";
    private static final String DN_CA = "CN=AC Raiz Politica,O=TCC,C=BR";
    private static final String DN_FOLHA = "CN=folha.politica.exemplo,O=TCC,C=BR";

    private static final ValidationPolicy SO_65_E_87 =
            ValidationPolicy.requireBoth(EnumSet.of(PQCAlgorithm.ML_DSA_65, PQCAlgorithm.ML_DSA_87));

    /** Um cenário da matriz: a cadeia apresentada e o que a biblioteca deve decidir. */
    private record Cenario(String id, String titulo, X509Certificate folha, X509Certificate raiz,
                           boolean strictAceita, boolean restritaAceita,
                           ValidationReason.Code motivoEsperado) {
    }

    /** Veredito de um verificador para um cenário. */
    private record Veredito(boolean aceita, String detalhe) {
        String rotulo() {
            return aceita ? "aceita" : "rejeita";
        }
    }

    @Test
    @DisplayName("matriz: verificadores legados aceitam pela parte clássica, a política rejeita")
    void matriz_de_politica() throws Exception {
        List<Cenario> cenarios = montaCenarios();
        boolean opensslDisponivel = OpensslRunner.available();

        List<String[]> linhas = new ArrayList<>();
        for (Cenario c : cenarios) {
            List<X509Certificate> cadeia = List.of(c.folha(), c.raiz());

            Veredito jdk = jdkPkix(c);
            Veredito openssl = opensslDisponivel ? opensslVerify(c) : new Veredito(false, "indisponivel");
            HybridChainValidationResult strict = HybridCertificateValidator.validateHybridChain(cadeia);
            HybridChainValidationResult restrita =
                    HybridCertificateValidator.validateHybridChain(cadeia, SO_65_E_87);
            HybridChainValidationResult classica =
                    HybridCertificateValidator.validateHybridChain(cadeia, ValidationPolicy.classicalOnly());

            // Apenas a biblioteca é afirmada; JDK e OpenSSL são medidos e registrados.
            assertThat(strict.accepted()).as("strict() em %s", c.id()).isEqualTo(c.strictAceita());
            assertThat(restrita.accepted()).as("REQUIRE_BOTH {65,87} em %s", c.id())
                    .isEqualTo(c.restritaAceita());
            assertThat(classica.accepted()).as("CLASSICAL_ONLY em %s", c.id()).isTrue();
            assertThat(classica.classicalValid()).as("parte clássica íntegra em %s", c.id()).isTrue();
            if (c.motivoEsperado() != null) {
                assertThat(restrita.reasons()).extracting(ValidationReason::code)
                        .contains(c.motivoEsperado());
            }

            linhas.add(new String[] {c.titulo(), jdk.rotulo(),
                    opensslDisponivel ? openssl.rotulo() : "n/d",
                    rotulo(strict), rotulo(restrita), rotulo(classica), motivos(restrita)});

            evidencia.caso(AREA, c.id(), c.titulo())
                    .nota("JDK PKIX (sem BouncyCastle)", jdk.rotulo())
                    .nota("openssl verify", opensslDisponivel ? openssl.rotulo() : "indisponivel")
                    .nota("Biblioteca strict()", rotulo(strict))
                    .nota("Biblioteca REQUIRE_BOTH {ML-DSA-65, ML-DSA-87}", rotulo(restrita))
                    .nota("Biblioteca CLASSICAL_ONLY", rotulo(classica))
                    .nota("Dimensão clássica (diagnóstico)", String.valueOf(restrita.classicalValid()))
                    .nota("Dimensão pós-quântica (diagnóstico)", String.valueOf(restrita.pqcValid()))
                    .nota("Motivos (REQUIRE_BOTH {65,87})", motivos(restrita))
                    .texto("jdk-pkix.txt", jdk.detalhe() + "\n")
                    .texto("openssl-verify.txt", openssl.detalhe() + "\n")
                    .texto("motivos-strict.txt", strict.reasons().toString() + "\n")
                    .texto("motivos-restrita.txt", restrita.reasons().toString() + "\n")
                    .bytes("folha.der", exporter.exportCertificateToDERBytes(c.folha()))
                    .bytes("raiz.der", exporter.exportCertificateToDERBytes(c.raiz()))
                    .encerra();
        }

        var resumo = evidencia.caso(AREA, "matriz", "Matriz: verificadores legados × política da biblioteca")
                .nota("Versão do OpenSSL", OpensslRunner.version())
                .nota("Política restrita", "REQUIRE_BOTH {ML-DSA-65, ML-DSA-87}");
        resumo.texto("matriz.txt", tabela(linhas));
        resumo.texto("Todos os certificados adversariais têm assinatura clássica válida, produzida")
                .texto("com a chave clássica verdadeira da AC. JDK e OpenSSL foram executados e seus")
                .texto("veredictos registrados; apenas o comportamento da biblioteca é afirmado.")
                .encerra();
    }

    // ------------------------------------------------------------------ cenários

    private List<Cenario> montaCenarios() throws Exception {
        HybridAlgorithmPair par192 = HybridAlgorithmPair.recommended(192); // ECDSA P-384 + ML-DSA-65
        HybridKeyPair chavesCa = api.generateHybridKeyPair(par192);
        X509Certificate raiz = raizAutoassinada(par192, chavesCa, DN_CA);
        HybridKeyPair chavesFolha = api.generateHybridKeyPair(par192);
        HybridKeyPair chavesAtacante = api.generateHybridKeyPair(par192);

        HybridAlgorithmPair par128 = HybridAlgorithmPair.recommended(128); // ECDSA P-256 + ML-DSA-44
        HybridKeyPair chavesCa44 = api.generateHybridKeyPair(par128);
        X509Certificate raiz44 = raizAutoassinada(par128, chavesCa44, DN_CA);
        HybridKeyPair chavesFolha44 = api.generateHybridKeyPair(par128);

        return List.of(
                new Cenario("integro", "Íntegro",
                        folha(par192, chavesFolha, HybridSigner.of(classico(chavesCa), pqc(chavesCa)), raiz),
                        raiz, true, true, null),
                new Cenario("assinadores-misturados",
                        "Assinadores misturados (clássica da AC + ML-DSA do atacante)",
                        folha(par192, chavesFolha, HybridSigner.of(classico(chavesCa), pqc(chavesAtacante)), raiz),
                        raiz, false, false, ValidationReason.Code.ALT_SIGNATURE_INVALID),
                new Cenario("stripping", "Stripping (só clássico, chave da AC)",
                        folha(par192, chavesFolha, HybridSigner.classicalOnly(classico(chavesCa)), raiz),
                        raiz, false, false, ValidationReason.Code.ALT_EXTENSIONS_MISSING),
                new Cenario("algoritmo-fora-da-lista", "Algoritmo alternativo fora da lista (ML-DSA-44)",
                        folha(par128, chavesFolha44, HybridSigner.of(classico(chavesCa44), pqc(chavesCa44)), raiz44),
                        raiz44, true, false, ValidationReason.Code.ALT_ALGORITHM_NOT_ALLOWED));
    }

    private static X509Certificate folha(HybridAlgorithmPair par, HybridKeyPair sujeito, HybridSigner assinador,
                                         X509Certificate emissor) throws Exception {
        HybridCertificateConfig config = HybridCertificateConfig.builder()
                .withAlgorithmPair(par)
                .withSubjectDN(DN_FOLHA)
                .withIssuerDN(DN_CA)
                .withValidityDays(365)
                .build();
        PublicKey pqcSujeito = assinador.hasPqc() ? sujeito.getPQCPublicKey() : null;
        return HybridX509CertificateBuilder.build(config, sujeito.getClassicalPublicKey(), pqcSujeito,
                assinador, emissor);
    }

    private static ContentSigner classico(HybridKeyPair chaves) throws Exception {
        return assinador(ClassicalAlgorithm.getSignatureAlgorithmForKey(chaves.getClassicalPublicKey()),
                chaves.getClassicalPrivateKey());
    }

    private static ContentSigner pqc(HybridKeyPair chaves) throws Exception {
        return assinador(chaves.getPQCAlgorithm(), chaves.getPQCPrivateKey());
    }

    private static ContentSigner assinador(String algoritmo, PrivateKey chave) throws Exception {
        return new JcaContentSignerBuilder(algoritmo).setProvider("BC").build(chave);
    }

    // ------------------------------------------------------------------ verificadores legados

    /** PKIX com os provedores padrão do JDK: sem BouncyCastle e sem verificador de extensões. */
    private static Veredito jdkPkix(Cenario c) {
        try {
            CertificateFactory fabrica = CertificateFactory.getInstance("X.509");
            PKIXParameters parametros = new PKIXParameters(Set.of(new TrustAnchor(c.raiz(), null)));
            parametros.setRevocationEnabled(false);
            CertPathValidator validador = CertPathValidator.getInstance("PKIX");
            validador.validate(fabrica.generateCertPath(List.of(c.folha())), parametros);
            return new Veredito(true, "CertPathValidator(" + validador.getProvider().getName()
                    + ").validate: OK");
        } catch (Exception e) {
            return new Veredito(false, e.getClass().getSimpleName() + ": " + e.getMessage());
        }
    }

    private Veredito opensslVerify(Cenario c) throws Exception {
        Path dir = Files.createTempDirectory("a9-openssl-");
        try {
            Path raiz = dir.resolve("raiz.pem");
            Path folha = dir.resolve("folha.pem");
            Files.writeString(raiz, exporter.exportCertificateToPEMString(c.raiz()), StandardCharsets.US_ASCII);
            Files.writeString(folha, exporter.exportCertificateToPEMString(c.folha()), StandardCharsets.US_ASCII);
            OpensslRunner.Result r = OpensslRunner.run("openssl", "verify", "-CAfile", raiz.toString(),
                    folha.toString());
            String saida = r.output().replace(dir.toString(), "<tmp>").strip();
            return new Veredito(r.ok(), "exit=" + r.exitCode() + "\n" + saida);
        } finally {
            try (var arquivos = Files.list(dir)) {
                for (Path p : (Iterable<Path>) arquivos::iterator) {
                    Files.deleteIfExists(p);
                }
            }
            Files.deleteIfExists(dir);
        }
    }

    // ------------------------------------------------------------------ formatação

    private static String rotulo(HybridChainValidationResult r) {
        return r.accepted() ? "aceita" : "rejeita";
    }

    private static String motivos(HybridChainValidationResult r) {
        if (r.reasons().isEmpty()) {
            return "—";
        }
        return r.reasons().stream()
                .map(m -> m.code() + "@" + m.chainIndex())
                .collect(Collectors.joining(", "));
    }

    private static String tabela(List<String[]> linhas) {
        String[] cabecalho = {"Cenário", "JDK PKIX", "openssl verify", "strict()",
                "REQUIRE_BOTH {65,87}", "CLASSICAL_ONLY", "Motivo (REQUIRE_BOTH {65,87})"};
        int[] larguras = new int[cabecalho.length];
        for (int i = 0; i < cabecalho.length; i++) {
            larguras[i] = cabecalho[i].length();
            for (String[] l : linhas) {
                larguras[i] = Math.max(larguras[i], l[i].length());
            }
        }
        StringBuilder sb = new StringBuilder();
        linha(sb, cabecalho, larguras);
        String[] separador = new String[cabecalho.length];
        for (int i = 0; i < separador.length; i++) {
            separador[i] = "-".repeat(larguras[i]);
        }
        linha(sb, separador, larguras);
        for (String[] l : linhas) {
            linha(sb, l, larguras);
        }
        return sb.toString();
    }

    private static void linha(StringBuilder sb, String[] celulas, int[] larguras) {
        sb.append("| ");
        for (int i = 0; i < celulas.length; i++) {
            sb.append(String.format("%-" + larguras[i] + "s", celulas[i])).append(" | ");
        }
        sb.setLength(sb.length() - 1);
        sb.append('\n');
    }
}
