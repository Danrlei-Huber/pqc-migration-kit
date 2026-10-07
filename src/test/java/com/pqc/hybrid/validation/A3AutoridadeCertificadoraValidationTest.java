package com.pqc.hybrid.validation;

import com.pqc.hybrid.core.certificate.HybridCertificateAuthority;
import com.pqc.hybrid.core.certificate.HybridCertificateValidator;
import com.pqc.hybrid.core.config.HybridAlgorithmPair;
import com.pqc.hybrid.core.config.HybridCertificateConfig;
import com.pqc.hybrid.core.keygen.HybridKeyPair;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Área 3 — operação como Autoridade Certificadora híbrida.
 *
 * <p>Builds a three-level chain (root → sub-CA → end entity), records every certificate plus
 * the concatenated chain, validates it in both dimensions, and — where an OpenSSL binary
 * exists — records the transcript of an external verifier accepting it.
 *
 * @author PQC Hybrid Team
 * @version 1.0.0-BETA
 */
@DisplayName("Área 3 — autoridade certificadora")
class A3AutoridadeCertificadoraValidationTest extends ValidationTestBase {

    private static final String AREA = "03-autoridade-certificadora";
    private static final HybridAlgorithmPair PAR = HybridAlgorithmPair.recommended(192);

    private static final String DN_RAIZ = "CN=PQC Hybrid Root CA,O=TCC,C=BR";
    private static final String DN_SUB = "CN=PQC Hybrid Issuing CA,O=TCC,C=BR";
    private static final String DN_FOLHA = "CN=secure.tcc.br,O=TCC,C=BR";

    @Test
    @DisplayName("uma cadeia raiz → sub-CA → folha valida nas duas dimensões")
    void cadeia_de_tres_niveis() throws Exception {
        HybridKeyPair chavesRaiz = api.generateHybridKeyPair(PAR);
        HybridCertificateAuthority raiz = api.createRootCA(
                configCA(DN_RAIZ, DN_RAIZ, 1), chavesRaiz);
        X509Certificate certRaiz = raiz.getCertificate();

        HybridKeyPair chavesSub = api.generateHybridKeyPair(PAR);
        X509Certificate certSub = api.issueCertificate(raiz, configCA(DN_SUB, DN_RAIZ, 0),
                chavesSub);

        HybridCertificateAuthority subCa = new HybridCertificateAuthority(chavesSub, certSub);
        HybridKeyPair chavesFolha = api.generateHybridKeyPair(PAR);
        X509Certificate certFolha = api.issueCertificate(subCa,
                HybridCertificateConfig.builder()
                        .withAlgorithmPair(PAR)
                        .withSubjectDN(DN_FOLHA)
                        .withIssuerDN(DN_SUB)
                        .withValidityDays(365)
                        .withSubjectAltNames(List.of("secure.tcc.br", "www.tcc.br"))
                        .build(),
                chavesFolha);

        List<X509Certificate> cadeia = List.of(certFolha, certSub, certRaiz);
        var resultado = api.validateCertificateChain(cadeia);

        assertThat(resultado.classicalValid()).as("dimensão clássica (PKIX)").isTrue();
        assertThat(resultado.pqcValid()).as("dimensão pós-quântica (alt-signature)").isTrue();
        assertThat(resultado.isValid()).isTrue();

        // Cada elo também precisa fechar isoladamente contra o seu emissor.
        assertThat(api.validateCertificateAgainstIssuer(certFolha, certSub).isAllValid()).isTrue();
        assertThat(api.validateCertificateAgainstIssuer(certSub, certRaiz).isAllValid()).isTrue();
        assertThat(api.validateCertificateAgainstIssuer(certRaiz, certRaiz).isAllValid()).isTrue();

        String pemRaiz = exporter.exportCertificateToPEMString(certRaiz);
        String pemSub = exporter.exportCertificateToPEMString(certSub);
        String pemFolha = exporter.exportCertificateToPEMString(certFolha);

        var caso = evidencia.caso(AREA, "cadeia-tres-niveis",
                        "Cadeia híbrida raiz → sub-CA → entidade final")
                .nota("Par de algoritmos", PAR.getDescription())
                .nota("Raiz", certRaiz.getSubjectX500Principal().getName())
                .nota("Sub-CA", certSub.getSubjectX500Principal().getName())
                .nota("Entidade final", certFolha.getSubjectX500Principal().getName())
                .nota("basicConstraints da raiz", "CA:TRUE, pathLen=1")
                .nota("basicConstraints da sub-CA", "CA:TRUE, pathLen=0")
                .nota("Validação clássica (PKIX)", String.valueOf(resultado.classicalValid()))
                .nota("Validação pós-quântica", String.valueOf(resultado.pqcValid()))
                .bytes("raiz.der", exporter.exportCertificateToDERBytes(certRaiz))
                .bytes("subca.der", exporter.exportCertificateToDERBytes(certSub))
                .bytes("folha.der", exporter.exportCertificateToDERBytes(certFolha))
                .texto("raiz.pem", pemRaiz)
                .texto("subca.pem", pemSub)
                .texto("folha.pem", pemFolha)
                .texto("cadeia.pem", pemFolha + pemSub + pemRaiz);

        if (OpensslRunner.available()) {
            Path ancora = caso.dir().resolve("raiz.pem");
            Path intermediarios = caso.dir().resolve("subca.pem");
            Path folha = caso.dir().resolve("folha.pem");
            var verify = OpensslRunner.run("openssl", "verify",
                    "-CAfile", ancora.toString(),
                    "-untrusted", intermediarios.toString(),
                    folha.toString());
            assertThat(verify.ok())
                    .as("um verificador externo deve aceitar a cadeia: %s", verify.output())
                    .isTrue();
            caso.texto("openssl-verify.txt",
                    "$ openssl verify -CAfile raiz.pem -untrusted subca.pem folha.pem\n"
                            + verify.output() + "exit=" + verify.exitCode() + "\n");
            caso.nota("openssl verify", "aceita (exit 0)");
        } else {
            caso.nota("openssl verify", "não executado: binário ausente");
        }
        caso.encerra();
    }

    @Test
    @DisplayName("a cadeia é rejeitada quando um elo é substituído por outro emissor")
    void cadeia_quebrada_e_rejeitada() {
        HybridKeyPair chavesRaiz = api.generateHybridKeyPair(PAR);
        X509Certificate certRaiz = raizAutoassinada(PAR, chavesRaiz, DN_RAIZ);
        HybridKeyPair chavesFolha = api.generateHybridKeyPair(PAR);
        X509Certificate certFolha = folhaEmitidaPor(PAR, chavesRaiz, certRaiz, chavesFolha,
                DN_FOLHA);

        // Uma raiz diferente, com o mesmo DN, para simular a troca da âncora de confiança.
        HybridKeyPair chavesImpostora = api.generateHybridKeyPair(PAR);
        X509Certificate raizImpostora = raizAutoassinada(PAR, chavesImpostora, DN_RAIZ);

        var legitima = api.validateCertificateChain(List.of(certFolha, certRaiz));
        var forjada = api.validateCertificateChain(List.of(certFolha, raizImpostora));

        assertThat(legitima.isValid()).isTrue();
        assertThat(forjada.isValid())
                .as("a cadeia com âncora trocada não pode validar")
                .isFalse();
        assertThat(forjada.classicalValid()).isFalse();
        assertThat(forjada.pqcValid()).isFalse();

        evidencia.caso(AREA, "cadeia-com-ancora-trocada",
                        "Rejeição de cadeia cuja âncora foi substituída")
                .nota("DN das duas raízes", DN_RAIZ + " (idêntico)")
                .nota("Cadeia legítima", "clássica=" + legitima.classicalValid()
                        + ", pqc=" + legitima.pqcValid())
                .nota("Cadeia com raiz impostora", "clássica=" + forjada.classicalValid()
                        + ", pqc=" + forjada.pqcValid())
                .texto("Mesmo com o Distinguished Name idêntico, a substituição da âncora é")
                .texto("detectada nas duas dimensões: nem a assinatura clássica nem a")
                .texto("alternativa fecham contra o material da raiz impostora.")
                .bytes("raiz-legitima.der", exporter.exportCertificateToDERBytes(certRaiz))
                .bytes("raiz-impostora.der", exporter.exportCertificateToDERBytes(raizImpostora))
                .bytes("folha.der", exporter.exportCertificateToDERBytes(certFolha))
                .encerra();
    }

    @Test
    @DisplayName("o encadeamento de nomes é verificado contra o certificado do emissor")
    void encadeamento_de_nomes() {
        HybridKeyPair chavesRaiz = api.generateHybridKeyPair(PAR);
        X509Certificate certRaiz = raizAutoassinada(PAR, chavesRaiz, DN_RAIZ);
        HybridKeyPair chavesFolha = api.generateHybridKeyPair(PAR);
        X509Certificate certFolha = folhaEmitidaPor(PAR, chavesRaiz, certRaiz, chavesFolha,
                DN_FOLHA);

        HybridKeyPair outrasChaves = api.generateHybridKeyPair(PAR);
        X509Certificate outraCa = raizAutoassinada(PAR, outrasChaves, "CN=Outra CA,O=TCC,C=BR");

        assertThat(HybridCertificateValidator.validateIssuerLinkage(certFolha, certRaiz)).isTrue();
        assertThat(HybridCertificateValidator.validateIssuerLinkage(certFolha, outraCa)).isFalse();

        evidencia.caso(AREA, "encadeamento-de-nomes",
                        "Encadeamento de nomes conforme RFC 5280 §6.1.3(a)(4)")
                .nota("Emissor declarado na folha", certFolha.getIssuerX500Principal().getName())
                .nota("Sujeito da raiz legítima", certRaiz.getSubjectX500Principal().getName())
                .nota("Encadeia com a raiz legítima", "sim")
                .nota("Sujeito da outra CA", outraCa.getSubjectX500Principal().getName())
                .nota("Encadeia com a outra CA", "não")
                .texto("A comparação usa X500Principal.equals, que compara formas canônicas em")
                .texto("vez de strings cruas, de modo que codificações equivalentes do mesmo")
                .texto("nome são tratadas como iguais.")
                .encerra();
    }

    private static HybridCertificateConfig configCA(String sujeito, String emissor, int pathLen) {
        return HybridCertificateConfig.builder()
                .withAlgorithmPair(PAR)
                .withSubjectDN(sujeito)
                .withIssuerDN(emissor)
                .withValidityDays(3650)
                .asCertificateAuthority(true)
                .withPathLenConstraint(pathLen)
                .build();
    }

}
