package com.pqc.hybrid.validation;

import com.pqc.hybrid.core.certificate.HybridCertificateValidator;
import com.pqc.hybrid.core.certificate.HybridX509CertificateBuilder;
import com.pqc.hybrid.core.config.HybridAlgorithmPair;
import com.pqc.hybrid.core.config.HybridCertificateConfig;
import com.pqc.hybrid.core.keygen.HybridKeyPair;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.cert.X509Certificate;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Área 6 — validação de certificados e cadeias.
 *
 * <p>Records the {@code ValidationResult} for the happy path and for every failure mode the
 * library is expected to catch. A validator is only as good as what it rejects, so the failure
 * cases carry as much evidential weight as the successful one.
 *
 * @author PQC Hybrid Team
 * @version 1.0.0-BETA
 */
@DisplayName("Área 6 — validação")
class A6ValidacaoValidationTest extends ValidationTestBase {

    private static final String AREA = "06-validacao";
    private static final HybridAlgorithmPair PAR = HybridAlgorithmPair.recommended(192);
    private static final String DN_CA = "CN=Validacao Root CA,O=TCC,C=BR";
    private static final String DN_FOLHA = "CN=folha.tcc.br,O=TCC,C=BR";

    @Test
    @DisplayName("o caminho feliz aprova em todas as verificações")
    void caminho_feliz() {
        HybridKeyPair chavesCa = api.generateHybridKeyPair(PAR);
        X509Certificate certCa = raizAutoassinada(PAR, chavesCa, DN_CA);
        HybridKeyPair chavesFolha = api.generateHybridKeyPair(PAR);
        X509Certificate folha = folhaEmitidaPor(PAR, chavesCa, certCa, chavesFolha, DN_FOLHA);

        var resultado = api.validateCertificateAgainstIssuer(folha, certCa);

        assertThat(resultado.isAllValid()).isTrue();
        assertThat(resultado.isHybridFullyValid()).isTrue();

        evidencia.caso(AREA, "caminho-feliz", "Certificado legítimo validado contra o emissor")
                .nota("Não expirado", String.valueOf(resultado.isNotExpiredValid()))
                .nota("DNs e encadeamento", String.valueOf(resultado.isDnsValid()))
                .nota("Período de validade", String.valueOf(resultado.isValidityPeriodValid()))
                .nota("Chave pública", String.valueOf(resultado.isPublicKeyValid()))
                .nota("Assinatura clássica", String.valueOf(resultado.isSignatureValid()))
                .nota("Extensões PQC", String.valueOf(resultado.isPqcExtensionsValid()))
                .nota("Assinatura alternativa", String.valueOf(resultado.isPqcSignatureValid()))
                .nota("Veredito global", String.valueOf(resultado.isAllValid()))
                .texto("validation-result.txt", resultado.toString())
                .bytes("folha.der", exporter.exportCertificateToDERBytes(folha))
                .bytes("emissor.der", exporter.exportCertificateToDERBytes(certCa))
                .encerra();
    }

    @Test
    @DisplayName("cada modo de falha é detectado e registrado")
    void modos_de_falha() {
        HybridKeyPair chavesCa = api.generateHybridKeyPair(PAR);
        X509Certificate certCa = raizAutoassinada(PAR, chavesCa, DN_CA);
        HybridKeyPair chavesFolha = api.generateHybridKeyPair(PAR);
        X509Certificate folha = folhaEmitidaPor(PAR, chavesCa, certCa, chavesFolha, DN_FOLHA);

        HybridKeyPair chavesEstranhas = api.generateHybridKeyPair(PAR);
        X509Certificate outraCa = raizAutoassinada(PAR, chavesEstranhas, "CN=Outra CA,O=TCC,C=BR");

        // 1) Emissor errado: nomes, assinatura clássica e alternativa devem falhar juntos.
        var emissorErrado = api.validateCertificateAgainstIssuer(folha, outraCa);
        assertThat(emissorErrado.isDnsValid()).isFalse();
        assertThat(emissorErrado.isSignatureValid()).isFalse();
        assertThat(emissorErrado.isPqcSignatureValid()).isFalse();

        // 2) Chave pública de emissor errada.
        var chaveErrada = api.validateCertificate(folha,
                chavesEstranhas.getClassicalPublicKey());
        assertThat(chaveErrada.isSignatureValid()).isFalse();

        // 3) Sem chave de emissor: só a autoassinatura é conferível, e a folha não é autoassinada.
        var semEmissor = api.validateCertificate(folha, null);
        assertThat(semEmissor.isSignatureValid())
                .as("nenhuma assinatura foi conferida, logo nenhuma pode ser dada como válida")
                .isFalse();

        // 4) Certificado sem as extensões Catalyst.
        X509Certificate classicoApenas = HybridX509CertificateBuilder.builder(
                        HybridCertificateConfig.builder()
                                .withAlgorithmPair(PAR)
                                .withSubjectDN(DN_FOLHA)
                                .withIssuerDN(DN_FOLHA)
                                .withValidityDays(365)
                                .build(), chavesFolha)
                .withPQCExtensions(false).build();
        assertThat(HybridCertificateValidator.validatePQCExtensions(classicoApenas)).isFalse();
        var semExtensoes = api.validateCertificateAgainstIssuer(classicoApenas, classicoApenas);
        assertThat(semExtensoes.isPqcExtensionsValid()).isFalse();
        assertThat(semExtensoes.isPqcSignatureValid()).isFalse();
        assertThat(semExtensoes.isAllValid()).isFalse();

        evidencia.caso(AREA, "modos-de-falha", "Modos de falha detectados pela validação")
                .nota("Emissor errado — DNs", String.valueOf(emissorErrado.isDnsValid()))
                .nota("Emissor errado — assinatura clássica",
                        String.valueOf(emissorErrado.isSignatureValid()))
                .nota("Emissor errado — assinatura alternativa",
                        String.valueOf(emissorErrado.isPqcSignatureValid()))
                .nota("Chave pública de emissor errada",
                        String.valueOf(chaveErrada.isSignatureValid()))
                .nota("Sem chave de emissor (folha emitida por CA)",
                        String.valueOf(semEmissor.isSignatureValid()))
                .nota("Certificado sem extensões Catalyst — extensões",
                        String.valueOf(semExtensoes.isPqcExtensionsValid()))
                .nota("Certificado sem extensões Catalyst — assinatura alternativa",
                        String.valueOf(semExtensoes.isPqcSignatureValid()))
                .texto("emissor-errado.txt", emissorErrado.toString())
                .texto("chave-emissor-errada.txt", chaveErrada.toString())
                .texto("sem-chave-de-emissor.txt", semEmissor.toString())
                .texto("sem-extensoes-catalyst.txt", semExtensoes.toString())
                .bytes("certificado-sem-extensoes.der",
                        exporter.exportCertificateToDERBytes(classicoApenas))
                .encerra();
    }

    @Test
    @DisplayName("a cadeia é avaliada em duas dimensões independentes")
    void cadeia_em_duas_dimensoes() {
        HybridKeyPair chavesCa = api.generateHybridKeyPair(PAR);
        X509Certificate certCa = raizAutoassinada(PAR, chavesCa, DN_CA);
        HybridKeyPair chavesFolha = api.generateHybridKeyPair(PAR);
        X509Certificate folha = folhaEmitidaPor(PAR, chavesCa, certCa, chavesFolha, DN_FOLHA);

        var resultado = api.validateCertificateChain(List.of(folha, certCa));

        assertThat(resultado.classicalValid()).isTrue();
        assertThat(resultado.pqcValid()).isTrue();
        assertThat(resultado.isValid()).isTrue();

        evidencia.caso(AREA, "cadeia-duas-dimensoes",
                        "Validação de cadeia nas dimensões clássica e pós-quântica")
                .nota("Elos da cadeia", "2 (folha → raiz)")
                .nota("Dimensão clássica (CertPathValidator PKIX)",
                        String.valueOf(resultado.classicalValid()))
                .nota("Dimensão pós-quântica (alt-signature por elo)",
                        String.valueOf(resultado.pqcValid()))
                .nota("Veredito global", String.valueOf(resultado.isValid()))
                .texto("As duas dimensões são calculadas de forma independente e combinadas por")
                .texto("conjunção: a cadeia só é válida quando ambas passam. A dimensão")
                .texto("pós-quântica percorre cada elo verificando a assinatura alternativa")
                .texto("contra a chave alternativa do emissor, sobre o pre-TBS reconstruído.")
                .bytes("folha.der", exporter.exportCertificateToDERBytes(folha))
                .bytes("raiz.der", exporter.exportCertificateToDERBytes(certCa))
                .encerra();
    }
}
