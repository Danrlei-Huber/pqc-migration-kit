package com.pqc.hybrid.validation;

import com.pqc.hybrid.core.config.HybridAlgorithmPair;
import com.pqc.hybrid.core.keygen.HybridKeyPair;
import com.pqc.hybrid.core.signature.HybridSignatureManager;
import com.pqc.hybrid.core.signature.HybridSignaturePair;
import com.pqc.hybrid.core.util.printer.CertificatePrinter;
import com.pqc.hybrid.core.util.printer.HybridCertificateInspector;
import com.pqc.hybrid.core.util.printer.KeyInfoPrinter;
import com.pqc.hybrid.core.util.printer.SignaturePrinter;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Área 7 — exportação e inspeção.
 *
 * <p>Records that PEM and DER carry the same certificate, saves the four printer reports
 * verbatim, and documents the deliberate absence of private key export.
 *
 * @author PQC Hybrid Team
 * @version 1.0.0-BETA
 */
@DisplayName("Área 7 — exportação e inspeção")
class A7ExportacaoInspecaoValidationTest extends ValidationTestBase {

    private static final String AREA = "07-exportacao-inspecao";

    @Test
    @DisplayName("PEM e DER carregam exatamente o mesmo certificado")
    void pem_equivale_a_der() throws Exception {
        HybridAlgorithmPair par = HybridAlgorithmPair.recommended(192);
        HybridKeyPair chaves = api.generateHybridKeyPair(par);
        X509Certificate cert = raizAutoassinada(par, chaves, "CN=exportacao.tcc.br,O=TCC,C=BR");

        byte[] der = exporter.exportCertificateToDERBytes(cert);
        String pem = exporter.exportCertificateToPEMString(cert);

        // Decodifica o PEM de volta e compara com o DER, byte a byte.
        String base64 = pem.replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "")
                .replaceAll("\\s", "");
        byte[] derDoPem = Base64.getDecoder().decode(base64);

        assertThat(derDoPem)
                .as("o PEM deve decodificar exatamente para os mesmos bytes do DER")
                .isEqualTo(der);
        assertThat(der).isEqualTo(cert.getEncoded());

        // E o DER precisa reconstruir um certificado equivalente.
        X509Certificate reconstruido = (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(der));
        assertThat(reconstruido).isEqualTo(cert);

        evidencia.caso(AREA, "pem-equivale-der", "Equivalência entre as saídas PEM e DER")
                .nota("Certificado em DER", der.length + " bytes")
                .nota("Certificado em PEM", pem.getBytes(StandardCharsets.US_ASCII).length
                        + " bytes (base64 com envelope)")
                .nota("PEM decodificado == DER", "sim, byte a byte")
                .nota("DER reconstrói o certificado", "sim")
                .nota("SHA-256 do DER", EvidenceRecorder.sha256(der))
                .bytes("certificado.der", der)
                .texto("certificado.pem", pem)
                .encerra();
    }

    @Test
    @DisplayName("a exportação de chave privada não é oferecida pela biblioteca")
    void chave_privada_nao_e_exportavel() {
        // O CertificateExporter expõe apenas exportação de certificado. A ausência de um
        // caminho para material privado é uma decisão de projeto, e a campanha registra isso
        // como propriedade verificada e não como omissão.
        var metodos = com.pqc.hybrid.core.util.export.CertificateExporter.class.getMethods();
        boolean exportaPrivada = false;
        StringBuilder assinaturas = new StringBuilder();
        for (var metodo : metodos) {
            if (metodo.getDeclaringClass() != Object.class) {
                assinaturas.append("  ").append(metodo.getReturnType().getSimpleName())
                        .append(' ').append(metodo.getName()).append('\n');
                String nome = metodo.getName().toLowerCase();
                exportaPrivada |= nome.contains("private") || nome.contains("key");
            }
        }

        assertThat(exportaPrivada)
                .as("nenhum método do exportador deve tratar chave privada")
                .isFalse();

        evidencia.caso(AREA, "sem-exportacao-de-chave-privada",
                        "Ausência deliberada de exportação de chave privada")
                .nota("Formatos suportados", "PEM e DER, apenas para certificados")
                .nota("Métodos que tratam chave privada", "nenhum")
                .texto("api-do-exportador.txt",
                        "Métodos públicos de CertificateExporter:\n" + assinaturas)
                .texto("A decisão reduz o risco de exposição indevida de material criptográfico.")
                .texto("Em produção, a chave privada permanece no HSM/KMS e chega à biblioteca")
                .texto("apenas como ContentSigner, pela Layer 1.")
                .encerra();
    }

    @Test
    @DisplayName("os quatro relatórios de inspeção são gerados sobre os objetos reais")
    void relatorios_de_inspecao() {
        HybridAlgorithmPair par = HybridAlgorithmPair.recommended(192);
        HybridKeyPair chaves = api.generateHybridKeyPair(par);
        X509Certificate cert = raizAutoassinada(par, chaves, "CN=inspecao.tcc.br,O=TCC,C=BR");
        HybridSignaturePair assinaturas = HybridSignatureManager.sign(
                "conteudo inspecionado".getBytes(StandardCharsets.UTF_8), chaves);

        HybridCertificateInspector inspetor = new HybridCertificateInspector();
        CertificatePrinter certPrinter = new CertificatePrinter();
        KeyInfoPrinter keyPrinter = new KeyInfoPrinter();
        SignaturePrinter sigPrinter = new SignaturePrinter();

        String inspecao = inspetor.inspectCertificateToString(cert);

        assertThat(inspetor.isHybridCertificate(cert))
                .as("o inspetor deve reconhecer o certificado como híbrido")
                .isTrue();
        // O relatório nomeia as extensões alternativas em vez de imprimir os OIDs crus.
        assertThat(inspecao).contains(
                "HYBRID SIGNATURE DETECTED",
                "Alternative Signature Value (detected)",
                "Alternative Public Key Info (detected)",
                "ML-DSA-65");

        evidencia.caso(AREA, "relatorios-de-inspecao", "Relatórios produzidos pelos inspetores")
                .nota("Reconhecido como híbrido", String.valueOf(inspetor.isHybridCertificate(cert)))
                .nota("Chave pública", keyPrinter.formatKeyCompact(chaves.getClassicalPublicKey()))
                .nota("Tamanho total das assinaturas", sigPrinter.getReadableSize(assinaturas))
                .texto("inspecao-hibrida.txt", inspecao)
                .texto("certificado.txt", certPrinter.formatCertificate(cert))
                .texto("certificado-compacto.txt", certPrinter.formatCompact(cert))
                .texto("chave-publica-classica.txt",
                        keyPrinter.formatPublicKeyDetails(chaves.getClassicalPublicKey()))
                .texto("chave-publica-pqc.txt", keyPrinter.formatKey(chaves.getPQCPublicKey()))
                .texto("assinaturas.txt", sigPrinter.formatHybridSignature(assinaturas))
                .texto("assinaturas-comparacao.txt",
                        sigPrinter.formatSignatureComparison(assinaturas))
                .encerra();
    }

    @Test
    @DisplayName("o gravador de evidência recusa nomes que sugiram material privado")
    void gravador_recusa_material_privado() {
        var caso = evidencia.caso(AREA, "guarda-material-privado",
                "Salvaguarda contra gravação de material privado");

        assertThatThrownBy(() -> caso.bytes("chave.key", new byte[]{1}))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("apenas material publico");
        assertThatThrownBy(() -> caso.bytes("chave-privada.der", new byte[]{1}))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> caso.bytes("private-key.pem", new byte[]{1}))
                .isInstanceOf(IllegalArgumentException.class);

        caso.nota("Extensões recusadas", ".key, .p12, .pkcs8, .jks")
            .nota("Nomes recusados", "qualquer um contendo \"private\" ou \"privada\"")
            .texto("A campanha grava em diretório versionado, então a salvaguarda é ativa e não")
            .texto("apenas convencional: uma tentativa de gravar material privado falha em vez")
            .texto("de produzir um segredo commitável. O .gitignore mantém os padrões de chave")
            .texto("privada ignorados como segunda linha de defesa.")
            .encerra();
    }
}
