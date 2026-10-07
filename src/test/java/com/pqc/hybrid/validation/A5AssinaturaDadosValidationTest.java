package com.pqc.hybrid.validation;

import com.pqc.hybrid.core.config.HybridAlgorithmPair;
import com.pqc.hybrid.core.keygen.HybridKeyPair;
import com.pqc.hybrid.core.signature.HybridSignatureManager;
import com.pqc.hybrid.core.signature.HybridSignaturePair;
import com.pqc.hybrid.core.util.printer.SignaturePrinter;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Área 5 — assinatura de dados arbitrários.
 *
 * <p>Records the hybrid envelope and its two halves, the AND-logic behaviour under tampering,
 * and the domain separation the FIPS 204 context string provides.
 *
 * @author PQC Hybrid Team
 * @version 1.0.0-BETA
 */
@DisplayName("Área 5 — assinatura de dados")
class A5AssinaturaDadosValidationTest extends ValidationTestBase {

    private static final String AREA = "05-assinatura-dados";
    private static final byte[] DADOS =
            "Documento critico que exige protecao por dois algoritmos independentes."
                    .getBytes(StandardCharsets.UTF_8);

    @Test
    @DisplayName("o envelope híbrido separa as duas assinaturas por um prefixo de tamanho")
    void envelope_hibrido() throws Exception {
        HybridAlgorithmPair par = HybridAlgorithmPair.recommended(192);
        HybridKeyPair chaves = api.generateHybridKeyPair(par);

        byte[] envelope = api.signData(DADOS, chaves);
        assertThat(api.verifySignature(DADOS, envelope, chaves)).isTrue();

        // Formato: [4 bytes BE com o tamanho da clássica][clássica][PQC].
        ByteBuffer buffer = ByteBuffer.wrap(envelope);
        int tamanhoClassica = buffer.getInt();
        byte[] classica = new byte[tamanhoClassica];
        buffer.get(classica);
        byte[] pqc = new byte[envelope.length - Integer.BYTES - tamanhoClassica];
        buffer.get(pqc);

        assertThat(tamanhoClassica)
                .as("a assinatura ECDSA tem tamanho variável e precisa do prefixo explícito")
                .isBetween(64, 160);
        assertThat(pqc)
                .as("assinatura ML-DSA-65 tem 3309 bytes segundo o FIPS 204")
                .hasSize(3309);

        HybridSignaturePair pares = HybridSignatureManager.sign(DADOS, chaves);
        SignaturePrinter printer = new SignaturePrinter();

        evidencia.caso(AREA, "envelope-hibrido", "Envelope de assinatura híbrida")
                .nota("Par de algoritmos", par.getDescription())
                .nota("Dados assinados", DADOS.length + " bytes")
                .nota("Envelope completo", envelope.length + " bytes")
                .nota("Prefixo de tamanho", Integer.BYTES + " bytes (big-endian)")
                .nota("Assinatura clássica", tamanhoClassica + " bytes")
                .nota("Assinatura ML-DSA-65", pqc.length + " bytes")
                .nota("Sobrecarga sobre a clássica isolada",
                        String.format("%.1fx", (double) envelope.length / tamanhoClassica))
                .bytes("dados-assinados.bin", DADOS)
                .bytes("envelope.bin", envelope)
                .bytes("assinatura-classica.bin", classica)
                .bytes("assinatura-pqc.bin", pqc)
                .texto("envelope.hex", hex(envelope, 32))
                .texto("relatorio-assinatura.txt", printer.formatHybridSignature(pares))
                .texto("comparacao.txt", printer.formatSignatureComparison(pares))
                .texto("estatisticas.txt", printer.formatSignatureStatistics(pares))
                .encerra();
    }

    @Test
    @DisplayName("a lógica E rejeita adulteração do dado e de qualquer uma das metades")
    void logica_e_sob_adulteracao() throws Exception {
        HybridAlgorithmPair par = HybridAlgorithmPair.recommended(192);
        HybridKeyPair chaves = api.generateHybridKeyPair(par);
        byte[] envelope = api.signData(DADOS, chaves);

        byte[] dadoAdulterado = DADOS.clone();
        dadoAdulterado[0] ^= 0x01;

        ByteBuffer buffer = ByteBuffer.wrap(envelope);
        int tamanhoClassica = buffer.getInt();

        byte[] classicaCorrompida = envelope.clone();
        classicaCorrompida[Integer.BYTES + tamanhoClassica - 1] ^= 0x01;

        byte[] pqcCorrompida = envelope.clone();
        pqcCorrompida[envelope.length - 1] ^= 0x01;

        boolean original = api.verifySignature(DADOS, envelope, chaves);
        boolean comDadoAdulterado = api.verifySignature(dadoAdulterado, envelope, chaves);
        boolean comClassicaCorrompida = api.verifySignature(DADOS, classicaCorrompida, chaves);
        boolean comPqcCorrompida = api.verifySignature(DADOS, pqcCorrompida, chaves);

        assertThat(original).isTrue();
        assertThat(comDadoAdulterado).as("um bit alterado no dado invalida o conjunto").isFalse();
        assertThat(comClassicaCorrompida)
                .as("corromper apenas a metade clássica já invalida o conjunto").isFalse();
        assertThat(comPqcCorrompida)
                .as("corromper apenas a metade pós-quântica já invalida o conjunto").isFalse();

        evidencia.caso(AREA, "logica-e-adulteracao", "Verificação sob lógica E e detecção de adulteração")
                .nota("Assinatura íntegra", resultado(original))
                .nota("Dado com 1 bit alterado", resultado(comDadoAdulterado))
                .nota("Metade clássica corrompida", resultado(comClassicaCorrompida))
                .nota("Metade pós-quântica corrompida", resultado(comPqcCorrompida))
                .texto("A verificação exige as duas metades: comprometer apenas uma delas não")
                .texto("basta para produzir um resultado positivo. É a propriedade que sustenta")
                .texto("a defesa em profundidade do modelo híbrido.")
                .bytes("envelope-integro.bin", envelope)
                .bytes("envelope-classica-corrompida.bin", classicaCorrompida)
                .bytes("envelope-pqc-corrompida.bin", pqcCorrompida)
                .bytes("dado-adulterado.bin", dadoAdulterado)
                .encerra();
    }

    @Test
    @DisplayName("o contexto FIPS 204 separa domínios de uso da mesma chave")
    void separacao_por_contexto() throws Exception {
        HybridAlgorithmPair par = HybridAlgorithmPair.recommended(192);
        HybridKeyPair chaves = api.generateHybridKeyPair(par);

        byte[] ctxFaturamento = "faturamento".getBytes(StandardCharsets.UTF_8);
        byte[] ctxAuditoria = "auditoria".getBytes(StandardCharsets.UTF_8);

        byte[] comContexto = api.signData(DADOS, chaves, ctxFaturamento);
        byte[] semContexto = api.signData(DADOS, chaves);

        boolean mesmoContexto = api.verifySignature(DADOS, comContexto, chaves, ctxFaturamento);
        boolean outroContexto = api.verifySignature(DADOS, comContexto, chaves, ctxAuditoria);
        boolean nenhumContexto = api.verifySignature(DADOS, comContexto, chaves);
        boolean semCtxComCtx = api.verifySignature(DADOS, semContexto, chaves, ctxFaturamento);

        assertThat(mesmoContexto).isTrue();
        assertThat(outroContexto).as("contexto diferente não pode verificar").isFalse();
        assertThat(nenhumContexto).as("ausência de contexto não pode verificar").isFalse();
        assertThat(semCtxComCtx).as("assinatura sem contexto não verifica sob um").isFalse();

        evidencia.caso(AREA, "separacao-por-contexto", "Separação de domínio pelo contexto FIPS 204")
                .nota("Contexto usado na assinatura", "\"faturamento\"")
                .nota("Verifica com \"faturamento\"", resultado(mesmoContexto))
                .nota("Verifica com \"auditoria\"", resultado(outroContexto))
                .nota("Verifica sem contexto", resultado(nenhumContexto))
                .nota("Assinatura sem contexto, verificada com um", resultado(semCtxComCtx))
                .nota("Limite do contexto", "255 bytes, imposto pelo provedor")
                .texto("O contexto é vinculado à metade pós-quântica: RSA e ECDSA não têm")
                .texto("parâmetro equivalente. Como a verificação exige as duas metades, o par")
                .texto("como um todo fica separado por domínio.")
                .bytes("envelope-ctx-faturamento.bin", comContexto)
                .bytes("envelope-sem-contexto.bin", semContexto)
                .bytes("contexto-faturamento.bin", ctxFaturamento)
                .encerra();
    }

    @Test
    @DisplayName("a via clássica isolada continua conferível para compatibilidade")
    void verificacao_apenas_classica() throws Exception {
        HybridAlgorithmPair par = HybridAlgorithmPair.recommended(192);
        HybridKeyPair chaves = api.generateHybridKeyPair(par);
        HybridSignaturePair pares = HybridSignatureManager.sign(DADOS, chaves);

        boolean hibrida = HybridSignatureManager.verify(DADOS, pares, chaves);
        boolean apenasClassica = HybridSignatureManager.verifyClassicalOnly(DADOS, pares, chaves);

        assertThat(hibrida).isTrue();
        assertThat(apenasClassica).isTrue();

        evidencia.caso(AREA, "verificacao-apenas-classica",
                        "Conferência isolada da metade clássica")
                .nota("Verificação híbrida (E)", resultado(hibrida))
                .nota("Verificação apenas clássica", resultado(apenasClassica))
                .nota("Algoritmo clássico", pares.getClassicalAlgorithm())
                .nota("Algoritmo pós-quântico", pares.getPQCAlgorithm())
                .texto("verifyClassicalOnly existe para conferir a compatibilidade com a via")
                .texto("clássica. Note que ela não herda a separação por contexto, que é")
                .texto("propriedade da metade pós-quântica.")
                .bytes("assinatura-classica.bin", pares.getClassicalSignature())
                .bytes("assinatura-pqc.bin", pares.getPQCSignature())
                .encerra();
    }

    private static String resultado(boolean valido) {
        return valido ? "VÁLIDA" : "INVÁLIDA";
    }
}
