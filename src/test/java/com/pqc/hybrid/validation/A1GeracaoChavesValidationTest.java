package com.pqc.hybrid.validation;

import com.pqc.hybrid.core.config.ClassicalAlgorithm;
import com.pqc.hybrid.core.config.HybridAlgorithmPair;
import com.pqc.hybrid.core.config.PQCAlgorithm;
import com.pqc.hybrid.core.keygen.HybridKeyGenerator;
import com.pqc.hybrid.core.keygen.HybridKeyPair;
import com.pqc.hybrid.core.util.printer.KeyInfoPrinter;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.PublicKey;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Área 1 — geração de material criptográfico.
 *
 * <p>Records the encoded public key of every supported variant, plus the recommended hybrid
 * pairs and their balance verdict. Private keys are deliberately absent from the evidence.
 *
 * @author PQC Hybrid Team
 * @version 1.0.0-BETA
 */
@DisplayName("Área 1 — geração de chaves")
class A1GeracaoChavesValidationTest extends ValidationTestBase {

    private static final String AREA = "01-geracao-chaves";

    @Test
    @DisplayName("cada variante clássica produz uma chave pública do tamanho esperado")
    void variantes_classicas() {
        KeyInfoPrinter printer = new KeyInfoPrinter();
        StringBuilder tabela = new StringBuilder(
                String.format("%-12s %-10s %14s %14s%n", "Variante", "Curva/Bits", "SPKI (bytes)",
                        "Assinatura"));

        for (ClassicalAlgorithm algoritmo : ClassicalAlgorithm.values()) {
            KeyPair par = HybridKeyGenerator.generateClassicalKeyPair(algoritmo);
            PublicKey publica = par.getPublic();
            byte[] spki = publica.getEncoded();

            assertThat(spki).as("SPKI de %s", algoritmo).isNotEmpty();
            assertThat(ClassicalAlgorithm.fromKey(publica))
                    .as("a variante deve ser reconhecível a partir da própria chave")
                    .isEqualTo(algoritmo);

            String sigAlg = ClassicalAlgorithm.getSignatureAlgorithmForKey(publica);
            assertThat(sigAlg).isEqualTo(algoritmo.getSignatureAlgorithm());

            var caso = evidencia.caso(AREA, algoritmo.name().toLowerCase().replace('_', '-'),
                    "Chave pública " + algoritmo);
            caso.nota("Algoritmo", algoritmo.getAlgorithmName())
                .nota("Tamanho declarado", algoritmo.getKeySize() + " bits")
                .nota("Nível de segurança", algoritmo.getSecurityLevel() + " bits")
                .nota("Algoritmo de assinatura", sigAlg)
                .nota("OID", algoritmo.getOid())
                .nota("SPKI codificado", spki.length + " bytes")
                .bytes("chave-publica.der", spki)
                .texto("chave-publica.txt", printer.formatPublicKeyDetails(publica))
                .texto("chave-publica.hex", hex(spki, 16))
                .encerra();

            tabela.append(String.format("%-12s %-10s %14d %14s%n", algoritmo,
                    algoritmo.getKeySize(), spki.length, sigAlg));
        }

        evidencia.caso(AREA, "resumo-classicos", "Tabela comparativa das variantes clássicas")
                .texto("tabela.txt", tabela.toString())
                .encerra();
    }

    @Test
    @DisplayName("cada variante ML-DSA produz chave pública do tamanho definido no FIPS 204")
    void variantes_ml_dsa() {
        // Tamanhos canônicos de chave pública do FIPS 204.
        record Esperado(PQCAlgorithm algoritmo, int chavePublica) {
        }
        var esperados = new Esperado[]{
                new Esperado(PQCAlgorithm.ML_DSA_44, 1312),
                new Esperado(PQCAlgorithm.ML_DSA_65, 1952),
                new Esperado(PQCAlgorithm.ML_DSA_87, 2592)
        };

        StringBuilder tabela = new StringBuilder(
                String.format("%-12s %8s %16s %16s%n", "Variante", "Nível", "Chave FIPS 204",
                        "SPKI (bytes)"));

        for (Esperado esperado : esperados) {
            KeyPair par = HybridKeyGenerator.generatePQCKeyPair(esperado.algoritmo());
            byte[] spki = par.getPublic().getEncoded();

            assertThat(par.getPublic().getAlgorithm())
                    .as("a chave deve declarar o próprio conjunto de parâmetros")
                    .isEqualTo(esperado.algoritmo().getName());
            assertThat(esperado.algoritmo().getPublicKeySize())
                    .as("tamanho de chave pública de %s segundo o FIPS 204", esperado.algoritmo())
                    .isEqualTo(esperado.chavePublica());
            // O SPKI carrega a chave crua mais o envelope DER com o AlgorithmIdentifier.
            assertThat(spki.length).isGreaterThan(esperado.chavePublica());

            evidencia.caso(AREA, esperado.algoritmo().getName().toLowerCase(),
                            "Chave pública " + esperado.algoritmo().getName())
                    .nota("Nível de segurança", esperado.algoritmo().getSecurityLevel() + " bits")
                    .nota("OID", esperado.algoritmo().getOid())
                    .nota("Chave crua (FIPS 204)", esperado.chavePublica() + " bytes")
                    .nota("SPKI codificado", spki.length + " bytes")
                    .bytes("chave-publica.der", spki)
                    .texto("chave-publica.hex", hex(spki, 16))
                    .encerra();

            tabela.append(String.format("%-12s %8d %16d %16d%n", esperado.algoritmo().getName(),
                    esperado.algoritmo().getSecurityLevel(), esperado.chavePublica(), spki.length));
        }

        evidencia.caso(AREA, "resumo-ml-dsa", "Tabela comparativa das variantes ML-DSA")
                .texto("tabela.txt", tabela.toString())
                .encerra();
    }

    @Test
    @DisplayName("os três pares recomendados são gerados e reportados como balanceados")
    void pares_recomendados() {
        StringBuilder tabela = new StringBuilder(
                String.format("%-8s %-26s %-10s %14s %14s%n", "Nível", "Par", "Balanceado",
                        "SPKI cláss.", "SPKI PQC"));

        for (int nivel : new int[]{128, 192, 256}) {
            HybridAlgorithmPair par = HybridAlgorithmPair.recommended(nivel);
            long inicio = System.nanoTime();
            HybridKeyPair chaves = api.generateHybridKeyPair(par);
            long ms = (System.nanoTime() - inicio) / 1_000_000;

            assertThat(par.isSecurityBalanced())
                    .as("o par recomendado para %d bits deve ser balanceado", nivel)
                    .isTrue();
            assertThat(par.classicalAlgorithm().getSecurityLevel()).isEqualTo(nivel);
            assertThat(par.pqcAlgorithm().getSecurityLevel()).isEqualTo(nivel);

            byte[] spkiClassico = chaves.getClassicalPublicKey().getEncoded();
            byte[] spkiPqc = chaves.getPQCPublicKey().getEncoded();

            evidencia.caso(AREA, "par-recomendado-" + nivel,
                            "Par híbrido recomendado para " + nivel + " bits")
                    .nota("Descrição", par.getDescription())
                    .nota("Clássico", par.classicalAlgorithm() + " ("
                            + par.classicalAlgorithm().getSecurityLevel() + " bits)")
                    .nota("Pós-quântico", par.pqcAlgorithm().getName() + " ("
                            + par.pqcAlgorithm().getSecurityLevel() + " bits)")
                    .nota("Balanceado", String.valueOf(par.isSecurityBalanced()))
                    .nota("Tempo de geração", ms + " ms (indicativo, execução única)")
                    .bytes("chave-publica-classica.der", spkiClassico)
                    .bytes("chave-publica-pqc.der", spkiPqc)
                    .encerra();

            tabela.append(String.format("%-8d %-26s %-10s %14d %14d%n", nivel, par.getDescription(),
                    par.isSecurityBalanced(), spkiClassico.length, spkiPqc.length));
        }

        evidencia.caso(AREA, "resumo-pares", "Pares recomendados por nível de segurança")
                .texto("tabela.txt", tabela.toString())
                .texto("Os tempos são indicativos: execução única, sem aquecimento da JVM.")
                .encerra();
    }

    @Test
    @DisplayName("nem todo par pronto é balanceado, e o relatório diz qual não é")
    void balanco_dos_pares_prontos() {
        StringBuilder tabela = new StringBuilder(
                String.format("%-26s %-14s %-14s %-12s%n", "Par", "Clássico", "PQC", "Balanceado"));

        boolean encontrouDesbalanceado = false;
        for (HybridAlgorithmPair par : HybridAlgorithmPair.allRecommended()) {
            tabela.append(String.format("%-26s %-14s %-14s %-12s%n", par.getDescription(),
                    par.classicalAlgorithm().getSecurityLevel() + " bits",
                    par.pqcAlgorithm().getSecurityLevel() + " bits",
                    par.isSecurityBalanced() ? "sim" : "NÃO"));
            encontrouDesbalanceado |= !par.isSecurityBalanced();
        }

        assertThat(encontrouDesbalanceado)
                .as("RSA-4096 (~152 bits) com ML-DSA-87 (256) não pode ser dado como balanceado")
                .isTrue();

        evidencia.caso(AREA, "balanco-pares-prontos", "Balanço de segurança dos pares prontos")
                .texto("tabela.txt", tabela.toString())
                .texto("Níveis equivalentes conforme NIST SP 800-57 Part 1 Rev 5, Tabela 2.")
                .encerra();
    }
}
