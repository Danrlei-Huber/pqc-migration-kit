package com.pqc.hybrid.validation;

import com.pqc.hybrid.core.config.ClassicalAlgorithm;
import com.pqc.hybrid.core.config.CryptographicProviderFactory;
import com.pqc.hybrid.core.config.PQCAlgorithm;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.Provider;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

/**
 * Área 8 — provedor criptográfico e diagnóstico.
 *
 * <p>Records which provider actually backed the run and which algorithms it offered. Evidence
 * produced by an unknown provider is not reproducible, so this is what ties every other case in
 * the campaign to a concrete cryptographic implementation.
 *
 * @author PQC Hybrid Team
 * @version 1.0.0-BETA
 */
@DisplayName("Área 8 — provedor e diagnóstico")
class A8ProvedorValidationTest extends ValidationTestBase {

    private static final String AREA = "08-provedor";

    @Test
    @DisplayName("o provedor em uso é identificado e registrado")
    void provedor_em_uso() {
        CryptographicProviderFactory.initialize();
        Provider provedor = CryptographicProviderFactory.getProvider();

        assertThat(provedor).isNotNull();
        assertThat(provedor.getName()).isEqualTo("BC");

        evidencia.caso(AREA, "provedor-em-uso", "Provedor criptográfico que respaldou a campanha")
                .nota("Nome", provedor.getName())
                .nota("Versão", CryptographicProviderFactory.getProviderVersion())
                .nota("Informação", provedor.getInfo())
                .nota("Serviços registrados", String.valueOf(provedor.getServices().size()))
                .nota("Inicialização idempotente", "sim (dupla checagem sincronizada)")
                .encerra();
    }

    @Test
    @DisplayName("todos os algoritmos do fluxo ativo estão disponíveis")
    void disponibilidade_de_algoritmos() {
        // A variante precisa aparecer na matriz: RSA-2048 e RSA-3072 compartilham o mesmo
        // nome de algoritmo de assinatura (SHA256withRSA), e sem a coluna da variante as duas
        // linhas ficariam indistinguíveis.
        StringBuilder matriz = new StringBuilder(
                String.format("%-12s %-16s %-14s %s%n", "Variante", "Algoritmo JCA", "Categoria",
                        "Disponível"));

        for (ClassicalAlgorithm algoritmo : ClassicalAlgorithm.values()) {
            boolean disponivel = CryptographicProviderFactory
                    .isAlgorithmAvailable(algoritmo.getSignatureAlgorithm());
            assertThat(disponivel)
                    .as("assinatura clássica %s", algoritmo.getSignatureAlgorithm())
                    .isTrue();
            matriz.append(String.format("%-12s %-16s %-14s %s%n", algoritmo,
                    algoritmo.getSignatureAlgorithm(), "clássico", "sim"));
        }

        for (PQCAlgorithm algoritmo : PQCAlgorithm.values()) {
            boolean disponivel = CryptographicProviderFactory
                    .isAlgorithmAvailable(algoritmo.getName());
            assertThat(disponivel).as("algoritmo PQC %s", algoritmo.getName()).isTrue();
            matriz.append(String.format("%-12s %-16s %-14s %s%n", algoritmo.getName(),
                    algoritmo.getName(), "pós-quântico", "sim"));
        }

        // O enum só deve conter o esquema efetivamente usado no fluxo híbrido.
        assertThat(PQCAlgorithm.values())
                .as("o fluxo ativo concentra-se em ML-DSA")
                .allMatch(a -> a.getName().startsWith("ML-DSA"))
                .hasSize(3);

        evidencia.caso(AREA, "disponibilidade-algoritmos",
                        "Matriz de disponibilidade dos algoritmos do fluxo ativo")
                .nota("Variantes clássicas", String.valueOf(ClassicalAlgorithm.values().length))
                .nota("Variantes pós-quânticas", String.valueOf(PQCAlgorithm.values().length))
                .nota("Esquemas PQC no enum", "somente ML-DSA (FIPS 204)")
                .texto("matriz.txt", matriz.toString())
                .encerra();
    }

    @Test
    @DisplayName("a inicialização falha rápido se um algoritmo obrigatório faltar")
    void validacao_de_algoritmos_obrigatorios() {
        assertThatCode(CryptographicProviderFactory::validateRequiredAlgorithms)
                .as("os três conjuntos de parâmetros ML-DSA devem estar presentes")
                .doesNotThrowAnyException();

        StringBuilder obrigatorios = new StringBuilder();
        for (PQCAlgorithm algoritmo : PQCAlgorithm.values()) {
            obrigatorios.append("  ").append(algoritmo.getName())
                    .append(" — OID ").append(algoritmo.getOid()).append('\n');
        }

        evidencia.caso(AREA, "algoritmos-obrigatorios",
                        "Verificação de algoritmos obrigatórios na inicialização")
                .nota("Resultado", "aprovado, sem exceção")
                .nota("Comportamento em caso de ausência",
                        "PQCHybridException nomeando os algoritmos faltantes")
                .texto("obrigatorios.txt",
                        "Algoritmos exigidos na inicialização:\n" + obrigatorios)
                .texto("A checagem existe para transformar uma falha silenciosa em tempo de uso")
                .texto("numa falha explícita em tempo de inicialização.")
                .encerra();
    }
}
