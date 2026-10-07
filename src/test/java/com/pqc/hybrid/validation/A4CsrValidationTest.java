package com.pqc.hybrid.validation;

import com.pqc.hybrid.core.common.oid.AlgorithmOIDRegistry;
import com.pqc.hybrid.core.config.ClassicalAlgorithm;
import com.pqc.hybrid.core.config.HybridAlgorithmPair;
import com.pqc.hybrid.core.keygen.HybridKeyPair;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Área 4 — requisições PKCS#10 híbridas.
 *
 * <p>Records the CSR in DER and PEM, the OpenSSL decode, and evidence that the requester's
 * post-quantum public key travels in the {@code altSubjectPublicKeyInfo} attribute alongside
 * the conventional classical key.
 *
 * @author PQC Hybrid Team
 * @version 1.0.0-BETA
 */
@DisplayName("Área 4 — requisições PKCS#10 híbridas")
class A4CsrValidationTest extends ValidationTestBase {

    private static final String AREA = "04-requisicoes-csr";
    private static final String DN = "CN=requisitante.tcc.br,O=TCC,C=BR";

    @Test
    @DisplayName("a CSR híbrida carrega as duas chaves e as duas assinaturas")
    void csr_hibrida() throws Exception {
        HybridAlgorithmPair par = HybridAlgorithmPair.recommended(192);
        HybridKeyPair chaves = api.generateHybridKeyPair(par);

        PKCS10CertificationRequest csr = api.generateCertificateSigningRequest(DN, chaves);
        byte[] der = csr.getEncoded();

        assertThat(der).isNotEmpty();
        assertThat(csr.getSubject().toString()).contains("requisitante.tcc.br");

        // A chave clássica ocupa o campo convencional do PKCS#10.
        byte[] spkiClassico = csr.getSubjectPublicKeyInfo().getEncoded();
        assertThat(spkiClassico)
                .as("o campo convencional deve conter a chave clássica do requisitante")
                .isEqualTo(chaves.getClassicalPublicKey().getEncoded());

        // A assinatura principal usa o digest compatível com a força da chave.
        String sigAlgEsperado = ClassicalAlgorithm.getSignatureAlgorithmForKey(
                chaves.getClassicalPublicKey());
        assertThat(csr.getSignatureAlgorithm().getAlgorithm().getId())
                .as("algoritmo da assinatura principal da CSR")
                .isEqualTo(oidDe(sigAlgEsperado));

        // A chave PQC viaja no atributo altSubjectPublicKeyInfo.
        var atributos = csr.getAttributes(
                new ASN1ObjectIdentifier(AlgorithmOIDRegistry.OID_SUBJECT_ALT_PUBLIC_KEY_INFO));
        assertThat(atributos)
                .as("a CSR deve trazer o atributo altSubjectPublicKeyInfo (2.5.29.72)")
                .isNotEmpty();

        String pem = pemDe("CERTIFICATE REQUEST", der);

        var caso = evidencia.caso(AREA, "csr-hibrida-192", "Requisição PKCS#10 híbrida de 192 bits")
                .nota("Sujeito", csr.getSubject().toString())
                .nota("Par de algoritmos", par.getDescription())
                .nota("Algoritmo da assinatura principal", sigAlgEsperado
                        + " (OID " + csr.getSignatureAlgorithm().getAlgorithm().getId() + ")")
                .nota("Chave clássica (campo convencional)", spkiClassico.length + " bytes")
                .nota("Atributo altSubjectPublicKeyInfo", "presente ("
                        + AlgorithmOIDRegistry.OID_SUBJECT_ALT_PUBLIC_KEY_INFO + ")")
                .nota("Requisição completa", der.length + " bytes (DER)")
                .bytes("requisicao.der", der)
                .texto("requisicao.pem", pem)
                .bytes("chave-publica-classica.der", spkiClassico)
                .bytes("chave-publica-pqc.der", chaves.getPQCPublicKey().getEncoded());

        if (OpensslRunner.available()) {
            Path pemFile = caso.dir().resolve("requisicao.pem");
            var decode = OpensslRunner.run("openssl", "req", "-in", pemFile.toString(),
                    "-noout", "-text");
            assertThat(decode.ok())
                    .as("openssl deve decodificar a CSR: %s", decode.output())
                    .isTrue();
            caso.texto("openssl-req.txt", decode.output());
            caso.nota("openssl req -text", "decodifica sem erro");

            var verifica = OpensslRunner.run("openssl", "req", "-in", pemFile.toString(),
                    "-noout", "-verify");
            caso.texto("openssl-req-verify.txt",
                    "$ openssl req -in requisicao.pem -noout -verify\n"
                            + verifica.output() + "exit=" + verifica.exitCode() + "\n");
            caso.nota("openssl req -verify", verifica.ok()
                    ? "assinatura própria da CSR conferida" : "exit " + verifica.exitCode());
        } else {
            caso.nota("openssl", "não executado: binário ausente");
        }
        caso.encerra();
    }

    @Test
    @DisplayName("a CSR é emitida para os três níveis recomendados")
    void csr_por_nivel() throws Exception {
        StringBuilder tabela = new StringBuilder(
                String.format("%-8s %-26s %14s %14s%n", "Nível", "Par", "CSR (bytes)",
                        "Assinatura"));

        for (int nivel : new int[]{128, 192, 256}) {
            HybridAlgorithmPair par = HybridAlgorithmPair.recommended(nivel);
            HybridKeyPair chaves = api.generateHybridKeyPair(par);
            PKCS10CertificationRequest csr = api.generateCertificateSigningRequest(
                    "CN=nivel" + nivel + ".tcc.br,O=TCC,C=BR", chaves);
            byte[] der = csr.getEncoded();

            assertThat(csr.getAttributes(new ASN1ObjectIdentifier(
                    AlgorithmOIDRegistry.OID_SUBJECT_ALT_PUBLIC_KEY_INFO))).isNotEmpty();

            String sigAlg = ClassicalAlgorithm.getSignatureAlgorithmForKey(
                    chaves.getClassicalPublicKey());

            evidencia.caso(AREA, "csr-nivel-" + nivel, "CSR híbrida de " + nivel + " bits")
                    .nota("Par de algoritmos", par.getDescription())
                    .nota("Algoritmo da assinatura", sigAlg)
                    .nota("Tamanho", der.length + " bytes (DER)")
                    .bytes("requisicao.der", der)
                    .texto("requisicao.pem", pemDe("CERTIFICATE REQUEST", der))
                    .encerra();

            tabela.append(String.format("%-8d %-26s %14d %14s%n", nivel, par.getDescription(),
                    der.length, sigAlg));
        }

        evidencia.caso(AREA, "resumo-csr", "Tamanho das requisições por nível")
                .texto("tabela.txt", tabela.toString())
                .encerra();
    }

    /** @return the DER wrapped in a PEM envelope with the given label. */
    private static String pemDe(String label, byte[] der) {
        String base64 = Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(der);
        return "-----BEGIN " + label + "-----\n" + base64 + "\n-----END " + label + "-----\n";
    }

    /** @return the signature OID for a JCA signature algorithm name used by this library. */
    private static String oidDe(String jcaName) {
        return switch (jcaName) {
            case "SHA256withECDSA" -> "1.2.840.10045.4.3.2";
            case "SHA384withECDSA" -> "1.2.840.10045.4.3.3";
            case "SHA512withECDSA" -> "1.2.840.10045.4.3.4";
            case "SHA256withRSA" -> "1.2.840.113549.1.1.11";
            case "SHA512withRSA" -> "1.2.840.113549.1.1.13";
            default -> throw new IllegalArgumentException("OID desconhecido para " + jcaName);
        };
    }
}
