package com.pqc.hybrid.validation;

import com.pqc.hybrid.core.certificate.HybridSigner;
import com.pqc.hybrid.core.certificate.HybridX509CertificateBuilder;
import com.pqc.hybrid.core.config.ClassicalAlgorithm;
import com.pqc.hybrid.core.config.HybridAlgorithmPair;
import com.pqc.hybrid.core.config.HybridCertificateConfig;
import com.pqc.hybrid.core.keygen.HybridKeyPair;
import com.pqc.hybrid.core.util.printer.HybridCertificateInspector;

import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.security.cert.X509Certificate;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Área 2 — emissão de certificados híbridos no modelo Catalyst.
 *
 * <p>Records, for each recommended security level, the issued certificate in PEM and DER, the
 * OpenSSL textual decode, and the measured size and criticality of the three Catalyst
 * extensions. Also records a certificate built through Layer 1, where the private keys reach
 * the builder only as {@link ContentSigner}s.
 *
 * @author PQC Hybrid Team
 * @version 1.0.0-BETA
 */
@DisplayName("Área 2 — emissão de certificados híbridos")
class A2EmissaoCertificadosValidationTest extends ValidationTestBase {

    private static final String AREA = "02-emissao-certificados";
    private static final String OID_CHAVE_ALT = "2.5.29.72";
    private static final String OID_ALG_ALT = "2.5.29.73";
    private static final String OID_ASSINATURA_ALT = "2.5.29.74";

    @Test
    @DisplayName("cada nível emite um certificado com as três extensões Catalyst")
    void emissao_por_nivel() throws Exception {
        HybridCertificateInspector inspetor = new HybridCertificateInspector();

        for (int nivel : new int[]{128, 192, 256}) {
            HybridAlgorithmPair par = HybridAlgorithmPair.recommended(nivel);
            HybridKeyPair chaves = api.generateHybridKeyPair(par);
            X509Certificate cert = raizAutoassinada(par, chaves, "CN=nivel" + nivel + ".tcc.br,O=TCC,C=BR");

            byte[] der = exporter.exportCertificateToDERBytes(cert);
            String pem = exporter.exportCertificateToPEMString(cert);

            byte[] ext72 = cert.getExtensionValue(OID_CHAVE_ALT);
            byte[] ext73 = cert.getExtensionValue(OID_ALG_ALT);
            byte[] ext74 = cert.getExtensionValue(OID_ASSINATURA_ALT);

            assertThat(ext72).as("subjectAltPublicKeyInfo em %d bits", nivel).isNotNull();
            assertThat(ext73).as("altSignatureAlgorithm em %d bits", nivel).isNotNull();
            assertThat(ext74).as("altSignatureValue em %d bits", nivel).isNotNull();
            assertThat(cert.getCriticalExtensionOIDs())
                    .as("por padrão as extensões alternativas não são críticas")
                    .doesNotContain(OID_CHAVE_ALT, OID_ALG_ALT, OID_ASSINATURA_ALT);
            assertThat(cert.getSigAlgName())
                    .as("o digest deve acompanhar a força da chave")
                    .isEqualToIgnoringCase(
                            ClassicalAlgorithm.getSignatureAlgorithmForKey(
                                    chaves.getClassicalPublicKey()));

            var caso = evidencia.caso(AREA, "nivel-" + nivel,
                            "Certificado híbrido autoassinado de " + nivel + " bits")
                    .nota("Par de algoritmos", par.getDescription())
                    .nota("Algoritmo de assinatura", cert.getSigAlgName()
                            + " (OID " + cert.getSigAlgOID() + ")")
                    .nota("Sujeito", cert.getSubjectX500Principal().getName())
                    .nota("Número serial", cert.getSerialNumber().toString())
                    .nota("Certificado completo", der.length + " bytes (DER)")
                    .nota("2.5.29.72 subjectAltPublicKeyInfo", ext72.length + " bytes, não crítica")
                    .nota("2.5.29.73 altSignatureAlgorithm", ext73.length + " bytes, não crítica")
                    .nota("2.5.29.74 altSignatureValue", ext74.length + " bytes, não crítica")
                    .bytes("certificado.der", der)
                    .texto("certificado.pem", pem)
                    .texto("inspecao.txt", inspetor.inspectCertificateToString(cert))
                    .bytes("extensao-2.5.29.72.der", ext72)
                    .bytes("extensao-2.5.29.73.der", ext73)
                    .bytes("extensao-2.5.29.74.der", ext74);

            if (OpensslRunner.available()) {
                Path pemFile = caso.dir().resolve("certificado.pem");
                var decode = OpensslRunner.run("openssl", "x509", "-in", pemFile.toString(),
                        "-noout", "-text");
                assertThat(decode.ok()).as("openssl deve decodificar o certificado").isTrue();
                caso.texto("openssl-x509.txt", decode.output());
            }
            caso.encerra();
        }
    }

    @Test
    @DisplayName("a criticidade das extensões 73/74 é o ponto de controle da migração")
    void criticidade_configuravel() throws Exception {
        HybridAlgorithmPair par = HybridAlgorithmPair.recommended(192);
        HybridKeyPair chaves = api.generateHybridKeyPair(par);

        for (boolean critica : new boolean[]{false, true}) {
            HybridCertificateConfig config = HybridCertificateConfig.builder()
                    .withAlgorithmPair(par)
                    .withSubjectDN("CN=criticidade.tcc.br,O=TCC,C=BR")
                    .withIssuerDN("CN=criticidade.tcc.br,O=TCC,C=BR")
                    .withValidityDays(365)
                    .withAltSignatureExtensionsCritical(critica)
                    .build();
            X509Certificate cert = HybridX509CertificateBuilder.builder(config, chaves)
                    .withPQCExtensions(true).build();

            if (critica) {
                assertThat(cert.getCriticalExtensionOIDs())
                        .contains(OID_ALG_ALT, OID_ASSINATURA_ALT);
            } else {
                assertThat(cert.getNonCriticalExtensionOIDs())
                        .contains(OID_ALG_ALT, OID_ASSINATURA_ALT);
            }
            // A chave alternativa permanece não crítica nos dois modos.
            assertThat(cert.getNonCriticalExtensionOIDs()).contains(OID_CHAVE_ALT);

            evidencia.caso(AREA, critica ? "criticidade-estrita" : "criticidade-compativel",
                            "Extensões alternativas " + (critica ? "críticas" : "não críticas"))
                    .nota("altSignatureExtensionsCritical", String.valueOf(critica))
                    .nota("Extensões críticas", cert.getCriticalExtensionOIDs().toString())
                    .nota("Extensões não críticas", cert.getNonCriticalExtensionOIDs().toString())
                    .nota("Consequência", critica
                            ? "verificador conforme a RFC 5280 rejeita: impede downgrade silencioso"
                            : "verificador clássico ignora as extensões e aceita pela assinatura clássica")
                    .bytes("certificado.der", exporter.exportCertificateToDERBytes(cert))
                    .texto("certificado.pem", exporter.exportCertificateToPEMString(cert))
                    .encerra();
        }
    }

    @Test
    @DisplayName("Layer 1 emite sem que a chave privada precise ser conhecida pelo construtor")
    void layer1_signer_externo() throws Exception {
        HybridAlgorithmPair par = HybridAlgorithmPair.recommended(192);
        HybridKeyPair chaves = api.generateHybridKeyPair(par);

        // Layer 1: o construtor recebe apenas as chaves públicas do sujeito e dois ContentSigner.
        // É a forma de integrar HSM, KMS e tokens, em que a chave privada nunca entra na JVM.
        ContentSigner assinadorClassico = new JcaContentSignerBuilder(
                ClassicalAlgorithm.getSignatureAlgorithmForKey(chaves.getClassicalPublicKey()))
                .setProvider("BC").build(chaves.getClassicalPrivateKey());
        ContentSigner assinadorPqc = new JcaContentSignerBuilder(chaves.getPQCAlgorithm())
                .setProvider("BC").build(chaves.getPQCPrivateKey());

        HybridCertificateConfig config = HybridCertificateConfig.builder()
                .withAlgorithmPair(par)
                .withSubjectDN("CN=layer1.tcc.br,O=TCC,C=BR")
                .withIssuerDN("CN=layer1.tcc.br,O=TCC,C=BR")
                .withValidityDays(365)
                .build();

        X509Certificate cert = HybridX509CertificateBuilder.build(config,
                chaves.getClassicalPublicKey(), chaves.getPQCPublicKey(),
                new HybridSigner(assinadorClassico, assinadorPqc), null);

        assertThat(cert.getExtensionValue(OID_CHAVE_ALT)).isNotNull();
        assertThat(cert.getExtensionValue(OID_ASSINATURA_ALT)).isNotNull();
        assertThat(api.validateCertificateAgainstIssuer(cert, cert).isAllValid())
                .as("o certificado emitido por Layer 1 deve validar contra si mesmo")
                .isTrue();

        evidencia.caso(AREA, "layer1-signer-externo",
                        "Emissão via Layer 1 com ContentSigner fornecido externamente")
                .nota("Assinador clássico", assinadorClassico.getAlgorithmIdentifier()
                        .getAlgorithm().getId())
                .nota("Assinador alternativo", assinadorPqc.getAlgorithmIdentifier()
                        .getAlgorithm().getId())
                .nota("Chave privada exigida pelo construtor", "nenhuma")
                .nota("Validação contra si mesmo", "aprovada nas duas dimensões")
                .bytes("certificado.der", exporter.exportCertificateToDERBytes(cert))
                .texto("certificado.pem", exporter.exportCertificateToPEMString(cert))
                .encerra();
    }

    @Test
    @DisplayName("a ordem de assinatura do Catalyst é observável no certificado emitido")
    void ordem_de_assinatura() {
        HybridAlgorithmPair par = HybridAlgorithmPair.recommended(192);
        HybridKeyPair chaves = api.generateHybridKeyPair(par);
        X509Certificate cert = raizAutoassinada(par, chaves, "CN=ordem.tcc.br,O=TCC,C=BR");

        // A assinatura PQC cobre o pre-TBS (com a 72, sem 73/74) e a clássica cobre o TBS
        // completo. Se a ordem fosse outra, nenhuma das duas revalidaria.
        assertThat(api.validatePQCSignature(cert, chaves))
                .as("a assinatura alternativa revalida sobre o pre-TBS reconstruído")
                .isTrue();
        assertThat(api.validateCertificate(cert, cert.getPublicKey()).isSignatureValid())
                .as("a assinatura clássica revalida sobre o TBS completo")
                .isTrue();

        evidencia.caso(AREA, "ordem-de-assinatura", "Ordem de assinatura do modelo Catalyst")
                .texto("1. chave pública clássica nos campos tradicionais do TBS")
                .texto("2. extensão 2.5.29.72 com a chave pública alternativa")
                .texto("3. extensão 2.5.29.73 com o algoritmo da assinatura alternativa")
                .texto("4. assinatura PQC sobre o pre-TBS (contém 72 e 73; sem o campo")
                .texto("   signature e sem a 74)")
                .texto("5. extensão 2.5.29.74 com a assinatura PQC")
                .texto("6. assinatura clássica sobre o TBS completo")
                .texto("")
                .texto("Ambas revalidam no certificado emitido, o que só ocorre se a ordem")
                .texto("acima for respeitada na emissão e reproduzida na validação.")
                .nota("Assinatura alternativa sobre pre-TBS", "válida")
                .nota("Assinatura clássica sobre TBS", "válida")
                .bytes("tbs-certificate.der", tbs(cert))
                .encerra();
    }

    private static byte[] tbs(X509Certificate cert) {
        try {
            return cert.getTBSCertificate();
        } catch (Exception e) {
            throw new IllegalStateException("Falha ao extrair o TBSCertificate", e);
        }
    }

}
