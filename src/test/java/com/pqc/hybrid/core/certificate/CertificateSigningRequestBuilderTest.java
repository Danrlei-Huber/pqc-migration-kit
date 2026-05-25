package com.pqc.hybrid.core.certificate;

import com.pqc.hybrid.core.BaseTest;
import com.pqc.hybrid.core.config.CryptographicProviderFactory;
import com.pqc.hybrid.core.keygen.HybridKeyPair;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("Hybrid CSR Tests")
class CertificateSigningRequestBuilderTest extends BaseTest {

    @BeforeAll
    static void setUpAll() {
        CryptographicProviderFactory.initialize();
    }

    private HybridKeyPair newHybridKeyPair() throws Exception {
        KeyPairGenerator pqcGen = KeyPairGenerator.getInstance("ML-DSA-65", "BC");
        KeyPairGenerator ecGen = KeyPairGenerator.getInstance("EC", "BC");
        ecGen.initialize(new ECGenParameterSpec("secp384r1"));
        KeyPair pqcKp = pqcGen.generateKeyPair();
        KeyPair ecKp = ecGen.generateKeyPair();
        return new HybridKeyPair(
                ecKp.getPublic(), ecKp.getPrivate(),
                pqcKp.getPublic(), pqcKp.getPrivate(),
                "ECDSA", "ML-DSA-65");
    }

    @Test
    @DisplayName("should build a hybrid CSR with a valid classical signature and alternative key material")
    void shouldBuildHybridCsr() throws Exception {
        HybridKeyPair keyPair = newHybridKeyPair();

        PKCS10CertificationRequest csr =
                new CertificateSigningRequestBuilder("CN=csr.example.com,O=Test,C=US", keyPair).build();

        assertThat(csr).isNotNull();

        // The classical (primary) signature must validate against the classical public key.
        boolean classicalValid = csr.isSignatureValid(
                new JcaContentVerifierProviderBuilder().setProvider("BC")
                        .build(keyPair.getClassicalPublicKey()));
        assertThat(classicalValid).isTrue();

        // The alternative (PQC) public key + signature are carried as CSR attributes,
        // distinguishing a hybrid request from a classical-only one.
        assertThat(csr.getAttributes()).isNotEmpty();
    }
}
