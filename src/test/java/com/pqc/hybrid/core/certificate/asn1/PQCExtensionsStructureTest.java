package com.pqc.hybrid.core.certificate.asn1;

import com.pqc.hybrid.core.BaseTest;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.*;

@DisplayName("PQCExtensionsStructure Tests")
class PQCExtensionsStructureTest extends BaseTest {

    @Test
    @DisplayName("should create PQCExtensionsStructure with valid parameters")
    void test_create_with_valid_parameters() {
        // Arrange
        AlgorithmIdentifier altSignatureAlgorithm = new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.3.4"));
        byte[] altSignatureValue = new byte[]{1, 2, 3, 4, 5};
        SubjectPublicKeyInfo subjectAltPublicKeyInfo = new SubjectPublicKeyInfo(
                new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.3.5")),
                new byte[]{9, 8, 7, 6, 5});

        // Act
        PQCExtensionsStructure extensions = new PQCExtensionsStructure(
                altSignatureAlgorithm,
                altSignatureValue,
                subjectAltPublicKeyInfo);

        // Assert
        assertThat(extensions).isNotNull();
        assertThat(extensions.getAltSignatureAlgorithm()).isEqualTo(altSignatureAlgorithm);
        assertThat(extensions.getAltSignatureValue()).containsExactly(1, 2, 3, 4, 5);
        assertThat(extensions.getSubjectAltPublicKeyInfo()).isEqualTo(subjectAltPublicKeyInfo);
        assertThat(extensions.getAltSignatureAlgorithmOID()).isEqualTo("1.2.3.4");
    }

    @Test
    @DisplayName("should allow null altSignatureAlgorithm (does not throw exception in constructor)")
    void test_create_with_null_altSignatureAlgorithm_no_exception() {
        // Arrange
        byte[] altSignatureValue = new byte[]{1, 2, 3};
        SubjectPublicKeyInfo subjectAltPublicKeyInfo = new SubjectPublicKeyInfo(
                new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.3")),
                new byte[]{4, 5, 6});

        // Act
        PQCExtensionsStructure extensions = new PQCExtensionsStructure(null, altSignatureValue, subjectAltPublicKeyInfo);

        // Assert
        assertThat(extensions).isNotNull();
        assertThat(extensions.getAltSignatureAlgorithm()).isNull();
        assertThat(extensions.getAltSignatureValue()).containsExactly(1, 2, 3);
        assertThat(extensions.getSubjectAltPublicKeyInfo()).isEqualTo(subjectAltPublicKeyInfo);
    }

    @Test
    @DisplayName("should allow null altSignatureAlgorithm in constructor (NPE thrown later when used)")
    void test_create_with_null_altSignatureAlgorithm_throws_exception_later() {
        // Arrange
        byte[] altSignatureValue = new byte[]{1, 2, 3};
        SubjectPublicKeyInfo subjectAltPublicKeyInfo = new SubjectPublicKeyInfo(
                new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.3")),
                new byte[]{4, 5, 6});

        // Act
        PQCExtensionsStructure extensions = new PQCExtensionsStructure(null, altSignatureValue, subjectAltPublicKeyInfo);

        // Assert - constructor allows null but accessing OID throws NPE
        assertThat(extensions.getAltSignatureAlgorithm()).isNull();
        assertThatThrownBy(() -> extensions.getAltSignatureAlgorithmOID())
                .isInstanceOf(NullPointerException.class);
    }

    @Test
    @DisplayName("should allow null subjectAltPublicKeyInfo (does not throw exception in constructor)")
    void test_create_with_null_subjectAltPublicKeyInfo_no_exception() {
        // Arrange
        AlgorithmIdentifier altSignatureAlgorithm = new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.3"));
        byte[] altSignatureValue = new byte[]{4, 5, 6};

        // Act
        PQCExtensionsStructure extensions = new PQCExtensionsStructure(altSignatureAlgorithm, altSignatureValue, null);

        // Assert
        assertThat(extensions).isNotNull();
        assertThat(extensions.getAltSignatureAlgorithm()).isEqualTo(altSignatureAlgorithm);
        assertThat(extensions.getAltSignatureValue()).containsExactly(4, 5, 6);
        assertThat(extensions.getSubjectAltPublicKeyInfo()).isNull();
    }

    @Test
    @DisplayName("should return cloned arrays to prevent internal state modification")
    void test_returns_cloned_arrays() {
        // Arrange
        AlgorithmIdentifier altSignatureAlgorithm = new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.3"));
        byte[] originalAltSignatureValue = new byte[]{1, 2, 3};
        SubjectPublicKeyInfo subjectAltPublicKeyInfo = new SubjectPublicKeyInfo(
                new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.3.4")),
                new byte[]{7, 8, 9});

        // Act
        PQCExtensionsStructure extensions = new PQCExtensionsStructure(
                altSignatureAlgorithm,
                originalAltSignatureValue,
                subjectAltPublicKeyInfo);
        byte[] returnedValue1 = extensions.getAltSignatureValue();
        byte[] returnedValue2 = extensions.getAltSignatureValue();

        // Assert
        assertThat(returnedValue1).containsExactly(1, 2, 3);
        assertThat(returnedValue2).containsExactly(1, 2, 3);
        // Ensure they are different array instances (cloned)
        assertThat(returnedValue1).isNotSameAs(returnedValue2);
        // Ensure modifying returned array doesn't affect internal state
        returnedValue1[0] = 99;
        assertThat(extensions.getAltSignatureValue()[0]).isEqualTo((byte) 1);
    }

    @Test
    @DisplayName("should correctly parse ASN.1 encoded bytes")
    void test_parse_from_encoded_bytes() throws Exception {
        // Arrange
        AlgorithmIdentifier altSignatureAlgorithm = new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.3.4"));
        byte[] altSignatureValue = new byte[]{1, 2, 3, 4, 5};
        SubjectPublicKeyInfo subjectAltPublicKeyInfo = new SubjectPublicKeyInfo(
                new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.3.5")),
                new byte[]{9, 8, 7, 6, 5});

        PQCExtensionsStructure original = new PQCExtensionsStructure(
                altSignatureAlgorithm,
                altSignatureValue,
                subjectAltPublicKeyInfo);

        // Act
        byte[] encoded = original.getEncoded();
        PQCExtensionsStructure parsed = PQCExtensionsStructure.parse(encoded);

        // Assert
        assertThat(parsed).isNotNull();
        assertThat(parsed.getAltSignatureAlgorithm()).isEqualTo(altSignatureAlgorithm);
        assertThat(parsed.getAltSignatureValue()).containsExactly(1, 2, 3, 4, 5);
        assertThat(parsed.getSubjectAltPublicKeyInfo()).isEqualTo(subjectAltPublicKeyInfo);
    }

    @Test
    @DisplayName("should correctly build using builder pattern")
    void test_build_using_builder() {
        // Arrange
        AlgorithmIdentifier altSignatureAlgorithm = new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.3.4"));
        byte[] altSignatureValue = new byte[]{1, 2, 3, 4, 5};
        SubjectPublicKeyInfo subjectAltPublicKeyInfo = new SubjectPublicKeyInfo(
                new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.3.5")),
                new byte[]{9, 8, 7, 6, 5});

        // Act
        PQCExtensionsStructure extensions = PQCExtensionsStructure.builder()
                .withAltSignatureAlgorithm(altSignatureAlgorithm)
                .withAltSignatureValue(altSignatureValue)
                .withSubjectAltPublicKeyInfo(subjectAltPublicKeyInfo)
                .build();

        // Assert
        assertThat(extensions).isNotNull();
        assertThat(extensions.getAltSignatureAlgorithm()).isEqualTo(altSignatureAlgorithm);
        assertThat(extensions.getAltSignatureValue()).containsExactly(1, 2, 3, 4, 5);
        assertThat(extensions.getSubjectAltPublicKeyInfo()).isEqualTo(subjectAltPublicKeyInfo);
    }

    @Test
    @DisplayName("should throw exception when created with null altSignatureValue")
    void test_create_with_null_altSignatureValue_throws_exception() {
        // Arrange
        AlgorithmIdentifier altSignatureAlgorithm = new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.3"));
        SubjectPublicKeyInfo subjectAltPublicKeyInfo = new SubjectPublicKeyInfo(
                new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.3.4")),
                new byte[]{7, 8, 9});

        // Act & Assert
        assertThatThrownBy(() -> new PQCExtensionsStructure(altSignatureAlgorithm, null, subjectAltPublicKeyInfo))
                .isInstanceOf(NullPointerException.class);
    }

    @Test
    @DisplayName("should throw exception when building without altSignatureValue")
    void test_build_without_altSignatureValue_throws_exception() {
        // Arrange
        AlgorithmIdentifier altSignatureAlgorithm = new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.3"));
        SubjectPublicKeyInfo subjectAltPublicKeyInfo = new SubjectPublicKeyInfo(
                new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.3.4")),
                new byte[]{7, 8, 9});

        // Act & Assert
        assertThatThrownBy(() -> PQCExtensionsStructure.builder()
                .withAltSignatureAlgorithm(altSignatureAlgorithm)
                .withSubjectAltPublicKeyInfo(subjectAltPublicKeyInfo)
                .build())
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("altSignatureValue is required");
    }

    @Test
    @DisplayName("should throw exception when building without subjectAltPublicKeyInfo")
    void test_build_without_subjectAltPublicKeyInfo_throws_exception() {
        // Arrange
        AlgorithmIdentifier altSignatureAlgorithm = new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.3"));
        byte[] altSignatureValue = new byte[]{4, 5, 6};

        // Act & Assert
        assertThatThrownBy(() -> PQCExtensionsStructure.builder()
                .withAltSignatureAlgorithm(altSignatureAlgorithm)
                .withAltSignatureValue(altSignatureValue)
                .build())
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("subjectAltPublicKeyInfo is required");
    }

    @Test
    @DisplayName("should create correct string representation")
    void test_toString_representation() {
        // Arrange
        AlgorithmIdentifier altSignatureAlgorithm = new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.3.4"));
        byte[] altSignatureValue = new byte[]{1, 2, 3, 4, 5};
        SubjectPublicKeyInfo subjectAltPublicKeyInfo = new SubjectPublicKeyInfo(
                new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.3.5")),
                new byte[]{9, 8, 7, 6, 5});

        // Act
        PQCExtensionsStructure extensions = new PQCExtensionsStructure(
                altSignatureAlgorithm,
                altSignatureValue,
                subjectAltPublicKeyInfo);

        // Assert
        String toString = extensions.toString();
        assertThat(toString).contains("altSignatureAlgorithm=1.2.3.4");
        assertThat(toString).contains("altSignatureValue=5 bytes");
        assertThat(toString).contains("subjectAltPublicKeyInfo=1.2.3.5");
    }
}