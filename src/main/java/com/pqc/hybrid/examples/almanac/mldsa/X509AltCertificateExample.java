import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Date;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.SubjectAltPublicKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
/**
 * Create a self-signed P-256 ECDSA certificate with an alt signature and public key based on ML-DSA-44
 */
public class X509AltCertificateExample
{
 private static long ONE_YEAR = 365 * 24 * 60 * 60 * 1000L;
 public static void main(String[] args)
 throws Exception
 {
 Security.addProvider(new BouncyCastleProvider());
 KeyPairGenerator kpGen = KeyPairGenerator.getInstance("ML-DSA", "BC");
 kpGen.initialize(MLDSAParameterSpec.ml_dsa_44, new SecureRandom());
 KeyPair kp = kpGen.generateKeyPair();
 PrivateKey privKey = kp.getPrivate();
 PublicKey pubKey = kp.getPublic();
 KeyPairGenerator ecKpGen = KeyPairGenerator.getInstance("EC", "BC");
 ecKpGen.initialize(new ECNamedCurveGenParameterSpec("P-256"), new SecureRandom());
 KeyPair ec
 PrivateKey ecPrivKey = ecKp.getPrivate();
 PublicKey ecPubKey = ecKp.getPublic();
 X500Name issuer = new X500Name("CN=ML-DSA ECDSA Alt Extension Certificate");
 //
 // create base certificate - version 3
 //
 ContentSigner sigGen = new JcaContentSignerBuilder("SHA256withECDSA").setProvider("BC").build(ecPrivKey);
 ContentSigner altSigGen = new JcaContentSignerBuilder("ML-DSA-44").setProvider("BC").build(privKey);
 X509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(
 issuer, BigInteger.valueOf(1),
 new Date(System.currentTimeMillis() - 50000),
 new Date(System.currentTimeMillis() + ONE_YEAR),
 issuer, ecPubKey)
 .addExtension(Extension.keyUsage, true,
 new X509KeyUsage(X509KeyUsage.digitalSignature))
 .addExtension(Extension.extendedKeyUsage, true,
 new DERSequence(KeyPurposeId.anyExtendedKeyUsage))
 .addExtension(new ASN1ObjectIdentifier("2.5.29.17"), true,
 new GeneralNames(new GeneralName(GeneralName.rfc822Name, "test@test.test")))
 .addExtension(Extension.subjectAltPublicKeyInfo, false,
SubjectAltPublicKeyInfo.getInstance(kp.getPublic().getEncoded()));
 X509Certificate cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certGen.build(sigGen, false,
altSigGen));
 // check validity and verify
 cert.checkValidity(new Date());
 cert.verify(cert.getPublicKey());
 // create a certificate holder to allow checking of the altSignature.
 X509CertificateHolder certHolder = new JcaX509CertificateHolder(cert);
 SubjectPublicKeyInfo altPubKey =
SubjectPublicKeyInfo.getInstance(certHolder.getExtension(Extension.subjectAltPublicKeyInfo).getParsedValue());
 if (certHolder.isAlternativeSignatureValid(new JcaContentVerifierProviderBuilder().setProvider("BC").build(altPubKey)))
 {
 System.out.println("alternative signature verified on certificate");
 System.exit(0);
 }
 System.exit(1);
 }
}
