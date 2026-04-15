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
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
/**
 * Create a basic self-signed certificate using ML-DSA-44.
 */
public class MLDSACertificateExample
{
private static long ONE_YEAR = 365 * 24 * 60 * 60 * 1000L;
public static void main(String[] args)
throws Exception
{
Security.addProvider(new BouncyCastleProvider());
// generate an ML-DSA-44 key pair
KeyPairGenerator kpGen = KeyPairGenerator.getInstance("ML-DSA", "BC");
 kpGen.initialize(MLDSAParameterSpec.ml_dsa_44, new SecureRandom());
KeyPair kp = kpGen.generateKeyPair();
PrivateKey privKey = kp.getPrivate();
PublicKey pubKey = kp.getPublic();
 X500Name issuer = new X500Name("CN=ML-DSA Certificate");
//
 // create base certificate - version 3
 //
ContentSigner sigGen = new JcaContentSignerBuilder("ML-DSA-44").setProvider("BC").build(privKey);
X509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(
issuer, BigInteger.valueOf(1),
new Date(System.currentTimeMillis() - 50000),
new Date(System.currentTimeMillis() + ONE_YEAR),
issuer, pubKey)
 .addExtension(Extension.keyUsage, true,
new X509KeyUsage(X509KeyUsage.encipherOnly))
 .addExtension(Extension.extendedKeyUsage, true,
new DERSequence(KeyPurposeId.anyExtendedKeyUsage))
 .addExtension(Extension.subjectAlternativeName, true,
new GeneralNames(new GeneralName(GeneralName.rfc822Name, "test@test.test")));
 X509Certificate cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certGen.build(sigGen));
 //
 // check validity
 //
 cert.checkValidity(new Date());
 try
 {
 cert.verify(cert.getPublicKey());
 System.out.println("ML-DSA certificate verified");
 System.exit(0);
 }
 catch (Exception e)
 {
 System.exit(1);
 }
 }
}