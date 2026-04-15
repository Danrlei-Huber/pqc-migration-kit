import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
/**
 * Create a basic PKCS10 request using ML-DSA-44.
 */
public class MLDSAPKCS10Example
{
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
 X500Name subject = new X500Name("CN=ML-DSA Certification Request");
 //
 // Create
 //
 ContentSigner sigGen = new JcaContentSignerBuilder("ML-DSA-44").setProvider("BC").build(privKey);
 PKCS10CertificationRequestBuilder pkcs10Gen = new JcaPKCS10CertificationRequestBuilder(subject, pubKey);
 PKCS10CertificationRequest pkcs10 = pkcs10Gen.build(sigGen);
 if (pkcs10.isSignatureValid(new
JcaContentVerifierProviderBuilder().setProvider("BC").build(pkcs10.getSubjectPublicKeyInfo())))
 {
 System.out.println("ML-DSA PKCS#10 request verified");
 System.exit(0);
 }
 System.exit(1);
 }
}
