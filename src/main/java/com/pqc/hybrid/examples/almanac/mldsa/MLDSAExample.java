import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;
/**
 * Example of ML-DSA signature generation using the ML-DSA-65 parameter set.
 */
public class MLDSAExample
{
 private static byte[] msg = Strings.toByteArray("Hello, world!");
 public static void main(String[] args)
 throws Exception
 {
 Security.addProvider(new BouncyCastleProvider());
 // Generate ML-DSA key pair.
 KeyPairGenerator kpGen = KeyPairGenerator.getInstance("MLDSA", "BC");
 kpGen.initialize(MLDSAParameterSpec.ml_dsa_65);
 KeyPair kp = kpGen.generateKeyPair();
 // Create ML-DSA signature object.
 Signature mlDsa = Signature.getInstance("MLDSA");
 // Create ML-DSA signature - without a SecureRandom we are
 // indicating we want to create a Deterministic one.
 mlDsa.initSign(kp.getPrivate());
 mlDsa.update(msg);
 byte[] signature = mlDsa.sign();
 // Verify ML-DSA signature.
 mlDsa.initVerify(kp.getPublic());
 mlDsa.update(msg);
 if (mlDsa.verify(signature))
 {
 System.out.println("ML-DSA-65 signature created and verified successfully");
 System.exit(0);
 }
 System.exit(1);
 }
}
