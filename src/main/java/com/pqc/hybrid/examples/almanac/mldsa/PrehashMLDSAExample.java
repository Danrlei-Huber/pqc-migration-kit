import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.Signature;
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Strings;
/**
 * Example of Pre-hash ML-DSA signature generation using the ML-DSA-65 parameter set.
 */
public class PrehashMLDSAExample
{
 private static byte[] msg = Strings.toByteArray("Hello, world!");
 public static void main(String[] args)
 throws Exception
 {
 Security.addProvider(new BouncyCastleProvider());
 // Generate ML-DSA key pair - this will result in a key pair specifically encoded
 // for use with pre-hash ML-DSA signatures only.
 KeyPairGenerator kpGen = KeyPairGenerator.getInstance("SHA512withMLDSA", "BC");
 kpGen.initialize(MLDSAParameterSpec.ml_dsa_65_with_sha512);
 KeyPair kp = kpGen.generateKeyPair();
 // Create ML-DSA signature object.
 Signature mlDsa = Signature.getInstance("SHA512withMLDSA");
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
 System.out.println("Pre-hash ML-DSA-65 signature created and verified successfully");
 System.exit(0);
 }
 System.exit(1);
 }
}