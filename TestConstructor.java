
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;

public class TestConstructor {
    public static void main(String[] args) {
        try {
            byte[] altSignatureValue = new byte[]{1, 2, 3};
            SubjectPublicKeyInfo subjectAltPublicKeyInfo = new SubjectPublicKeyInfo(
                    new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.3")),
                    new byte[]{4, 5, 6});
            
            System.out.println("Testing null altSignatureAlgorithm...");
            // This should work since we don't immediately use altSignatureAlgorithm
            com.pqc.hybrid.core.certificate.asn1.PQCExtensionsStructure ext = 
                new com.pqc.hybrid.core.certificate.asn1.PQCExtensionsStructure(
                    null, altSignatureValue, subjectAltPublicKeyInfo);
            System.out.println("Constructor succeeded, altSignatureAlgorithm is null: " + (ext.getAltSignatureAlgorithm() == null));
            
            System.out.println("Testing null altSignatureValue...");
            try {
                // This should fail on the .clone() call
                ext = new com.pqc.hybrid.core.certificate.asn1.PQCExtensionsStructure(
                    new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.3")), 
                    null, 
                    subjectAltPublicKeyInfo);
                System.out.println("This should not print");
            } catch (NullPointerException e) {
                System.out.println("Got expected NPE for null altSignatureValue: " + e.getMessage());
            }
            
            System.out.println("Testing null subjectAltPublicKeyInfo...");
            // This should work since we just store the reference
            ext = new com.pqc.hybrid.core.certificate.asn1.PQCExtensionsStructure(
                new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.3")), 
                altSignatureValue, 
                null);
            System.out.println("Constructor succeeded, subjectAltPublicKeyInfo is null: " + (ext.getSubjectAltPublicKeyInfo() == null));
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

