
public class TestNullOID {
    public static void main(String[] args) {
        try {
            org.bouncycastle.asn1.x509.AlgorithmIdentifier algId = null;
            System.out.println(algId.getAlgorithm().getId());
        } catch (Exception e) {
            System.out.println("Exception: " + e.getClass().getName() + ": " + e.getMessage());
        }
    }
}

