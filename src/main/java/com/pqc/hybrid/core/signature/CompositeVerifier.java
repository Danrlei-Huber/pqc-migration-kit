package com.pqc.hybrid.core.signature;

import com.pqc.hybrid.core.config.CompositeAlgorithm;
import com.pqc.hybrid.core.config.CryptographicProviderFactory;
import com.pqc.hybrid.core.keygen.CompositePublicKey;
import com.pqc.hybrid.core.keygen.HybridKeyPair;

import java.security.Provider;
import java.security.Signature;

/**
 * <b>EXPERIMENTAL.</b> Composite signature verification following
 * {@code draft-ietf-lamps-pq-composite-sigs}.
 *
 * <p>This is part of the parallel <i>Composite</i> signature path and is
 * <b>not wired into {@link com.pqc.hybrid.core.api.PQCHybridCertificateAPI}</b>.
 * The production flow uses the Catalyst / dual-signature model via
 * {@link DualSignatureStrategy}. APIs here may change without notice.
 */
public final class CompositeVerifier {

    private static final String BC = "BC";

    private CompositeVerifier() {
        throw new AssertionError("Cannot instantiate CompositeVerifier");
    }

    public static boolean verify(byte[] data, byte[] compositeSignature, HybridKeyPair keyPair) {
        return verify(data, compositeSignature, keyPair, new byte[0]);
    }

    public static boolean verify(byte[] data, byte[] compositeSignature, HybridKeyPair keyPair, byte[] ctx) {
        try {
            CryptographicProviderFactory.initialize();
            Provider provider = CryptographicProviderFactory.getProvider();

            CompositePublicKey compPub = extractCompositePublicKey(keyPair);
            CompositeAlgorithm algorithm = compPub.getCompositeAlgorithm();

            byte[] mRep = MessageRepresentativeBuilder.build(data, algorithm, ctx);

            int mldsaSigSize = algorithm.getMldsaSignatureSize();
            byte[] mldsaSig = new byte[mldsaSigSize];
            byte[] tradSig = new byte[compositeSignature.length - mldsaSigSize];
            System.arraycopy(compositeSignature, 0, mldsaSig, 0, mldsaSigSize);
            System.arraycopy(compositeSignature, mldsaSigSize, tradSig, 0, tradSig.length);

            boolean mldsaValid = verifyComponent(mRep, mldsaSig, compPub.getMldsaPublicKey(),
                    algorithm.getPQCAlgorithm().getName(), provider);
            boolean tradValid = verifyComponent(mRep, tradSig, compPub.getTradPublicKey(),
                    CompositeSigner.getTradSignatureAlgorithm(algorithm), provider);

            return mldsaValid && tradValid;

        } catch (Exception e) {
            throw new RuntimeException("Composite verification failed", e);
        }
    }

    private static boolean verifyComponent(byte[] data, byte[] signature,
                                            java.security.PublicKey key,
                                            String algorithm, Provider provider) throws Exception {
        Signature sig = Signature.getInstance(algorithm, provider);
        sig.initVerify(key);
        sig.update(data);
        return sig.verify(signature);
    }

    private static CompositePublicKey extractCompositePublicKey(HybridKeyPair keyPair) {
        java.security.PublicKey klass = keyPair.getClassicalPublicKey();
        java.security.PublicKey pqc = keyPair.getPQCPublicKey();
        if (klass instanceof CompositePublicKey comp) return comp;
        if (pqc instanceof CompositePublicKey comp) return comp;
        throw new IllegalArgumentException("KeyPair does not contain a CompositePublicKey");
    }
}
