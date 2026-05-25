package com.pqc.hybrid.core.signature;

import com.pqc.hybrid.core.config.CompositeAlgorithm;
import com.pqc.hybrid.core.config.CryptographicProviderFactory;
import com.pqc.hybrid.core.keygen.CompositePrivateKey;
import com.pqc.hybrid.core.keygen.HybridKeyPair;

import java.io.ByteArrayOutputStream;
import java.security.Provider;
import java.security.Signature;

/**
 * <b>EXPERIMENTAL.</b> Composite signature generation following
 * {@code draft-ietf-lamps-pq-composite-sigs}.
 *
 * <p>This is part of the parallel <i>Composite</i> signature path and is
 * <b>not wired into {@link com.pqc.hybrid.core.api.PQCHybridCertificateAPI}</b>.
 * The production flow uses the Catalyst / dual-signature model via
 * {@link DualSignatureStrategy}. APIs here may change without notice.
 */
public final class CompositeSigner {

    private static final String BC = "BC";

    private CompositeSigner() {
        throw new AssertionError("Cannot instantiate CompositeSigner");
    }

    public static byte[] sign(byte[] data, HybridKeyPair keyPair) {
        return sign(data, keyPair, new byte[0]);
    }

    public static byte[] sign(byte[] data, HybridKeyPair keyPair, byte[] ctx) {
        try {
            CryptographicProviderFactory.initialize();
            Provider provider = CryptographicProviderFactory.getProvider();

            CompositePrivateKey compPriv = extractCompositePrivateKey(keyPair);
            CompositeAlgorithm algorithm = compPriv.getCompositeAlgorithm();

            byte[] mRep = MessageRepresentativeBuilder.build(data, algorithm, ctx);

            byte[] mldsaSig = signComponent(mRep, compPriv.getMldsaPrivateKey(),
                    algorithm.getPQCAlgorithm().getName(), provider);
            byte[] tradSig = signComponent(mRep, compPriv.getTradPrivateKey(),
                    getTradSignatureAlgorithm(algorithm), provider);

            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            baos.writeBytes(mldsaSig);
            baos.writeBytes(tradSig);
            return baos.toByteArray();
        } catch (Exception e) {
            throw new RuntimeException("Composite signing failed", e);
        }
    }

    private static byte[] signComponent(byte[] data, java.security.PrivateKey key,
                                         String algorithm, Provider provider) throws Exception {
        Signature sig = Signature.getInstance(algorithm, provider);
        sig.initSign(key);
        sig.update(data);
        return sig.sign();
    }

    private static CompositePrivateKey extractCompositePrivateKey(HybridKeyPair keyPair) {
        java.security.PrivateKey klass = keyPair.getClassicalPrivateKey();
        java.security.PrivateKey pqc = keyPair.getPQCPrivateKey();
        if (klass instanceof CompositePrivateKey comp) return comp;
        if (pqc instanceof CompositePrivateKey comp) return comp;
        throw new IllegalArgumentException("KeyPair does not contain a CompositePrivateKey");
    }

    static String getTradSignatureAlgorithm(CompositeAlgorithm algorithm) {
        return algorithm.getTradSignatureAlgorithm();
    }
}
