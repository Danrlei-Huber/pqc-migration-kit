package com.pqc.hybrid.core.keygen;

import com.pqc.hybrid.core.config.CompositeAlgorithm;
import com.pqc.hybrid.core.config.CryptographicProviderFactory;
import com.pqc.hybrid.core.config.ClassicalAlgorithm;
import com.pqc.hybrid.core.exception.PQCHybridException;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;

/**
 * <b>EXPERIMENTAL.</b> Generates composite key pairs for the composite signature
 * path ({@code draft-ietf-lamps-pq-composite-sigs}).
 *
 * <p>Part of the parallel <i>Composite</i> path; <b>not wired into
 * {@link com.pqc.hybrid.core.api.PQCHybridCertificateAPI}</b>, which uses the
 * Catalyst / dual-signature model. APIs here may change without notice.
 */
public final class CompositeKeyGenerator {

    private static final SecureRandom RANDOM = new SecureRandom();

    private CompositeKeyGenerator() {
        throw new AssertionError("Cannot instantiate CompositeKeyGenerator");
    }

    public static HybridKeyPair generate(CompositeAlgorithm algorithm) {
        try {
            CryptographicProviderFactory.initialize();
            var provider = CryptographicProviderFactory.getProvider();

            byte[] mldsaSeed = new byte[algorithm.getMldsaSeedSize()];
            RANDOM.nextBytes(mldsaSeed);

            KeyPairGenerator mldsaKpg = KeyPairGenerator.getInstance(algorithm.getPQCAlgorithm().getName(), provider);
            KeyPair mldsaKp = mldsaKpg.generateKeyPair();

            KeyPairGenerator tradKpg = KeyPairGenerator.getInstance(algorithm.getTradKeyAlgorithm(), provider);
            if ("RSA".equals(algorithm.getTradAlgorithmName())) {
                tradKpg.initialize(algorithm.getTradKeySize(), RANDOM);
            } else if ("ECDSA".equals(algorithm.getTradAlgorithmName()) || "EC".equals(algorithm.getTradKeyAlgorithm())) {
                String curveName = switch (algorithm.getTradKeySize()) {
                    case 256 -> "secp256r1";
                    case 384 -> "secp384r1";
                    case 521 -> "secp521r1";
                    default -> "secp256r1";
                };
                tradKpg.initialize(new ECGenParameterSpec(curveName), RANDOM);
            } else if ("Ed25519".equals(algorithm.getTradAlgorithmName())) {
                tradKpg = KeyPairGenerator.getInstance("Ed25519", provider);
            } else if ("Ed448".equals(algorithm.getTradAlgorithmName())) {
                tradKpg = KeyPairGenerator.getInstance("Ed448", provider);
            }
            KeyPair tradKp = tradKpg.generateKeyPair();

            CompositePublicKey compPub = new CompositePublicKey(mldsaKp.getPublic(), tradKp.getPublic(), algorithm);
            CompositePrivateKey compPriv = new CompositePrivateKey(
                    mldsaKp.getPrivate(), tradKp.getPrivate(), mldsaSeed, algorithm);

            return new HybridKeyPair(
                    compPub, compPriv,
                    compPub, compPriv,
                    algorithm.getTradAlgorithmName(),
                    algorithm.getPQCAlgorithm().getName());

        } catch (Exception e) {
            throw new PQCHybridException("Composite key generation failed", e);
        }
    }
}
