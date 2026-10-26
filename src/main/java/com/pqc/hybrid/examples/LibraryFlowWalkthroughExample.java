package com.pqc.hybrid.examples;

import com.pqc.hybrid.core.api.PQCHybridCertificateAPI;
import com.pqc.hybrid.core.certificate.HybridCertificateAuthority;
import com.pqc.hybrid.core.certificate.HybridCertificateValidator;
import com.pqc.hybrid.core.common.oid.AlgorithmOIDRegistry;
import com.pqc.hybrid.core.config.ClassicalAlgorithm;
import com.pqc.hybrid.core.config.HybridAlgorithmPair;
import com.pqc.hybrid.core.config.HybridCertificateConfig;
import com.pqc.hybrid.core.config.PQCAlgorithm;
import com.pqc.hybrid.core.keygen.HybridKeyPair;
import com.pqc.hybrid.core.model.HybridCertificateInfo;
import com.pqc.hybrid.core.util.printer.CertificatePrinter;
import com.pqc.hybrid.core.util.printer.HybridCertificateInspector;
import com.pqc.hybrid.core.util.printer.KeyInfoPrinter;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;
import java.util.logging.LogManager;

/**
 * Example: End-to-end walkthrough of the hybrid PQC library's PRODUCTION flow, printing the
 * <b>complete objects</b> consumed and produced at every step.
 *
 * <p>Where the focused examples show summaries, this one dumps the full material so the data
 * transformations are fully auditable in the terminal — useful as evidence/appendix for the TCC:
 *
 * <pre>
 *   1. initialize the API                                  -> API + strategy objects
 *   2. generate two hybrid key pairs (Root CA + leaf)      -> full algorithm pairs + full key pairs (PEM)
 *   3. sign/verify raw data                                -> full byte[] envelope, decoded part by part
 *   4. create a self-signed hybrid Root CA                 -> full CA certificate (PEM)
 *   5. issue an end-entity certificate signed by the CA    -> full leaf cert (PEM) + Catalyst extensions (DER)
 *   6. validate the full chain (classical PKIX + PQC)      -> chain verdict
 * </pre>
 *
 * <p>The Catalyst model carries the PQC material in the ITU-T X.509 alternative-signature
 * extensions {@code 2.5.29.72} (subjectAltPublicKeyInfo), {@code 2.5.29.73}
 * (altSignatureAlgorithm) and {@code 2.5.29.74} (altSignatureValue).
 *
 * <p>Output is intentionally long and complete. Flags:
 * <ul>
 *   <li>{@code -v} / {@code --verbose} — keep the library's java.util.logging INFO lines.</li>
 *   <li>{@code -s} / {@code --summary} — truncate the big crypto blobs (keys/signatures) to a preview.</li>
 * </ul>
 *
 * @author PQC Hybrid Team
 * @version 1.0.0-BETA
 */
public class LibraryFlowWalkthroughExample {

    // ITU-T X.509 (2019) alternative-signature extension OIDs (the "Catalyst" PQC material).
    private static final String OID_SUBJECT_ALT_PUBLIC_KEY_INFO = "2.5.29.72";
    private static final String OID_ALT_SIGNATURE_ALGORITHM = "2.5.29.73";
    private static final String OID_ALT_SIGNATURE_VALUE = "2.5.29.74";

    private static final KeyInfoPrinter KEY_PRINTER = new KeyInfoPrinter();
    private static final CertificatePrinter CERT_PRINTER = new CertificatePrinter();
    private static final HybridCertificateInspector INSPECTOR = new HybridCertificateInspector();

    /** When true, big base64/hex blobs are truncated to a short preview ({@code --summary}). */
    private static boolean summary = false;

    public static void main(String[] args) {
        boolean verbose = false;
        for (String a : args) {
            if (a.equals("-v") || a.equals("--verbose")) verbose = true;
            if (a.equals("-s") || a.equals("--summary")) summary = true;
        }
        // Silence the library's java.util.logging INFO lines unless -v was given.
        if (!verbose) {
            LogManager.getLogManager().reset();
        }

        banner("PQC HYBRID LIBRARY — END-TO-END FLOW WALKTHROUGH (complete objects)");

        try {
            // ───────────────────────────────────────────────────────────────────────────
            step(1, "Initialize the API (BouncyCastle provider + PQC algorithm checks)");
            // ───────────────────────────────────────────────────────────────────────────
            PQCHybridCertificateAPI api = new PQCHybridCertificateAPI();
            api.initialize();
            field("strategy", api.getSignatureStrategy().getStrategyName());
            field("library", PQCHybridCertificateAPI.getLibraryInfo());
            field("version", api.getVersion());
            field("initialized", String.valueOf(api.isInitialized()));
            field("object", api.toString());

            // ───────────────────────────────────────────────────────────────────────────
            step(2, "Generate two hybrid key pairs (Root CA @256-bit, end-entity @192-bit)");
            // ───────────────────────────────────────────────────────────────────────────
            HybridAlgorithmPair caAlg = HybridAlgorithmPair.recommended(256);
            HybridAlgorithmPair leafAlg = HybridAlgorithmPair.recommended(192);

            System.out.println("\n   INPUT object — HybridAlgorithmPair (Root CA):");
            printAlgorithmPair(caAlg);
            System.out.println("\n   INPUT object — HybridAlgorithmPair (end-entity):");
            printAlgorithmPair(leafAlg);

            HybridKeyPair caKeyPair = api.generateHybridKeyPair(caAlg);
            HybridKeyPair leafKeyPair = api.generateHybridKeyPair(leafAlg);

            System.out.println("\n   OUTPUT object — HybridKeyPair (Root CA): " + caKeyPair);
            printKeyPairFull(caKeyPair);
            System.out.println("\n   OUTPUT object — HybridKeyPair (end-entity): " + leafKeyPair);
            printKeyPairFull(leafKeyPair);

            // ───────────────────────────────────────────────────────────────────────────
            step(3, "Sign + verify raw data with the dual signature (object: byte[] envelope)");
            // ───────────────────────────────────────────────────────────────────────────
            byte[] data = "Documento crítico assinado de forma híbrida (clássica + PQC)"
                    .getBytes(StandardCharsets.UTF_8);
            System.out.println("   INPUT object — message (byte[" + data.length + "]):");
            field("utf-8", new String(data, StandardCharsets.UTF_8));
            field("hex", hex(data));
            field("base64", b64(data));

            byte[] signature = api.signData(data, leafKeyPair);
            System.out.println("\n   OUTPUT object — signature envelope (byte[" + signature.length + "]):");
            decodeAndPrintEnvelope(signature, leafKeyPair);

            System.out.println("\n   verify(original) ......... " + verdict(api.verifySignature(data, signature, leafKeyPair)));
            byte[] tampered = data.clone();
            tampered[0] ^= 0x01; // flip one bit of the message
            boolean tamperedOk = api.verifySignature(tampered, signature, leafKeyPair);
            System.out.println("   verify(tampered message) . " + verdict(tamperedOk)
                    + (tamperedOk ? "" : "  <- tampering detected"));

            // ───────────────────────────────────────────────────────────────────────────
            step(4, "Create a self-signed hybrid Root CA (object: X509Certificate)");
            // ───────────────────────────────────────────────────────────────────────────
            HybridCertificateConfig caConfig = HybridCertificateConfig.builder()
                    .withAlgorithmPair(caAlg)
                    .withSubjectDN("CN=PQC Hybrid Root CA,O=TCC,C=BR")
                    .withIssuerDN("CN=PQC Hybrid Root CA,O=TCC,C=BR")
                    .withSerialNumber(BigInteger.valueOf(1))
                    .withValidityDays(3650)
                    .asCertificateAuthority(true)
                    .build();
            System.out.println("   INPUT object — HybridCertificateConfig (Root CA):");
            printConfig(caConfig);

            HybridCertificateAuthority ca = api.createRootCA(caConfig, caKeyPair);
            X509Certificate caCert = ca.getCertificate();
            System.out.println("\n   OUTPUT object — HybridCertificateAuthority: " + ca);
            System.out.println("\n   OUTPUT object — Root CA X509Certificate:");
            printCertificateFull(caCert);

            // ───────────────────────────────────────────────────────────────────────────
            step(5, "Issue an end-entity certificate signed by the CA (Catalyst PQC extensions)");
            // ───────────────────────────────────────────────────────────────────────────
            HybridCertificateConfig leafConfig = HybridCertificateConfig.builder()
                    .withAlgorithmPair(leafAlg)
                    .withSubjectDN("CN=secure.example.com,O=TCC,C=BR")
                    .withIssuerDN("CN=PQC Hybrid Root CA,O=TCC,C=BR")
                    .withSerialNumber(BigInteger.valueOf(1001))
                    .withValidityDays(365)
                    .build();
            System.out.println("   INPUT object — HybridCertificateConfig (end-entity):");
            printConfig(leafConfig);

            X509Certificate leafCert = api.issueCertificate(ca, leafConfig, leafKeyPair);
            System.out.println("\n   OUTPUT object — end-entity X509Certificate:");
            printCertificateFull(leafCert);

            System.out.println("\n   Catalyst alternative-signature extensions on the leaf (full DER):");
            printExtFull(leafCert, OID_SUBJECT_ALT_PUBLIC_KEY_INFO, "subjectAltPublicKeyInfo (PQC public key)");
            printExtFull(leafCert, OID_ALT_SIGNATURE_ALGORITHM, "altSignatureAlgorithm   (PQC alg id)");
            printExtFull(leafCert, OID_ALT_SIGNATURE_VALUE, "altSignatureValue       (PQC signature)");
            System.out.println("      api.validatePQCExtensions ......... " + verdict(api.validatePQCExtensions(leafCert)));
            System.out.println("      inspector.isHybridCertificate() ... " + INSPECTOR.isHybridCertificate(leafCert));

            HybridCertificateInfo info = api.getCertificateInfo(leafCert, leafKeyPair);
            System.out.println("\n   OUTPUT object — HybridCertificateInfo (full):");
            printCertificateInfoFull(info);

            // Inspector's own full inspection report.
            System.out.println("\n   Inspector report:");
            printIndented(INSPECTOR.inspectCertificateToString(leafCert));

            // ───────────────────────────────────────────────────────────────────────────
            step(6, "Validate the full chain (classical PKIX + post-quantum dimensions)");
            // ───────────────────────────────────────────────────────────────────────────
            List<X509Certificate> chain = List.of(leafCert, caCert); // leaf -> root
            HybridCertificateValidator.HybridChainValidationResult chainResult =
                    api.validateCertificateChain(chain);
            field("chain", "leaf -> root (" + chain.size() + " certs)");
            field("classical valid", verdict(chainResult.classicalValid()));
            field("pqc valid", verdict(chainResult.pqcValid()));
            field("chain valid", verdict(chainResult.isValid()));

            banner("FLOW COMPLETED SUCCESSFULLY");

        } catch (Exception e) {
            System.err.println("\nFlow failed: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }

    // ── object printers ────────────────────────────────────────────────────────────────

    private static void printAlgorithmPair(HybridAlgorithmPair pair) {
        ClassicalAlgorithm c = pair.classicalAlgorithm();
        PQCAlgorithm p = pair.pqcAlgorithm();
        field("description", pair.getDescription());
        field("securityBalanced", String.valueOf(pair.isSecurityBalanced()));
        field("nistStandardized", String.valueOf(pair.areNistStandardized()));
        System.out.println("      classical -> " + c.name());
        field("  algorithmName", c.getAlgorithmName());
        field("  keySize", c.getKeySize() + " bits");
        field("  oid", c.getOid());
        field("  signatureAlgorithm", c.getSignatureAlgorithm());
        field("  securityLevel", c.getSecurityLevel() + " bits");
        System.out.println("      pqc -> " + p.name());
        field("  name", p.getName());
        field("  oid", p.getOid());
        field("  securityLevel", p.getSecurityLevel() + " bits");
        field("  publicKeySize", p.getPublicKeySize() + " bytes (approx)");
        field("  category", p.getCategory().toString());
    }

    private static void printKeyPairFull(HybridKeyPair kp) {
        field("label", kp.getLabel());
        field("classicalAlgorithm", kp.getClassicalAlgorithm());
        field("pqcAlgorithm", kp.getPQCAlgorithm());
        field("generationTime", String.valueOf(kp.getGenerationTime()));
        System.out.println("      ── classical keys ──");
        System.out.println("      " + KEY_PRINTER.formatKeyCompact(kp.getClassicalPublicKey()));
        pem("PUBLIC KEY (" + kp.getClassicalAlgorithm() + ", X.509/SPKI)", kp.getClassicalPublicKey());
        pem("PRIVATE KEY (" + kp.getClassicalAlgorithm() + ", PKCS#8) [SENSITIVE]", kp.getClassicalPrivateKey());
        System.out.println("      ── post-quantum keys ──");
        System.out.println("      " + KEY_PRINTER.formatKeyCompact(kp.getPQCPublicKey()));
        pem("PUBLIC KEY (" + kp.getPQCAlgorithm() + ", X.509/SPKI)", kp.getPQCPublicKey());
        pem("PRIVATE KEY (" + kp.getPQCAlgorithm() + ", PKCS#8) [SENSITIVE]", kp.getPQCPrivateKey());
    }

    /** Decodes the [4-byte BE classical length][classical][pqc] envelope and prints each part fully. */
    private static void decodeAndPrintEnvelope(byte[] envelope, HybridKeyPair kp) {
        ByteBuffer buf = ByteBuffer.wrap(envelope);
        int classicalLen = buf.getInt();
        byte[] classical = new byte[classicalLen];
        buf.get(classical);
        byte[] pqc = new byte[envelope.length - Integer.BYTES - classicalLen];
        buf.get(pqc);

        field("framing", "[4-byte BE length][classical][pqc]");
        field("classicalLengthPrefix", classicalLen + " bytes");
        System.out.println("      ── classical signature (" + kp.getClassicalAlgorithm()
                + ", " + classical.length + " bytes) ──");
        field("hex", hex(classical));
        field("base64", b64(classical));
        System.out.println("      ── pqc signature (" + kp.getPQCAlgorithm()
                + ", " + pqc.length + " bytes) ──");
        field("base64", b64(pqc));
        field("totalEnvelope", envelope.length + " bytes");
        field("fullEnvelopeBase64", b64(envelope));
    }

    private static void printConfig(HybridCertificateConfig c) {
        field("version", c.getVersion());
        field("subjectDN", c.getSubjectDN());
        field("issuerDN", c.getIssuerDN());
        field("serialNumber", String.valueOf(c.getSerialNumber()));
        field("validityDays", String.valueOf(c.getValidityDays()));
        field("algorithmPair", c.getAlgorithmPair().getDescription());
        field("includePrimarySignature", String.valueOf(c.isIncludePrimarySignature()));
        field("includeAlternativeSignature", String.valueOf(c.isIncludeAlternativeSignature()));
        field("isCertificateAuthority", String.valueOf(c.isCertificateAuthority()));
        field("pathLenConstraint", String.valueOf(c.getPathLenConstraint()));
        field("subjectAltNames", String.valueOf(c.getSubjectAltNames()));
    }

    private static void printCertificateFull(X509Certificate cert) {
        printIndented(CERT_PRINTER.formatCertificate(cert));
        try {
            pemRaw("CERTIFICATE", cert.getEncoded());
        } catch (Exception e) {
            System.out.println("      (could not encode certificate: " + e.getMessage() + ")");
        }
    }

    private static void printExtFull(X509Certificate cert, String oid, String label) {
        byte[] raw = cert.getExtensionValue(oid);
        boolean critical = cert.getCriticalExtensionOIDs() != null && cert.getCriticalExtensionOIDs().contains(oid);
        if (raw == null) {
            System.out.println("      [" + oid + "] " + label + " -> ABSENT");
            return;
        }
        System.out.println("      [" + oid + "] " + label
                + " -> " + raw.length + " B DER, " + (critical ? "CRITICAL" : "non-critical"));
        field("  der.hex", hex(raw));
    }

    private static void printCertificateInfoFull(HybridCertificateInfo info) {
        field("subjectDN", info.getSubjectDN());
        field("issuerDN", info.getIssuerDN());
        field("classicalAlgorithm (subject)", String.valueOf(info.getClassicalAlgorithm()));
        field("pqcAlgorithm (subject)", String.valueOf(info.getPQCAlgorithm()));
        String oid = info.getPQCAlgorithmOID();
        field("pqcAlgorithmOID (issuer altSig)", oid + " = " + AlgorithmOIDRegistry.getAlgorithmName(oid));
        field("hasPQCExtensions", String.valueOf(info.hasPQCExtensions()));
        field("hasPQCSignature", String.valueOf(info.hasPQCSignature()));
        field("pqcPublicKeySize", info.getPQCPublicKeySize() + " bytes");
        field("pqcSignatureSize", info.getPQCSignatureSize() + " bytes");
        field("generationInstant", String.valueOf(info.getGenerationInstant()));
        byte[] pqcPub = info.getPQCPublicKeyBytes();
        if (pqcPub != null) field("pqcPublicKeyBytes.base64", b64(pqcPub));
        byte[] pqcSig = info.getPQCSignature();
        if (pqcSig != null) field("pqcSignature.base64", b64(pqcSig));
    }

    // ── low-level formatting helpers ─────────────────────────────────────────────────────

    private static void banner(String title) {
        String line = "═".repeat(72);
        System.out.println("\n╔" + line + "╗");
        System.out.printf("║ %-70s ║%n", title);
        System.out.println("╚" + line + "╝");
    }

    private static void step(int n, String title) {
        System.out.println("\n──────────────────────────────────────────────────────────────────");
        System.out.println(" STEP " + n + ": " + title);
        System.out.println("──────────────────────────────────────────────────────────────────");
    }

    private static void field(String name, String value) {
        System.out.println("      " + name + " " + ".".repeat(Math.max(2, 28 - name.length())) + " " + value);
    }

    private static void printIndented(String block) {
        for (String l : block.split("\n")) {
            System.out.println("      " + l);
        }
    }

    /** Prints an encoded {@link Key} as a PEM-style block (complete, wrapped at 64 cols). */
    private static void pem(String label, Key key) {
        pemRaw(label, key.getEncoded());
    }

    private static void pemRaw(String label, byte[] der) {
        if (summary) {
            field(label, head(Base64.getEncoder().encodeToString(der), 64) + " (" + der.length + " B, --summary)");
            return;
        }
        String b64 = Base64.getEncoder().encodeToString(der);
        System.out.println("      -----BEGIN " + label + "-----");
        for (int i = 0; i < b64.length(); i += 64) {
            System.out.println("      " + b64.substring(i, Math.min(i + 64, b64.length())));
        }
        System.out.println("      -----END " + label + "-----");
    }

    /** Full base64 (single line) unless --summary, then truncated. */
    private static String b64(byte[] data) {
        String s = Base64.getEncoder().encodeToString(data);
        return summary ? head(s, 64) + " (" + data.length + " B)" : s;
    }

    /** Full lowercase hex unless --summary, then truncated. */
    private static String hex(byte[] data) {
        StringBuilder sb = new StringBuilder(data.length * 2);
        for (byte b : data) sb.append(String.format("%02x", b));
        String s = sb.toString();
        return summary ? head(s, 64) + " (" + data.length + " B)" : s;
    }

    private static String verdict(boolean b) {
        return b ? "VALID" : "INVALID";
    }

    private static String head(String s, int n) {
        return s.length() > n ? s.substring(0, n) + "..." : s;
    }
}
