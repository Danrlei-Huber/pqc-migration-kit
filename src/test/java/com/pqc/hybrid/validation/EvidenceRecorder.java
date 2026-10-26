package com.pqc.hybrid.validation;

import org.junit.jupiter.api.extension.ExtensionContext;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Collects the raw evidence produced by the module validation campaign and writes it, together
 * with a manifest, under the evidence root (by default {@code evidencias/}, overridable with
 * {@code -Dvalidacao.saida=<path>}).
 *
 * <p>Only <b>public</b> material is ever recorded: certificates, CSRs, public keys and
 * signatures. Private keys are never written — the library does not export them, and the
 * repository's {@code .gitignore} keeps private-key extensions ignored as a second line of
 * defence.
 *
 * <p>The recorder is a per-session singleton stored as a {@link ExtensionContext.Store.CloseableResource}
 * in the <b>root</b> extension context. That is what guarantees exactly one flush per test
 * session: {@code @AfterAll} would fire once per class, producing a partial manifest.
 *
 * @author PQC Hybrid Team
 * @version 1.0.0-BETA
 */
public final class EvidenceRecorder implements ExtensionContext.Store.CloseableResource {

    private static final String OUTPUT_PROPERTY = "validacao.saida";
    private static final String DEFAULT_OUTPUT = "evidencias";
    private static final ExtensionContext.Namespace NAMESPACE =
            ExtensionContext.Namespace.create(EvidenceRecorder.class);

    private final Path root;
    private final Instant startedAt = Instant.now();
    private final List<Artifact> artifacts = new ArrayList<>();
    private final List<CaseRecord> cases = new ArrayList<>();

    private EvidenceRecorder(Path root) {
        this.root = root;
    }

    /**
     * Returns the session-wide recorder, creating (and registering for flush) on first use.
     *
     * @param context any extension context; the root context is used for storage
     * @return the shared recorder
     */
    public static EvidenceRecorder forSession(ExtensionContext context) {
        return context.getRoot()
                .getStore(NAMESPACE)
                .getOrComputeIfAbsent(EvidenceRecorder.class,
                        key -> new EvidenceRecorder(resolveRoot()),
                        EvidenceRecorder.class);
    }

    private static Path resolveRoot() {
        String configured = System.getProperty(OUTPUT_PROPERTY);
        return Path.of(configured == null || configured.isBlank() ? DEFAULT_OUTPUT : configured)
                .toAbsolutePath()
                .normalize();
    }

    /** @return the evidence root directory. */
    public Path root() {
        return root;
    }

    /**
     * Opens a case: creates {@code <root>/<area>/<caso>/} and returns a handle that writes
     * artifacts into it and accumulates notes for the case report.
     *
     * @param area  area directory, e.g. {@code "01-geracao-chaves"}
     * @param caso  case directory, e.g. {@code "ecdsa-p384"}
     * @param titulo human-readable title for the manifest
     * @return the case handle
     */
    public EvidenceCase caso(String area, String caso, String titulo) {
        Path dir = root.resolve(area).resolve(caso);
        try {
            Files.createDirectories(dir);
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to create evidence directory " + dir, e);
        }
        EvidenceCase handle = new EvidenceCase(this, area, caso, titulo, dir);
        cases.add(handle.record);
        return handle;
    }

    /**
     * Records that a case could not run — typically because an external tool is absent. The
     * absence of evidence must appear in the manifest rather than silently vanish.
     */
    public void puloRegistrado(String area, String caso, String titulo, String motivo) {
        CaseRecord record = new CaseRecord(area, caso, titulo);
        record.skipped = motivo;
        cases.add(record);
    }

    void register(Artifact artifact) {
        artifacts.add(artifact);
    }

    @Override
    public void close() throws IOException {
        Files.createDirectories(root);
        Files.writeString(root.resolve("ambiente.txt"), EnvironmentProbe.describe(startedAt),
                StandardCharsets.UTF_8);
        Files.writeString(root.resolve("manifesto.json"), ManifestWriter.toJson(this),
                StandardCharsets.UTF_8);
        Files.writeString(root.resolve("MANIFESTO.md"), ManifestWriter.toMarkdown(this),
                StandardCharsets.UTF_8);
        Files.writeString(root.resolve("SHA256SUMS"), ManifestWriter.toSha256Sums(this),
                StandardCharsets.UTF_8);
    }

    Instant startedAt() {
        return startedAt;
    }

    List<Artifact> artifacts() {
        return artifacts;
    }

    List<CaseRecord> cases() {
        return cases;
    }

    // ------------------------------------------------------------------ case handle

    /** Writes the artifacts of a single validation case and accumulates its report notes. */
    public static final class EvidenceCase {

        private final EvidenceRecorder recorder;
        private final Path dir;
        private final CaseRecord record;

        private EvidenceCase(EvidenceRecorder recorder, String area, String caso, String titulo,
                             Path dir) {
            this.recorder = recorder;
            this.dir = dir;
            this.record = new CaseRecord(area, caso, titulo);
        }

        /** @return the directory this case writes into. */
        public Path dir() {
            return dir;
        }

        /** Adds a {@code chave: valor} line to the case report. */
        public EvidenceCase nota(String chave, String valor) {
            record.notes.put(chave, valor);
            return this;
        }

        /** Adds a free-form paragraph to the case report. */
        public EvidenceCase texto(String linha) {
            record.lines.add(linha);
            return this;
        }

        /**
         * Writes raw bytes as an artifact and records its SHA-256.
         *
         * @param nome file name inside the case directory
         * @param dados the bytes to persist
         * @return this handle
         */
        public EvidenceCase bytes(String nome, byte[] dados) {
            guardaMaterialPublico(nome);
            Path file = dir.resolve(nome);
            try {
                Files.write(file, dados);
            } catch (IOException e) {
                throw new UncheckedIOException("Failed to write artifact " + file, e);
            }
            recorder.register(new Artifact(relative(file), dados.length, sha256(dados),
                    record.area, record.caso));
            record.artifacts.add(nome);
            return this;
        }

        /** Writes UTF-8 text as an artifact and records its SHA-256. */
        public EvidenceCase texto(String nome, String conteudo) {
            return bytes(nome, conteudo.getBytes(StandardCharsets.UTF_8));
        }

        /**
         * Finishes the case, writing {@code relatorio.txt} from the accumulated notes.
         * Intended to be called once, at the end of the test method.
         */
        public void encerra() {
            StringBuilder sb = new StringBuilder();
            sb.append(record.titulo).append('\n');
            sb.append("=".repeat(Math.min(record.titulo.length(), 78))).append("\n\n");
            record.notes.forEach((k, v) -> sb.append(String.format("%-38s %s%n", k + ':', v)));
            if (!record.lines.isEmpty()) {
                sb.append('\n');
                record.lines.forEach(line -> sb.append(line).append('\n'));
            }
            if (!record.artifacts.isEmpty()) {
                sb.append("\nArtefatos gravados neste caso:\n");
                record.artifacts.forEach(a -> sb.append("  - ").append(a).append('\n'));
            }
            Path file = dir.resolve("relatorio.txt");
            byte[] conteudo = sb.toString().getBytes(StandardCharsets.UTF_8);
            try {
                Files.write(file, conteudo);
            } catch (IOException e) {
                throw new UncheckedIOException("Failed to write case report " + file, e);
            }
            // O relatório também é evidência: entra no manifesto e no SHA256SUMS, ainda que não
            // se liste a si próprio entre os artefatos do caso.
            recorder.register(new Artifact(relative(file), conteudo.length, sha256(conteudo),
                    record.area, record.caso));
        }

        private String relative(Path file) {
            return recorder.root.relativize(file).toString().replace('\\', '/');
        }

        /**
         * Refuses file names that would carry private key material. The campaign only ever
         * records public artifacts; this makes an accidental slip fail loudly instead of
         * writing a secret into a versioned directory.
         */
        private static void guardaMaterialPublico(String nome) {
            String lower = nome.toLowerCase();
            if (lower.endsWith(".key") || lower.endsWith(".p12") || lower.endsWith(".pkcs8")
                    || lower.endsWith(".jks") || lower.contains("private")
                    || lower.contains("privada")) {
                throw new IllegalArgumentException(
                        "A campanha grava apenas material publico; nome recusado: " + nome);
            }
        }
    }

    // ------------------------------------------------------------------ records

    record Artifact(String path, long size, String sha256, String area, String caso) {
    }

    static final class CaseRecord {
        final String area;
        final String caso;
        final String titulo;
        final Map<String, String> notes = new LinkedHashMap<>();
        final List<String> lines = new ArrayList<>();
        final List<String> artifacts = new ArrayList<>();
        String skipped;

        CaseRecord(String area, String caso, String titulo) {
            this.area = area;
            this.caso = caso;
            this.titulo = titulo;
        }
    }

    static String sha256(byte[] data) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(data);
            StringBuilder sb = new StringBuilder(digest.length * 2);
            for (byte b : digest) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }
}
