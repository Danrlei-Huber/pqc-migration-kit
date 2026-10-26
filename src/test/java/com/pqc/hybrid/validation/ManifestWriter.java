package com.pqc.hybrid.validation;

import com.pqc.hybrid.validation.EvidenceRecorder.Artifact;
import com.pqc.hybrid.validation.EvidenceRecorder.CaseRecord;

import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Renders the evidence manifest in two forms: {@code MANIFESTO.md} for a reader and
 * {@code manifesto.json} for tooling. The manifest is what turns a pile of files into auditable
 * evidence — it ties every artifact to the case that produced it and to a SHA-256 that can be
 * re-checked later.
 *
 * <p>JSON is emitted by hand rather than through a library: the project has no JSON dependency,
 * and the shape here is a flat, fully controlled structure.
 *
 * @author PQC Hybrid Team
 * @version 1.0.0-BETA
 */
final class ManifestWriter {

    private ManifestWriter() {
        throw new AssertionError("Cannot instantiate ManifestWriter");
    }

    static String toMarkdown(EvidenceRecorder recorder) {
        String timestamp = DateTimeFormatter.ISO_OFFSET_DATE_TIME
                .withZone(ZoneId.systemDefault()).format(recorder.startedAt());

        StringBuilder sb = new StringBuilder();
        sb.append("# Manifesto de evidência — validação do módulo\n\n");
        sb.append("Gerado por `mvn test -Pvalidacao` em ").append(timestamp).append(".\n\n");
        sb.append("Todo artefato listado abaixo é **material público** — certificados, ")
          .append("requisições, chaves públicas e assinaturas. Nenhuma chave privada é ")
          .append("gravada.\n\n");
        sb.append("Ambiente completo em [`ambiente.txt`](ambiente.txt). ")
          .append("Versão legível por máquina em [`manifesto.json`](manifesto.json).\n\n");

        sb.append("## Resumo\n\n");
        long executados = recorder.cases().stream().filter(c -> c.skipped == null).count();
        long pulados = recorder.cases().size() - executados;
        sb.append("- Casos executados: **").append(executados).append("**\n");
        sb.append("- Casos pulados: **").append(pulados).append("**\n");
        sb.append("- Artefatos gravados: **").append(recorder.artifacts().size()).append("**\n");
        sb.append("- Bytes totais: **")
          .append(recorder.artifacts().stream().mapToLong(Artifact::size).sum())
          .append("**\n\n");

        Map<String, List<CaseRecord>> porArea = recorder.cases().stream()
                .collect(Collectors.groupingBy(c -> c.area, LinkedHashMap::new,
                        Collectors.toList()));

        for (Map.Entry<String, List<CaseRecord>> area : porArea.entrySet()) {
            sb.append("## ").append(area.getKey()).append("\n\n");
            for (CaseRecord caso : area.getValue()) {
                sb.append("### ").append(caso.caso).append(" — ").append(caso.titulo).append("\n\n");
                if (caso.skipped != null) {
                    sb.append("> **Pulado.** ").append(caso.skipped).append("\n\n");
                    continue;
                }
                if (!caso.notes.isEmpty()) {
                    caso.notes.forEach((k, v) ->
                            sb.append("- **").append(k).append(":** ").append(v).append('\n'));
                    sb.append('\n');
                }
                List<Artifact> doCaso = recorder.artifacts().stream()
                        .filter(a -> a.area().equals(caso.area) && a.caso().equals(caso.caso))
                        .toList();
                if (!doCaso.isEmpty()) {
                    sb.append("| Artefato | Bytes | SHA-256 |\n|---|---:|---|\n");
                    for (Artifact a : doCaso) {
                        sb.append("| `").append(a.path()).append("` | ")
                          .append(a.size()).append(" | `").append(a.sha256()).append("` |\n");
                    }
                    sb.append('\n');
                }
            }
        }

        sb.append("## Conferência de integridade\n\n");
        sb.append("```sh\n");
        sb.append("# a partir do diretorio evidencias/\n");
        sb.append("sha256sum -c SHA256SUMS\n");
        sb.append("```\n");
        return sb.toString();
    }

    static String toJson(EvidenceRecorder recorder) {
        String timestamp = DateTimeFormatter.ISO_OFFSET_DATE_TIME
                .withZone(ZoneId.systemDefault()).format(recorder.startedAt());

        StringBuilder sb = new StringBuilder();
        sb.append("{\n");
        sb.append("  \"geradoEm\": \"").append(escape(timestamp)).append("\",\n");
        sb.append("  \"provedor\": \"").append(escape(EnvironmentProbe.providerDescription()))
          .append("\",\n");
        sb.append("  \"openssl\": \"").append(escape(OpensslRunner.version())).append("\",\n");
        sb.append("  \"java\": \"").append(escape(System.getProperty("java.version")))
          .append("\",\n");

        sb.append("  \"casos\": [\n");
        for (int i = 0; i < recorder.cases().size(); i++) {
            CaseRecord caso = recorder.cases().get(i);
            sb.append("    {\n");
            sb.append("      \"area\": \"").append(escape(caso.area)).append("\",\n");
            sb.append("      \"caso\": \"").append(escape(caso.caso)).append("\",\n");
            sb.append("      \"titulo\": \"").append(escape(caso.titulo)).append("\",\n");
            sb.append("      \"pulado\": ")
              .append(caso.skipped == null ? "null" : "\"" + escape(caso.skipped) + "\"")
              .append(",\n");
            sb.append("      \"notas\": {");
            String notas = caso.notes.entrySet().stream()
                    .map(e -> "\n        \"" + escape(e.getKey()) + "\": \""
                            + escape(e.getValue()) + "\"")
                    .collect(Collectors.joining(","));
            sb.append(notas).append(notas.isEmpty() ? "}\n" : "\n      }\n");
            sb.append("    }").append(i + 1 < recorder.cases().size() ? "," : "").append('\n');
        }
        sb.append("  ],\n");

        sb.append("  \"artefatos\": [\n");
        for (int i = 0; i < recorder.artifacts().size(); i++) {
            Artifact a = recorder.artifacts().get(i);
            sb.append("    {\"caminho\": \"").append(escape(a.path()))
              .append("\", \"bytes\": ").append(a.size())
              .append(", \"sha256\": \"").append(a.sha256())
              .append("\", \"area\": \"").append(escape(a.area()))
              .append("\", \"caso\": \"").append(escape(a.caso())).append("\"}")
              .append(i + 1 < recorder.artifacts().size() ? "," : "").append('\n');
        }
        sb.append("  ]\n}\n");
        return sb.toString();
    }

    /** @return the SHA256SUMS body, in the format {@code sha256sum -c} expects. */
    static String toSha256Sums(EvidenceRecorder recorder) {
        return recorder.artifacts().stream()
                .map(a -> a.sha256() + "  " + a.path())
                .collect(Collectors.joining("\n", "", "\n"));
    }

    private static String escape(String value) {
        if (value == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder(value.length() + 8);
        for (char c : value.toCharArray()) {
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> {
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
                }
            }
        }
        return sb.toString();
    }
}
