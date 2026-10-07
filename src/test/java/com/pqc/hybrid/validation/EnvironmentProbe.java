package com.pqc.hybrid.validation;

import com.pqc.hybrid.core.config.CryptographicProviderFactory;

import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;

/**
 * Captures the environment a validation run happened in, so the evidence can be reproduced and
 * audited later. Without this, a directory of certificates says nothing about which JDK,
 * provider or commit produced it.
 *
 * @author PQC Hybrid Team
 * @version 1.0.0-BETA
 */
final class EnvironmentProbe {

    private EnvironmentProbe() {
        throw new AssertionError("Cannot instantiate EnvironmentProbe");
    }

    /** @return a human-readable environment report for the given run start time. */
    static String describe(Instant startedAt) {
        StringBuilder sb = new StringBuilder();
        sb.append("Ambiente de execucao da campanha de validacao\n");
        sb.append("=".repeat(60)).append("\n\n");
        line(sb, "Data/hora do inicio", DateTimeFormatter.ISO_OFFSET_DATE_TIME
                .withZone(ZoneId.systemDefault()).format(startedAt));
        line(sb, "Java", System.getProperty("java.version")
                + " (" + System.getProperty("java.vendor") + ")");
        line(sb, "JVM", System.getProperty("java.vm.name")
                + " " + System.getProperty("java.vm.version"));
        line(sb, "Sistema operacional", System.getProperty("os.name")
                + " " + System.getProperty("os.version")
                + " (" + System.getProperty("os.arch") + ")");
        line(sb, "Provedor criptografico", providerDescription());
        line(sb, "OpenSSL", OpensslRunner.version());
        line(sb, "Commit", gitCommit());
        line(sb, "Arvore de trabalho", gitDirty());
        return sb.toString();
    }

    /** @return provider name and version, or the failure reason. */
    static String providerDescription() {
        try {
            CryptographicProviderFactory.initialize();
            return CryptographicProviderFactory.getProvider().getName()
                    + " " + CryptographicProviderFactory.getProviderVersion();
        } catch (Exception e) {
            return "indisponivel (" + e.getMessage() + ")";
        }
    }

    private static String gitCommit() {
        try {
            OpensslRunner.Result result = OpensslRunner.run("git", "rev-parse", "HEAD");
            return result.ok() ? result.output().strip() : "desconhecido";
        } catch (Exception e) {
            return "desconhecido";
        }
    }

    private static String gitDirty() {
        try {
            OpensslRunner.Result result = OpensslRunner.run("git", "status", "--porcelain");
            if (!result.ok()) {
                return "desconhecida";
            }
            return result.output().isBlank()
                    ? "limpa"
                    : "com alteracoes nao commitadas";
        } catch (Exception e) {
            return "desconhecida";
        }
    }

    private static void line(StringBuilder sb, String label, String value) {
        sb.append(String.format("%-24s %s%n", label + ':', value));
    }
}
