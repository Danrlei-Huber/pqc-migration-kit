package com.pqc.hybrid.validation;

import org.junit.jupiter.api.Assumptions;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;

/**
 * Runs the {@code openssl} command line so certificates produced by this library can be checked
 * by a verifier that is not this library.
 *
 * <p>Shared by the validation campaign and by
 * {@code com.pqc.hybrid.core.certificate.LegacyVerifierCompatibilityTest}, so process handling
 * lives in one place.
 *
 * @author PQC Hybrid Team
 * @version 1.0.0-BETA
 */
public final class OpensslRunner {

    private static final int TIMEOUT_SECONDS = 60;

    private OpensslRunner() {
        throw new AssertionError("Cannot instantiate OpensslRunner");
    }

    /** Result of a command: its exit code and its combined stdout/stderr. */
    public record Result(int exitCode, String output) {

        /** @return true when the command completed successfully. */
        public boolean ok() {
            return exitCode == 0;
        }
    }

    /**
     * Runs a command, merging stderr into stdout.
     *
     * @param command the command and its arguments
     * @return the exit code and combined output
     * @throws IOException          if the process cannot be started or times out
     * @throws InterruptedException if the wait is interrupted
     */
    public static Result run(String... command) throws IOException, InterruptedException {
        Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
        String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        if (!process.waitFor(TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
            process.destroyForcibly();
            throw new IOException("Timed out running: " + String.join(" ", command));
        }
        return new Result(process.exitValue(), output);
    }

    /** @return true if an {@code openssl} binary can be executed. */
    public static boolean available() {
        try {
            return run("openssl", "version").ok();
        } catch (Exception e) {
            return false;
        }
    }

    /** @return the {@code openssl version} banner, or a marker when unavailable. */
    public static String version() {
        try {
            Result result = run("openssl", "version");
            return result.ok() ? result.output().strip() : "indisponivel";
        } catch (Exception e) {
            return "indisponivel";
        }
    }

    /** Skips the calling test when no {@code openssl} binary is available. */
    public static void assumeAvailable() {
        Assumptions.assumeTrue(available(),
                "openssl nao esta disponivel nesta maquina; verificacao externa pulada");
    }
}
