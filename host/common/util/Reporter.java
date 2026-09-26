package card42.host.common.util;

import java.io.PrintStream;

/**
 * Progress and diagnostic sink for the host library.
 *
 * <p>The library never writes to {@code System.out} itself: a class that wants
 * to report progress takes a {@link Reporter} and calls {@link #info}.  Callers
 * bind it to stdout (a CLI tool), to the test harness, or leave it as
 * {@link #noop()} for a silent run.
 */
public interface Reporter {

    /** Reports one informational line. */
    void info(String message);

    /** A reporter that discards every message. */
    static Reporter noop() {
        return message -> {
        };
    }

    /** A reporter that prints every message as one line on {@code out}. */
    static Reporter to(PrintStream out) {
        return out::println;
    }
}
