package card42.host.common.report;

/**
 * Display SPI: shows a cardholder-facing message (status, prompt, ...).
 *
 * <p>The reference host stack only calls this for a short status line; the
 * actual screen rendering is out of scope of this project and lives in a
 * separate UI project.  {@link #NONE} is the no-op default.
 */
public interface Display {

    /** Shows a message to the cardholder. */
    void show(String message);

    /** The no-op display. */
    Display NONE = message -> {
    };
}
