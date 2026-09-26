package card42.host.common.transport;

import java.io.PrintStream;

/**
 * An open card connection with an optional APDU trace wrapper, shared by the
 * CLI commands.  It is the common "open the terminal, optionally trace every
 * exchange" step of {@code terminal pay}/{@code inspect}/{@code apdu} and
 * {@code card}; {@link #close()} disconnects the card.
 */
public final class TerminalSession implements AutoCloseable {

    private final Terminals.Connection connection;

    /** The terminal to use: the traced channel when tracing, else the raw terminal. */
    public final Terminal terminal;

    private TerminalSession(Terminals.Connection connection, Terminal terminal) {
        this.connection = connection;
        this.terminal = terminal;
    }

    /**
     * Opens the connection described by {@code host} (waiting up to
     * {@code wait} seconds) and wraps it with {@link TracingChannel} when
     * {@code trace} is set, printing every exchange to {@code traceOut}.
     */
    public static TerminalSession open(String host, int wait, boolean trace, PrintStream traceOut)
            throws Exception {
        Terminals.Connection connection = Terminals.open(host, wait);
        Terminal terminal = trace
                ? new Terminal(new TracingChannel(connection.card.getBasicChannel(), traceOut))
                : connection.terminal;
        return new TerminalSession(connection, terminal);
    }

    @Override
    public void close() throws Exception {
        connection.close();
    }
}
