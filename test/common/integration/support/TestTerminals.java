package card42.test;

import javax.smartcardio.CardTerminal;

import card42.host.common.transport.Terminals;

/**
 * Test-side terminal connection builder.
 *
 * <p>The integration suites are media-neutral: {@code -host=pcsc[:<index>]}
 * talks to a real card through the host stack, {@code -host=socket:<address>:<port>}
 * talks to the Java Card simulator.  Both descriptors are now handled by the
 * product {@link Terminals} (the socket provider is resolved at runtime), so
 * this helper is a thin, media-neutral alias.
 */
public final class TestTerminals {

    private TestTerminals() {
    }

    /**
     * Builds a terminal from a connection descriptor:
     * {@code socket:<address>:<port>} for the simulator or
     * {@code pcsc[:<reader-index>]} for a real card (default reader 0).
     */
    public static CardTerminal getTerminal(String[] connectionParams) throws Exception {
        return Terminals.getTerminal(connectionParams);
    }
}
