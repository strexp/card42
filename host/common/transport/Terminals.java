package card42.host.common.transport;

import java.net.InetSocketAddress;
import java.util.List;

import javax.smartcardio.Card;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.TerminalFactory;

/**
 * Builds and opens the card terminal connection used by the host stack.
 *
 * <p>Two connection descriptors are understood:
 *
 * <ul>
 *   <li>{@code pcsc[:<reader-index>]} - a real card through the default PC/SC
 *       {@link TerminalFactory} (default reader 0).</li>
 *   <li>{@code socket:<host>:<port>} - the Java Card simulator through the
 *       Oracle {@code SocketCardTerminalProvider}.  The provider is looked up at
 *       runtime by {@link TerminalFactory#getInstance}, so the host stack has no
 *       compile-time dependency on it; when it is not on the module path the
 *       caller gets a clear error.</li>
 * </ul>
 *
 * <p>This is product code (the CLI uses it); the integration suites share the
 * same descriptor grammar.
 */
public final class Terminals {

    static {
        // Take over the T=0 response retrieval from the JDK.  SunPCSC issues
        // the GET RESPONSE with the CLA of the command that returned '61 xx'
        // (sun/security/smartcardio/ChannelImpl.java), but EMV v4.4 Book 1
        // removed Part II (transport protocols) and defers to the EMV Contact
        // Interface Specification; the equivalent EMV v4.1 Book 1 §9.3.1.3
        // Table 32 fixes it at CLA='00'.  Strict cards (e.g. the ICBC Visa
        // contact card) reject the non-zero CLA with '6E00', so
        // Terminal.transmit performs the retrieval per EMV instead.
        System.setProperty("sun.security.smartcardio.t0GetResponse", "false");
    }

    private Terminals() {
    }

    /** An open card connection: the terminal, the connected card and the channel wrapper. */
    public static final class Connection implements AutoCloseable {
        public final CardTerminal cardTerminal;
        public final Card card;
        public final Terminal terminal;

        Connection(CardTerminal cardTerminal, Card card, Terminal terminal) {
            this.cardTerminal = cardTerminal;
            this.card = card;
            this.terminal = terminal;
        }

        @Override
        public void close() throws Exception {
            card.disconnect(true);
        }
    }

    /**
     * Builds a terminal from a connection descriptor
     * {@code pcsc[:<reader-index>]} or {@code socket:<host>:<port>}.
     */
    public static CardTerminal getTerminal(String[] connectionParams) throws Exception {
        if (connectionParams.length >= 1 && connectionParams[0].equals("socket")) {
            if (connectionParams.length != 3) {
                throw new IllegalArgumentException("Host must be socket:<host>:<port>");
            }
            return socketTerminal(connectionParams[1],
                    Integer.parseInt(connectionParams[2]));
        }
        if (connectionParams.length >= 1 && connectionParams[0].equals("pcsc")) {
            int index = connectionParams.length >= 2
                    ? Integer.parseInt(connectionParams[1]) : 0;
            List<CardTerminal> terminals = TerminalFactory.getDefault().terminals().list();
            if (index >= terminals.size()) {
                throw new IllegalArgumentException(
                        "PC/SC reader " + index + " not found (" + terminals.size() + " present)");
            }
            return terminals.get(index);
        }
        throw new IllegalArgumentException("Host must be pcsc[:<index>] or socket:<host>:<port>");
    }

    /**
     * Opens a connection for a descriptor, waiting up to {@code waitSeconds} for
     * a card (0 = the card must already be present).  The caller closes the
     * {@link Connection} to disconnect.
     */
    public static Connection open(String spec, int waitSeconds) throws Exception {
        CardTerminal terminal = getTerminal(spec.split(":"));
        if (!terminal.isCardPresent()) {
            if (waitSeconds <= 0
                    || !terminal.waitForCardPresent(waitSeconds * 1000L)) {
                throw new IllegalStateException("no card present on " + spec);
            }
        }
        Card card = terminal.connect("*");
        return new Connection(terminal, card, new Terminal(card.getBasicChannel()));
    }

    /**
     * The simulator's socket terminal.  The Oracle provider is resolved at
     * runtime; it is not a compile-time dependency of the host stack.
     */
    private static CardTerminal socketTerminal(String host, int port) throws Exception {
        TerminalFactory factory;
        try {
            factory = TerminalFactory.getInstance(
                    "SocketCardTerminalFactoryType",
                    List.of(new InetSocketAddress(host, port)),
                    "SocketCardTerminalProvider");
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException(
                    "socket transport needs the Java Card simulator's "
                    + "SocketCardTerminalProvider on the module path (see "
                    + "docs/specs/common/toolchain.md §6)", e);
        }
        List<CardTerminal> terminals = factory.terminals().list();
        if (terminals.isEmpty()) {
            throw new IllegalStateException("socket terminal at " + host + ":" + port
                    + " has no card terminal");
        }
        return terminals.get(0);
    }
}
