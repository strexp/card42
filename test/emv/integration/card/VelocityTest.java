package card42.test;

import javax.smartcardio.Card;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.ResponseAPDU;

import card42.host.emv.lib.Terminal;
import card42.host.common.util.Args;
import card42.host.common.codec.Responses;

/**
 * Offline velocity-checking tests (EMV v4.4 Book 3 Annex C §C9.3).
 *
 * It uses the boundary instance 43415244420106, which is personalized with
 * LCOL=5, UCOL=10 and the cumulative offline amount limits LCOTA=100 /
 * UCOTA=1000:
 *
 *   - two offline-approved TCs accumulate 100, reaching LCOTA;
 *   - the next first AC is forced online (ARQC) even though a TC is requested;
 *   - a successful online second AC resets the accumulators, so a later
 *     transaction can be approved offline again.
 *
 * Exits non-zero if any check fails.
 */
public class VelocityTest {

    private static final String VELOCITY_AID = "43415244420106";

    public static void main(String[] argv) throws Exception {
        Args args = new Args(argv, new String[] { "host" }, new String[0]);
        String host = args.get("host", "socket:localhost:9025");
        CardTerminal terminal = TestTerminals.getTerminal(host.split(":"));
        if (terminal == null || !terminal.waitForCardPresent(10000)) {
            throw new IllegalStateException("Connection to simulator failed on " + host);
        }
        Card card = terminal.connect("*");
        try {
            run(new Terminal(card.getBasicChannel()));
        } finally {
            card.disconnect(true);
        }
        if (Checks.failures() > 0) {
            System.out.println("FAILED: " + Checks.failures() + " velocity check(s)");
            System.exit(1);
        }
        System.out.println("ALL VELOCITY CHECKS PASSED");
    }

    static void run(Terminal terminal) throws Exception {
        System.out.println("--- offline velocity checking (" + VELOCITY_AID + ") ---");

        // T1/T2: two offline-approved transactions of 50 accumulate LCOTA=100.
        Checks.check("T1 first AC is TC", firstAc(terminal, 50, 0x40) == 0x40);
        Checks.check("T2 first AC is TC", firstAc(terminal, 50, 0x40) == 0x40);

        // T3: cumulative >= LCOTA forces the first AC online (ARQC) even though
        // the terminal asked for a TC; a successful second AC TC resets it.
        Checks.check("T3 first AC forced online (ARQC)", firstAc(terminal, 0, 0x40) == 0x80);
        Checks.check("T3 second AC is TC", secondAc(terminal, 0x40) == 0x40);

        // T4: after the successful online transaction the card approves offline.
        Checks.check("T4 first AC is TC after online reset",
                firstAc(terminal, 0, 0x40) == 0x40);

        // Count limit (docs/specs/common/toolchain.md §6): LCOL=5.  T4 was the first
        // offline approval (count 1), so four more reach 5 and the next first
        // AC is forced online.
        for (int i = 1; i <= 4; i++) {
            Checks.check("count T" + (4 + i) + " is TC",
                    firstAc(terminal, 0, 0x40) == 0x40);
        }
        Checks.check("LCOL=5 forces the next first AC online (ARQC)",
                firstAc(terminal, 0, 0x40) == 0x80);
        Checks.check("count test second AC TC resets the counters",
                secondAc(terminal, 0x40) == 0x40);
    }

    /** SELECT + GPO + a first GENERATE AC of amount; returns the CID or -1. */
    private static int firstAc(Terminal terminal, int amount, int requestedP1)
            throws Exception {
        ResponseAPDU sel = terminal.select(VELOCITY_AID);
        if (sel.getSW() != 0x9000) {
            Checks.fail("velocity SELECT -> " + Checks.sw(sel.getSW()));
            return -1;
        }
        ResponseAPDU gpo = terminal.gpo();
        if (gpo.getSW() != 0x9000) {
            Checks.fail("velocity GPO -> " + Checks.sw(gpo.getSW()));
            return -1;
        }
        ResponseAPDU ac = terminal.generateAc((byte) requestedP1, bcd(amount));
        if (ac.getSW() != 0x9000) {
            Checks.fail("velocity first AC -> " + Checks.sw(ac.getSW()));
            return -1;
        }
        return parseCid(ac);
    }

    /** A 6-byte BCD amount (the instance 06 CDOL1 is a single 9F02 06). */
    private static byte[] bcd(int amount) {
        byte[] b = new byte[6];
        for (int i = 5; i >= 0 && amount > 0; i--) {
            b[i] = (byte) (((amount % 100) / 10 << 4) | (amount % 10));
            amount /= 100;
        }
        return b;
    }

    /** The second GENERATE AC of the open session; returns the CID or -1. */
    private static int secondAc(Terminal terminal, int requestedP1) throws Exception {
        ResponseAPDU ac = terminal.generateAc((byte) requestedP1, new byte[6]);
        if (ac.getSW() != 0x9000) {
            Checks.fail("velocity second AC -> " + Checks.sw(ac.getSW()));
            return -1;
        }
        return parseCid(ac);
    }

    private static int parseCid(ResponseAPDU r) {
        return Responses.parseCid(r) & 0xFF;
    }
}
