package card42.test;

import javax.smartcardio.Card;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.ResponseAPDU;

import card42.host.emv.crypto.AcCrypto;
import card42.host.emv.lib.Terminal;
import card42.host.common.util.Args;
import card42.host.common.util.Hex;
import card42.host.common.codec.Responses;
import card42.host.common.codec.Tags;

/**
 * Positive test for the CCD Card Status Update (CSU) "Card Block" bit
 * (EMV v4.4 Book 3 Annex C §C10): a CSU with byte 2 b7 set, delivered with a
 * correct ARPC in the inline Issuer Authentication Data of the second GENERATE
 * AC, must block the whole card.
 *
 * <p>The card block is a card-wide, irreversible flag ({@code EMVAppletBase}
 * static {@code cardBlocked}), so this suite must run against a <em>fresh</em>
 * simulator and must be the last thing that touches the card.  It is therefore
 * driven by its own Makefile target ({@code test-emv-sim-block}) which restarts the
 * simulator, redeploys and re-personalizes before running this class.
 *
 * <p>The separate post-issuance {@code CARD BLOCK} command path is covered by
 * {@link IssuerScriptTest}.
 */
public class CardBlockTest {

    private static final String PAYMENT_AID = "43415244420101";
    private static final String PSE_AID = "315041592E5359532E4444463031";

    /** An "online approved" ARC (tag 8A). */
    private static final byte[] ARC_APPROVED = { 0x00, 0x00 };

    /** CSU: byte 2 = 0x80 (approve online) | 0x40 (Card Block). */
    private static final byte[] CSU_CARD_BLOCK = { 0x00, (byte) 0xC0, 0x00, 0x00 };

    public static void main(String[] argv) throws Exception {
        Args args = new Args(argv, new String[] { "host", "icc-key" }, new String[0]);
        String host = args.get("host", "socket:localhost:9025");
        byte[] iccKey = Hex.parse(args.get("icc-key",
                "343864C2E085AB3E433D2F982945E61F"));

        CardTerminal terminal = TestTerminals.getTerminal(host.split(":"));
        if (terminal == null || !terminal.waitForCardPresent(10000)) {
            throw new IllegalStateException("Connection to simulator failed on " + host);
        }
        Card card = terminal.connect("*");
        try {
            run(new Terminal(card.getBasicChannel()), iccKey);
        } finally {
            card.disconnect(true);
        }

        if (Checks.failures() > 0) {
            System.out.println("FAILED: " + Checks.failures() + " card-block check(s)");
            System.exit(1);
        }
        System.out.println("ALL CARD BLOCK CHECKS PASSED");
    }

    static void run(Terminal terminal, byte[] iccKey) throws Exception {
        System.out.println("--- CSU Card Block (Book 3 Annex C §C10) ---");

        ResponseAPDU sel = terminal.select(PAYMENT_AID);
        Checks.check("card block: SELECT", sel.getSW() == 0x9000, sel);
        if (sel.getSW() != 0x9000) {
            return;
        }
        byte[] pdol = Tags.find(sel.getData(), 0x9F38);
        byte[] pdolData = new byte[pdol == null ? 0 : AcCrypto.dolDataLength(pdol)];

        ResponseAPDU gpo = terminal.gpo(pdolData);
        Checks.check("card block: GPO", gpo.getSW() == 0x9000, gpo);
        if (gpo.getSW() != 0x9000) {
            return;
        }

        ResponseAPDU rec = terminal.readRecord(1, 1);
        Checks.check("card block: READ RECORD 1", rec.getSW() == 0x9000, rec);
        if (rec.getSW() != 0x9000) {
            return;
        }
        byte[] record1 = rec.getData();

        int atc = terminal.readAtc();
        byte[] cdol1 = Tags.find(record1, 0x8C);
        if (cdol1 == null) {
            Checks.fail("card block: record 1 has no CDOL1 (8C)");
            return;
        }
        ResponseAPDU first = terminal.generateAc((byte) 0x80,
                new byte[AcCrypto.dolDataLength(cdol1)]);
        Checks.check("card block: first AC is ARQC", first.getSW() == 0x9000
                && Responses.parseCid(first) == (byte) 0x80, first);
        if (first.getSW() != 0x9000) {
            return;
        }
        byte[] arqc = Responses.parseAc(first).ac;

        // Second AC with the Issuer Authentication Data (tag 91 = ARPC || CSU)
        // inline in CDOL2; the CSU requests a card block.
        byte[] sk = AcCrypto.sessionKey(iccKey, atc);
        ResponseAPDU second = terminal.generateAc((byte) 0x40,
                cdol2Data(record1, arqc, sk, ARC_APPROVED, CSU_CARD_BLOCK));
        Checks.check("card block: second AC", second.getSW() == 0x9000, second);

        // The card-wide flag now rejects every SELECT, whatever the instance.
        Checks.check("SELECT payment after CSU card block -> 6A81",
                terminal.select(PAYMENT_AID).getSW(), 0x6A81);
        Checks.check("SELECT PSE after CSU card block -> 6A81",
                terminal.select(PSE_AID).getSW(), 0x6A81);
        Checks.check("READ RECORD after CSU card block -> 6A81",
                terminal.readRecord(1, 1).getSW(), 0x6A81);
        Checks.check("GET DATA after CSU card block -> 6A81",
                terminal.getData(0x9F, 0x36).getSW(), 0x6A81);
    }

    /** Builds CDOL2 data from record 1 with ARC (8A) and Issuer Auth Data (91). */
    private static byte[] cdol2Data(byte[] record1, byte[] arqc, byte[] sk,
                                    byte[] arc, byte[] csu) throws Exception {
        byte[] cdol2 = Tags.find(record1, 0x8D);
        if (cdol2 == null) {
            throw new IllegalStateException("record 1 has no CDOL2");
        }
        byte[] data = new byte[AcCrypto.dolDataLength(cdol2)];
        int arcOff = AcCrypto.dolValueOffset(cdol2, 0x8A);
        if (arcOff >= 0) {
            System.arraycopy(arc, 0, data, arcOff, 2);
        }
        int authOff = AcCrypto.dolValueOffset(cdol2, 0x91);
        if (authOff >= 0) {
            byte[] arpc = AcCrypto.computeArpcMethod2(sk, arqc, csu, new byte[0]);
            System.arraycopy(arpc, 0, data, authOff, 4);
            System.arraycopy(csu, 0, data, authOff + 4, 4);
        }
        return data;
    }
}
