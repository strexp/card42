package card42.test;

import java.util.Arrays;

import javax.smartcardio.Card;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.ResponseAPDU;

import card42.host.emv.crypto.SmCrypto;
import card42.host.emv.lib.Terminal;
import card42.host.common.util.Args;
import card42.host.common.util.Hex;
import card42.host.common.codec.Responses;
import card42.host.common.codec.Tags;
import card42.host.emv.kernel.data.TerminalDol;

/**
 * Transaction log tests (EMV v4.4 Book 3 Annex D4).
 *
 * It checks that the FCI carries the Log Entry (9F4D, SFI in 11..30 and the
 * record capacity), that GET DATA 9F4F returns the Log Format, that a finalized
 * transaction writes one plain value-concatenation record (record #1 is the
 * newest), that the ring overwrites the oldest entry and never grows past its
 * capacity, that the log SFI is not in the AFL, and that the log stays readable
 * while the application is invalidated (APPLICATION BLOCK).
 *
 * Exits non-zero if any check fails.
 */
public class LogTest {

    private static final String CONTACT_AID = "43415244420101";
    /** Instance 06 with a custom Log Format (9F4E not in CDOL1). */
    private static final String CUSTOM_AID = "43415244420106";
    private static final int LOG_SFI = 15;
    private static final int LOG_CAPACITY = 8;
    /** Number of terminal data bytes the contact instance's CDOL1 asks for. */
    private static int cdol1DataLength = 43;

    private static final byte[] SM_MAC_KEY =
            Hex.parse("911C3404804CCEBF458AA1191C152A3E");
    private static final byte[] SM_ENC_KEY =
            Hex.parse("BA915D4F3185B9EA620234D5FDAEBA9D");

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
            System.out.println("FAILED: " + Checks.failures() + " log check(s)");
            System.exit(1);
        }
        System.out.println("ALL LOG CHECKS PASSED");
    }

    static void run(Terminal terminal) throws Exception {
        System.out.println("--- transaction log ---");
        ResponseAPDU sel = terminal.select(CONTACT_AID);
        Checks.check("log: SELECT contact", sel.getSW() == 0x9000, sel);
        if (sel.getSW() != 0x9000) {
            return;
        }

        // The Log Entry (9F4D) lives in the FCI Issuer Discretionary Data and
        // gives the SFI (11..30) and the maximum number of records.
        byte[] entry = Tags.find(sel.getData(), 0x9F4D);
        Checks.check("FCI carries a Log Entry (9F4D)",
                entry != null && entry.length == 2, sel);
        if (entry != null) {
            Checks.check("Log Entry SFI in 11..30",
                    (entry[0] & 0xFF) >= 11 && (entry[0] & 0xFF) <= 30);
            Checks.check("Log Entry capacity", (entry[1] & 0xFF) == LOG_CAPACITY);
        }
        // The Log Entry must live in the FCI Issuer Discretionary Data
        // (BF0C or 73), not just anywhere in the FCI (EMV v4.4 Book 3 Annex D4).
        byte[] discretionary = Tags.find(sel.getData(), 0xBF0C);
        Checks.check("Log Entry is inside BF0C",
                discretionary != null
                        && Tags.find(discretionary, 0x9F4D) != null, sel);

        // The Log Format (9F4F) is read with GET DATA.
        ResponseAPDU lf = terminal.getData(0x9F, 0x4F);
        byte[] format = Tags.find(lf.getData(), 0x9F4F);
        Checks.check("GET DATA 9F4F returns the log format",
                format != null && format.length > 0, lf);
        int recordLength = format == null ? 0 : TerminalDol.dolDataLength(format);

        byte[] pdol = pdolData(terminal, CONTACT_AID);
        if (pdol == null) {
            return;
        }
        cdol1DataLength = deriveCdol1Length(terminal, CONTACT_AID, pdol);
        if (cdol1DataLength < 0) {
            return;
        }

        // A first AC that is a TC is final: exactly one log record is written.
        int atc = tcTransaction(terminal, pdol);
        if (atc < 0) {
            return;
        }
        byte[] rec1 = readLog(terminal, 1);
        Checks.check("log record 1 exists", rec1 != null);
        if (rec1 != null) {
            Checks.check("log record length", rec1.length == recordLength);
            Checks.check("log record is not wrapped in a 70 template",
                    rec1.length > 0 && rec1[0] != 0x70);
            Checks.check("log record 1 holds the transaction ATC",
                    rec1.length == recordLength
                            && (((rec1[11] & 0xFF) << 8) | (rec1[12] & 0xFF)) == atc);
            Checks.check("log record 1 holds the TC CID",
                    rec1.length == recordLength && rec1[13] == 0x40);
        }
        byte[] rec2 = readLog(terminal, 2);
        Checks.check("log record 2 is older than record 1",
                rec2 != null && rec1 != null && rec1.length == recordLength
                        && rec2.length == recordLength
                        && atcOf(rec1) > atcOf(rec2));

        // The log SFI is deliberately not advertised in the AFL.
        ResponseAPDU gpo = terminal.gpo(pdol);
        byte[] afl = gpo.getSW() == 0x9000 ? gpoAfl(gpo.getData()) : null;
        boolean logInAfl = false;
        if (afl != null) {
            for (int i = 0; i + 3 < afl.length; i += 4) {
                if (((afl[i] & 0xFF) >> 3) == LOG_SFI) {
                    logInAfl = true;
                }
            }
        }
        Checks.check("log SFI is not in the AFL", !logInAfl);

        // The ring: fill more than CAPACITY entries, then record 9 is missing.
        for (int i = 0; i < LOG_CAPACITY + 2; i++) {
            if (tcTransaction(terminal, pdol) < 0) {
                break;
            }
        }
        byte[] wrap1 = readLog(terminal, 1);
        byte[] wrap8 = readLog(terminal, 8);
        Checks.check("log record 1 after wrap", wrap1 != null);
        Checks.check("log record 8 after wrap", wrap8 != null);
        Checks.check("ring keeps the newest record first",
                wrap1 != null && wrap8 != null && atcOf(wrap1) > atcOf(wrap8));
        Checks.check("log record 9 is missing -> 6A83",
                terminal.readRecord(9, LOG_SFI).getSW(), 0x6A83);

        // Write timing (docs/specs/common/toolchain.md §6): an unfinished online
        // transaction (first AC ARQC, no second AC) writes no record.
        int countBefore = countRecords(terminal);
        terminal.select(CONTACT_AID);
        terminal.gpo(pdol);
        ResponseAPDU unfinished = terminal.generateAc((byte) 0x80, cdol1DataLength);
        Checks.check("timing: first AC is ARQC", unfinished.getSW() == 0x9000
                && parseCid(unfinished) == (byte) 0x80, unfinished);
        Checks.check("no log record for an unfinished online transaction",
                countRecords(terminal) == countBefore);

        // The log stays readable while the application is invalidated.
        verifyReadableWhenBlocked(terminal, pdol);

        // A custom Log Format whose field is not in CDOL1 is zero-filled
        // (docs/specs/common/toolchain.md §6).
        verifyCustomFormat(terminal);
    }

    /**
     * Instance 06 has a custom Log Format 9F02 06 || 9F4E 04: 9F02 is a CDOL1
     * field and is copied from the transaction, while 9F4E is not and must be
     * zero-filled without overrunning the record (EMV v4.4 Book 3 Annex D4).
     */
    private static void verifyCustomFormat(Terminal terminal) throws Exception {
        System.out.println("--- custom log format (" + CUSTOM_AID + ") ---");
        ResponseAPDU sel = terminal.select(CUSTOM_AID);
        Checks.check("custom: SELECT", sel.getSW() == 0x9000, sel);
        if (sel.getSW() != 0x9000) {
            return;
        }
        ResponseAPDU lf = terminal.getData(0x9F, 0x4F);
        byte[] format = Tags.find(lf.getData(), 0x9F4F);
        Checks.check("custom GET DATA 9F4F",
                format != null && format.length == 6, lf);
        int recordLength = format == null ? 0 : TerminalDol.dolDataLength(format);
        Checks.check("custom record length", recordLength == 10);

        ResponseAPDU gpo = terminal.gpo();
        Checks.check("custom GPO", gpo.getSW() == 0x9000, gpo);
        if (gpo.getSW() != 0x9000) {
            return;
        }
        byte[] cdol1 = new byte[6]; // instance 06 CDOL1 is a single 9F02 06
        cdol1[5] = 0x10; // amount 000000000010
        ResponseAPDU ac = terminal.generateAc((byte) 0x40, cdol1);
        // A previous suite (BoundaryTest) may have left the CVR "Last Online
        // Transaction Not Completed" bit set on this instance, which forces
        // this transaction online (EMV v4.4 Book 3 §9.2.3.2).  Complete it so the custom
        // record is written either way.
        if (ac.getSW() == 0x9000 && Responses.parseCid(ac) == (byte) 0x80) {
            ac = terminal.generateAc((byte) 0x40, cdol1); // second AC (CDOL2 = 9F02 06)
        }
        Checks.check("custom first AC is final", ac.getSW() == 0x9000
                && Responses.parseCid(ac) != (byte) 0x80, ac);
        byte[] rec = readLog(terminal, 1);
        Checks.check("custom record exists", rec != null);
        if (rec != null && rec.length == recordLength) {
            Checks.check("custom record holds the amount", rec[5] == 0x10);
            Checks.check("custom record zero-fills the non-CDOL1 field",
                    rec[6] == 0 && rec[7] == 0 && rec[8] == 0 && rec[9] == 0);
        }
    }

    /** SELECT + GPO + a first AC requested as a TC; returns the ATC or -1. */
    private static int tcTransaction(Terminal terminal, byte[] pdol) throws Exception {
        ResponseAPDU sel = terminal.select(CONTACT_AID);
        if (sel.getSW() != 0x9000) {
            Checks.fail("log txn SELECT -> " + Checks.sw(sel.getSW()));
            return -1;
        }
        ResponseAPDU gpo = terminal.gpo(pdol);
        if (gpo.getSW() != 0x9000) {
            Checks.fail("log txn GPO -> " + Checks.sw(gpo.getSW()));
            return -1;
        }
        int atc = readAtc(terminal);
        ResponseAPDU ac = terminal.generateAc((byte) 0x40, cdol1DataLength);
        if (ac.getSW() != 0x9000) {
            Checks.fail("log txn AC -> " + Checks.sw(ac.getSW()));
            return -1;
        }
        Checks.check("log txn first AC is TC", parseCid(ac) == 0x40, ac);
        return atc;
    }

    /**
     * APPLICATION BLOCK the contact instance, check that the log and the log
     * format stay readable while it is invalidated, then unblock it again so
     * the other suites still work (EMV v4.4 Book 3 Annex D4).
     */
    private static void verifyReadableWhenBlocked(Terminal terminal, byte[] pdol)
            throws Exception {
        System.out.println("--- transaction log while blocked ---");
        ResponseAPDU sel = terminal.select(CONTACT_AID);
        if (sel.getSW() != 0x9000) {
            Checks.fail("block: SELECT -> " + Checks.sw(sel.getSW()));
            return;
        }
        terminal.gpo(pdol);
        ResponseAPDU first = terminal.generateAc((byte) 0x80, cdol1DataLength);
        if (first.getSW() != 0x9000) {
            Checks.fail("block: first AC -> " + Checks.sw(first.getSW()));
            return;
        }
        byte[] ac = Responses.parseAc(first).ac;
        SmCrypto.ScriptSession session = new SmCrypto.ScriptSession(SM_MAC_KEY, SM_ENC_KEY);
        session.start(ac);
        Checks.check("APPLICATION BLOCK",
                terminal.transmit(session.command(0x1E, 0x00, 0x00).getBytes()).getSW(),
                0x9000);
        Checks.check("blocked SELECT -> 6283", terminal.select(CONTACT_AID).getSW(), 0x6283);
        Checks.check("log readable while blocked",
                terminal.readRecord(1, LOG_SFI).getSW(), 0x9000);
        Checks.check("GET DATA 9F4F while blocked",
                terminal.getData(0x9F, 0x4F).getSW(), 0x9000);

        // Unblock to leave the card usable for the later suites.
        terminal.select(CONTACT_AID);
        terminal.gpo(pdol);
        ResponseAPDU aac = terminal.generateAc((byte) 0x80, cdol1DataLength);
        SmCrypto.ScriptSession unblock = new SmCrypto.ScriptSession(SM_MAC_KEY, SM_ENC_KEY);
        unblock.start(Responses.parseAc(aac).ac);
        Checks.check("APPLICATION UNBLOCK",
                terminal.transmit(unblock.command(0x18, 0x00, 0x00).getBytes()).getSW(),
                0x9000);
        Checks.check("SELECT after unblock -> 9000",
                terminal.select(CONTACT_AID).getSW(), 0x9000);
    }

    // --- helpers ------------------------------------------------------------

    private static byte[] pdolData(Terminal terminal, String aid) throws Exception {
        ResponseAPDU r = terminal.select(aid);
        if (r.getSW() != 0x9000) {
            Checks.fail("log: SELECT " + aid + " -> " + Checks.sw(r.getSW()));
            return null;
        }
        byte[] pdol = Tags.find(r.getData(), 0x9F38);
        return new byte[pdol == null ? 0 : TerminalDol.dolDataLength(pdol)];
    }

    /**
     * Derives the CDOL1 data length from the personalised CDOL1 (record 1,
     * tag 8C) instead of hardcoding the sample card's 43 bytes
     * (docs/specs/common/toolchain.md §6).
     */
    private static int deriveCdol1Length(Terminal terminal, String aid, byte[] pdol)
            throws Exception {
        ResponseAPDU gpo = terminal.gpo(pdol);
        if (gpo.getSW() != 0x9000) {
            Checks.fail("log: CDOL1 derivation GPO -> " + Checks.sw(gpo.getSW()));
            return -1;
        }
        ResponseAPDU rec = terminal.readRecord(1, 1);
        if (rec.getSW() != 0x9000) {
            Checks.fail("log: CDOL1 derivation READ RECORD 1 -> "
                    + Checks.sw(rec.getSW()));
            return -1;
        }
        byte[] cdol1 = Tags.find(rec.getData(), 0x8C);
        if (cdol1 == null) {
            Checks.fail("log: record 1 has no CDOL1 (8C)");
            return -1;
        }
        return TerminalDol.dolDataLength(cdol1);
    }

    private static int readAtc(Terminal terminal) throws Exception {
        return terminal.readAtc();
    }

    private static byte[] readLog(Terminal terminal, int rec) throws Exception {
        ResponseAPDU r = terminal.readRecord(rec, LOG_SFI);
        return r.getSW() == 0x9000 ? r.getData() : null;
    }

    /** The ATC stored at offset 11 of a default-format log record. */
    private static int atcOf(byte[] record) {
        return ((record[11] & 0xFF) << 8) | (record[12] & 0xFF);
    }

    /** Number of stored log records (reads until the first missing one). */
    private static int countRecords(Terminal terminal) throws Exception {
        int n = 0;
        for (int rec = 1; rec <= LOG_CAPACITY + 1; rec++) {
            if (terminal.readRecord(rec, LOG_SFI).getSW() != 0x9000) {
                break;
            }
            n++;
        }
        return n;
    }

    private static byte parseCid(ResponseAPDU r) {
        return Responses.parseCid(r);
    }

    private static byte[] gpoAfl(byte[] gpo) {
        return Responses.gpoAfl(gpo);
    }
}
