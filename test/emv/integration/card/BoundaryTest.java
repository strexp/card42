package card42.test;

import java.util.Arrays;

import javax.smartcardio.Card;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import card42.host.emv.oda.SdaVerifier;
import card42.host.emv.lib.IssuerKey;
import card42.host.emv.crypto.AcCrypto;
import card42.host.emv.lib.Terminal;
import card42.host.emv.lib.Apdus;
import card42.host.common.util.Args;
import card42.host.common.util.Hex;
import card42.host.common.codec.Responses;
import card42.host.common.codec.Tags;

/**
 * Boundary and negative tests for the payment command set
 * (docs/specs/common/toolchain.md §6).  It complements {@link EmvFlowTest} (the
 * positive smoke test) with:
 *
 *   - GENERATE AC request/response hierarchy (EMV v4.4 Book 3 section 9.3) and the
 *     P1/P2 and third-AC rules;
 *   - CDA / DDA boundaries: CDA downgraded to AAC, CDA without an ICC key,
 *     a CDOL without 9F37, INTERNAL AUTHENTICATE P1/P2;
 *   - VERIFY format errors, GET DATA tag handling and the GPO '83' template
 *     boundaries.
 *
 * It uses three instances:
 *
 *   43415244420101 - the production contact instance (READY, DDA/CDA keys);
 *   43415244420104 - the direct-path success instance (READY, no DDA/PIN key);
 *   43415244420106 - the boundary instance (READY, DDA/PIN keys, 5-digit PIN,
 *                  CDOL1 without 9F37).
 *
 * Exits non-zero if any check fails.
 */
public class BoundaryTest {

    private static final String CONTACT_AID = "43415244420101";
    private static final String NO_KEY_AID = "43415244420104";
    private static final String BOUNDARY_AID = "43415244420106";

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
            System.out.println("FAILED: " + Checks.failures() + " boundary check(s)");
            System.exit(1);
        }
        System.out.println("ALL BOUNDARY CHECKS PASSED");
    }

    static void run(Terminal terminal) throws Exception {
        byte[] pdolData = pdolData(terminal, CONTACT_AID);
        if (pdolData == null) {
            return;
        }
        verifyGenerateAcHierarchy(terminal, CONTACT_AID, pdolData);
        verifyCdaBoundaries(terminal, CONTACT_AID, pdolData);
        verifyGetData(terminal, CONTACT_AID, pdolData);
        verifyVerifyBoundaries(terminal, CONTACT_AID, pdolData);
        verifySelectBoundaries(terminal);
        verifyChallengeBoundaries(terminal, CONTACT_AID);
        verifyGpoBoundaries(terminal, CONTACT_AID, pdolData);
        verifyChainingAndReadRecord(terminal, CONTACT_AID);
        verifyNoKeyBoundaries(terminal);
        verifyBoundaryInstance(terminal);
    }

    /**
     * Command chaining (EMV v4.4 Book 3 §6.5.13): only VERIFY and
     * PIN CHANGE/UNBLOCK may be chained.  A non-final fragment (CLA b5=1) is
     * answered with 9000 and its command data is accumulated; the last fragment
     * runs the function.  A chained command of any other INS is refused with
     * 6884, an interrupted chain with 6883 and a chained VERIFY whose
     * accumulation fails with 6800 (EMV v4.4 Book 3 §6.5.12.5).  READ RECORD P2 b3-b1
     * must be 100 (EMV v4.4 Book 3 Table 22 / EMV v4.4 Book 1 Table 4).
     */
    private static void verifyChainingAndReadRecord(Terminal terminal, String aid)
            throws Exception {
        System.out.println("--- command chaining / READ RECORD P2 ---");
        terminal.select(aid);

        // Chaining is only supported for VERIFY and PIN CHANGE/UNBLOCK: every
        // other chained command is refused with 6884 (EMV v4.4 Book 3 §6.5.13).
        // GET DATA is '8x' (Book 3 Table 3), so its chained form is CLA '90'.
        Checks.check("chained GET DATA (CLA 90) -> 6884",
                terminal.transmit(new CommandAPDU(0x90, 0xCA, 0x9F, 0x36)).getSW(), 0x6884);
        Checks.check("chained APPLICATION BLOCK (CLA 9C) -> 6884",
                terminal.transmit(new CommandAPDU(0x9C, 0x1E, 0x00, 0x00,
                        Hex.parse("8E0400000000"))).getSW(), 0x6884);

        // A chained VERIFY accumulates the command data: the non-final fragment
        // is answered with 9000 and the final fragment performs the PIN check
        // over the concatenation of the fixed 8-byte Table 25 block
        // (0x24 12 || 34 FF FF FF FF FF = the 4-digit PIN 1234).
        Checks.check("chained VERIFY fragment -> 9000",
                terminal.transmit(new CommandAPDU(0x10, 0x20, 0x00, 0x80,
                        new byte[] { 0x24, 0x12 })).getSW(), 0x9000);
        Checks.check("chained VERIFY final verifies the PIN",
                terminal.transmit(new CommandAPDU(0x00, 0x20, 0x00, 0x80,
                        new byte[] { 0x34, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
                                (byte) 0xFF, (byte) 0xFF })).getSW(), 0x9000);

        // A wrong PIN across the chain is reported by the last fragment.
        Checks.check("chained VERIFY wrong PIN fragment -> 9000",
                terminal.transmit(new CommandAPDU(0x10, 0x20, 0x00, 0x80,
                        new byte[] { 0x24, (byte) 0x99 })).getSW(), 0x9000);
        Checks.check("chained VERIFY wrong PIN final -> 63C2",
                terminal.transmit(new CommandAPDU(0x00, 0x20, 0x00, 0x80,
                        new byte[] { (byte) 0x99, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
                                (byte) 0xFF, (byte) 0xFF })).getSW(), 0x63C2);
        Checks.check("VERIFY correct PIN resets the counter",
                terminal.verifyOfflinePin("1234").getSW(), 0x9000);

        // A chain that is not completed with the expected last command is
        // refused with 6883 (the last command of the chain was not received).
        Checks.check("chained VERIFY fragment -> 9000",
                terminal.transmit(new CommandAPDU(0x10, 0x20, 0x00, 0x80,
                        new byte[] { 0x24, 0x12 })).getSW(), 0x9000);
        Checks.check("interrupted chain -> 6883",
                terminal.transmit(new CommandAPDU(0x00, 0xB2, 0x01, 0x0C)).getSW(), 0x6883);

        // A chained VERIFY whose accumulation overflows the 255-byte short-APDU
        // data field is reported as 6800 (EMV v4.4 Book 3 §6.5.12.5).
        Checks.check("chained VERIFY 255-byte fragment -> 9000",
                terminal.transmit(new CommandAPDU(0x10, 0x20, 0x00, 0x80,
                        new byte[255])).getSW(), 0x9000);
        Checks.check("chained VERIFY overflow -> 6800",
                terminal.transmit(new CommandAPDU(0x00, 0x20, 0x00, 0x80,
                        new byte[1])).getSW(), 0x6800);

        // READ RECORD P2 b3-b1 must be 100 (EMV v4.4 Book 3 Table 22 / EMV v4.4 Book 1 Table 4).
        Checks.check("READ RECORD P2 b3-b1 != 100 -> 6A81",
                terminal.transmit(new CommandAPDU(0x00, 0xB2, 0x01, 0x00))
                        .getSW(), 0x6A81);
    }

    // --- GENERATE AC hierarchy ----------------------------------------------

    private static void verifyGenerateAcHierarchy(Terminal terminal, String aid,
            byte[] pdolData) throws Exception {
        System.out.println("--- GENERATE AC hierarchy ---");

        // A terminal AAC request (P1=00) must return an AAC even when the card
        // would approve the transaction (EMV v4.4 Book 3 section 9.3.1).
        byte[] cdol1 = beginSession(terminal, aid, pdolData);
        if (cdol1 != null) {
            byte[] data = cdolData(cdol1);
            ResponseAPDU r = terminal.generateAc((byte) 0x00, data);
            Checks.check("GENERATE AC AAC request", r.getSW() == 0x9000, r);
            if (r.getSW() == 0x9000) {
                Responses.AcResponse ac = Responses.parseAc(r);
                Checks.check("AAC request returns AAC", ac.cid == 0x00);
                Checks.check("AAC CID has no advice/reason bits", (ac.cid & 0x3F) == 0);
            }
        }

        // A terminal ARQC request (P1=80) with no TVR bits: the card decides TC
        // but may only downgrade, so it must still return an ARQC
        // (EMV v4.4 Book 3 §9.3).
        cdol1 = beginSession(terminal, aid, pdolData);
        if (cdol1 != null) {
            ResponseAPDU r = terminal.generateAc((byte) 0x80, cdolData(cdol1));
            Checks.check("GENERATE AC ARQC request", r.getSW() == 0x9000, r);
            if (r.getSW() == 0x9000) {
                Responses.AcResponse ac = Responses.parseAc(r);
                Checks.check("ARQC request is not upgraded to TC", ac.cid == (byte) 0x80);
                Checks.check("ARQC CID has no advice/reason bits", (ac.cid & 0x3F) == 0);
            }
        }

        // The GENERATE AC command data must be exactly the CDOL1-related data
        // (EMV v4.4 Book 3 §6.5.5.3): a longer or shorter data field is 6700.
        cdol1 = beginSession(terminal, aid, pdolData);
        if (cdol1 != null) {
            byte[] data = cdolData(cdol1);
            byte[] longer = Arrays.copyOf(data, data.length + 1);
            Checks.check("GENERATE AC data longer than CDOL -> 6700",
                    terminal.generateAc((byte) 0x80, longer).getSW(), 0x6700);
        }
        cdol1 = beginSession(terminal, aid, pdolData);
        if (cdol1 != null && cdol1.length > 0) {
            byte[] data = cdolData(cdol1);
            byte[] shorter = Arrays.copyOf(data, data.length - 1);
            Checks.check("GENERATE AC data shorter than CDOL -> 6700",
                    terminal.generateAc((byte) 0x80, shorter).getSW(), 0x6700);
        }

        // P1 b8-b7 = 11 is RFU and shall not be verified (EMV v4.4 Book 3
        // §6.3.6): the card must not reject the command and returns its own
        // decision (AAC/TC/ARQC).
        cdol1 = beginSession(terminal, aid, pdolData);
        if (cdol1 != null) {
            ResponseAPDU r = terminal.generateAc((byte) 0xC0, cdolData(cdol1));
            Checks.check("GENERATE AC RFU P1 is not verified", r.getSW() == 0x9000, r);
            if (r.getSW() == 0x9000) {
                int type = Responses.parseAc(r).cid & 0xC0;
                Checks.check("RFU P1 yields a defined CID type",
                        type == 0x00 || type == 0x40 || type == 0x80);
            }
        }

        // P2 != 00 -> 6A81 (EMV v4.4 Book 3 Table 11).
        cdol1 = beginSession(terminal, aid, pdolData);
        if (cdol1 != null) {
            Checks.check("GENERATE AC P2 != 00 -> 6A81",
                    terminal.generateAcRaw(0x80, 0x01, cdolData(cdol1)).getSW(), 0x6A81);
        }

        // P1 b5-b4 = 11 (RFU offline data authentication type) is not verified
        // (EMV v4.4 Book 3 §6.3.6): it is treated as "no CDA/XDA signature
        // requested", so the command succeeds like an ODA=00 request.
        cdol1 = beginSession(terminal, aid, pdolData);
        if (cdol1 != null) {
            ResponseAPDU r = terminal.generateAc((byte) 0x98, cdolData(cdol1));
            Checks.check("GENERATE AC b5-b4=11 (RFU) is not verified", r.getSW() == 0x9000, r);
            if (r.getSW() == 0x9000) {
                Checks.check("RFU ODA bits do not request CDA",
                        Tags.find(r.getData(), 0x9F4B) == null);
            }
        }

        // P1 b5-b4 = 01 (XDA requested, not implemented) -> 6A81 (EMV v4.4 Book 3 Table 12).
        cdol1 = beginSession(terminal, aid, pdolData);
        if (cdol1 != null) {
            Checks.check("GENERATE AC b5-b4=01 (XDA) -> 6A81",
                    terminal.generateAc((byte) 0x88, cdolData(cdol1)).getSW(), 0x6A81);
        }

        // P1 b6 (RFU) must be ignored, not decoded as part of the ODA field
        // (EMV v4.4 Book 3 §6.3.6); ARQC + CDA + b6 is still a CDA request.
        cdol1 = beginSession(terminal, aid, pdolData);
        if (cdol1 != null) {
            byte[] data = cdolData(cdol1);
            int tvr = AcCrypto.dolValueOffset(cdol1, 0x95);
            if (tvr >= 0) {
                data[tvr] = (byte) 0x80; // IAC-Denial: card decides AAC
            }
            ResponseAPDU r = terminal.generateAc((byte) 0xB0, data); // ARQC+CDA+b6
            Checks.check("GENERATE AC b6 RFU ignored", r.getSW() == 0x9000, r);
        }

        // A second GENERATE AC shall return only a TC or an AAC (EMV v4.4 Book 3
        // §9.3/§9.3.2), so an ARQC or RFU request must not be rejected; the card
        // treats it as a TC request it may still downgrade.  Each case needs its
        // own session because the applet allows only one second AC per transaction.
        for (byte p1 : new byte[] { (byte) 0x80, (byte) 0xC0 }) {
            cdol1 = beginSession(terminal, aid, pdolData);
            if (cdol1 != null) {
                ResponseAPDU first = terminal.generateAc((byte) 0x80, cdolData(cdol1));
                Checks.check("hierarchy: first AC", first.getSW() == 0x9000, first);
                // The second AC's command data must match the personalized CDOL2
                // (record 1 tag 8D); derive its length instead of hardcoding it
                // (docs/specs/common/toolchain.md §6).
                byte[] cdol2 = cdolData(cdol2Definition(terminal));
                ResponseAPDU r = terminal.generateAc(p1, cdol2);
                Checks.check("second AC P1=" + Integer.toHexString(p1 & 0xFF)
                        + " yields a TC or AAC", r.getSW() == 0x9000, r);
                if (r.getSW() == 0x9000) {
                    int type = Responses.parseAc(r).cid & 0xC0;
                    Checks.check("second AC P1=" + Integer.toHexString(p1 & 0xFF)
                            + " CID is TC or AAC", type == 0x00 || type == 0x40);
                }
            }
        }
    }

    // --- CDA / DDA boundaries -----------------------------------------------

    private static void verifyCdaBoundaries(Terminal terminal, String aid,
            byte[] pdolData) throws Exception {
        System.out.println("--- CDA / DDA boundaries ---");

        // CDA requested but the card decides AAC (IAC-Denial TVR bit): the
        // response must be a normal cryptogram without 9F4B (EMV v4.4 Book 2 §6.6.1).
        byte[] cdol1 = beginSession(terminal, aid, pdolData);
        if (cdol1 != null) {
            byte[] data = cdolData(cdol1);
            int tvr = AcCrypto.dolValueOffset(cdol1, 0x95);
            if (tvr < 0) {
                Checks.fail("CDA+AAC: CDOL1 has no TVR (95)");
            } else {
                data[tvr] = (byte) 0x80;
                ResponseAPDU r = terminal.generateAc((byte) 0x90, data); // ARQC + CDA
                Checks.check("CDA with AAC decision", r.getSW() == 0x9000, r);
                if (r.getSW() == 0x9000) {
                    Checks.check("CDA downgraded to AAC has no SDAD",
                            Tags.find(r.getData(), 0x9F4B) == null, r);
                    Checks.check("CDA downgraded CID is AAC", Responses.parseAc(r).cid == 0x00);
                }
            }
        }

        // INTERNAL AUTHENTICATE P1/P2 != 00 -> 6A81 (EMV v4.4 Book 3 Table 4/19).
        terminal.select(aid);
        Checks.check("INTERNAL AUTHENTICATE P1 != 00 -> 6A81",
                terminal.internalAuthenticateRaw(1, 0, new byte[4]).getSW(), 0x6A81);
        Checks.check("INTERNAL AUTHENTICATE P2 != 00 -> 6A81",
                terminal.internalAuthenticateRaw(0, 1, new byte[4]).getSW(), 0x6A81);
    }

    // --- VERIFY / GET DATA / GPO boundaries ---------------------------------

    private static void verifyGetData(Terminal terminal, String aid, byte[] pdolData)
            throws Exception {
        System.out.println("--- GET DATA ---");
        beginSession(terminal, aid, pdolData);

        byte[] atc = Tags.find(terminal.getData(0x9F, 0x36).getData(), 0x9F36);
        Checks.check("GET DATA 9F36 -> 9F36 02 xxxx", atc != null && atc.length == 2);

        byte[] lastOnline = Tags.find(terminal.getData(0x9F, 0x13).getData(), 0x9F13);
        Checks.check("GET DATA 9F13 -> 9F13 02 xxxx",
                lastOnline != null && lastOnline.length == 2);

        // GET DATA 9F17 tracks the offline PIN try counter (EMV v4.4 Book 3 §6.5.7).
        byte[] before = Tags.find(terminal.getData(0x9F, 0x17).getData(), 0x9F17);
        Checks.check("GET DATA 9F17 -> 9F17 01 xx",
                before != null && before.length == 1);
        Checks.check("VERIFY wrong PIN -> 63C2",
                terminal.verifyOfflinePin("0000").getSW(), 0x63C2);
        byte[] after = Tags.find(terminal.getData(0x9F, 0x17).getData(), 0x9F17);
        Checks.check("9F17 decremented after a failed VERIFY",
                before != null && after != null && after.length == 1
                        && (after[0] & 0xFF) == (before[0] & 0xFF) - 1);
        Checks.check("VERIFY correct PIN resets the counter",
                terminal.verifyOfflinePin("1234").getSW(), 0x9000);
        byte[] reset = Tags.find(terminal.getData(0x9F, 0x17).getData(), 0x9F17);
        Checks.check("9F17 reset after a successful VERIFY",
                reset != null && reset.length == 1 && reset[0] == 3);

        // The Log Format (tag 9F4F) is served once the transaction log exists
        // (EMV v4.4 Book 3 Annex D4); unknown tags are 6A81/6A88 (Table 5).
        ResponseAPDU logFormat = terminal.getData(0x9F, 0x4F);
        byte[] format = logFormat.getSW() == 0x9000
                ? Tags.find(logFormat.getData(), 0x9F4F) : null;
        Checks.check("GET DATA 9F4F -> 9F4F log format",
                format != null && format.length > 0, logFormat);
        Checks.check("GET DATA P1 != 9F -> 6A81", terminal.getData(0x9E, 0x36).getSW(), 0x6A81);
        Checks.check("GET DATA unknown 9Fxx -> 6A88",
                terminal.getData(0x9F, 0x99).getSW(), 0x6A88);
    }

    private static void verifyVerifyBoundaries(Terminal terminal, String aid,
            byte[] pdolData) throws Exception {
        System.out.println("--- VERIFY format ---");
        beginSession(terminal, aid, pdolData);

        // P2 = 80 (plaintext) or 88 (enciphered RSA) are the defined values;
        // 81-87 are 'RFU for this specification' (EMV v4.4 Book 3 Table 24).
        // The card cannot interpret an RFU qualifier and refuses it with 6A81
        // (Book 3 Table 4); note the general "do not verify RFU" rule of
        // Book 3 §6.3.6 cannot be applied to a P2 that selects the data format.
        Checks.check("VERIFY P2 != 80/88 -> 6A81",
                terminal.verifyRaw(0, 0x81, new byte[0]).getSW(), 0x6A81);

        // Plaintext PIN block: fixed 16 nibbles = 8 bytes, format byte C=0010,
        // N=4..12, 'F' filler (EMV v4.4 Book 3 Table 25).
        Checks.check("VERIFY plaintext C != 2 -> 6A80",
                terminal.verifyRaw(0, 0x80,
                        new byte[] { 0x34, 0x12, 0x34, (byte) 0xFF, (byte) 0xFF,
                                (byte) 0xFF, (byte) 0xFF, (byte) 0xFF }).getSW(), 0x6A80);
        Checks.check("VERIFY plaintext N < 4 -> 6A80",
                terminal.verifyRaw(0, 0x80,
                        new byte[] { 0x23, 0x12, 0x34, (byte) 0xFF, (byte) 0xFF,
                                (byte) 0xFF, (byte) 0xFF, (byte) 0xFF }).getSW(), 0x6A80);
        Checks.check("VERIFY plaintext N > 12 -> 6A80",
                terminal.verifyRaw(0, 0x80,
                        new byte[] { 0x2D, 0x12, 0x34, (byte) 0xFF, (byte) 0xFF,
                                (byte) 0xFF, (byte) 0xFF, (byte) 0xFF }).getSW(), 0x6A80);
        Checks.check("VERIFY plaintext Lc != 8 -> 6700",
                terminal.verifyRaw(0, 0x80, new byte[] { 0x24, 0x12 }).getSW(), 0x6700);
        Checks.check("VERIFY plaintext bad pad nibble -> 6A80",
                terminal.verifyRaw(0, 0x80,
                        new byte[] { 0x25, 0x12, 0x34, 0x5A, (byte) 0xFF,
                                (byte) 0xFF, (byte) 0xFF, (byte) 0xFF }).getSW(), 0x6A80);
        Checks.check("VERIFY plaintext bad filler byte -> 6A80",
                terminal.verifyRaw(0, 0x80,
                        new byte[] { 0x24, 0x12, 0x34, 0x00, (byte) 0xFF,
                                (byte) 0xFF, (byte) 0xFF, (byte) 0xFF }).getSW(), 0x6A80);

        // P1 is fixed to 00 (EMV v4.4 Book 3 §6.5.12.2, Table 23).
        Checks.check("VERIFY P1 != 00 -> 6A81",
                terminal.verifyRaw(1, 0x80,
                        new byte[] { 0x24, 0x12, 0x34, (byte) 0xFF, (byte) 0xFF,
                                (byte) 0xFF, (byte) 0xFF, (byte) 0xFF }).getSW(), 0x6A81);

        // The class byte's b8-b5 nibble must be '0' (inter-industry) or '8'
        // (proprietary to this specification); any other value is outside the
        // scope of EMV (EMV v4.4 Book 3 §6.3.1 Table 2/3).
        Checks.check("VERIFY CLA 0x20 -> 6A81",
                terminal.transmit(new CommandAPDU(0x20, 0x20, 0x00, 0x80,
                        new byte[] { 0x24, 0x12, 0x34, (byte) 0xFF, (byte) 0xFF,
                                (byte) 0xFF, (byte) 0xFF, (byte) 0xFF })).getSW(), 0x6A81);
        Checks.check("GENERATE AC CLA 0x20 -> 6A81",
                terminal.transmit(new CommandAPDU(0x20, 0xAE, 0x00, 0x00,
                        new byte[0])).getSW(), 0x6A81);
    }

    /**
     * SELECT reference/options boundaries.  EMV v4.4 Book 1 §11.3.2 Table 6/7
     * defines P1='04' (select by name) and P2='00' (first or only occurrence);
     * P2='02' (next occurrence, §11.3.5) is not selectable through the classic
     * Java Card JCRE, which performs the AID match before dispatching to the
     * applet.  jcsl therefore answers 6A82 for a non-matching reference/option
     * (a platform limitation, not a claim that EMV forbids P2='02');
     * EMVAppletBase also validates P1/P2 defensively when it is selected.
     */
    private static void verifySelectBoundaries(Terminal terminal) throws Exception {
        System.out.println("--- SELECT P1/P2 ---");
        Checks.check("SELECT P1 != 04 -> 6A82",
                terminal.transmit(new CommandAPDU(0x00, 0xA4, 0x00, 0x00,
                        Hex.parse(CONTACT_AID))).getSW(), 0x6A82);
        Checks.check("SELECT P2 != 00 -> 6A82",
                terminal.transmit(new CommandAPDU(0x00, 0xA4, 0x04, 0x02,
                        Hex.parse(CONTACT_AID))).getSW(), 0x6A82);
        // An AID no instance serves is not found (EMV v4.4 Book 1 §11.3.2).
        Checks.check("SELECT unmatched AID -> 6A82",
                terminal.select("A0000000031010").getSW(), 0x6A82);
        Checks.check("SELECT P1=04 P2=00 -> 9000",
                terminal.select(CONTACT_AID).getSW(), 0x9000);
    }

    /**
     * GET CHALLENGE boundaries (EMV v4.4 Book 3 §6.5.6.2, Table 16): P1 and P2
     * must be 00, otherwise 6A81.
     */
    private static void verifyChallengeBoundaries(Terminal terminal, String aid)
            throws Exception {
        System.out.println("--- GET CHALLENGE ---");
        terminal.select(aid);
        Checks.check("GET CHALLENGE P1 != 00 -> 6A81",
                terminal.transmit(new CommandAPDU(0x00, 0x84, 0x01, 0x00, 256))
                        .getSW(), 0x6A81);
        Checks.check("GET CHALLENGE P2 != 00 -> 6A81",
                terminal.transmit(new CommandAPDU(0x00, 0x84, 0x00, 0x01, 256))
                        .getSW(), 0x6A81);
        Checks.check("GET CHALLENGE P1=P2=00 -> 9000",
                terminal.getChallenge().getSW(), 0x9000);
        // The ICC Unpredictable Number must be unpredictable to an attacker
        // (EMV v4.4 Book 2 §7.2 step 2 / Book 3 §6.5.6.2): two consecutive
        // challenges differ.
        byte[] un1 = terminal.getChallenge().getData();
        byte[] un2 = terminal.getChallenge().getData();
        Checks.check("consecutive GET CHALLENGE values differ",
                un1.length == 8 && un2.length == 8
                        && !java.util.Arrays.equals(un1, un2));
    }

    private static void verifyGpoBoundaries(Terminal terminal, String aid, byte[] pdolData)
            throws Exception {
        System.out.println("--- GPO boundaries ---");
        terminal.select(aid);

        Checks.check("GPO P1 != 00 -> 6A81",
                terminal.gpoRaw(0x01, 0x00, new byte[] { (byte) 0x83, 0x00 }).getSW(), 0x6A81);
        Checks.check("GPO P2 != 00 -> 6A81",
                terminal.gpoRaw(0x00, 0x01, new byte[] { (byte) 0x83, 0x00 }).getSW(), 0x6A81);
        Checks.check("GPO without a '83' template -> 6700",
                terminal.gpoNoData().getSW(), 0x6700);
        Checks.check("GPO '83' value length mismatch -> 6700",
                terminal.gpoRaw(0x00, 0x00,
                        Apdus.commandTemplate(0x1E, new byte[30])).getSW(), 0x6700);

        // Trailing bytes after the '83' value are a wrong-data condition.
        byte[] trailing = new byte[2 + pdolData.length + 1];
        trailing[0] = (byte) 0x83;
        trailing[1] = (byte) pdolData.length;
        trailing[trailing.length - 1] = (byte) 0xFF;
        Checks.check("GPO trailing byte after '83' -> 6A80",
                terminal.gpoRaw(0x00, 0x00, trailing).getSW(), 0x6A80);
    }

    // --- instances without a key / without 9F37 ------------------------------

    private static void verifyNoKeyBoundaries(Terminal terminal) throws Exception {
        System.out.println("--- no DDA/PIN key (" + NO_KEY_AID + ") ---");
        Checks.check("SELECT " + NO_KEY_AID,
                terminal.select(NO_KEY_AID).getSW(), 0x9000);

        // This instance has no PDOL, so a non-empty '83' value is a length error.
        Checks.check("GPO non-empty '83' without a PDOL -> 6700",
                terminal.gpo(new byte[] { (byte) 0xAA, (byte) 0xBB }).getSW(), 0x6700);
        Checks.check("GPO empty '83' without a PDOL",
                terminal.gpo().getSW(), 0x9000);

        // No ICC DDA/CDA key -> CDA and INTERNAL AUTHENTICATE are 6985.
        Checks.check("CDA without an ICC key -> 6985",
                terminal.generateAc((byte) 0x90, new byte[32]).getSW(), 0x6985);
        Checks.check("INTERNAL AUTHENTICATE without a key -> 6985",
                terminal.internalAuthenticate(new byte[4]).getSW(), 0x6985);
    }

    // --- boundary instance: 5-digit PIN, CDOL without 9F37 ------------------

    private static void verifyBoundaryInstance(Terminal terminal) throws Exception {
        System.out.println("--- boundary instance (" + BOUNDARY_AID + ") ---");
        ResponseAPDU sel = terminal.select(BOUNDARY_AID);
        Checks.check("SELECT " + BOUNDARY_AID, sel.getSW() == 0x9000, sel);
        if (sel.getSW() != 0x9000) {
            return;
        }

        ResponseAPDU gpo = terminal.gpo();
        Checks.check("GPO boundary instance", gpo.getSW() == 0x9000, gpo);
        if (gpo.getSW() != 0x9000) {
            return;
        }
        byte[] aipBytes = gpoAip(gpo.getData());
        int aip = ((aipBytes[0] & 0xFF) << 8) | (aipBytes[1] & 0xFF);
        byte[] afl = gpoAfl(gpo.getData());

        // A 5-digit plaintext offline PIN (odd digit count, 0xF padded).
        Checks.check("VERIFY 5-digit plaintext PIN",
                terminal.verifyOfflinePin("12345").getSW(), 0x9000);

        // A normal first AC succeeds (the DDA key exists), but a CDA request is
        // refused because CDOL1 does not contain 9F37.  The issuer is required
        // to ensure CDOL1 and CDOL2 contain the Unpredictable Number (tag 9F37)
        // so the CDA signature covers it (EMV v4.4 Book 2 §6 footnote 10).
        Checks.check("GENERATE AC CDA without 9F37 -> 6985",
                freshAc(terminal, BOUNDARY_AID, (byte) 0x90, new byte[6]).getSW(), 0x6985);
        Checks.check("GENERATE AC without 9F37 (no CDA)",
                freshAc(terminal, BOUNDARY_AID, (byte) 0x80, new byte[6]).getSW(), 0x9000);
        // Complete the session opened by the ARQC with an AAC: a dangling first
        // AC leaves the persistent 'Last Online Transaction Not Completed' bit
        // set and would force the next suite's transaction online
        // (EMV v4.4 Book 3 §9.2.3.2).
        terminal.generateAc((byte) 0x00, new byte[6]);

        // Enciphered offline PIN: 4/5/12 digits, odd padding, bad format byte.
        SdaVerifier.Result sdaResult = SdaVerifier.verify(terminal, afl, aip, TestKeys.caKeyStore());
        Checks.check("SDA issuer public key certificate and SSAD"
                + (sdaResult.ok ? "" : " (" + sdaResult.reason + ")"), sdaResult.ok);
        IssuerKey issuer = sdaResult.key;
        if (issuer == null) {
            return;
        }
        SdaVerifier.Result pinResult = SdaVerifier.recoverPinKey(terminal, issuer);
        Checks.check("ICC PIN public key certificate"
                + (pinResult.ok ? "" : " (" + pinResult.reason + ")"), pinResult.ok);
        IssuerKey pinKey = pinResult.key;
        if (pinKey == null) {
            return;
        }

        Checks.check("VERIFY enciphered 5-digit PIN",
                terminal.verifyEncryptedPin(encipher("12345", pinKey, terminal)).getSW(), 0x9000);

        // A block whose ICC Unpredictable Number does not match the one issued
        // by GET CHALLENGE must be refused with 6984 (EMV v4.4 Book 2 §7.2 step 7).
        byte[] challenge = EmvFlowTest.getChallenge(terminal);
        byte[] wrongUn = Arrays.copyOf(challenge, challenge.length);
        wrongUn[0] ^= 0x01;
        Checks.check("VERIFY enciphered wrong ICC UN -> 6984",
                terminal.verifyEncryptedPin(AcCrypto.emvEncipherPin(
                        AcCrypto.iso9564Format2("12345"), wrongUn,
                        pinKey.modulus, pinKey.exponent)).getSW(), 0x6984);

        // A GET CHALLENGE challenge is valid only for the next command
        // (EMV v4.4 Book 3 §6.5.6.1): an intervening command invalidates it, so
        // a block built from it is refused with 6984.
        byte[] staleUn = EmvFlowTest.getChallenge(terminal);
        byte[] staleBlock = AcCrypto.emvEncipherPin(AcCrypto.iso9564Format2("12345"),
                staleUn, pinKey.modulus, pinKey.exponent);
        terminal.getData(0x9F, 0x36); // any intervening command
        Checks.check("VERIFY enciphered after an intervening command -> 6984",
                terminal.verifyEncryptedPin(staleBlock).getSW(), 0x6984);

        Checks.check("VERIFY enciphered format != 2 -> 6A80",
                terminal.verifyEncryptedPin(
                        encipherBlock((byte) 0x34, new byte[] { 0x12, 0x34 },
                                pinKey, terminal)).getSW(), 0x6A80);
        Checks.check("VERIFY enciphered N > 12 -> 6A80",
                terminal.verifyEncryptedPin(
                        encipherBlock((byte) 0x2D, new byte[] { 0x12, 0x34 },
                                pinKey, terminal)).getSW(), 0x6A80);
        // A 4- and a 12-digit block are accepted as format 2 but are wrong PINs.
        Checks.check("VERIFY enciphered wrong 4-digit PIN -> 63C2",
                terminal.verifyEncryptedPin(encipher("9999", pinKey, terminal)).getSW(), 0x63C2);
        Checks.check("VERIFY enciphered wrong 12-digit PIN -> 63C1",
                terminal.verifyEncryptedPin(encipher("999999999999", pinKey, terminal)).getSW(), 0x63C1);
        Checks.check("VERIFY enciphered 5-digit PIN after retries",
                terminal.verifyEncryptedPin(encipher("12345", pinKey, terminal)).getSW(), 0x9000);
    }

    // --- shared helpers ------------------------------------------------------

    /** The PDOL-related data length of the FCI, or null when SELECT fails. */
    private static byte[] pdolData(Terminal terminal, String aid) throws Exception {
        ResponseAPDU r = terminal.select(aid);
        Checks.check("SELECT " + aid, r.getSW() == 0x9000, r);
        if (r.getSW() != 0x9000) {
            return null;
        }
        byte[] pdol = Tags.find(r.getData(), 0x9F38);
        return new byte[pdol == null ? 0 : AcCrypto.dolDataLength(pdol)];
    }

    /**
     * Starts a fresh transaction on aid and returns the CDOL1 definition from
     * record 1, or null (with a recorded failure) when a prerequisite fails.
     */
    private static byte[] beginSession(Terminal terminal, String aid, byte[] pdolData)
            throws Exception {
        ResponseAPDU sel = terminal.select(aid);
        if (sel.getSW() != 0x9000) {
            Checks.fail("session SELECT " + aid + " -> " + Checks.sw(sel.getSW()));
            return null;
        }
        ResponseAPDU gpo = terminal.gpo(pdolData);
        if (gpo.getSW() != 0x9000) {
            Checks.fail("session GPO -> " + Checks.sw(gpo.getSW()));
            return null;
        }
        ResponseAPDU rec = terminal.readRecord(1, 1);
        if (rec.getSW() != 0x9000) {
            Checks.fail("session READ RECORD 1 -> " + Checks.sw(rec.getSW()));
            return null;
        }
        byte[] cdol1 = Tags.find(rec.getData(), 0x8C);
        if (cdol1 == null) {
            Checks.fail("session record 1 has no CDOL1 (8C)");
            return null;
        }
        return cdol1;
    }

    /** A zero-filled CDOL data field of the length described by cdol. */
    private static byte[] cdolData(byte[] cdol) {
        return new byte[cdol == null ? 0 : AcCrypto.dolDataLength(cdol)];
    }

    /** The CDOL2 definition (tag 8D) of record 1 in the current session. */
    private static byte[] cdol2Definition(Terminal terminal) throws Exception {
        ResponseAPDU rec = terminal.readRecord(1, 1);
        if (rec.getSW() != 0x9000) {
            Checks.fail("CDOL2: READ RECORD 1 -> " + Checks.sw(rec.getSW()));
            return null;
        }
        return Tags.find(rec.getData(), 0x8D);
    }

    /** A fresh SELECT + GPO + first GENERATE AC on an instance without a PDOL. */
    private static ResponseAPDU freshAc(Terminal terminal, String aid, byte p1, byte[] data)
            throws Exception {
        terminal.select(aid);
        terminal.gpo();
        return terminal.generateAc(p1, data);
    }

    private static byte[] encipher(String pin, IssuerKey key, Terminal terminal)
            throws Exception {
        byte[] iccUn = EmvFlowTest.getChallenge(terminal);
        return AcCrypto.emvEncipherPin(AcCrypto.iso9564Format2(pin), iccUn,
                key.modulus, key.exponent);
    }

    /** Enciphers an 8-byte PIN block (explicit format byte) as EMV v4.4 Book 2 Table 25. */
    private static byte[] encipherBlock(byte format, byte[] digits,
            IssuerKey key, Terminal terminal) throws Exception {
        byte[] block = new byte[8];
        Arrays.fill(block, (byte) 0xFF);
        block[0] = format;
        System.arraycopy(digits, 0, block, 1, digits.length);
        byte[] iccUn = EmvFlowTest.getChallenge(terminal);
        return AcCrypto.emvEncipherPin(block, iccUn, key.modulus, key.exponent);
    }

    /** The AIP of a format 1 or format 2 GPO response. */
    private static byte[] gpoAip(byte[] gpo) {
        return Responses.gpoAip(gpo);
    }

    /** The AFL of a format 1 or format 2 GPO response. */
    private static byte[] gpoAfl(byte[] gpo) {
        return Responses.gpoAfl(gpo);
    }
}
