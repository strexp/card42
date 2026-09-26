package card42.test;

import java.io.ByteArrayOutputStream;
import java.util.Arrays;

import javax.smartcardio.Card;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import card42.host.emv.crypto.SmCrypto;
import card42.host.emv.crypto.AcCrypto;
import card42.host.emv.lib.Terminal;
import card42.host.common.util.Args;
import card42.host.common.util.Bytes;
import card42.host.common.util.Hex;
import card42.host.common.codec.Responses;
import card42.host.common.codec.Tags;
import card42.host.emv.kernel.data.TerminalDol;
import card42.host.common.codec.TlvWriter;

/**
 * Issuer script and post-issuance command tests (EMV v4.4 Book 2 §8.2, §9.2/§9.3).
 *
 * It drives the Format 1 secure-messaging MAC chain of {@link SmCrypto} against
 * the contact instance and covers:
 *
 *   - PIN CHANGE/UNBLOCK (P2=00) delivered in a 71 script, including the MAC
 *     chain across two commands and the 9F5B Issuer Script Results encoding;
 *   - APPLICATION BLOCK / UNBLOCK across a re-selection (the invalidated
 *     application answers SELECT with 6283 until it is unblocked);
 *   - a MAC error (6A80) and the subsequent 6985;
 *   - the generic EXTERNAL AUTHENTICATE path (instance 43415244420106, AIP byte 1
 *     bit 3 set) with a correct and a wrong ARPC Method 1;
 *   - CARD BLOCK last, which permanently disables every application.
 *
 * Exits non-zero if any check fails.
 */
public class IssuerScriptTest {

    private static final String CONTACT_AID = "43415244420101";
    private static final String NO_KEY_AID = "43415244420104";
    private static final String GENERIC_AID = "43415244420106";
    private static final String PSE_AID = "315041592E5359532E4444463031";

    // ICC master keys derived from the issuer master keys in perso/emv/sample-test.perso
    // with the CV '5' method (Option B, EMV v4.4 Book 2 §A1.4.2) for
    // PAN 1234567890, PAN sequence 00.
    private static final byte[] ICC_KEY =
            Hex.parse("343864C2E085AB3E433D2F982945E61F");
    private static final byte[] SM_MAC_KEY =
            Hex.parse("911C3404804CCEBF458AA1191C152A3E");
    private static final byte[] SM_ENC_KEY =
            Hex.parse("BA915D4F3185B9EA620234D5FDAEBA9D");
    /** SM MAC key of the generic instance 06 (no encipherment key). */
    private static final byte[] GENERIC_MAC_KEY =
            Hex.parse("8CBCD9CB5ED34FD3DF5EF2B06492D552");
    private static final byte[] ARC_APPROVED = { 0x00, 0x00 };

    /** Number of terminal data bytes the contact instance's CDOL1 asks for. */
    private static int cdol1DataLength = 43;

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
            System.out.println("FAILED: " + Checks.failures() + " issuer script check(s)");
            System.exit(1);
        }
        System.out.println("ALL ISSUER SCRIPT CHECKS PASSED");
    }

    static void run(Terminal terminal) throws Exception {
        byte[] pdol = pdolData(terminal, CONTACT_AID);
        if (pdol == null) {
            return;
        }
        cdol1DataLength = deriveCdol1Length(terminal, CONTACT_AID, pdol);
        if (cdol1DataLength < 0) {
            return;
        }
        verifyPinUnblock(terminal, pdol);
        verifyApplicationBlockUnblock(terminal, pdol);
        verifyMacError(terminal, pdol);
        verifyPostIssuanceBoundaries(terminal, pdol);
        verifyMalformedMac(terminal, pdol);
        verifyMacTruncation(terminal, pdol);
        verifyPlaintextObject(terminal, pdol);
        verifyPinUnblockResetsPtc(terminal, pdol);
        verifyChainedPinUnblock(terminal, pdol);
        verifyScriptChain(terminal, pdol);
        verifyCvrScriptCount(terminal, pdol);
        verifyEncWithoutKey(terminal);
        verifyCsuApplicationBlock(terminal, pdol);
        verifyCsuPinTryCounter(terminal, pdol);
        verifyInlineAuthMissing(terminal);
        verifyGenericExternalAuthenticate(terminal);
        // CARD BLOCK disables the whole card, so it goes last.  The CCD CSU
        // byte 2 b7 "Card Block" branch (IssuerAuth.applyCsu) is deliberately
        // not exercised positively: like the post-issuance CARD BLOCK below it
        // calls EMVAppletBase.blockCard(), a card-wide static flag with no
        // unblock, so a successful positive test would permanently break this
        // and every later suite.  The CSU Application Block branch (b6) is
        // covered by verifyCsuApplicationBlock, and the same blockCard() effect
        // is covered by the post-issuance CARD BLOCK test below.
        verifyCardBlock(terminal, pdol);
    }

    // --- PIN CHANGE/UNBLOCK in a 71 script ----------------------------------

    private static void verifyPinUnblock(Terminal terminal, byte[] pdol)
            throws Exception {
        System.out.println("--- issuer script: PIN CHANGE/UNBLOCK ---");
        byte[] firstAc = beginArqcSession(terminal, CONTACT_AID, pdol);
        if (firstAc == null) {
            return;
        }
        SmCrypto.ScriptSession session = new SmCrypto.ScriptSession(SM_MAC_KEY, SM_ENC_KEY);
        session.start(firstAc);

        byte[] script = buildScript(0x71, "01020304",
                session.command(0x24, 0x00, 0x00).getBytes(),
                session.command(0x24, 0x00, 0x00).getBytes());
        SmCrypto.IssuerScript parsed = SmCrypto.parseIssuerScript(script);
        Checks.check("71 script identifier", parsed.scriptId != null
                && parsed.scriptId.length == 4);
        Checks.check("71 script command count", parsed.commands.size() == 2);
        if (parsed.commands.size() != 2) {
            return;
        }
        for (int i = 0; i < parsed.commands.size(); i++) {
            ResponseAPDU r = terminal.transmit(parsed.commands.get(i));
            Checks.check("71 command " + i, r.getSW(), 0x9000);
        }
        // A Format 1 confidentiality object (tag 87) exercises the encipherment
        // session key: PIN CHANGE/UNBLOCK P2=00 ignores the PIN data but still
        // decrypts it (EMV v4.4 Book 2 §9.2).
        ResponseAPDU enciphered = terminal.transmit(
                session.command(0x24, 0x00, 0x00, null,
                        AcCrypto.iso9564Format2("1234")).getBytes());
        Checks.check("PIN CHANGE/UNBLOCK with enciphered PIN data",
                enciphered.getSW(), 0x9000);
        byte[] results = SmCrypto.issuerScriptResults(2, 0, parsed.scriptId);
        Checks.check("9F5B successful result", (results[0] & 0xF0) == 0x20
                && (results[0] & 0x0F) == 0);
        Checks.bytes(Hex.parse("01020304"),
                Arrays.copyOfRange(results, 1, 5), "9F5B script identifier");
    }

    // --- APPLICATION BLOCK / UNBLOCK ----------------------------------------

    private static void verifyApplicationBlockUnblock(Terminal terminal, byte[] pdol)
            throws Exception {
        System.out.println("--- post-issuance: APPLICATION BLOCK/UNBLOCK ---");
        byte[] firstAc = beginArqcSession(terminal, CONTACT_AID, pdol);
        if (firstAc == null) {
            return;
        }
        SmCrypto.ScriptSession session = new SmCrypto.ScriptSession(SM_MAC_KEY, SM_ENC_KEY);
        session.start(firstAc);
        // APPLICATION UNBLOCK on a valid application is a no-op success
        // (EMV v4.4 Book 3 section 6.5.2).
        Checks.check("APPLICATION UNBLOCK on a valid application -> 9000",
                terminal.transmit(session.command(0x18, 0x00, 0x00).getBytes()).getSW(),
                0x9000);
        Checks.check("APPLICATION BLOCK",
                terminal.transmit(session.command(0x1E, 0x00, 0x00).getBytes()).getSW(),
                0x9000);

        // The invalidated application answers SELECT with 6283 (EMV v4.4 Book 3 §6.5.1).
        Checks.check("SELECT invalidated -> 6283",
                terminal.select(CONTACT_AID).getSW(), 0x6283);

        // A fresh session on the invalidated application: the first AC is an
        // AAC, and the issuer can still unblock it (EMV v4.4 Book 3 §6.5.2).
        terminal.select(CONTACT_AID);
        terminal.gpo(pdol);
        ResponseAPDU first = terminal.generateAc((byte) 0x80, cdol1DataLength);
        Checks.check("invalidated first AC", first.getSW() == 0x9000, first);
        if (first.getSW() != 0x9000) {
            return;
        }
        byte[] aac = Responses.parseAc(first).ac;
        SmCrypto.ScriptSession unblock = new SmCrypto.ScriptSession(SM_MAC_KEY, SM_ENC_KEY);
        unblock.start(aac);
        // APPLICATION BLOCK on an already invalidated application is still a
        // success (EMV v4.4 Book 3 section 6.5.1).
        Checks.check("APPLICATION BLOCK on an invalidated application -> 9000",
                terminal.transmit(unblock.command(0x1E, 0x00, 0x00).getBytes()).getSW(),
                0x9000);
        Checks.check("APPLICATION UNBLOCK",
                terminal.transmit(unblock.command(0x18, 0x00, 0x00).getBytes()).getSW(),
                0x9000);
        Checks.check("SELECT after unblock -> 9000",
                terminal.select(CONTACT_AID).getSW(), 0x9000);
    }

    // --- MAC error ----------------------------------------------------------

    private static void verifyMacError(Terminal terminal, byte[] pdol) throws Exception {
        System.out.println("--- post-issuance: MAC error ---");
        byte[] firstAc = beginArqcSession(terminal, CONTACT_AID, pdol);
        if (firstAc == null) {
            return;
        }
        SmCrypto.ScriptSession session = new SmCrypto.ScriptSession(SM_MAC_KEY, SM_ENC_KEY);
        session.start(firstAc);

        byte[] bad = session.command(0x24, 0x00, 0x00).getBytes();
        bad[bad.length - 1] ^= 0x01;
        Checks.check("corrupted MAC -> 6A80", terminal.transmit(bad).getSW(), 0x6A80);
        // After a MAC failure the rest of the transaction is refused with 6985;
        // re-preparing the session at the same ATC must not resurrect it
        // (docs/specs/common/toolchain.md §6).
        Checks.check("command after MAC failure -> 6985",
                terminal.transmit(session.command(0x24, 0x00, 0x00).getBytes()).getSW(),
                0x6985);

        // A new transaction (new ATC) resets the secure-messaging session.
        byte[] freshAc = beginArqcSession(terminal, CONTACT_AID, pdol);
        if (freshAc != null) {
            SmCrypto.ScriptSession recovered = new SmCrypto.ScriptSession(SM_MAC_KEY, SM_ENC_KEY);
            recovered.start(freshAc);
            Checks.check("new ATC resets the MAC failure",
                    terminal.transmit(recovered.command(0x24, 0x00, 0x00).getBytes()).getSW(),
                    0x9000);
        }

        // A plaintext post-issuance command (no Format 1 secure messaging) is
        // refused.  The CLA must be '8x' for APPLICATION BLOCK (EMV v4.4 Book 3
        // Table 3); the low nibble is not 'C' here, so no SM is recognised.
        terminal.select(CONTACT_AID);
        terminal.gpo(pdol);
        terminal.generateAc((byte) 0x80, cdol1DataLength);
        Checks.check("plaintext APPLICATION BLOCK -> 6985",
                terminal.transmit(new CommandAPDU(0x80, 0x1E, 0x00, 0x00)).getSW(),
                0x6985);
    }

    // --- post-issuance command boundaries (docs/specs/common/toolchain.md §6) ----------

    private static void verifyPostIssuanceBoundaries(Terminal terminal, byte[] pdol)
            throws Exception {
        System.out.println("--- post-issuance boundaries ---");

        // No first AC yet: the MAC chain cannot have started -> 6985.
        terminal.select(CONTACT_AID);
        terminal.gpo(pdol);
        Checks.check("post-issuance before the first AC -> 6985",
                terminal.transmit(new CommandAPDU(0x8C, 0x1E, 0x00, 0x00,
                        Hex.parse("8E0400000000"))).getSW(), 0x6985);

        // P1 != 00 / P2 != 00 -> 6A81; a Format 2 CLA (84) is not implemented
        // and is refused with 6985 (EMV v4.4 Book 3 Table 6 allows 8C or 84).
        byte[] firstAc = beginArqcSession(terminal, CONTACT_AID, pdol);
        if (firstAc == null) {
            return;
        }
        SmCrypto.ScriptSession session = new SmCrypto.ScriptSession(SM_MAC_KEY, SM_ENC_KEY);
        session.start(firstAc);
        Checks.check("post-issuance P1 != 00 -> 6A81",
                terminal.transmit(session.command(0x1E, 0x01, 0x00).getBytes()).getSW(),
                0x6A81);
        Checks.check("post-issuance P2 != 00 -> 6A81",
                terminal.transmit(session.command(0x1E, 0x00, 0x01).getBytes()).getSW(),
                0x6A81);
        Checks.check("Format 2 CLA 84 -> 6985",
                terminal.transmit(new CommandAPDU(0x84, 0x1E, 0x00, 0x00,
                        Hex.parse("8E0400000000"))).getSW(), 0x6985);

        // An instance without the SM MAC master key refuses post-issuance
        // commands with 6985 (instance 04 has no EMV CPS v2.0 Annex A DGI '8000' MAC UDK).
        ResponseAPDU sel = terminal.select(NO_KEY_AID);
        Checks.check("SELECT " + NO_KEY_AID, sel.getSW() == 0x9000, sel);
        if (sel.getSW() == 0x9000) {
            terminal.gpo();
            Checks.check("post-issuance without a MAC key -> 6985",
                    terminal.transmit(new CommandAPDU(0x8C, 0x1E, 0x00, 0x00,
                            Hex.parse("8E0400000000"))).getSW(), 0x6985);
        }
    }

    /**
     * Malformed Format 1 data fields are rejected with 6A80: the MAC object not
     * last, two MAC objects, a MAC shorter than 4 or longer than 8 bytes, and a
     * truncated object (docs/specs/common/toolchain.md §6).
     */
    private static void verifyMalformedMac(Terminal terminal, byte[] pdol)
            throws Exception {
        System.out.println("--- malformed Format 1 data fields ---");
        byte[] firstAc = beginArqcSession(terminal, CONTACT_AID, pdol);
        if (firstAc == null) {
            return;
        }
        SmCrypto.ScriptSession session = new SmCrypto.ScriptSession(SM_MAC_KEY, SM_ENC_KEY);
        session.start(firstAc);

        // These are rejected structurally before the MAC is checked, so no
        // valid MAC is needed and the session is not poisoned.
        Checks.check("8E not last -> 6A80",
                terminal.transmit(new CommandAPDU(0x8C, 0x24, 0x00, 0x00,
                        Hex.parse("8E040000000081021234"))).getSW(), 0x6A80);
        Checks.check("two 8E objects -> 6A80",
                terminal.transmit(new CommandAPDU(0x8C, 0x24, 0x00, 0x00,
                        Hex.parse("8E04000000008E0400000000"))).getSW(), 0x6A80);
        Checks.check("MAC length 3 -> 6A80",
                terminal.transmit(new CommandAPDU(0x8C, 0x24, 0x00, 0x00,
                        Hex.parse("8E03000000"))).getSW(), 0x6A80);
        Checks.check("MAC length 9 -> 6A80",
                terminal.transmit(new CommandAPDU(0x8C, 0x24, 0x00, 0x00,
                        Hex.parse("8E090000000000000000"))).getSW(), 0x6A80);
        Checks.check("truncated object -> 6A80",
                terminal.transmit(new CommandAPDU(0x8C, 0x24, 0x00, 0x00,
                        Hex.parse("8E"))).getSW(), 0x6A80);

        // The session still works after the structural failures (they do not
        // set the MAC-failure flag).
        Checks.check("valid command after structural failures",
                terminal.transmit(session.command(0x24, 0x00, 0x00).getBytes()).getSW(),
                0x9000);
    }

    /**
     * A 4-byte MAC is accepted (EMV v4.4 Book 2 section 9.2.1) while the MAC chain keeps
     * advancing with the full 8 bytes (section 9.2.3.1).
     */
    private static void verifyMacTruncation(Terminal terminal, byte[] pdol)
            throws Exception {
        System.out.println("--- MAC truncation ---");
        byte[] firstAc = beginArqcSession(terminal, CONTACT_AID, pdol);
        if (firstAc == null) {
            return;
        }
        SmCrypto.ScriptSession session = new SmCrypto.ScriptSession(SM_MAC_KEY, SM_ENC_KEY);
        session.setMacLength(4);
        session.start(firstAc);
        CommandAPDU first = session.command(0x24, 0x00, 0x00);
        Checks.check("4-byte MAC object length", first.getData()[1] & 0xFF, 0x04);
        Checks.check("4-byte MAC accepted",
                terminal.transmit(first.getBytes()).getSW(), 0x9000);
        Checks.check("second command chains with the full MAC",
                terminal.transmit(session.command(0x24, 0x00, 0x00).getBytes()).getSW(),
                0x9000);
    }

    /** A plaintext '81' data object is accepted and its content ignored. */
    private static void verifyPlaintextObject(Terminal terminal, byte[] pdol)
            throws Exception {
        System.out.println("--- plaintext '81' object ---");
        byte[] firstAc = beginArqcSession(terminal, CONTACT_AID, pdol);
        if (firstAc == null) {
            return;
        }
        SmCrypto.ScriptSession session = new SmCrypto.ScriptSession(SM_MAC_KEY, SM_ENC_KEY);
        session.start(firstAc);
        Checks.check("PIN CHANGE/UNBLOCK with an 81 object",
                terminal.transmit(session.commandWithObjects(0x24, 0x00, 0x00,
                        Hex.parse("81021234")).getBytes()).getSW(), 0x9000);
    }

    /**
     * PIN CHANGE/UNBLOCK P2=00 resets the PIN Try Counter: lock the offline PIN
     * (9F17=0), send the command through secure messaging, then the correct PIN
     * is accepted again (docs/specs/common/toolchain.md §6).
     */
    private static void verifyPinUnblockResetsPtc(Terminal terminal, byte[] pdol)
            throws Exception {
        System.out.println("--- PIN CHANGE/UNBLOCK resets the PTC ---");
        terminal.select(CONTACT_AID);
        Checks.check("wrong PIN #1", terminal.verifyOfflinePin("0000").getSW(), 0x63C2);
        Checks.check("wrong PIN #2", terminal.verifyOfflinePin("0000").getSW(), 0x63C1);
        Checks.check("wrong PIN #3", terminal.verifyOfflinePin("0000").getSW(), 0x63C0);
        Checks.check("PIN blocked", terminal.verifyOfflinePin("1234").getSW(), 0x6983);
        byte[] ptc = Tags.find(terminal.getData(0x9F, 0x17).getData(), 0x9F17);
        Checks.check("9F17 == 0 while blocked", ptc != null && ptc[0] == 0);

        byte[] firstAc = beginArqcSession(terminal, CONTACT_AID, pdol);
        if (firstAc == null) {
            return;
        }
        SmCrypto.ScriptSession session = new SmCrypto.ScriptSession(SM_MAC_KEY, SM_ENC_KEY);
        session.start(firstAc);
        Checks.check("PIN CHANGE/UNBLOCK P2=00",
                terminal.transmit(session.command(0x24, 0x00, 0x00).getBytes()).getSW(),
                0x9000);
        ptc = Tags.find(terminal.getData(0x9F, 0x17).getData(), 0x9F17);
        Checks.check("9F17 restored after PIN CHANGE/UNBLOCK", ptc != null && ptc[0] == 3);
        Checks.check("correct PIN accepted after unblock",
                terminal.verifyOfflinePin("1234").getSW(), 0x9000);

        // P2=01/02 (PIN change) is not implemented and is refused with 6A81.
        firstAc = beginArqcSession(terminal, CONTACT_AID, pdol);
        if (firstAc == null) {
            return;
        }
        session = new SmCrypto.ScriptSession(SM_MAC_KEY, SM_ENC_KEY);
        session.start(firstAc);
        Checks.check("PIN CHANGE/UNBLOCK P2=01 -> 6A81",
                terminal.transmit(session.command(0x24, 0x00, 0x01).getBytes()).getSW(),
                0x6A81);
        Checks.check("PIN CHANGE/UNBLOCK P2=02 -> 6A81",
                terminal.transmit(session.command(0x24, 0x00, 0x02).getBytes()).getSW(),
                0x6A81);
    }

    /**
     * A chained PIN CHANGE/UNBLOCK (EMV v4.4 Book 3 §6.5.13): the non-final
     * fragment (CLA b5=1) is MAC-verified and answered with 9000 but does not
     * reset the PIN Try Counter; the last fragment performs the unblock.  The
     * SM MAC chain advances across both fragments (EMV v4.4 Book 2 §9.2.3.1).
     */
    private static void verifyChainedPinUnblock(Terminal terminal, byte[] pdol)
            throws Exception {
        System.out.println("--- chained PIN CHANGE/UNBLOCK ---");
        // Lock the offline PIN (PTC = 0).
        terminal.select(CONTACT_AID);
        terminal.verifyOfflinePin("0000");
        terminal.verifyOfflinePin("0000");
        terminal.verifyOfflinePin("0000");
        Checks.check("PIN locked before the chained unblock",
                terminal.verifyOfflinePin("1234").getSW(), 0x6983);

        // A lone non-final fragment must not reset the counter: abort the chain
        // with a SELECT, then the PTC is still 0 (EMV v4.4 Book 3 §6.5.13).
        byte[] firstAc = beginArqcSession(terminal, CONTACT_AID, pdol);
        if (firstAc == null) {
            return;
        }
        SmCrypto.ScriptSession session = new SmCrypto.ScriptSession(SM_MAC_KEY, SM_ENC_KEY);
        session.start(firstAc);
        Checks.check("chained PIN CHANGE/UNBLOCK fragment -> 9000",
                terminal.transmit(session.commandChained(0x24, 0x00, 0x00).getBytes())
                        .getSW(), 0x9000);
        terminal.select(CONTACT_AID);
        byte[] ptc = Tags.find(terminal.getData(0x9F, 0x17).getData(), 0x9F17);
        Checks.check("non-final fragment does not reset the PTC",
                ptc != null && ptc[0] == 0);

        // A complete chain resets the counter on its last fragment.
        firstAc = beginArqcSession(terminal, CONTACT_AID, pdol);
        if (firstAc == null) {
            return;
        }
        session = new SmCrypto.ScriptSession(SM_MAC_KEY, SM_ENC_KEY);
        session.start(firstAc);
        Checks.check("chained PIN CHANGE/UNBLOCK fragment -> 9000",
                terminal.transmit(session.commandChained(0x24, 0x00, 0x00).getBytes())
                        .getSW(), 0x9000);
        Checks.check("final PIN CHANGE/UNBLOCK -> 9000",
                terminal.transmit(session.command(0x24, 0x00, 0x00).getBytes())
                        .getSW(), 0x9000);
        ptc = Tags.find(terminal.getData(0x9F, 0x17).getData(), 0x9F17);
        Checks.check("last fragment restores the PTC", ptc != null && ptc[0] == 3);
        Checks.check("correct PIN accepted after the chained unblock",
                terminal.verifyOfflinePin("1234").getSW(), 0x9000);
    }

    /**
     * The MAC chain is continuous across two issuer scripts: a 71 command
     * followed by a 72 command must use the full 8-byte MAC of the first as its
     * ICV (EMV v4.4 Book 2 §9.2.3.1).
     */
    private static void verifyScriptChain(Terminal terminal, byte[] pdol)
            throws Exception {
        System.out.println("--- MAC chain across 71 -> 72 ---");
        byte[] firstAc = beginArqcSession(terminal, CONTACT_AID, pdol);
        if (firstAc == null) {
            return;
        }
        SmCrypto.ScriptSession session = new SmCrypto.ScriptSession(SM_MAC_KEY, SM_ENC_KEY);
        session.start(firstAc);

        byte[] script71 = buildScript(0x71, "0A0B0C0D",
                session.command(0x24, 0x00, 0x00).getBytes());
        byte[] script72 = buildScript(0x72, "0E0F1011",
                session.command(0x24, 0x00, 0x00).getBytes());
        SmCrypto.IssuerScript s71 = SmCrypto.parseIssuerScript(script71);
        SmCrypto.IssuerScript s72 = SmCrypto.parseIssuerScript(script72);
        Checks.check("71 script parsed", s71.commands.size() == 1);
        Checks.check("72 script parsed", s72.commands.size() == 1);
        Checks.check("71 command",
                terminal.transmit(s71.commands.get(0)).getSW(), 0x9000);
        Checks.check("72 command continues the chain",
                terminal.transmit(s72.commands.get(0)).getSW(), 0x9000);

        // Issuer Script Results (EMV v4.4 Book 4 Annex A5) and the TVR failure bits.
        byte[] results = SmCrypto.issuerScriptResults(2, 0, s72.scriptId);
        Checks.check("72 script results", (results[0] & 0xF0) == 0x20);
        byte[] tvr = new byte[5];
        SmCrypto.setScriptFailure(tvr, false);
        Checks.check("TVR before final AC bit", (tvr[4] & 0x20) != 0);
        SmCrypto.setScriptFailure(tvr, true);
        Checks.check("TVR after final AC bit", (tvr[4] & 0x10) != 0);
    }

    /**
     * CVR byte 4 b8-b5 is the number of secure-messaging commands successfully
     * processed in the current transaction (EMV v4.4 Book 3 §9.2.3.2).  It must
     * not carry the previous transaction's count into the next transaction's
     * first GENERATE AC before any command is processed.
     */
    /**
     * CVR byte 4 bits b8-b5 "Issuer Script Commands Processed" (EMV v4.4 Book 3
     * §9.2.3.2).  Book 3 does not limit the count to the current transaction;
     * this project declares the convention that it counts only the current
     * transaction and is cleared by SELECT, so a later transaction reports
     * zero.  This test pins that project interpretation.
     */
    private static void verifyCvrScriptCount(Terminal terminal, byte[] pdol)
            throws Exception {
        System.out.println("--- CVR byte 4 script count is per transaction"
                + " (project convention) ---");
        // Transaction A: process two secure-messaging commands.
        byte[] firstAc = beginArqcSession(terminal, CONTACT_AID, pdol);
        if (firstAc == null) {
            return;
        }
        SmCrypto.ScriptSession session = new SmCrypto.ScriptSession(SM_MAC_KEY, SM_ENC_KEY);
        session.start(firstAc);
        Checks.check("CVR count: command 1",
                terminal.transmit(session.command(0x24, 0x00, 0x00).getBytes()).getSW(),
                0x9000);
        Checks.check("CVR count: command 2",
                terminal.transmit(session.command(0x24, 0x00, 0x00).getBytes()).getSW(),
                0x9000);

        // Transaction B: no script has run yet, so the first AC's CVR byte 4
        // b8-b5 must be 0.
        terminal.select(CONTACT_AID);
        ResponseAPDU gpo = terminal.gpo(pdol);
        Checks.check("CVR count: GPO", gpo.getSW(), 0x9000);
        ResponseAPDU first = terminal.generateAc((byte) 0x80, cdol1DataLength);
        Checks.check("CVR count: first AC", first.getSW(), 0x9000);
        if (first.getSW() == 0x9000) {
            byte[] iad = Responses.parseAc(first).iad;
            int count = iad == null ? -1 : (iad[6] >> 4) & 0x0F;
            Checks.check("CVR byte 4 b8-b5 is 0 in the next transaction's first AC"
                    + " (got " + count + ")", count == 0);
        }
    }

    /**
     * A '87' confidentiality object on an instance with the MAC key but without
     * the encipherment key (EMV CPS v2.0 Annex A DGI '8000' ENC UDK) is refused with 6985 (docs/specs/common/toolchain.md §6).
     */
    private static void verifyEncWithoutKey(Terminal terminal) throws Exception {
        System.out.println("--- 87 object without an encipherment key ---");
        byte[] arqc = beginGenericArqcSession(terminal);
        if (arqc == null) {
            return;
        }
        SmCrypto.ScriptSession session = new SmCrypto.ScriptSession(GENERIC_MAC_KEY, null);
        session.start(arqc);
        // The cryptogram content is irrelevant: the card refuses because no
        // encipherment master key was personalized (EMV v4.4 Book 2 §9.2/§9.3).
        Checks.check("87 object without ENC UDK -> 6985",
                terminal.transmit(session.commandWithObjects(0x24, 0x00, 0x00,
                        Hex.parse("8703011122")).getBytes()).getSW(), 0x6985);

        // With the key present (instance 01) a wrong padding indicator is 6A80.
        byte[] pdol = pdolData(terminal, CONTACT_AID);
        if (pdol == null) {
            return;
        }
        byte[] firstAc = beginArqcSession(terminal, CONTACT_AID, pdol);
        if (firstAc == null) {
            return;
        }
        SmCrypto.ScriptSession withKey = new SmCrypto.ScriptSession(SM_MAC_KEY, SM_ENC_KEY);
        withKey.start(firstAc);
        Checks.check("87 padding indicator != 01 -> 6A80",
                terminal.transmit(withKey.commandWithObjects(0x24, 0x00, 0x00,
                        Hex.parse("8703021122")).getBytes()).getSW(), 0x6A80);
    }

    /**
     * CCD CSU byte 2 b6 "Application Block": a successful inline issuer
     * authentication invalidates the application (SELECT -> 6283).  The
     * application is then unblocked again with secure messaging so the later
     * suites still work (docs/specs/common/toolchain.md §6).
     */
    private static void verifyCsuApplicationBlock(Terminal terminal, byte[] pdol)
            throws Exception {
        System.out.println("--- CSU Application Block ---");
        byte[] firstAc = beginArqcSession(terminal, CONTACT_AID, pdol);
        if (firstAc == null) {
            return;
        }
        int atc = readAtc(terminal);
        byte[] sk = AcCrypto.sessionKey(ICC_KEY, atc);
        ResponseAPDU rec1 = terminal.readRecord(1, 1);
        byte[] cdol2Def = Tags.find(rec1.getData(), 0x8D);
        if (cdol2Def == null) {
            Checks.fail("CSU block: record 1 has no CDOL2");
            return;
        }
        byte[] cdol2 = new byte[TerminalDol.dolDataLength(cdol2Def)];
        int authOff = AcCrypto.dolValueOffset(cdol2Def, 0x91);
        byte[] csu = { 0x00, (byte) 0xA0, 0x00, 0x00 }; // Approve + Application Block
        byte[] arpc = AcCrypto.computeArpcMethod2(sk, firstAc, csu, new byte[0]);
        System.arraycopy(arpc, 0, cdol2, authOff, 4);
        System.arraycopy(csu, 0, cdol2, authOff + 4, 4);
        ResponseAPDU second = terminal.generateAc((byte) 0x40, cdol2);
        Checks.check("CSU Application Block second AC", second.getSW() == 0x9000, second);
        Checks.check("CSU Application Block invalidates the application",
                terminal.select(CONTACT_AID).getSW(), 0x6283);

        // Unblock it again so the later suites see a READY application.
        terminal.select(CONTACT_AID);
        terminal.gpo(pdol);
        ResponseAPDU aac = terminal.generateAc((byte) 0x80, cdol1DataLength);
        if (aac.getSW() != 0x9000) {
            Checks.fail("CSU block: invalidated first AC -> "
                    + Checks.sw(aac.getSW()));
            return;
        }
        SmCrypto.ScriptSession session = new SmCrypto.ScriptSession(SM_MAC_KEY, SM_ENC_KEY);
        session.start(Responses.parseAc(aac).ac);
        Checks.check("APPLICATION UNBLOCK after CSU block",
                terminal.transmit(session.command(0x18, 0x00, 0x00).getBytes()).getSW(),
                0x9000);
        Checks.check("SELECT after CSU block unblock",
                terminal.select(CONTACT_AID).getSW(), 0x9000);
    }

    /**
     * CSU "Update PIN Try Counter" (EMV v4.4 Book 3 Annex C §C10): the counter
     * is set to the CSU byte 1 b4-b1 value, including 0 (lock) and intermediate
     * values, and 9F17 reports it.
     */
    private static void verifyCsuPinTryCounter(Terminal terminal, byte[] pdol)
            throws Exception {
        System.out.println("--- CSU Update PIN Try Counter ---");
        // PTC = 1: one wrong PIN blocks it.
        Checks.check("CSU Update PTC = 1 second AC", sendCsu(terminal, pdol,
                new byte[] { 0x01, (byte) 0x90, 0x00, 0x00 }).getSW(), 0x9000);
        Checks.check("9F17 == 1 after CSU", readPtc(terminal), 0x01);
        Checks.check("wrong PIN -> 63C0", terminal.verifyOfflinePin("0000").getSW(), 0x63C0);
        Checks.check("PIN blocked after one wrong try",
                terminal.verifyOfflinePin("1234").getSW(), 0x6983);

        // PTC = 0: locked immediately (OwnerPIN cannot express this).
        Checks.check("CSU Update PTC = 0 second AC", sendCsu(terminal, pdol,
                new byte[] { 0x00, (byte) 0x90, 0x00, 0x00 }).getSW(), 0x9000);
        Checks.check("9F17 == 0 after CSU", readPtc(terminal), 0x00);
        Checks.check("PIN blocked at PTC 0", terminal.verifyOfflinePin("1234").getSW(), 0x6983);

        // Restore the default PTL (3).
        Checks.check("CSU Update PTC = 3 second AC", sendCsu(terminal, pdol,
                new byte[] { 0x03, (byte) 0x90, 0x00, 0x00 }).getSW(), 0x9000);
        Checks.check("9F17 == 3 restored", readPtc(terminal), 0x03);
        Checks.check("correct PIN accepted", terminal.verifyOfflinePin("1234").getSW(), 0x9000);
    }

    /** Sends a second GENERATE AC whose CDOL2 carries ARPC(4) || csu(4). */
    private static ResponseAPDU sendCsu(Terminal terminal, byte[] pdol, byte[] csu)
            throws Exception {
        byte[] firstAc = beginArqcSession(terminal, CONTACT_AID, pdol);
        if (firstAc == null) {
            return new ResponseAPDU(new byte[] { 0x6F, 0x00 });
        }
        int atc = readAtc(terminal);
        byte[] sk = AcCrypto.sessionKey(ICC_KEY, atc);
        ResponseAPDU rec1 = terminal.readRecord(1, 1);
        byte[] cdol2Def = Tags.find(rec1.getData(), 0x8D);
        byte[] cdol2 = new byte[TerminalDol.dolDataLength(cdol2Def)];
        int authOff = AcCrypto.dolValueOffset(cdol2Def, 0x91);
        byte[] arpc = AcCrypto.computeArpcMethod2(sk, firstAc, csu, new byte[0]);
        System.arraycopy(arpc, 0, cdol2, authOff, 4);
        System.arraycopy(csu, 0, cdol2, authOff + 4, 4);
        return terminal.generateAc((byte) 0x40, cdol2);
    }

    /** Reads the PIN Try Counter (9F17). */
    private static byte readPtc(Terminal terminal) throws Exception {
        byte[] ptc = Tags.find(terminal.getData(0x9F, 0x17).getData(), 0x9F17);
        return ptc == null ? (byte) 0xFF : ptc[0];
    }

    /**
     * CCD without the inline Issuer Authentication Data (tag 91): the second     * GENERATE AC performs no issuer authentication, follows the terminal
     * request and still records the online ATC (docs/specs/common/toolchain.md §6).
     * Instance 04 is a CCD profile whose CDOL2 has no 91.
     */
    private static void verifyInlineAuthMissing(Terminal terminal) throws Exception {
        System.out.println("--- CCD without inline Issuer Authentication Data ---");
        ResponseAPDU sel = terminal.select(NO_KEY_AID);
        Checks.check("no-91 SELECT " + NO_KEY_AID, sel.getSW() == 0x9000, sel);
        if (sel.getSW() != 0x9000) {
            return;
        }
        ResponseAPDU gpo = terminal.gpo();
        Checks.check("no-91 GPO", gpo.getSW() == 0x9000, gpo);
        if (gpo.getSW() != 0x9000) {
            return;
        }
        // Instance 04 has a 64-byte CDOL1/CDOL2 (32 x '95 01'), so both data
        // fields are 32 bytes.
        ResponseAPDU first = terminal.generateAc((byte) 0x80, 32);
        Checks.check("no-91 first AC is ARQC", first.getSW() == 0x9000
                && Responses.parseCid(first) == (byte) 0x80, first);
        int atc = readAtc(terminal);
        ResponseAPDU second = terminal.generateAc((byte) 0x40, new byte[32]);
        Checks.check("no-91 second AC follows the terminal request (TC)",
                second.getSW() == 0x9000 && Responses.parseCid(second) == 0x40, second);
        byte[] lastOnline = Tags.find(
                terminal.getData(0x9F, 0x13).getData(), 0x9F13);
        Checks.check("no-91 online success writes 9F13",
                lastOnline != null && lastOnline.length == 2
                        && (((lastOnline[0] & 0xFF) << 8) | (lastOnline[1] & 0xFF)) == atc);
    }

    // --- generic EXTERNAL AUTHENTICATE (instance with AIP b3 set) -----------

    private static void verifyGenericExternalAuthenticate(Terminal terminal)
            throws Exception {
        System.out.println("--- generic EXTERNAL AUTHENTICATE (" + GENERIC_AID + ") ---");

        // Before the first AC there is nothing to authenticate against.
        terminal.select(GENERIC_AID);
        terminal.gpo();
        Checks.check("EXTERNAL AUTHENTICATE before the first AC -> 6985",
                terminal.externalAuthenticate(new byte[10]).getSW(), 0x6985);

        byte[] arqc = beginGenericArqcSession(terminal);
        if (arqc == null) {
            return;
        }
        int atc = readAtc(terminal);
        byte[] sk = AcCrypto.sessionKey(ICC_KEY, atc);
        byte[] arpc = AcCrypto.computeArpcMethod1(sk, arqc, ARC_APPROVED);
        byte[] issuerAuthData = Bytes.concat(arpc, ARC_APPROVED);

        // P1/P2 must be 00 (EMV v4.4 Book 3 Table 9/4); the error does not consume the
        // single EXTERNAL AUTHENTICATE of the transaction.
        Checks.check("EXTERNAL AUTHENTICATE P1 != 00 -> 6A81",
                terminal.transmit(new CommandAPDU(0x00, 0x82, 0x01, 0x00,
                        issuerAuthData)).getSW(), 0x6A81);
        Checks.check("EXTERNAL AUTHENTICATE P2 != 00 -> 6A81",
                terminal.transmit(new CommandAPDU(0x00, 0x82, 0x00, 0x01,
                        issuerAuthData)).getSW(), 0x6A81);

        // Lc boundaries (EMV v4.4 Book 3 section 6.5.4): < 8 and > 16 are 6700; these
        // do not consume the single attempt either.
        Checks.check("EXTERNAL AUTHENTICATE Lc < 8 -> 6700",
                terminal.transmit(new CommandAPDU(0x00, 0x82, 0x00, 0x00,
                        new byte[4])).getSW(), 0x6700);
        Checks.check("EXTERNAL AUTHENTICATE Lc > 16 -> 6700",
                terminal.transmit(new CommandAPDU(0x00, 0x82, 0x00, 0x00,
                        new byte[17])).getSW(), 0x6700);

        Checks.check("EXTERNAL AUTHENTICATE correct ARPC",
                terminal.externalAuthenticate(issuerAuthData).getSW(), 0x9000);
        byte[] lastOnline = Tags.find(
                terminal.getData(0x9F, 0x13).getData(), 0x9F13);
        Checks.check("EXTERNAL AUTHENTICATE success writes 9F13 == ATC",
                lastOnline != null && lastOnline.length == 2
                        && (((lastOnline[0] & 0xFF) << 8) | (lastOnline[1] & 0xFF)) == atc);
        Checks.check("second EXTERNAL AUTHENTICATE -> 6985",
                terminal.externalAuthenticate(issuerAuthData).getSW(), 0x6985);
        // After a successful issuer authentication the second AC approves a TC.
        ResponseAPDU second = terminal.generateAc((byte) 0x40, new byte[6]);
        Checks.check("second AC after EXTERNAL AUTHENTICATE",
                second.getSW() == 0x9000, second);
        if (second.getSW() == 0x9000) {
            Checks.check("second AC is TC", Responses.parseAc(second).cid == (byte) 0x40);
        }

        // Method 2 over EXTERNAL AUTHENTICATE (no ARC): the standard 8-byte
        // field ARPC(4) || CSU(4) verifies directly (EMV v4.4 Book 2 §8.2.2).
        arqc = beginGenericArqcSession(terminal);
        if (arqc == null) {
            return;
        }
        atc = readAtc(terminal);
        sk = AcCrypto.sessionKey(ICC_KEY, atc);
        byte[] csu = new byte[4]; // no block, no counter update
        byte[] method2 = Bytes.concat(
                AcCrypto.computeArpcMethod2(sk, arqc, csu, new byte[0]), csu);
        Checks.check("EXTERNAL AUTHENTICATE Method 2 (Lc = 8) -> 9000",
                terminal.externalAuthenticate(method2).getSW(), 0x9000);

        // Method 2 with CSU byte 1 b8 = 1 ("Proprietary Authentication Data
        // Included"): the proprietary bytes participate in the ARPC
        // (EMV v4.4 Book 2 §8.2.2).
        arqc = beginGenericArqcSession(terminal);
        if (arqc == null) {
            return;
        }
        atc = readAtc(terminal);
        sk = AcCrypto.sessionKey(ICC_KEY, atc);
        byte[] proprietary = Hex.parse("A1B2C3D4");
        csu = new byte[] { (byte) 0x80, 0x00, 0x00, 0x00 };
        byte[] method2Prop = Bytes.concat(
                AcCrypto.computeArpcMethod2(sk, arqc, csu, proprietary),
                csu, proprietary);
        Checks.check("EXTERNAL AUTHENTICATE Method 2 with proprietary -> 9000",
                terminal.externalAuthenticate(method2Prop).getSW(), 0x9000);

        // Lc == 8 with garbage is neither a valid Method 1 nor Method 2 ARPC.
        arqc = beginGenericArqcSession(terminal);
        if (arqc == null) {
            return;
        }
        Checks.check("EXTERNAL AUTHENTICATE Lc = 8 garbage -> 6300",
                terminal.transmit(new CommandAPDU(0x00, 0x82, 0x00, 0x00,
                        new byte[8])).getSW(), 0x6300);

        // A wrong ARPC fails with 6300 and makes the card decline (AAC).
        arqc = beginGenericArqcSession(terminal);
        if (arqc == null) {
            return;
        }
        atc = readAtc(terminal);
        sk = AcCrypto.sessionKey(ICC_KEY, atc);
        arpc = AcCrypto.computeArpcMethod1(sk, arqc, ARC_APPROVED);
        arpc[0] ^= 0x01;
        issuerAuthData = Bytes.concat(arpc, ARC_APPROVED);
        Checks.check("EXTERNAL AUTHENTICATE wrong ARPC -> 6300",
                terminal.externalAuthenticate(issuerAuthData).getSW(), 0x6300);
        second = terminal.generateAc((byte) 0x40, new byte[6]);
        Checks.check("second AC after failed auth", second.getSW() == 0x9000, second);
        if (second.getSW() == 0x9000) {
            Checks.check("failed auth forces AAC", Responses.parseAc(second).cid == 0x00);
        }
    }

    // --- CARD BLOCK (must be the last test; EMV v4.4 Book 3 §10.10) ---------

    private static void verifyCardBlock(Terminal terminal, byte[] pdol) throws Exception {
        System.out.println("--- post-issuance: CARD BLOCK ---");
        byte[] firstAc = beginArqcSession(terminal, CONTACT_AID, pdol);
        if (firstAc == null) {
            return;
        }
        SmCrypto.ScriptSession session = new SmCrypto.ScriptSession(SM_MAC_KEY, SM_ENC_KEY);
        session.start(firstAc);
        Checks.check("CARD BLOCK",
                terminal.transmit(session.command(0x16, 0x00, 0x00).getBytes()).getSW(),
                0x9000);
        // A repeated CARD BLOCK reports 9000 whether the card was already
        // blocked or not (EMV v4.4 Book 3 §6.5.3.5).
        Checks.check("repeated CARD BLOCK -> 9000",
                terminal.transmit(session.command(0x16, 0x00, 0x00).getBytes()).getSW(),
                0x9000);
        // CARD BLOCK disables every application: all SELECTs answer 6A81.
        Checks.check("SELECT contact after CARD BLOCK -> 6A81",
                terminal.select(CONTACT_AID).getSW(), 0x6A81);
        Checks.check("SELECT PSE after CARD BLOCK -> 6A81",
                terminal.select(PSE_AID).getSW(), 0x6A81);
        Checks.check("SELECT generic after CARD BLOCK -> 6A81",
                terminal.select(GENERIC_AID).getSW(), 0x6A81);
        // The transaction log is no longer readable either (docs/specs/common/toolchain.md §6).
        Checks.check("READ RECORD after CARD BLOCK -> 6A81",
                terminal.readRecord(1, 15).getSW(), 0x6A81);
        Checks.check("GET DATA 9F4F after CARD BLOCK -> 6A81",
                terminal.getData(0x9F, 0x4F).getSW(), 0x6A81);
    }

    // --- helpers ------------------------------------------------------------

    /** A 71/72 template: 9F18 script id followed by one 86 per command. */
    private static byte[] buildScript(int tag, String scriptIdHex, byte[]... commands) {
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        TlvWriter.writeTlv(body, 0x9F18, Hex.parse(scriptIdHex));
        for (byte[] command : commands) {
            TlvWriter.writeTlv(body, 0x86, command);
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        TlvWriter.writeTlv(out, tag, body.toByteArray());
        return out.toByteArray();
    }

    private static byte[] pdolData(Terminal terminal, String aid) throws Exception {
        ResponseAPDU r = terminal.select(aid);
        Checks.check("SELECT " + aid, r.getSW() == 0x9000, r);
        if (r.getSW() != 0x9000) {
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
            Checks.fail("CDOL1 derivation: GPO -> " + Checks.sw(gpo.getSW()));
            return -1;
        }
        ResponseAPDU rec = terminal.readRecord(1, 1);
        if (rec.getSW() != 0x9000) {
            Checks.fail("CDOL1 derivation: READ RECORD 1 -> " + Checks.sw(rec.getSW()));
            return -1;
        }
        byte[] cdol1 = Tags.find(rec.getData(), 0x8C);
        if (cdol1 == null) {
            Checks.fail("CDOL1 derivation: record 1 has no CDOL1 (8C)");
            return -1;
        }
        return TerminalDol.dolDataLength(cdol1);
    }

    private static byte[] beginArqcSession(Terminal terminal, String aid, byte[] pdol)
            throws Exception {
        terminal.select(aid);
        ResponseAPDU gpo = terminal.gpo(pdol);
        if (gpo.getSW() != 0x9000) {
            Checks.fail("session GPO -> " + Checks.sw(gpo.getSW()));
            return null;
        }
        ResponseAPDU first = terminal.generateAc((byte) 0x80, cdol1DataLength);
        if (first.getSW() != 0x9000) {
            Checks.fail("session first AC -> " + Checks.sw(first.getSW()));
            return null;
        }
        return Responses.parseAc(first).ac;
    }

    private static byte[] beginGenericArqcSession(Terminal terminal) throws Exception {
        terminal.select(GENERIC_AID);
        ResponseAPDU gpo = terminal.gpo();
        if (gpo.getSW() != 0x9000) {
            Checks.fail("generic GPO -> " + Checks.sw(gpo.getSW()));
            return null;
        }
        ResponseAPDU first = terminal.generateAc((byte) 0x80, 6);
        if (first.getSW() != 0x9000) {
            Checks.fail("generic first AC -> " + Checks.sw(first.getSW()));
            return null;
        }
        return Responses.parseAc(first).ac;
    }

    private static int readAtc(Terminal terminal) throws Exception {
        return terminal.readAtc();
    }
}
