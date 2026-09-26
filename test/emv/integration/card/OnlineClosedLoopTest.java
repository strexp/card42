package card42.test;

import javax.smartcardio.Card;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.ResponseAPDU;

import card42.host.emv.crypto.SmCrypto;
import card42.host.emv.crypto.AcCrypto;
import card42.host.emv.app.issuer.IssuerHost;
import card42.host.emv.kernel.script.IssuerScriptProcessor;
import card42.host.emv.lib.Terminal;
import card42.host.common.util.Args;
import card42.host.common.util.Hex;
import card42.host.common.codec.Responses;
import card42.host.common.codec.Tags;
import card42.host.emv.kernel.data.TerminalDol;

/**
 * Online closed-loop test: a full CCD transaction driven end to end by an
 * {@link IssuerHost} and an {@link IssuerScriptProcessor} (EMV v4.4 Book 2 §8.2,
 * EMV v4.4 Book 3 Annex C §C10, EMV v4.4 Book 4 §6.3.9/Annex A5).
 *
 * <p>The flow: first GENERATE AC (ARQC) -> the issuer host computes ARPC
 * Method 2 and a CSU and delivers them inline in CDOL2 of the second GENERATE
 * AC -> the card approves with a TC and records 9F13 -> the issuer host builds
 * a 72 issuer script and the terminal processes it, reporting 9F5B and the TVR
 * script bits.  A second, deliberately corrupted script checks the failure path.
 *
 * <p>Exits non-zero if any check fails.
 */
public class OnlineClosedLoopTest {

    private static final String CONTACT_AID = "43415244420101";
    private static final byte[] ICC_KEY =
            Hex.parse("343864C2E085AB3E433D2F982945E61F");
    private static final byte[] SM_MAC_KEY =
            Hex.parse("911C3404804CCEBF458AA1191C152A3E");
    private static final byte[] SM_ENC_KEY =
            Hex.parse("BA915D4F3185B9EA620234D5FDAEBA9D");

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
            System.out.println("FAILED: " + Checks.failures() + " online closed-loop check(s)");
            System.exit(1);
        }
        System.out.println("ALL ONLINE CLOSED-LOOP CHECKS PASSED");
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

        // --- first AC: the card returns an ARQC ---
        terminal.select(CONTACT_AID);
        ResponseAPDU gpo = terminal.gpo(pdol);
        Checks.check("GPO", gpo.getSW() == 0x9000, gpo);
        ResponseAPDU first = terminal.generateAc((byte) 0x80, cdol1DataLength);
        Checks.check("first AC is ARQC", first.getSW() == 0x9000
                && Responses.parseCid(first) == (byte) 0x80, first);
        if (first.getSW() != 0x9000) {
            return;
        }
        Responses.AcResponse ac1 = Responses.parseAc(first);
        int atc = terminal.readAtc();

        // --- the issuer host answers: ARPC Method 2 + CSU inline in CDOL2 ---
        IssuerHost issuer = new IssuerHost(ICC_KEY);
        issuer.setFirstAc(ac1.ac, atc);
        byte[] auth = issuer.inlineIssuerAuthData(IssuerHost.CSU_APPROVE, 0);

        ResponseAPDU second = sendSecondAc(terminal, auth);
        Checks.check("second AC approves with a TC", second.getSW() == 0x9000
                && Responses.parseCid(second) == (byte) 0x40, second);
        byte[] lastOnline = Tags.find(
                terminal.getData(0x9F, 0x13).getData(), 0x9F13);
        Checks.check("9F13 == ATC after issuer authentication",
                lastOnline != null && lastOnline.length == 2
                        && (((lastOnline[0] & 0xFF) << 8) | (lastOnline[1] & 0xFF)) == atc);

        // --- issuer script after the final AC: a PIN CHANGE/UNBLOCK ---
        SmCrypto.ScriptSession session =
                new SmCrypto.ScriptSession(SM_MAC_KEY, SM_ENC_KEY);
        session.start(ac1.ac);
        byte[] okScript = IssuerHost.script(0x72, "AABBCCDD",
                session.command(0x24, 0x00, 0x00).getBytes());
        IssuerScriptProcessor.Result ok =
                IssuerScriptProcessor.process(terminal, true, okScript);
        Checks.check("issuer script command sent", ok.commandsSent == 1);
        Checks.check("issuer script succeeded", !ok.anyFailed);
        Checks.bytes(Hex.parse("20AABBCCDD"), ok.results, "9F5B successful result");

        // --- a corrupted script: the failure path and the TVR bit ---
        byte[] bad = session.command(0x24, 0x00, 0x00).getBytes();
        bad[bad.length - 1] ^= 0x01; // break the MAC
        byte[] failScript = IssuerHost.script(0x72, "11223344", bad);
        IssuerScriptProcessor.Result fail =
                IssuerScriptProcessor.process(terminal, true, failScript);
        Checks.check("failing script reported", fail.anyFailed && fail.failedAfterFinalAc);
        Checks.check("9F5B failed at command 1",
                (fail.results[0] & 0xF0) == 0x10 && (fail.results[0] & 0x0F) == 0x01);
        Checks.bytes(Hex.parse("11223344"),
                java.util.Arrays.copyOfRange(fail.results, 1, 5),
                "9F5B failing script identifier");
        byte[] tvr = new byte[5];
        IssuerScriptProcessor.applyToTvr(fail, tvr);
        Checks.check("TVR byte 5 script-failed-after-final-AC bit",
                (tvr[4] & 0x10) != 0);
    }

    /** Sends the second GENERATE AC with the Issuer Authentication Data in CDOL2. */
    private static ResponseAPDU sendSecondAc(Terminal terminal, byte[] issuerAuthData)
            throws Exception {
        ResponseAPDU rec1 = terminal.readRecord(1, 1);
        byte[] cdol2Def = Tags.find(rec1.getData(), 0x8D);
        if (cdol2Def == null) {
            Checks.fail("second AC: record 1 has no CDOL2 (8D)");
            return new ResponseAPDU(new byte[] { 0x6F, 0x00 });
        }
        byte[] cdol2 = new byte[TerminalDol.dolDataLength(cdol2Def)];
        int off = AcCrypto.dolValueOffset(cdol2Def, 0x91);
        if (off < 0) {
            Checks.fail("second AC: CDOL2 has no inline issuer auth data (91)");
            return new ResponseAPDU(new byte[] { 0x6F, 0x00 });
        }
        System.arraycopy(issuerAuthData, 0, cdol2, off, issuerAuthData.length);
        return terminal.generateAc((byte) 0x40, cdol2);
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

    private static int deriveCdol1Length(Terminal terminal, String aid, byte[] pdol)
            throws Exception {
        ResponseAPDU gpo = terminal.gpo(pdol);
        if (gpo.getSW() != 0x9000) {
            Checks.fail("CDOL1 derivation: GPO -> " + Checks.sw(gpo.getSW()));
            return -1;
        }
        ResponseAPDU rec = terminal.readRecord(1, 1);
        byte[] cdol1 = Tags.find(rec.getData(), 0x8C);
        if (cdol1 == null) {
            Checks.fail("CDOL1 derivation: record 1 has no CDOL1 (8C)");
            return -1;
        }
        return TerminalDol.dolDataLength(cdol1);
    }
}
