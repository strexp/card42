package card42.test;

import java.util.Arrays;
import java.util.Random;

import javax.smartcardio.Card;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.ResponseAPDU;

import card42.host.emv.oda.CamVerifier;
import card42.host.emv.oda.SdaVerifier;
import card42.host.emv.lib.IssuerKey;
import card42.host.emv.crypto.AcCrypto;
import card42.host.emv.kernel.ContactKernel;
import card42.host.emv.kernel.core.Authorization;
import card42.host.emv.kernel.core.Issuer;
import card42.host.emv.kernel.core.PinProvider;
import card42.host.emv.kernel.core.TransactionResult;
import card42.host.common.util.Bcd;
import card42.host.emv.kernel.data.TerminalConfig;
import card42.host.emv.kernel.data.TransactionRequest;
import card42.host.emv.lib.Terminal;
import card42.host.common.util.Args;
import card42.host.common.util.Hex;
import card42.host.common.util.Reporter;
import card42.host.common.codec.Responses;
import card42.host.common.codec.Tags;

/**
 * End-to-end smoke test for the card42 applets (docs/specs/common/toolchain.md §6).
 *
 * It runs a minimal EMV terminal flow:
 *
 *   SELECT directory (PPSE, falling back to PSE) -> SELECT payment AID ->
 *   GET PROCESSING OPTIONS -> READ RECORD -> VERIFY -> GENERATE AC
 *
 * The directory is chosen by probing: a default build refuses PPSE on the
 * contact interface (6A82) and the test falls back to the PSE.  Build with
 * TEST_CONTACTLESS=1 to make the PPSE / contactless flow selectable on the
 * simulator.  The VERIFY expectation is derived from the AIP returned by GPO,
 * so the same test covers both the contact and the contactless role.
 *
 * The APDU sequence lives in {@link Terminal}, the SDA / PIN certificate
 * verification in {@link SdaVerifier} and the AC / PIN cryptography in
 * {@link AcCrypto}.  The GPO response is parsed from either format 1 (tag 80)
 * or format 2 (tag 77), as the card returns format 2 for a contactless
 * instance (EMV v4.4 Book 3 §6.5.8).
 *
 * Exits non-zero if any check fails.
 */
public class EmvFlowTest {

    private static final String PSE_AID = "315041592E5359532E4444463031";
    private static final String PPSE_AID = "325041592E5359532E4444463031";

    /** Number of terminal data bytes the personalised CDOL1 asks for. */
    private static int cdol1DataLength = 43;

    public static void main(String[] argv) throws Exception {
        Args args = new Args(argv, new String[] { "host", "icc-key" }, new String[0]);
        String host = args.get("host", "socket:localhost:9025");
        // ICC master key used by perso/emv/sample.perso; needed to recompute the AC
        // (EMV v4.4 Book 2 Annex A1.4).  Option B derivation of the issuer
        // master key 0F0E...0100 for PAN 1234567890, PAN sequence 00.
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
            System.out.println("FAILED: " + Checks.failures() + " check(s)");
            System.exit(1);
        }
        System.out.println("ALL CHECKS PASSED");
    }

    private static void run(Terminal terminal, byte[] iccKey) throws Exception {
        ResponseAPDU r = terminal.select(PPSE_AID);

        String directory;
        String paymentAid;
        if (r.getSW() == 0x9000) {
            directory = "PPSE";
            byte[] aid = Tags.find(r.getData(), 0x4F);
            paymentAid = aid == null ? null : Hex.format(aid);
            System.out.println("PPSE FCI    : " + Hex.format(r.getData()));
            ResponseAPDU rr = terminal.readRecord(1, 1);
            Checks.check("PPSE rejects READ RECORD", rr.getSW() == 0x6A82, rr);
        } else {
            System.out.println("PPSE refused (SW=" + Checks.sw(r.getSW()) + "), using PSE");
            r = terminal.select(PSE_AID);
            Checks.check("SELECT PSE", r.getSW() == 0x9000, r);
            directory = "PSE";
            ResponseAPDU rec = terminal.readRecord(1, 1);
            Checks.check("READ RECORD PSE", rec.getSW() == 0x9000, rec);
            byte[] aid = Tags.find(rec.getData(), 0x4F);
            paymentAid = aid == null ? null : Hex.format(aid);
        }

        System.out.println("Directory   : " + directory);
        System.out.println("Payment AID : " + paymentAid);
        if (paymentAid == null) {
            Checks.check("directory advertises a payment AID", false, r);
            return;
        }

        r = terminal.select(paymentAid);
        Checks.check("SELECT payment", r.getSW() == 0x9000, r);

        // Optional data objects (EMV v4.4 Book 3 Annex A Table 37): the IINE
        // (9F0C) and ASRPD (9F0A) are carried inside the FCI issuer
        // discretionary data (BF0C).
        byte[] fci = r.getData();
        byte[] bf0c = Tags.find(fci, 0xBF0C);
        Checks.check("FCI carries the IINE (9F0C)",
                bf0c != null && Tags.find(bf0c, 0x9F0C) != null, r);
        Checks.check("FCI carries the ASRPD (9F0A)",
                bf0c != null && Tags.find(bf0c, 0x9F0A) != null, r);

        // PDOL from the ADF FCI (EMV v4.4 Book 3 §6.5.8): the GPO command data is
        // built from it.  Without a PDOL the terminal sends '83 00'.
        byte[] pdol = Tags.find(r.getData(), 0x9F38);
        byte[] pdolData = new byte[pdol == null ? 0 : AcCrypto.dolDataLength(pdol)];
        System.out.println("PDOL        : " + (pdol == null ? "(none)" : Hex.format(pdol))
                + " -> " + pdolData.length + " data byte(s)");

        // ATC accounting (EMV v4.4 Book 2 Annex D3): SELECT must
        // not touch the counter; a successful GPO advances it once per session.
        verifyAtcAccounting(terminal, paymentAid, pdolData);

        r = terminal.gpo(pdolData);
        Checks.check("GET PROCESSING OPTIONS", r.getSW() == 0x9000, r);
        byte[] gpo = r.getData();
        byte[] aipBytes = gpoAip(gpo);
        int aip = ((aipBytes[0] & 0xFF) << 8) | (aipBytes[1] & 0xFF);
        byte[] afl = gpoAfl(gpo);
        boolean contact = (aip & 0x1000) != 0; // CVM supported
        System.out.printf("GPO         : %s (AIP=%04X, %s, %s)%n",
                Hex.format(gpo), aip, contact ? "contact" : "contactless",
                (gpo[0] & 0xFF) == 0x77 ? "format 2" : "format 1");

        r = terminal.readRecord(1, 1);
        Checks.check("READ RECORD payment", r.getSW() == 0x9000, r);
        byte[] record1 = r.getData();
        // Derive the CDOL1 data length from the personalised CDOL1 (record 1,
        // tag 8C) instead of hardcoding the sample card's 43 bytes
        // (docs/specs/common/toolchain.md §6).
        byte[] cdol1Definition = Tags.find(record1, 0x8C);
        if (cdol1Definition != null) {
            cdol1DataLength = AcCrypto.dolDataLength(cdol1Definition);
        }

        // Optional record data objects (EMV v4.4 Book 3 Annex A Table 37): the
        // Token Requestor ID (9F19), PAR (9F24) and Last 4 Digits of PAN (9F25).
        Checks.check("record 1 carries the Token Requestor ID (9F19)",
                Tags.find(record1, 0x9F19) != null, r);
        Checks.check("record 1 carries the PAR (9F24)",
                Tags.find(record1, 0x9F24) != null, r);
        Checks.check("record 1 carries the Last 4 Digits of PAN (9F25)",
                Tags.find(record1, 0x9F25) != null, r);

        // READ RECORD state words (EMV v4.4 Book 3 §6.5.11): an SFI outside the
        // advertised AFL is a missing file (6A82), while a record without data
        // in the existing SFI 1 file is a missing record (6A83).
        Checks.check("READ RECORD unauthorized SFI -> 6A82",
                terminal.readRecord(1, 2).getSW(), 0x6A82);
        Checks.check("READ RECORD missing record -> 6A83",
                terminal.readRecord(6, 1).getSW(), 0x6A83);

        // Offline Static Data Authentication (EMV v4.4 Book 2 §5).
        SdaVerifier.Result sdaResult = SdaVerifier.verify(terminal, afl, aip, TestKeys.caKeyStore());
        Checks.check("SDA issuer public key certificate and SSAD"
                + (sdaResult.ok ? "" : " (" + sdaResult.reason + ")"), sdaResult.ok);
        IssuerKey issuer = sdaResult.key;

        // Offline Dynamic Data Authentication (EMV v4.4 Book 2 §6.5) and CDA
        // (EMV v4.4 Book 2 §6.6) share the ICC public key certificate in
        // record 5; the AIP advertises which of the two the card supports.
        IssuerKey iccPublicKey = null;
        if (((aip & 0x2000) != 0 || (aip & 0x0100) != 0) && issuer != null) {
            SdaVerifier.Result icc = SdaVerifier.recoverIccKey(terminal, issuer);
            Checks.check("ICC public key certificate"
                    + (icc.ok ? "" : " (" + icc.reason + ")"), icc.ok);
            iccPublicKey = icc.key;
        }
        if ((aip & 0x2000) != 0) {
            verifyDda(terminal, iccPublicKey);
        }

        // The ATC is needed to recompute the expected cryptogram.  GET DATA does
        // not change it, so reading it before GENERATE AC is safe
        // (EMV v4.4 Book 2 Annex D3).
        int atc = readAtc(terminal);
        System.out.println("ATC         : " + (atc < 0 ? "unavailable" : String.format("%04X", atc)));

        r = terminal.verifyOfflinePin("1234");
        if (contact) {
            Checks.check("VERIFY contact PIN", r.getSW() == 0x9000, r);
        } else {
            Checks.check("VERIFY contactless -> 6985", r.getSW() == 0x6985, r);
        }

        // Enciphered offline PIN (EMV v4.4 Book 2 §7.2).
        verifyEncryptedPin(terminal, contact, issuer);

        // GENERATE AC regression.  The smoke test used to check only the status
        // word, which let two crypto bugs hide:
        //  - setSessionKey() wrote the right half of the session key over the
        //    left half;
        //  - getCDOL1DataLength() returned the CDOL *definition* length instead
        //    of the terminal data length.
        // Recompute the ARQC from the ICC master key and the on-card ATC.
        r = terminal.generateAc((byte) 0x80, cdol1DataLength);
        Checks.check("GENERATE AC", r.getSW() == 0x9000, r);
        checkAc("GENERATE AC cryptogram", r, iccKey, aip, atc,
                new byte[cdol1DataLength]);

        // Online processing and issuer authentication (EMV v4.4 Book 2 §8.2):
        // the first AC returned an ARQC; the terminal goes online, receives the
        // ARPC and completes issuer authentication inline in CDOL2 of the second
        // GENERATE AC (CCD).  The card must then approve the TC request and
        // record the completed online transaction in the Last Online ATC (9F13).
        byte[] arqc = Responses.parseAc(r).ac;
        verifyOnlineFlow(terminal, paymentAid, pdolData, record1, iccKey, aip, arqc, atc);

        // A wrong ARPC must fail issuer authentication and make the card decline
        // the transaction (AAC) even though the terminal requested a TC
        // (EMV v4.4 Book 2 §8.2).
        verifyWrongArpc(terminal, paymentAid, pdolData, record1, iccKey, aip);

        // CCD Card Status Update handling (EMV v4.4 Book 3 Annex C §C9.3,
        // docs/specs/common/toolchain.md §6).
        verifyCsuDeclines(terminal, paymentAid, pdolData, record1, iccKey, aip);
        verifyCsuUpdatePtc(terminal, paymentAid, pdolData, record1, iccKey, aip);
        verifyWrongArpcCsuNotApplied(terminal, paymentAid, pdolData, record1, iccKey);
        verifyCsuGoOnline(terminal, paymentAid, pdolData, record1, iccKey);

        // AIP byte 1 bit 3 (EXTERNAL AUTHENTICATE support) is consistent with
        // the personalised AIPs (docs/specs/common/toolchain.md §6).
        verifyAipExternalAuth(terminal, paymentAid);

        // The CCD profile does not advertise EXTERNAL AUTHENTICATE, so INS=82 is
        // refused with 6985 (EMV v4.4 Book 2 §8.2).
        verifyExternalAuthenticateRefused(terminal, paymentAid, pdolData);

        // Card Action Analysis (EMV v4.4 Book 3 §10.8): the personalised IACs let
        // a TVR bit force an AAC or an ARQC even when the terminal asks for TC.
        verifyRiskManagement(terminal, paymentAid, pdolData, iccKey, aip);

        // Combined DDA/Application Cryptogram Generation (EMV v4.4 Book 2 §6.6)
        // needs a fresh session (one first AC per session).
        if ((aip & 0x0100) != 0) {
            verifyCda(terminal, paymentAid, pdolData, iccPublicKey, iccKey);
        }

        // At most two GENERATE AC per transaction; the third returns 6985
        // (EMV v4.4 Book 3 section 9.3.2).
        verifyThirdAcRejected(terminal, paymentAid, pdolData, record1, iccKey, aip);

        // Cumulative offline amount upper limit (docs/specs/common/toolchain.md §6).
        verifyAmountUpperLimit(terminal, paymentAid, pdolData, record1, iccKey, aip);

        // A second AC approved offline (the terminal could not go online, ARC
        // 'Y3') must be added to the offline accumulators
        // (EMV v4.4 Book 3 CCD §9.2.3.2).
        verifyOfflineApprovedSecondAcCounts(terminal, paymentAid, pdolData, record1,
                iccKey, aip);

        // An all-zero inline Issuer Authentication Data (no issuer response) at
        // an unable-to-go-online second AC must not be treated as a failed
        // issuer authentication
        // (EMV v4.4 Book 3 §10.11.1.1 / CCD Annex C §C10).
        verifyOfflineApprovedZeroIssuerAuth(terminal, paymentAid, pdolData, record1,
                iccKey, aip);

        // CVR byte 2 b1 "Last Online Transaction Not Completed" (EMV v4.4 Book 3 §9.2.3.2).
        verifyLastOnlineNotCompleted(terminal, paymentAid, pdolData, record1, iccKey);

        // A first AC that is an AAC may not be upgraded by the second AC
        // (EMV v4.4 Book 3 §9.3).
        verifyFirstAacCapsSecondAc(terminal, paymentAid, pdolData, record1, iccKey);

        // The contact kernel drives the same card through the same flow; run one
        // offline transaction and compare the AC with the independent recomputation
        // (docs/specs/emv/contact-kernel.md).
        verifyContactKernel(terminal, iccKey);
    }

    /**
     * Runs one offline transaction through the {@link ContactKernel} (contact
     * application selection, offline PIN CVM) and checks that the kernel agrees
     * with the hand-written flow above.
     */
    private static void verifyContactKernel(Terminal terminal, byte[] iccKey)
            throws Exception {
        // A zero amount keeps the card's offline amount accumulator unchanged, so
        // this kernel re-run does not disturb the suites that follow.
        TransactionRequest data = new TransactionRequest(TerminalConfig.forContact()
                .floorLimit(Long.MAX_VALUE) // offline
                .cvmRequiredLimit(0)
                .build());
        data.amountAuthorised = Bcd.longToBcd(0, 6);

        PinProvider pin = new PinProvider() {
            @Override
            public String pin() {
                return "1234";
            }
        };
        Issuer issuer = new Issuer() {
            @Override
            public Authorization authorize(byte[] arqc, int atc, TransactionResult result) {
                try {
                    byte[] sk = AcCrypto.sessionKey(iccKey, atc);
                    byte[] arpc = AcCrypto.computeArpcMethod2(sk, arqc, CSU_APPROVE, new byte[0]);
                    byte[] auth = new byte[8];
                    System.arraycopy(arpc, 0, auth, 0, 4);
                    System.arraycopy(CSU_APPROVE, 0, auth, 4, 4);
                    return new Authorization(ARC_APPROVED, auth);
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }
        };

        // The contact instance AIP, read directly: the main flow above may have
        // selected the contactless instance (a TEST_CONTACTLESS build makes the
        // PPSE selectable on the contact interface), so its AIP is not the
        // contact instance's.  Comparing with the direct GPO keeps the check
        // portable across the personalized ODA profile (0x7900 on the simulator,
        // 0x5800 on an SDA-only card such as the J3R180).
        ResponseAPDU sel = terminal.select("43415244420101");
        ResponseAPDU gpo = terminal.gpo(new byte[AcCrypto.dolDataLength(
                Tags.find(sel.getData(), 0x9F38))]);
        byte[] aipBytes = gpo.getSW() == 0x9000 ? gpoAip(gpo.getData()) : null;
        int contactAip = aipBytes == null ? -1
                : (((aipBytes[0] & 0xFF) << 8) | (aipBytes[1] & 0xFF));

        ContactKernel kernel = new ContactKernel(Reporter.to(System.out),
                TestKeys.caKeyStore(), new Random(29), pin);
        TransactionResult r = kernel.run(terminal, data, issuer);

        Checks.check("contact kernel selects the contact AID",
                "43415244420101".equals(r.aidHex()));
        Checks.check("contact kernel AIP matches the card ("
                        + (contactAip < 0 ? "?" : String.format("%04X", contactAip)) + ")",
                r.aip() == contactAip);
        Checks.check("contact kernel offline PIN CVM Results",
                Arrays.equals(r.cvmResults(), Hex.parse("010002")));
        Checks.check("contact kernel offline first AC is a TC",
                r.firstCid() == (byte) 0x40);
        byte[] expected = AcCrypto.expectedAc(iccKey, r.aip(), r.firstAc().atc,
                r.cdol1Data(), r.firstAc().iad);
        Checks.bytes(expected, r.firstAc().ac, "contact kernel first AC cryptogram");
    }

    /**
     * ATC accounting (EMV v4.4 Book 2 Annex D3): SELECT must not
     * change the counter and a successful GET PROCESSING OPTIONS must advance
     * it exactly once per session.
     */
    private static void verifyAtcAccounting(Terminal terminal, String paymentAid,
                                            byte[] pdolData) throws Exception {
        terminal.select(paymentAid);
        int before = readAtc(terminal);
        terminal.select(paymentAid);
        int afterSelect = readAtc(terminal);
        Checks.check("ATC unchanged by SELECT", afterSelect == before);

        terminal.gpo(pdolData);
        int afterGpo = readAtc(terminal);
        Checks.check("ATC advanced once by GPO", afterGpo == ((before + 1) & 0xFFFF));

        // A second GPO in the same session must not advance it again: the ATC
        // is incremented once per transaction/card session
        // (EMV v4.4 Book 2 Annex D3, Application Transaction Counter Considerations).
        terminal.gpo(pdolData);
        int afterSecondGpo = readAtc(terminal);
        Checks.check("ATC advanced once per session", afterSecondGpo == afterGpo);
    }

    /** Reads the ATC with GET DATA 9F36; a malformed/missing response fails. */
    private static int readAtc(Terminal terminal) throws Exception {
        return terminal.readAtc();
    }

    // --- online processing / issuer authentication (EMV v4.4 Book 2 §8.2) ----

    /** An "online approved" ARC and the matching CSU (Issuer Approves Online). */
    private static final byte[] ARC_APPROVED = { 0x00, 0x00 };
    private static final byte[] CSU_APPROVE = { 0x00, (byte) 0x80, 0x00, 0x00 };

    /**
     * Builds a CDOL2 data field from record 1 with the ARC (tag 8A) and the
     * Issuer Authentication Data (tag 91 = ARPC(4) || CSU(4)) filled in.
     */
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

    /** Reads the Last Online ATC Register (9F13), or -1. */
    private static int readLastOnlineAtc(Terminal terminal) throws Exception {
        byte[] value = Tags.find(terminal.getData(0x9F, 0x13).getData(), 0x9F13);
        if (value == null || value.length != 2) {
            return -1;
        }
        return ((value[0] & 0xFF) << 8) | (value[1] & 0xFF);
    }

    /**
     * Completes the online flow started by the first AC (an ARQC): computes the
     * ARPC (Method 2), sends the second GENERATE AC with the Issuer
     * Authentication Data inline in CDOL2, checks the returned TC and that 9F13
     * records the online ATC (EMV v4.4 Book 2 §8.2).
     */
    private static void verifyOnlineFlow(Terminal terminal, String paymentAid,
                                         byte[] pdolData, byte[] record1,
                                         byte[] iccKey, int aip, byte[] arqc,
                                         int atc) throws Exception {
        byte[] sk = AcCrypto.sessionKey(iccKey, atc);
        byte[] cdol2 = cdol2Data(record1, arqc, sk, ARC_APPROVED, CSU_APPROVE);

        ResponseAPDU r = terminal.generateAc((byte) 0x40, cdol2); // request TC
        Checks.check("online second AC", r.getSW() == 0x9000, r);
        if (r.getSW() != 0x9000) {
            return;
        }
        Responses.AcResponse ac = Responses.parseAc(r);
        Checks.check("online second AC returns TC", ac.cid == (byte) 0x40);
        if (atc >= 0 && ac.ac != null) {
            byte[] expected = AcCrypto.expectedAc(iccKey, aip, atc, cdol2, ac.iad);
            Checks.check("online second AC cryptogram", Arrays.equals(ac.ac, expected));
        }

        int last = readLastOnlineAtc(terminal);
        Checks.check("9F13 records the completed online ATC",
                atc >= 0 && last == atc);
    }

    /**
     * A wrong ARPC must fail issuer authentication and make the card decline
     * (AAC) although the terminal requested a TC (EMV v4.4 Book 3 §10.11.1.2).
     */
    private static void verifyWrongArpc(Terminal terminal, String paymentAid,
                                        byte[] pdolData, byte[] record1,
                                        byte[] iccKey, int aip) throws Exception {
        terminal.select(paymentAid);
        ResponseAPDU gpo = terminal.gpo(pdolData);
        if (gpo.getSW() != 0x9000) {
            Checks.fail("wrong ARPC: GPO -> " + Checks.sw(gpo.getSW()));
            return;
        }
        ResponseAPDU first = terminal.generateAc((byte) 0x80, cdol1DataLength);
        if (first.getSW() != 0x9000) {
            Checks.fail("wrong ARPC: first AC -> " + Checks.sw(first.getSW()));
            return;
        }
        byte[] arqc = Responses.parseAc(first).ac;
        int atc = readAtc(terminal);
        byte[] sk = AcCrypto.sessionKey(iccKey, atc);
        byte[] cdol2 = cdol2Data(record1, arqc, sk, ARC_APPROVED, CSU_APPROVE);

        byte[] definition = Tags.find(record1, 0x8D);
        int authOff = AcCrypto.dolValueOffset(definition, 0x91);
        cdol2[authOff] ^= 0x01; // corrupt the ARPC

        ResponseAPDU r = terminal.generateAc((byte) 0x40, cdol2); // request TC
        Checks.check("wrong ARPC second AC", r.getSW() == 0x9000, r);
        if (r.getSW() == 0x9000) {
            Checks.check("wrong ARPC forces AAC", Responses.parseAc(r).cid == 0x00);
        }
    }

    /**
     * The cryptogram types are hierarchical (TC &gt; ARQC &gt; AAC) and the second
     * GENERATE AC may only return a TC or an AAC; a first AC that the card
     * returned as an AAC (the terminal requested AAC) must therefore cap the
     * second AC at AAC even when the terminal asks for a TC
     * (EMV v4.4 Book 3 §9.3).
     */
    private static void verifyFirstAacCapsSecondAc(Terminal terminal, String paymentAid,
            byte[] pdolData, byte[] record1, byte[] iccKey) throws Exception {
        terminal.select(paymentAid);
        ResponseAPDU gpo = terminal.gpo(pdolData);
        if (gpo.getSW() != 0x9000) {
            Checks.fail("first AAC: GPO -> " + Checks.sw(gpo.getSW()));
            return;
        }
        ResponseAPDU first = terminal.generateAc((byte) 0x00, cdol1DataLength); // request AAC
        Checks.check("first AC request AAC", first.getSW() == 0x9000, first);
        if (first.getSW() != 0x9000) {
            return;
        }
        Checks.check("first AC is AAC", Responses.parseAc(first).cid == 0x00);
        int atc = readAtc(terminal);
        byte[] sk = AcCrypto.sessionKey(iccKey, atc);
        byte[] cdol2 = cdol2Data(record1, new byte[0], sk, ARC_APPROVED, CSU_APPROVE);
        ResponseAPDU second = terminal.generateAc((byte) 0x40, cdol2); // request TC
        Checks.check("first-AAC second AC", second.getSW() == 0x9000, second);
        if (second.getSW() == 0x9000) {
            Checks.check("first AAC caps the second AC at AAC",
                    Responses.parseAc(second).cid == 0x00);
        }
    }

    /** Starts a fresh session and returns the first AC (an ARQC), or null. */
    private static byte[] freshArqc(Terminal terminal, String aid, byte[] pdolData)
            throws Exception {
        terminal.select(aid);
        ResponseAPDU gpo = terminal.gpo(pdolData);
        if (gpo.getSW() != 0x9000) {
            Checks.fail("fresh ARQC: GPO -> " + Checks.sw(gpo.getSW()));
            return null;
        }
        ResponseAPDU first = terminal.generateAc((byte) 0x80, cdol1DataLength);
        if (first.getSW() != 0x9000) {
            Checks.fail("fresh ARQC: first AC -> " + Checks.sw(first.getSW()));
            return null;
        }
        return Responses.parseAc(first).ac;
    }

    /**
     * CCD CSU byte 2 b8 "Issuer Approves Online Transaction" not set: even a
     * correct ARPC must make the second AC decline (AAC) although the terminal
     * requested a TC (EMV v4.4 Book 3 §10.11.1.1 / Annex C §C10).
     */
    private static void verifyCsuDeclines(Terminal terminal, String paymentAid,
                                          byte[] pdolData, byte[] record1,
                                          byte[] iccKey, int aip) throws Exception {
        byte[] arqc = freshArqc(terminal, paymentAid, pdolData);
        if (arqc == null) {
            return;
        }
        int atc = readAtc(terminal);
        byte[] sk = AcCrypto.sessionKey(iccKey, atc);
        byte[] csu = { 0x00, 0x00, 0x00, 0x00 }; // no Issuer Approves bit
        byte[] cdol2 = cdol2Data(record1, arqc, sk, ARC_APPROVED, csu);
        ResponseAPDU r = terminal.generateAc((byte) 0x40, cdol2); // request TC
        Checks.check("CSU declines second AC", r.getSW() == 0x9000, r);
        if (r.getSW() == 0x9000) {
            Checks.check("CSU without Issuer Approves forces AAC",
                    Responses.parseAc(r).cid == 0x00);
        }
    }

    /**
     * CCD CSU byte 2 b5 "Update PIN Try Counter" with a non-zero value: a PIN
     * that was locked (9F17=0) is unblocked by a successful online transaction
     * (EMV v4.4 Book 3 Annex C §C10).
     */
    private static void verifyCsuUpdatePtc(Terminal terminal, String paymentAid,
                                           byte[] pdolData, byte[] record1,
                                           byte[] iccKey, int aip) throws Exception {
        if ((aip & 0x1000) == 0) {
            // A contactless instance has no offline PIN to update.
            System.out.println("  (contactless: CSU PIN Try Counter update skipped)");
            return;
        }
        // Lock the offline PIN first.
        terminal.select(paymentAid);
        Checks.check("CSU PTC: wrong PIN #1",
                terminal.verifyOfflinePin("0000").getSW(), 0x63C2);
        Checks.check("CSU PTC: wrong PIN #2",
                terminal.verifyOfflinePin("0000").getSW(), 0x63C1);
        Checks.check("CSU PTC: wrong PIN #3",
                terminal.verifyOfflinePin("0000").getSW(), 0x63C0);
        Checks.check("CSU PTC: PIN blocked",
                terminal.verifyOfflinePin("1234").getSW(), 0x6983);

        byte[] arqc = freshArqc(terminal, paymentAid, pdolData);
        if (arqc == null) {
            return;
        }
        int atc = readAtc(terminal);
        byte[] sk = AcCrypto.sessionKey(iccKey, atc);
        // CSU byte 1 = 0x03 (PTC value 3), byte 2 = 0x90 (Update PTC + Approve).
        byte[] csu = { 0x03, (byte) 0x90, 0x00, 0x00 };
        byte[] cdol2 = cdol2Data(record1, arqc, sk, ARC_APPROVED, csu);
        ResponseAPDU r = terminal.generateAc((byte) 0x40, cdol2); // request TC
        Checks.check("CSU PTC second AC", r.getSW() == 0x9000, r);
        if (r.getSW() == 0x9000) {
            Checks.check("CSU PTC approves the TC", Responses.parseAc(r).cid == 0x40);
        }
        byte[] ptc = Tags.find(terminal.getData(0x9F, 0x17).getData(), 0x9F17);
        Checks.check("CSU PTC restores 9F17", ptc != null && ptc[0] == 3);
        Checks.check("correct PIN accepted after CSU PTC update",
                terminal.verifyOfflinePin("1234").getSW(), 0x9000);
    }

    /**
     * A wrong ARPC must not apply the CSU: a CSU carrying the Card Block bit is
     * ignored and the application stays selectable (docs/specs/common/toolchain.md §6).
     */
    private static void verifyWrongArpcCsuNotApplied(Terminal terminal, String paymentAid,
                                                     byte[] pdolData, byte[] record1,
                                                     byte[] iccKey) throws Exception {
        byte[] arqc = freshArqc(terminal, paymentAid, pdolData);
        if (arqc == null) {
            return;
        }
        int atc = readAtc(terminal);
        byte[] sk = AcCrypto.sessionKey(iccKey, atc);
        byte[] csu = { 0x00, (byte) 0x40, 0x00, 0x00 }; // Card Block bit
        byte[] cdol2 = cdol2Data(record1, arqc, sk, ARC_APPROVED, csu);
        byte[] definition = Tags.find(record1, 0x8D);
        int authOff = AcCrypto.dolValueOffset(definition, 0x91);
        cdol2[authOff] ^= 0x01; // corrupt the ARPC
        ResponseAPDU r = terminal.generateAc((byte) 0x40, cdol2);
        Checks.check("wrong ARPC with CSU Card Block", r.getSW() == 0x9000, r);
        if (r.getSW() == 0x9000) {
            Checks.check("wrong ARPC forces AAC", Responses.parseAc(r).cid == 0x00);
        }
        Checks.check("CSU not applied after a wrong ARPC: SELECT still 9000",
                terminal.select(paymentAid).getSW(), 0x9000);
    }

    /**
     * CCD CSU byte 2 b4 "Set Go Online on Next Transaction": the next first AC
     * is forced online (ARQC); a later successful issuer authentication clears
     * the flag (EMV v4.4 Book 3 Annex C §C10).
     */
    private static void verifyCsuGoOnline(Terminal terminal, String paymentAid,
                                          byte[] pdolData, byte[] record1,
                                          byte[] iccKey) throws Exception {
        byte[] arqc = freshArqc(terminal, paymentAid, pdolData);
        if (arqc == null) {
            return;
        }
        int atc = readAtc(terminal);
        byte[] sk = AcCrypto.sessionKey(iccKey, atc);
        byte[] csu = { 0x00, (byte) 0x88, 0x00, 0x00 }; // Approve + Go Online
        ResponseAPDU r = terminal.generateAc((byte) 0x40,
                cdol2Data(record1, arqc, sk, ARC_APPROVED, csu));
        Checks.check("CSU go-online second AC", r.getSW() == 0x9000, r);
        if (r.getSW() == 0x9000) {
            Checks.check("CSU go-online approves the TC", Responses.parseAc(r).cid == 0x40);
        }

        // The next transaction must be forced online even for a TC request
        // (EMV v4.4 Book 3 §10.8).
        terminal.select(paymentAid);
        terminal.gpo(pdolData);
        ResponseAPDU next = terminal.generateAc((byte) 0x40, cdol1DataLength);
        Checks.check("CSU go-online forces the next first AC (ARQC)",
                next.getSW() == 0x9000 && Responses.parseAc(next).cid == (byte) 0x80, next);

        // Complete that transaction online; the successful issuer
        // authentication clears the go-online flag.
        byte[] arqc2 = Responses.parseAc(next).ac;
        int atc2 = readAtc(terminal);
        byte[] sk2 = AcCrypto.sessionKey(iccKey, atc2);
        byte[] csu2 = { 0x00, (byte) 0x80, 0x00, 0x00 }; // Approve only
        ResponseAPDU r2 = terminal.generateAc((byte) 0x40,
                cdol2Data(record1, arqc2, sk2, ARC_APPROVED, csu2));
        Checks.check("go-online clearing second AC", r2.getSW() == 0x9000, r2);

        terminal.select(paymentAid);
        terminal.gpo(pdolData);
        ResponseAPDU after = terminal.generateAc((byte) 0x40, cdol1DataLength);
        Checks.check("go-online flag cleared after issuer authentication",
                after.getSW() == 0x9000 && Responses.parseAc(after).cid == 0x40, after);
    }

    /**
     * AIP byte 1 bit 3 selects the issuer authentication method: the CCD
     * contact instance (0x79) does not advertise EXTERNAL AUTHENTICATE, while
     * the generic instance 06 (0x5C) does (docs/specs/common/toolchain.md §6).
     */
    private static void verifyAipExternalAuth(Terminal terminal, String paymentAid)
            throws Exception {
        ResponseAPDU sel = terminal.select(paymentAid);
        Checks.check("AIP: SELECT contact", sel.getSW() == 0x9000, sel);
        ResponseAPDU gpo = terminal.gpo(new byte[AcCrypto.dolDataLength(
                Tags.find(sel.getData(), 0x9F38))]);
        byte[] aipBytes = gpo.getSW() == 0x9000 ? gpoAip(gpo.getData()) : null;
        boolean contactB3 = aipBytes != null && (aipBytes[0] & 0x04) != 0;
        Checks.check("contact AIP does not advertise EXTERNAL AUTHENTICATE",
                !contactB3);

        // The generic test instance 06 advertises EXTERNAL AUTHENTICATE (AIP
        // 0x5C).  A card personalized without the test set (for example an
        // SDA-only J3R180) still has the instance created but with the default
        // role AIP (0x7900/0x6900): report a skip instead of failing on the
        // fixture.
        ResponseAPDU g = terminal.select("43415244420106");
        if (g.getSW() != 0x9000) {
            System.out.println("generic instance 06 not selectable (SW="
                    + Checks.sw(g.getSW()) + "): EXTERNAL AUTHENTICATE check skipped");
            return;
        }
        ResponseAPDU gpo2 = terminal.gpo();
        if (gpo2.getSW() != 0x9000) {
            // An instance created but not personalized stays in the
            // PERSONALISATION lifecycle and refuses GPO with 6985.
            System.out.println("generic instance 06 not personalized (GPO SW="
                    + Checks.sw(gpo2.getSW()) + "): EXTERNAL AUTHENTICATE check skipped");
            return;
        }
        byte[] aip2 = gpoAip(gpo2.getData());
        int genericAip = ((aip2[0] & 0xFF) << 8) | (aip2[1] & 0xFF);
        Checks.check("generic AIP advertises EXTERNAL AUTHENTICATE",
                (genericAip & 0x0400) != 0);
    }

    /** The CCD profile refuses EXTERNAL AUTHENTICATE with 6985 (EMV v4.4 Book 2 §8.2). */
    private static void verifyExternalAuthenticateRefused(Terminal terminal,
                                                          String paymentAid,
                                                          byte[] pdolData)
            throws Exception {
        terminal.select(paymentAid);
        terminal.gpo(pdolData);
        ResponseAPDU r = terminal.externalAuthenticate(new byte[10]);
        Checks.check("CCD EXTERNAL AUTHENTICATE -> 6985", r.getSW(), 0x6985);
    }

    /** The AIP of a format 1 or format 2 GPO response. */
    private static byte[] gpoAip(byte[] gpo) {
        return Responses.gpoAip(gpo);
    }

    /** The AFL of a format 1 or format 2 GPO response. */
    private static byte[] gpoAfl(byte[] gpo) {
        return Responses.gpoAfl(gpo);
    }

    /**
     * Terminal-side DDA (EMV v4.4 Book 2 §6.5): GET CHALLENGE, build the DDOL
     * data (the default DDOL is the 4-byte terminal Unpredictable Number),
     * send INTERNAL AUTHENTICATE and verify the returned SDAD.
     */
    private static void verifyDda(Terminal terminal, IssuerKey iccPublicKey)
            throws Exception {
        ResponseAPDU challenge = terminal.getChallenge();
        Checks.check("GET CHALLENGE", challenge.getSW() == 0x9000, challenge);
        if (challenge.getSW() != 0x9000) {
            return;
        }
        if (challenge.getData().length < 4) {
            Checks.fail("GET CHALLENGE returned " + challenge.getData().length
                    + " byte(s), need 4");
            return;
        }
        byte[] ddol = new byte[4];
        System.arraycopy(challenge.getData(), 0, ddol, 0, 4);

        ResponseAPDU r = terminal.internalAuthenticate(ddol);
        Checks.check("INTERNAL AUTHENTICATE", r.getSW() == 0x9000, r);
        if (r.getSW() != 0x9000) {
            return;
        }
        byte[] sdad = Tags.find(r.getData(), 0x9F4B);
        if (sdad == null) {
            // A generic (non-CCD) profile returns the primitive '80' SDAD.
            sdad = Tags.find(r.getData(), 0x80);
        }
        Checks.check("DDA SDAD present", sdad != null);
        if (sdad != null) {
            CamVerifier.Result dda = CamVerifier.verifyDda(sdad, ddol, iccPublicKey);
            Checks.check("DDA signed dynamic application data"
                    + (dda.ok ? "" : " (" + dda.reason + ")"), dda.ok);
        }
    }

    /**
     * Terminal-side CDA (EMV v4.4 Book 2 §6.6): a fresh session, GENERATE AC
     * with the CDA bit set and a CDOL1 data field carrying a terminal
     * Unpredictable Number, then verify the format 2 response
     * (9F27/9F36/9F4B/9F10).
     */
    private static void verifyCda(Terminal terminal, String paymentAid,
                                  byte[] pdolData,
                                  IssuerKey iccPublicKey,
                                  byte[] iccMasterKey) throws Exception {
        // A fresh SELECT resets the first/second AC session state.
        ResponseAPDU sel = terminal.select(paymentAid);
        Checks.check("CDA SELECT payment", sel.getSW() == 0x9000, sel);
        ResponseAPDU gpo = terminal.gpo(pdolData);
        Checks.check("CDA GPO", gpo.getSW() == 0x9000, gpo);
        if (gpo.getSW() != 0x9000) {
            return;
        }
        byte[] aipBytes = gpoAip(gpo.getData());
        int aip = ((aipBytes[0] & 0xFF) << 8) | (aipBytes[1] & 0xFF);

        ResponseAPDU rec1 = terminal.readRecord(1, 1);
        Checks.check("CDA READ RECORD 1", rec1.getSW() == 0x9000, rec1);
        if (rec1.getSW() != 0x9000) {
            return;
        }
        byte[] cdol1 = Tags.find(rec1.getData(), 0x8C);
        if (cdol1 == null) {
            Checks.check("CDA CDOL1 present", false);
            return;
        }
        int cdolLength = AcCrypto.dolDataLength(cdol1);
        int unOffset = AcCrypto.dolValueOffset(cdol1, 0x9F37);
        if (unOffset < 0) {
            Checks.check("CDA CDOL1 contains 9F37", false);
            return;
        }
        byte[] cdol1Data = new byte[cdolLength];
        byte[] un = new byte[] { 0x11, 0x22, 0x33, 0x44 };
        System.arraycopy(un, 0, cdol1Data, unOffset, 4);

        int atc = readAtc(terminal);

        ResponseAPDU r = terminal.generateAc((byte) 0x90, cdol1Data); // ARQC + CDA
        Checks.check("GENERATE AC CDA", r.getSW() == 0x9000, r);
        if (r.getSW() != 0x9000 || atc < 0) {
            return;
        }
        System.out.println("  info CDA response: " + Hex.format(r.getData()));
        Responses.AcResponse ac = Responses.parseAc(r);
        byte[] expected = AcCrypto.expectedAc(iccMasterKey, aip, atc, cdol1Data, ac.iad);
        Checks.check("first AC CVR sets CDA Performed",
                ac.iad != null && ac.iad.length > 3 && (ac.iad[3] & 0x08) != 0);
        CamVerifier.Result cda1 = CamVerifier.verifyCda(r.getData(), cdol1Data, null, pdolData,
                un, iccPublicKey, expected, 0x80);
        Checks.check("CDA signed dynamic application data"
                + (cda1.ok ? "" : " (" + cda1.reason + ")"), cda1.ok);
        if (!cda1.ok) {
            return;
        }
        byte[] firstAc = cda1.value;

        // Second GENERATE AC with CDA (TC): the Transaction Data Hash Code now
        // also covers the second AC's CDOL2 data (EMV v4.4 Book 2 section 6.6.1).  The
        // CCD profile carries the Issuer Authentication Data inline, so a valid
        // ARPC (Method 2) is built from the first AC.
        byte[] cdol2Definition = Tags.find(rec1.getData(), 0x8D);
        if (cdol2Definition == null) {
            Checks.fail("CDA: record 1 has no CDOL2 (8D)");
            return;
        }
        int un2Offset = AcCrypto.dolValueOffset(cdol2Definition, 0x9F37);
        if (un2Offset < 0) {
            Checks.fail("CDA: CDOL2 does not contain 9F37");
            return;
        }
        byte[] sk = AcCrypto.sessionKey(iccMasterKey, atc);
        byte[] cdol2Data = cdol2Data(rec1.getData(), firstAc, sk,
                ARC_APPROVED, CSU_APPROVE);
        byte[] un2 = new byte[] { 0x55, 0x66, 0x77, (byte) 0x88 };
        System.arraycopy(un2, 0, cdol2Data, un2Offset, 4);

        ResponseAPDU r2 = terminal.generateAc((byte) 0x50, cdol2Data); // TC + CDA
        Checks.check("GENERATE AC CDA (2nd)", r2.getSW() == 0x9000, r2);
        if (r2.getSW() != 0x9000) {
            return;
        }
        Responses.AcResponse ac2 = Responses.parseAc(r2);
        byte[] expected2 = AcCrypto.expectedAc(iccMasterKey, aip, atc, cdol2Data, ac2.iad);
        Checks.check("second AC CVR inherits CDA Performed",
                ac2.iad != null && ac2.iad.length > 3 && (ac2.iad[3] & 0x08) != 0);
        CamVerifier.Result cda2 = CamVerifier.verifyCda(r2.getData(), cdol1Data, cdol2Data,
                pdolData, un2, iccPublicKey, expected2, 0x40);
        Checks.check("second CDA signed dynamic application data"
                + (cda2.ok ? "" : " (" + cda2.reason + ")"), cda2.ok);
    }

    /**
     * Card Action Analysis (EMV v4.4 Book 3 §10.8): a personalised IAC-Denial
     * (bit 8 of byte 1) turns that TVR bit into an AAC, and any other TVR bit
     * falls through to the default IAC-Online (all bits set) and yields an
     * ARQC.  Both are requested as a TC, so the card must downgrade.
     */
    private static void verifyRiskManagement(Terminal terminal, String paymentAid,
                                             byte[] pdolData, byte[] iccMasterKey,
                                             int aip) throws Exception {
        // TVR bit 0x80 (byte 1) is also in IAC-Denial -> AAC.
        checkForcedDecision(terminal, paymentAid, pdolData, iccMasterKey, aip,
                (byte) 0x80, 0x00, "TVR forces AAC");
        // TVR bit 0x40 (byte 1) is not in IAC-Denial -> IAC-Online -> ARQC.
        checkForcedDecision(terminal, paymentAid, pdolData, iccMasterKey, aip,
                (byte) 0x40, 0x80, "TVR forces ARQC");
    }

    private static void checkForcedDecision(Terminal terminal, String paymentAid,
                                            byte[] pdolData, byte[] iccMasterKey,
                                            int aip, byte tvrByte, int expectedCid,
                                            String label) throws Exception {
        terminal.select(paymentAid);
        ResponseAPDU gpo = terminal.gpo(pdolData);
        Checks.check(label + ": GPO", gpo.getSW() == 0x9000, gpo);
        if (gpo.getSW() != 0x9000) {
            return;
        }
        ResponseAPDU rec1 = terminal.readRecord(1, 1);
        if (rec1.getSW() != 0x9000) {
            Checks.fail(label + ": READ RECORD 1 -> " + Checks.sw(rec1.getSW()));
            return;
        }
        byte[] cdol1 = Tags.find(rec1.getData(), 0x8C);
        if (cdol1 == null) {
            Checks.fail(label + ": record 1 has no CDOL1 (8C)");
            return;
        }
        int cdolLength = AcCrypto.dolDataLength(cdol1);
        int tvrOffset = AcCrypto.dolValueOffset(cdol1, 0x95);
        if (tvrOffset < 0) {
            Checks.check(label + ": CDOL1 contains 95", false);
            return;
        }
        byte[] cdol1Data = new byte[cdolLength];
        cdol1Data[tvrOffset] = tvrByte;

        int atc = readAtc(terminal);
        ResponseAPDU r = terminal.generateAc((byte) 0x40, cdol1Data); // request TC
        Checks.check(label, r.getSW() == 0x9000, r);
        if (r.getSW() != 0x9000) {
            return;
        }
        Responses.AcResponse ac = Responses.parseAc(r);
        Checks.check(label + ": CID", ac.cid == (byte) expectedCid);
        if (atc < 0 || ac.ac == null) {
            Checks.fail(label + ": cannot recompute the cryptogram");
            return;
        }
        byte[] expected = AcCrypto.expectedAc(iccMasterKey, aip, atc, cdol1Data, ac.iad);
        Checks.check(label + ": cryptogram",
                Arrays.equals(ac.ac, expected));
    }

    /** The third GENERATE AC of a transaction returns 6985 (EMV v4.4 Book 3 §9.3.2). */
    private static void verifyThirdAcRejected(Terminal terminal, String paymentAid,
                                              byte[] pdolData, byte[] record1,
                                              byte[] iccKey, int aip) throws Exception {
        terminal.select(paymentAid);
        terminal.gpo(pdolData);
        ResponseAPDU first = terminal.generateAc((byte) 0x80, cdol1DataLength);
        if (first.getSW() != 0x9000) {
            Checks.fail("third AC: first AC -> " + Checks.sw(first.getSW()));
            return;
        }
        byte[] arqc = Responses.parseAc(first).ac;
        int atc = readAtc(terminal);
        byte[] sk = AcCrypto.sessionKey(iccKey, atc);
        byte[] cdol2 = cdol2Data(record1, arqc, sk, ARC_APPROVED, CSU_APPROVE);
        terminal.generateAc((byte) 0x40, cdol2);
        ResponseAPDU third = terminal.generateAc((byte) 0x40, cdol2);
        Checks.check("third GENERATE AC -> 6985", third.getSW(), 0x6985);
        Checks.check("third GENERATE AC has an empty body",
                third.getData().length == 0, third);
    }

    /** An ARC that tells the card the terminal could not go online. */
    private static final byte[] ARC_UNABLE = { 0x59, 0x33 };

    /**
     * Cumulative offline amount upper limit (docs/specs/common/toolchain.md §6): instance
     * 01 is personalized with LCOTA=0 (disabled) and UCOTA=1000.  A CSU sets the
     * counters to the upper limits; the next first AC is then forced online and
     * a terminal that could not go online (ARC Y3) gets an AAC.  A final CSU
     * resets the counters so the later suites are unaffected.
     */
    private static void verifyAmountUpperLimit(Terminal terminal, String paymentAid,
                                               byte[] pdolData, byte[] record1,
                                               byte[] iccKey, int aip) throws Exception {
        if ((aip & 0x1000) == 0) {
            System.out.println("  (contactless: amount upper limit skipped)");
            return;
        }
        // Set the offline counters to the upper offline limits (CSU 0x01).
        byte[] arqc = freshArqc(terminal, paymentAid, pdolData);
        if (arqc == null) {
            return;
        }
        byte[] csu = { 0x00, (byte) 0x81, 0x00, 0x00 }; // Approve + Set to Upper
        ResponseAPDU r = terminal.generateAc((byte) 0x40, cdol2Data(record1, arqc,
                AcCrypto.sessionKey(iccKey, readAtc(terminal)), ARC_APPROVED, csu));
        Checks.check("CSU set-to-upper second AC", r.getSW() == 0x9000, r);

        // UCOTA is reached: the next first AC is forced online.
        terminal.select(paymentAid);
        terminal.gpo(pdolData);
        ResponseAPDU first = terminal.generateAc((byte) 0x40, cdol1DataLength);
        Checks.check("UCOTA reached forces the next first AC (ARQC)",
                first.getSW() == 0x9000 && Responses.parseAc(first).cid == (byte) 0x80, first);
        byte[] upperIad = Responses.parseAc(first).iad;
        Checks.check("UCOTA reached sets CVR byte 3 upper-amount bit",
                upperIad != null && upperIad.length > 5 && (upperIad[5] & 0x10) != 0, first);

        // The terminal cannot go online (ARC Y3): the second AC declines.
        byte[] arqc2 = Responses.parseAc(first).ac;
        byte[] cdol2 = cdol2Data(record1, arqc2,
                AcCrypto.sessionKey(iccKey, readAtc(terminal)), ARC_UNABLE,
                new byte[] { 0x00, (byte) 0x80, 0x00, 0x00 });
        ResponseAPDU second = terminal.generateAc((byte) 0x40, cdol2);
        Checks.check("UCOTA exceeded + ARC Y3 -> AAC",
                second.getSW() == 0x9000 && Responses.parseAc(second).cid == 0x00, second);

        // Reset the counters (CSU 0x02) so the rest of the run is unaffected.
        byte[] arqc3 = freshArqc(terminal, paymentAid, pdolData);
        if (arqc3 == null) {
            return;
        }
        byte[] csu3 = { 0x00, (byte) 0x82, 0x00, 0x00 }; // Approve + Reset
        ResponseAPDU reset = terminal.generateAc((byte) 0x40, cdol2Data(record1, arqc3,
                AcCrypto.sessionKey(iccKey, readAtc(terminal)), ARC_APPROVED, csu3));
        Checks.check("CSU reset clears the amount counters",
                reset.getSW() == 0x9000 && Responses.parseAc(reset).cid == 0x40, reset);
    }

    /**
     * A second GENERATE AC approved offline (the terminal could not go online,
     * ARC 'Y3', and the Default pair approves the TC) must be added to the
     * offline accumulators like any other offline-approved transaction
     * (EMV v4.4 Book 3 CCD §9.2.3.2): the next first AC then reports the upper
     * cumulative-amount limit.  Instance 01 personalises UCOTA=1000, so a single
     * offline-approved amount of 1100 exceeds it.
     */
    private static void verifyOfflineApprovedSecondAcCounts(Terminal terminal,
            String paymentAid, byte[] pdolData, byte[] record1, byte[] iccKey, int aip)
            throws Exception {
        if ((aip & 0x1000) == 0) {
            System.out.println("  (contactless: offline-approved second AC skipped)");
            return;
        }
        // Start from clean counters and a clear 'Last Online Not Completed' bit.
        resetOfflineCounters(terminal, paymentAid, pdolData, record1, iccKey);

        // T1: an ARQC whose second AC the Default pair approves offline (ARC Y3)
        // for an amount above UCOTA.
        byte[] cdol1 = new byte[cdol1DataLength];
        int amountOff = AcCrypto.dolValueOffset(Tags.find(record1, 0x8C), 0x9F02);
        if (amountOff >= 0) {
            System.arraycopy(Bcd.longToBcd(1100, 6), 0, cdol1, amountOff, 6);
        }
        terminal.select(paymentAid);
        terminal.gpo(pdolData);
        ResponseAPDU first = terminal.generateAc((byte) 0x80, cdol1);
        Checks.check("offline-approved second AC: first AC is ARQC",
                first.getSW() == 0x9000
                        && Responses.parseAc(first).cid == (byte) 0x80, first);
        if (first.getSW() != 0x9000) {
            return;
        }
        byte[] arqc = Responses.parseAc(first).ac;
        byte[] sk = AcCrypto.sessionKey(iccKey, readAtc(terminal));
        ResponseAPDU second = terminal.generateAc((byte) 0x40,
                cdol2Data(record1, arqc, sk, ARC_UNABLE, CSU_APPROVE));
        Checks.check("offline-approved second AC: second AC is TC",
                second.getSW() == 0x9000
                        && Responses.parseAc(second).cid == (byte) 0x40, second);

        // T2: the offline-approved amount is in the accumulator, so the next
        // first AC reports the upper cumulative-amount bit.
        terminal.select(paymentAid);
        terminal.gpo(pdolData);
        ResponseAPDU next = terminal.generateAc((byte) 0x40, new byte[cdol1DataLength]);
        Checks.check("offline-approved second AC counts toward UCOTA",
                next.getSW() == 0x9000 && (cvrByte3(next) & 0x10) != 0, next);

        // Leave the accumulators reset for the later suites.
        resetOfflineCounters(terminal, paymentAid, pdolData, record1, iccKey);
    }

    /**
     * C18: when the terminal could not go online (ARC 'Y3') and no issuer
     * response arrived, the all-zero inline Issuer Authentication Data (tag
     * '91') must not be treated as a failed issuer authentication.  The card
     * skips it, approves the requested TC and reports CVR1 "Issuer
     * Authentication Not Performed" together with CVR4 "Unable to go Online"
     * (EMV v4.4 Book 3 §10.11.1.2 / Annex C §C9.3).  Before the fix the
     * zero ARPC failed the inline check and forced an AAC.
     */
    private static void verifyOfflineApprovedZeroIssuerAuth(Terminal terminal,
            String paymentAid, byte[] pdolData, byte[] record1, byte[] iccKey, int aip)
            throws Exception {
        if ((aip & 0x1000) == 0) {
            System.out.println("  (contactless: zero-issuer-auth offline approval skipped)");
            return;
        }
        // A TVR floor-limit bit (not in IAC-Denial, matched by IAC-Online)
        // makes the card answer the requested ARQC.
        byte[] cdol1 = new byte[cdol1DataLength];
        int tvrOff = AcCrypto.dolValueOffset(Tags.find(record1, 0x8C), 0x95);
        if (tvrOff >= 0) {
            cdol1[tvrOff + 3] = (byte) 0x80;
        }
        terminal.select(paymentAid);
        terminal.gpo(pdolData);
        ResponseAPDU first = terminal.generateAc((byte) 0x80, cdol1);
        Checks.check("zero issuer auth: first AC is ARQC",
                first.getSW() == 0x9000
                        && Responses.parseAc(first).cid == (byte) 0x80, first);
        if (first.getSW() != 0x9000) {
            return;
        }

        // CDOL2 with tag '8A' = 'Y3' and tag '91' left all zero.
        byte[] cdol2 = Tags.find(record1, 0x8D);
        byte[] data = new byte[AcCrypto.dolDataLength(cdol2)];
        int arcOff = AcCrypto.dolValueOffset(cdol2, 0x8A);
        System.arraycopy(ARC_UNABLE, 0, data, arcOff, 2);
        ResponseAPDU second = terminal.generateAc((byte) 0x40, data); // request TC
        Checks.check("zero issuer auth + ARC Y3 -> TC",
                second.getSW() == 0x9000
                        && Responses.parseAc(second).cid == (byte) 0x40, second);
        if (second.getSW() != 0x9000) {
            return;
        }
        byte[] iad = Responses.parseAc(second).iad;
        Checks.check("zero issuer auth: CVR1 has no issuer-auth failure",
                iad != null && iad.length > 3 && (iad[3] & 0x01) == 0);
        Checks.check("zero issuer auth: CVR1 reports issuer auth not performed",
                iad != null && iad.length > 3 && (iad[3] & 0x02) != 0);
        Checks.check("zero issuer auth: CVR4 reports unable to go online",
                iad != null && iad.length > 7 && (iad[6] & 0x01) != 0);

        // Clear the 'Last Online Not Completed' bit and the counters.
        resetOfflineCounters(terminal, paymentAid, pdolData, record1, iccKey);
    }

    /** A completed online transaction whose CSU resets the offline accumulators. */
    private static void resetOfflineCounters(Terminal terminal, String paymentAid,
            byte[] pdolData, byte[] record1, byte[] iccKey) throws Exception {
        byte[] arqc = freshArqc(terminal, paymentAid, pdolData);
        if (arqc == null) {
            return;
        }
        byte[] sk = AcCrypto.sessionKey(iccKey, readAtc(terminal));
        terminal.generateAc((byte) 0x40, cdol2Data(record1, arqc, sk, ARC_APPROVED,
                new byte[] { 0x00, (byte) 0x82, 0x00, 0x00 }));
    }

    /** The CVR byte 3 of a GENERATE AC response, or -1 when the IAD is absent. */
    private static int cvrByte3(ResponseAPDU r) {
        Responses.AcResponse ac = Responses.parseAc(r);
        return ac.iad != null && ac.iad.length >= 6 ? (ac.iad[5] & 0xFF) : -1;
    }

    /**
     * CVR byte 2 b1 "Last Online Transaction Not Completed" (EMV v4.4 Book 3 §9.2.3.2):
     * a first AC that requests online and is never followed by a second AC sets
     * the bit in the next transaction's first AC, and that bit forces the next
     * transaction online; a completed online transaction clears it.
     */
    private static void verifyLastOnlineNotCompleted(Terminal terminal, String paymentAid,
                                                     byte[] pdolData, byte[] record1,
                                                     byte[] iccKey) throws Exception {
        // T1: request online (ARQC) and abandon the transaction (no second AC).
        terminal.select(paymentAid);
        terminal.gpo(pdolData);
        ResponseAPDU abandoned = terminal.generateAc((byte) 0x80, cdol1DataLength);
        Checks.check("last-online: abandoned first AC is ARQC",
                abandoned.getSW() == 0x9000
                        && Responses.parseAc(abandoned).cid == (byte) 0x80, abandoned);

        // T2: the not-completed bit forces the next transaction online even
        // though the terminal requests TC, and the first AC reports the bit.
        terminal.select(paymentAid);
        terminal.gpo(pdolData);
        ResponseAPDU forced = terminal.generateAc((byte) 0x40, cdol1DataLength);
        Checks.check("last-online: next first AC sets the not-completed bit",
                forced.getSW() == 0x9000 && (cvrByte2(forced) & 0x01) != 0, forced);
        Checks.check("last-online: bit forces the next transaction online",
                forced.getSW() == 0x9000
                        && Responses.parseAc(forced).cid == (byte) 0x80, forced);

        // Complete T2 online; a successful online transaction clears the bit.
        byte[] arqc = Responses.parseAc(forced).ac;
        int atc = readAtc(terminal);
        byte[] sk = AcCrypto.sessionKey(iccKey, atc);
        ResponseAPDU second = terminal.generateAc((byte) 0x40,
                cdol2Data(record1, arqc, sk, ARC_APPROVED, CSU_APPROVE));
        Checks.check("last-online: online completion", second.getSW() == 0x9000, second);

        // T3: the bit is cleared, so the terminal request is followed again.
        terminal.select(paymentAid);
        terminal.gpo(pdolData);
        ResponseAPDU cleared = terminal.generateAc((byte) 0x40, cdol1DataLength);
        Checks.check("last-online: completed transaction clears the bit",
                cleared.getSW() == 0x9000 && (cvrByte2(cleared) & 0x01) == 0, cleared);
        Checks.check("last-online: cleared bit stops forcing online",
                cleared.getSW() == 0x9000
                        && Responses.parseAc(cleared).cid == (byte) 0x40, cleared);
    }

    /** The CVR byte 2 of a GENERATE AC response, or -1 when the IAD is absent. */
    private static int cvrByte2(ResponseAPDU r) {
        Responses.AcResponse ac = Responses.parseAc(r);
        return ac.iad != null && ac.iad.length >= 5 ? (ac.iad[4] & 0xFF) : -1;
    }

    /** Compares the AC in a GENERATE AC response with the recomputed one. */
    private static void checkAc(String label, ResponseAPDU r, byte[] iccKey,
                                int aip, int atc, byte[] cdolData) throws Exception {
        if (r.getSW() != 0x9000) {
            return; // the caller already recorded the status word
        }
        if (atc < 0 || r.getData().length < 13) {
            Checks.fail(label + ": no usable response for the AC recomputation");
            return;
        }
        Responses.AcResponse ac = Responses.parseAc(r);
        byte[] expected = AcCrypto.expectedAc(iccKey, aip, atc, cdolData, ac.iad);
        System.out.println("  AC         : " + Hex.format(ac.ac)
                + " (expected " + Hex.format(expected) + ")");
        Checks.check(label, Arrays.equals(ac.ac, expected), r);
    }

    /**
     * Terminal-side enciphered offline PIN (EMV v4.4 Book 2 §7.2).  It recovers
     * the ICC PIN encipherment public key from the certificate in record 4,
     * obtains the ICC Unpredictable Number with GET CHALLENGE, builds the
     * Table 25 block (7F || PIN block || ICC UN || random padding) and sends it
     * in VERIFY P2=88.  A contactless instance must refuse it with 6985.
     */
    private static void verifyEncryptedPin(Terminal terminal, boolean contact,
                                           IssuerKey issuer) throws Exception {
        byte[] malformed = new byte[128]; // RSA-1024 sized, but no valid block

        if (!contact) {
            Checks.check("VERIFY P2=88 contactless -> 6985",
                    terminal.verifyEncryptedPin(malformed).getSW(), 0x6985);
            return;
        }
        if (issuer == null) {
            Checks.fail("encrypted PIN: issuer public key unavailable");
            return;
        }
        SdaVerifier.Result pinResult = SdaVerifier.recoverPinKey(terminal, issuer);
        Checks.check("ICC PIN public key certificate"
                + (pinResult.ok ? "" : " (" + pinResult.reason + ")"), pinResult.ok);
        IssuerKey pinKey = pinResult.key;
        if (pinKey == null) {
            return;
        }

        // Correct PIN: Table 25 block for the ISO 9564-1 format 2 block "1234".
        Checks.check("VERIFY enciphered PIN",
                terminal.verifyEncryptedPin(encipher("1234", pinKey, terminal)).getSW(), 0x9000);
        Checks.check("enciphered PIN success resets 9F17", readPtc(terminal) == 3);

        // A block that does not recover to a valid header must be refused
        // (EMV v4.4 Book 2 §7.2 step 7/8).
        Checks.check("VERIFY enciphered PIN malformed -> 6984",
                terminal.verifyEncryptedPin(malformed).getSW(), 0x6984);

        // A well-formed block with the wrong PIN decrements the try counter.
        Checks.check("VERIFY enciphered wrong PIN -> 63C2",
                terminal.verifyEncryptedPin(encipher("9999", pinKey, terminal)).getSW(), 0x63C2);
        Checks.check("enciphered wrong PIN decrements 9F17", readPtc(terminal) == 2);
        Checks.check("VERIFY enciphered PIN after retry",
                terminal.verifyEncryptedPin(encipher("1234", pinKey, terminal)).getSW(), 0x9000);
        Checks.check("enciphered PIN retry resets 9F17", readPtc(terminal) == 3);
    }

    /**
     * Enciphers a PIN with the EMV v4.4 Book 2 Table 25 structure, using the ICC
     * Unpredictable Number from a fresh GET CHALLENGE (EMV v4.4 Book 2 §7.2 step 2).
     */
    static byte[] encipher(String pin, IssuerKey key, Terminal terminal)
            throws Exception {
        byte[] iccUn = getChallenge(terminal);
        return AcCrypto.emvEncipherPin(AcCrypto.iso9564Format2(pin), iccUn,
                key.modulus, key.exponent);
    }

    /** GET CHALLENGE, returning the 8-byte ICC Unpredictable Number. */
    static byte[] getChallenge(Terminal terminal) throws Exception {
        ResponseAPDU r = terminal.getChallenge();
        Checks.check("GET CHALLENGE (enciphered PIN)", r.getSW() == 0x9000, r);
        if (r.getSW() != 0x9000 || r.getData().length != 8) {
            throw new IllegalStateException("GET CHALLENGE did not return 8 bytes");
        }
        return r.getData();
    }

    /** Reads the PIN Try Counter (9F17), or -1. */
    private static int readPtc(Terminal terminal) throws Exception {
        byte[] ptc = Tags.find(terminal.getData(0x9F, 0x17).getData(), 0x9F17);
        return ptc != null && ptc.length == 1 ? (ptc[0] & 0xFF) : -1;
    }
}
