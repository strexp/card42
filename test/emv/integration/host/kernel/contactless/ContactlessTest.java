package card42.test;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Random;

import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import card42.host.emv.crypto.SmCrypto;
import card42.host.emv.crypto.AcCrypto;
import card42.host.emv.app.issuer.IssuerHost;
import card42.host.emv.kernel.ContactlessKernel;
import card42.host.emv.kernel.core.Authorization;
import card42.host.emv.kernel.core.Issuer;
import card42.host.emv.kernel.core.KernelListener;
import card42.host.emv.kernel.core.TransactionResult;
import card42.host.emv.kernel.entry.EntryPoint;
import card42.host.emv.lib.Terminal;
import card42.host.common.util.Args;
import card42.host.common.util.Hex;
import card42.host.common.util.Reporter;
import card42.host.common.util.Bcd;
import card42.host.emv.kernel.data.TerminalConfig;
import card42.host.emv.kernel.data.TransactionRequest;
import card42.host.common.codec.TlvWriter;
import card42.host.emv.kernel.data.Tsi;
import card42.host.emv.kernel.data.Tvr;

/**
 * End-to-end contactless kernel test (docs/specs/emv/contactless.md,
 * docs/specs/common/toolchain.md §6).
 *
 * <p>It runs the {@link ContactlessKernel} over the contactless payment instance
 * (AID 43415244420102) through the PPSE:
 *
 * <pre>
 *   Entry Point -&gt; SELECT -&gt; GPO (TTQ) -&gt; READ RECORD -&gt; RSA ODA
 *     -&gt; restrictions -&gt; CVM -&gt; TRM -&gt; TAA -&gt; GENERATE AC
 *     -&gt; online -&gt; second GENERATE AC
 * </pre>
 *
 * <p>Three transactions are exercised: an online CDA transaction (ARQC then TC),
 * an offline CDA transaction (TC), and a transaction the terminal declines
 * through TAC-Denial (AAC).  The AC cryptograms are independently recomputed
 * from the ICC master key.
 *
 * <p>The PPSE is only selectable on the contact interface in a
 * {@code TEST_CONTACTLESS=1} build; a default build refuses it with 6A82 and
 * the test reports the skip without failing (matching {@link DirectoryTest}).
 */
public class ContactlessTest {

    private static final String PPSE_AID = "325041592E5359532E4444463031";
    private static final String CONTACTLESS_AID = "43415244420102";
    private static final byte[] ICC_KEY = Hex.parse("343864C2E085AB3E433D2F982945E61F");
    private static final byte[] SM_MAC_KEY = Hex.parse("911C3404804CCEBF458AA1191C152A3E");
    private static final byte[] SM_ENC_KEY = Hex.parse("BA915D4F3185B9EA620234D5FDAEBA9D");

    /** CSU: Issuer Approves Online Transaction (EMV v4.4 Book 3 Annex C §C10). */
    private static final byte[] CSU_APPROVE = { 0x00, (byte) 0x80, 0x00, 0x00 };

    public static void main(String[] argv) throws Exception {
        Args args = new Args(argv, new String[] { "host" }, new String[0]);
        String host = args.get("host", "socket:localhost:9025");
        CardTerminal terminal = TestTerminals.getTerminal(host.split(":"));
        if (terminal == null || !terminal.waitForCardPresent(10000)) {
            throw new IllegalStateException("Connection to simulator failed on " + host);
        }

        Card card = terminal.connect("*");
        try {
            run(new Terminal(card.getBasicChannel()), card.getBasicChannel());
        } finally {
            card.disconnect(true);
        }

        if (Checks.failures() > 0) {
            System.out.println("FAILED: " + Checks.failures() + " contactless check(s)");
            System.exit(1);
        }
        System.out.println("ALL CONTACTLESS CHECKS PASSED");
    }

    static void run(Terminal terminal, CardChannel channel) throws Exception {
        // Pure selection logic: exercises the kernel's own Entry Point
        // combination selection with multiple Directory Entries.
        entryPointCombinationSelection();

        ResponseAPDU ppse = terminal.select(PPSE_AID);
        if (ppse.getSW() != 0x9000) {
            Checks.check("PPSE refused on the contact interface", ppse.getSW(), 0x6A82);
            System.out.println("ContactlessTest skipped: build with TEST_CONTACTLESS=1");
            return;
        }
        onlineCdaTransaction(terminal);
        offlineCdaTransaction(terminal);
        terminalDeclinesAac(terminal);
        issuerDeclinesOnline(terminal);
        unableToGoOnlineTransaction(terminal);
        unableToGoOnlineApproved(terminal);
        cdaFailureDeclines(channel);
        issuerScriptTransaction(terminal);
        issuerScriptBeforeFinalAcFailure(terminal);
    }

    // --- Entry Point Combination Selection (EMV Contactless Book B v2.12 §3.3.2/§3.3.3.2) --------

    /**
     * Exercises the kernel's own combination selection with several Directory
     * Entries: ADF Name matching, 9F2A decoding (type bits, malformed length),
     * priority ordering and the earliest-entry tie-break.  It drives
     * {@code EntryPoint.selectCandidate} directly instead of
     * re-implementing the selection in the test.
     */
    private static void entryPointCombinationSelection() {
        System.out.println("--- contactless: Entry Point combination selection ---");
        String aidA = "43415244420102";
        String aidB = "43415244420103";
        String[] supported = { aidA, aidB };

        // The lowest priority value wins (1 is the highest priority).
        byte[] fci = ppseFci(dirEntry(aidA, 0x03, null), dirEntry(aidB, 0x01, null));
        Checks.check("Entry Point selects the highest-priority Combination",
                aidB.equals(EntryPoint.selectCandidate(fci, supported)));

        // Equal priorities: EMV Contactless Book B v2.12 §3.3.3.2 orders the
        // tied Combinations by their position in the PPSE (lowest order = the
        // first entry), so the earliest Directory Entry must be selected.
        byte[] tie = ppseFci(dirEntry(aidA, 0x02, null), dirEntry(aidB, 0x02, null));
        Checks.check("Entry Point tie-break keeps the earliest Directory Entry",
                aidA.equals(EntryPoint.selectCandidate(tie, supported)));

        // An unsupported requested kernel is skipped.
        byte[] unsupported = ppseFci(dirEntry(aidA, 0x01, new byte[] { 0x40 }));
        Checks.check("Entry Point skips an unsupported requested kernel",
                EntryPoint.selectCandidate(unsupported, supported) == null);

        // A two-byte 9F2A whose first byte is 00b is still a Requested Kernel ID
        // of 0 (byte 1), which is always supported (EMV Contactless Book B v2.12
        // §3.3.2.5 bullet C, applied regardless of the value-field length).
        byte[] twoByte = ppseFci(dirEntry(aidA, 0x01, new byte[] { 0x00, 0x01 }));
        Checks.check("Entry Point accepts a two-byte 9F2A via byte 1",
                aidA.equals(EntryPoint.selectCandidate(twoByte, supported)));

        // The Requested Kernel ID preserves the type bits (EMV Contactless Book B v2.12 §3.3.2 C).
        int typed = EntryPoint.requestedKernelId(
                dirEntry(aidA, 0x01, new byte[] { 0x40 }), aidA);
        Checks.check("9F2A b8b7=01b keeps the type bit (got 0x"
                + Integer.toHexString(typed) + ")", typed == 0x40);
        Checks.check("9F2A 00 01 (b8b7=00b) takes byte 1 as the Requested Kernel ID",
                EntryPoint.requestedKernelId(
                        dirEntry(aidA, 0x01, new byte[] { 0x00, 0x01 }), aidA) == 0);

        // A multi-byte 9F2A whose first byte is '00' is a Requested Kernel ID of
        // 0 (b8b7=00b, Short Kernel ID 000000b), not the brand default; only a
        // single-byte '00' selects the Table 3-6 default (EMV Contactless Book B
        // v2.12 §3.3.2.5 bullet C).
        String visa = "A0000000031010";
        Checks.check("multi-byte 9F2A 00 01 02 is Requested Kernel ID 0",
                EntryPoint.requestedKernelId(
                        dirEntry(visa, 0x01, new byte[] { 0x00, 0x01, 0x02 }), visa) == 0);
        Checks.check("single-byte 9F2A 00 uses the brand default",
                EntryPoint.requestedKernelId(
                        dirEntry(visa, 0x01, new byte[] { 0x00 }), visa) == 3);

        // Native kernel identifier decoding (EMV Contactless Book B v2.12 Table 3-5):
        // b8b7 = 10b/11b takes the full three-byte Extended Kernel ID; fewer
        // than three bytes is malformed and skipped.
        Checks.check("9F2A 80 01 02 (b8b7=10b) decodes to 0x800102",
                EntryPoint.requestedKernelId(
                        dirEntry(aidA, 0x01, new byte[] { (byte) 0x80, 0x01, 0x02 }),
                        aidA) == 0x800102);
        Checks.check("9F2A 80 (b8b7=10b, one byte) is rejected",
                EntryPoint.requestedKernelId(
                        dirEntry(aidA, 0x01, new byte[] { (byte) 0x80 }), aidA) == -1);

        // An ADF Name is RID (5 bytes) + PIX (0-11 bytes), so 5-16 bytes; an
        // over-long one is not a valid Combination and is skipped even though it
        // begins with a supported AID (EMV Contactless Book B v2.12 §3.3.2.5 bullet A).
        String overlongAdf = aidA + "0102030405060708090A0B0C"; // 18 bytes
        byte[] overlong = ppseFci(dirEntry(overlongAdf, 0x01, null),
                dirEntry(aidB, 0x02, null));
        Checks.check("Entry Point skips an over-long ADF Name",
                aidB.equals(EntryPoint.selectCandidate(overlong, supported)));

        // selectCandidates exposes the supported entries in priority order, the
        // order the kernel walks to retry after a refused SELECT
        // (EMV Contactless Book B v2.12 §3.3.3.5).
        java.util.List<EntryPoint.Candidate> ordered = EntryPoint.selectCandidates(
                ppseFci(dirEntry(aidA, 0x03, null), dirEntry(aidB, 0x01, null)), supported);
        Checks.check("selectCandidates orders the candidates by priority",
                ordered.size() == 2 && aidB.equals(ordered.get(0).adfHex)
                        && aidA.equals(ordered.get(1).adfHex));
    }

    /** A PPSE FCI wrapping the given 61 Directory Entry values. */
    private static byte[] ppseFci(byte[]... entries) {
        ByteArrayOutputStream bf0c = new ByteArrayOutputStream();
        for (byte[] entry : entries) {
            TlvWriter.writeTlv(bf0c, 0x61, entry);
        }
        ByteArrayOutputStream a5 = new ByteArrayOutputStream();
        TlvWriter.writeTlv(a5, 0xBF0C, bf0c.toByteArray());
        ByteArrayOutputStream fci = new ByteArrayOutputStream();
        TlvWriter.writeTlv(fci, 0xA5, a5.toByteArray());
        return fci.toByteArray();
    }

    /** One 61 Directory Entry with an ADF Name, priority and optional 9F2A. */
    private static byte[] dirEntry(String aidHex, int priority, byte[] kernelId) {
        ByteArrayOutputStream entry = new ByteArrayOutputStream();
        TlvWriter.writeTlv(entry, 0x4F, Hex.parse(aidHex));
        TlvWriter.writeTlv(entry, 0x87, new byte[] { (byte) priority });
        if (kernelId != null) {
            TlvWriter.writeTlv(entry, 0x9F2A, kernelId);
        }
        return entry.toByteArray();
    }

    /** A TAC byte array with byte 3 b8 set (the floor-limit bit). */
    private static byte[] tacOnline() {
        byte[] tac = new byte[5];
        tac[3] = (byte) 0x80;
        return tac;
    }

    /**
     * A contactless transaction request with EUR 5.00, the given floor limit and
     * CVM required limit, optional TAC overrides and the merchant-forced-online
     * flag.
     */
    private static TransactionRequest request(long floorLimit, long cvmRequiredLimit,
            byte[] tacOnline, byte[] tacDenial, byte[] tacDefault, boolean merchantForcedOnline) {
        TerminalConfig.Builder builder = TerminalConfig.builder()
                .floorLimit(floorLimit)
                .cvmRequiredLimit(cvmRequiredLimit);
        if (tacOnline != null) {
            builder.tacOnline(tacOnline);
        }
        if (tacDenial != null) {
            builder.tacDenial(tacDenial);
        }
        if (tacDefault != null) {
            builder.tacDefault(tacDefault);
        }
        TransactionRequest request = new TransactionRequest(builder.build());
        request.amountAuthorised = Bcd.longToBcd(500, 6);
        request.merchantForcedOnline = merchantForcedOnline;
        return request;
    }

    // --- Scenario 1: online, CDA, ARQC -> TC --------------------------------

    private static void onlineCdaTransaction(Terminal terminal) throws Exception {
        System.out.println("--- contactless: online CDA transaction ---");
        TransactionRequest data = request(0, 0, tacOnline(), null, null, false); // EUR 5.00

        final java.util.List<String> candidates = new java.util.ArrayList<String>();
        final java.util.List<KernelListener.Step> steps =
                new java.util.ArrayList<KernelListener.Step>();
        final card42.host.emv.kernel.core.Outcome[] reported =
                new card42.host.emv.kernel.core.Outcome[1];
        ContactlessKernel kernel = new ContactlessKernel(Reporter.to(System.out),
                TestKeys.caKeyStore(), new Random(7))
                .listener(new KernelListener() {
                    @Override
                    public void onCandidateList(java.util.List<String> adfNames) {
                        candidates.addAll(adfNames);
                    }

                    @Override
                    public void onStep(Step step, TransactionResult result) {
                        steps.add(step);
                    }

                    @Override
                    public void onOutcome(card42.host.emv.kernel.core.Outcome outcome) {
                        reported[0] = outcome;
                    }
                });
        TransactionResult r = kernel.run(terminal, data,
                new TestIssuer(ICC_KEY, CSU_APPROVE));

        Checks.check("listener receives the Entry Point Candidate List",
                candidates.contains(CONTACTLESS_AID));
        Checks.check("listener receives the processing steps",
                steps.contains(KernelListener.Step.APPLICATION_SELECTION)
                        && steps.contains(KernelListener.Step.COMPLETION));
        Checks.check("listener receives the Final Outcome", reported[0] != null);

        Checks.check("Entry Point selects the contactless AID",
                CONTACTLESS_AID.equals(r.aidHex()));
        // H3/H4: the Entry Point built the kernel activation and the kernel
        // produced an Outcome.
        Checks.check("Entry Point built the kernel activation",
                kernel.activation() != null
                        && CONTACTLESS_AID.equals(kernel.activation().adfName)
                        && kernel.activation().indicators != null);
        Checks.check("kernel Outcome is Approve", r.outcome() != null
                && r.outcome().finalOutcome == card42.host.emv.kernel.core.Outcome.APPROVE);
        Checks.check("AIP is the RSA contactless profile 0x6900 (XDA b8=0, CVM b5=0; "
                + "EMV v4.4 Book 3 Table 41)", r.aip() == 0x6900);
        Checks.check("CDA selected and performed", r.cdaSelected()
                && r.cdaPerformed() && !r.cdaFailed());
        // EMV v4.4 Book 3 §10.3: a single ODA method is selected
        // (XDA > CDA > DDA > SDA); SDA/DDA are not performed when CDA wins.
        Checks.check("SDA not performed when CDA is selected", !r.sdaPerformed());
        Checks.check("DDA not performed when CDA is selected", !r.ddaPerformed());
        Checks.check("CVM Results = No CVM performed (AIP b5=0)",
                Arrays.equals(r.cvmResults(), Hex.parse("3F0000")));
        Checks.check("TVR records the exceeded floor limit",
                Tvr.isSet(r.tvr(), 3, Tvr.FLOOR_LIMIT_EXCEEDED));
        Checks.check("TAA requests an ARQC", r.requestedFirstAc() == (byte) 0x80);
        Checks.check("first AC is an ARQC", r.firstCid() == (byte) 0x80);
        Checks.check("first AC is format 2", r.firstResponse()[0] == 0x77);
        Checks.check("second AC is a TC", r.secondCid() == (byte) 0x40);
        Checks.check("second AC is format 2", r.secondResponse()[0] == 0x77);
        Checks.check("IAD CVR sets CDA Performed", (r.firstAc().iad[3] & 0x08) != 0);
        Checks.check("TSI records ODA/TRM/issuer authentication (no CVM: AIP b5=0)",
                Tsi.isSet(r.tsi(), Tsi.ODA_PERFORMED)
                        && !Tsi.isSet(r.tsi(), Tsi.CVM_PERFORMED)
                        && Tsi.isSet(r.tsi(), Tsi.TERMINAL_RISK_MANAGEMENT_PERFORMED)
                        && Tsi.isSet(r.tsi(), Tsi.ISSUER_AUTH_PERFORMED));

        byte[] expectedFirst = AcCrypto.expectedAc(ICC_KEY, r.aip(), r.firstAc().atc,
                r.cdol1Data(), r.firstAc().iad);
        Checks.bytes(expectedFirst, r.firstAc().ac, "first AC cryptogram");
        byte[] expectedSecond = AcCrypto.expectedAc(ICC_KEY, r.aip(), r.firstAc().atc,
                r.cdol2Data(), r.secondAc().iad);
        Checks.bytes(expectedSecond, r.secondAc().ac, "second AC cryptogram");
    }

    // --- Scenario 2: offline, CDA, TC ---------------------------------------

    private static void offlineCdaTransaction(Terminal terminal) throws Exception {
        System.out.println("--- contactless: offline CDA transaction ---");
        TransactionRequest data = request(Long.MAX_VALUE, 0, null, null, null, false);

        ContactlessKernel kernel = new ContactlessKernel(Reporter.to(System.out), TestKeys.caKeyStore(), new Random(11));
        TransactionResult r = kernel.run(terminal, data,
                new TestIssuer(ICC_KEY, CSU_APPROVE));

        Checks.check("offline first AC is a TC", r.firstCid() == (byte) 0x40);
        Checks.check("offline transaction does not go online", !r.wentOnline());
        Checks.check("offline CDA performed and passed", r.cdaPerformed() && !r.cdaFailed());
        Checks.check("offline ODA performed sets the TSI bit",
                Tsi.isSet(r.tsi(), Tsi.ODA_PERFORMED));
        Checks.check("offline CVM Results = No CVM performed", Arrays.equals(r.cvmResults(),
                Hex.parse("3F0000")));

        byte[] expected = AcCrypto.expectedAc(ICC_KEY, r.aip(), r.firstAc().atc,
                r.cdol1Data(), r.firstAc().iad);
        Checks.bytes(expected, r.firstAc().ac, "offline first AC cryptogram");
    }

    // --- Scenario 3: terminal declines through TAC-Denial -------------------

    private static void terminalDeclinesAac(Terminal terminal) throws Exception {
        System.out.println("--- contactless: terminal declines (TAC-Denial) ---");
        // The floor-limit TVR bit (set by Terminal Risk Management) makes
        // TAC-Denial trigger (EMV v4.4 Book 3 §10.7).
        TransactionRequest data = request(0, 0, null, tacOnline(), null, false);

        ContactlessKernel kernel = new ContactlessKernel(Reporter.to(System.out), TestKeys.caKeyStore(), new Random(13));
        TransactionResult r = kernel.run(terminal, data,
                new TestIssuer(ICC_KEY, CSU_APPROVE));

        Checks.check("TAA requests an AAC", r.requestedFirstAc() == (byte) 0x00);
        Checks.check("first AC is an AAC", r.firstCid() == (byte) 0x00);
        Checks.check("AAC has no CDA SDAD", !r.cdaPerformed());
        Checks.check("declined transaction has no second AC", r.secondResponse() == null);
        Checks.check("declined transaction is marked declined", r.declined());
    }

    // --- Scenario 4: the issuer declines the online authorisation -----------

    /**
     * The online response carries a declining ARC; the terminal must request an
     * AAC at the second GENERATE AC and decline the transaction, not request a
     * TC (EMV v4.4 Book 4 §6.3.8).
     */
    private static void issuerDeclinesOnline(Terminal terminal) throws Exception {
        System.out.println("--- contactless: issuer declines online ---");
        TransactionRequest data = request(0, 0, tacOnline(), null, null, false);

        ContactlessKernel kernel = new ContactlessKernel(Reporter.to(System.out), TestKeys.caKeyStore(), new Random(17));
        TransactionResult r = kernel.run(terminal, data,
                new TestIssuer(ICC_KEY, CSU_APPROVE, false, Hex.parse("3035")));

        Checks.check("decline: first AC is an ARQC", r.firstCid() == (byte) 0x80);
        Checks.check("decline: second AC is an AAC", r.secondCid() == (byte) 0x00);
        Checks.check("decline: transaction is marked declined", r.declined());
        Checks.check("decline: ARC is the issuer's decline",
                Arrays.equals(r.arc(), Hex.parse("3035")));
    }

    // --- Scenario 5: unable to go online (Default pair) ---------------------

    /**
     * The terminal cannot reach the issuer; the Default pair decides the second
     * AC and the ARC is 'Z3' (declined) or 'Y3' (approved)
     * (EMV v4.4 Book 3 §10.7, Book 4 Annex A6 Table 35).
     */
    private static void unableToGoOnlineTransaction(Terminal terminal) throws Exception {
        System.out.println("--- contactless: unable to go online ---");
        // Default: floor-limit bit -> decline
        TransactionRequest data = request(0, 0, tacOnline(), null, tacOnline(), false);

        ContactlessKernel kernel = new ContactlessKernel(Reporter.to(System.out), TestKeys.caKeyStore(), new Random(19));
        TransactionResult r = kernel.run(terminal, data, (arqc, atc, result) -> null);

        Checks.check("unable online: first AC is an ARQC", r.firstCid() == (byte) 0x80);
        Checks.check("unable online: second AC is an AAC", r.secondCid() == (byte) 0x00);
        Checks.check("unable online: transaction is declined", r.declined());
        Checks.check("unable online: ARC is 'Z3'",
                Arrays.equals(r.arc(), new byte[] { 0x5A, 0x33 }));
        // No issuer response arrived, so the all-zero inline tag '91' must not
        // be treated as a failed issuer authentication
        // (EMV v4.4 Book 3 §10.11.1.1 / CCD Annex C §C10).
        Checks.check("unable online: CVR1 has no issuer-auth failure",
                (r.secondAc().iad[3] & 0x01) == 0);
        Checks.check("unable online: CVR1 reports issuer auth not performed",
                (r.secondAc().iad[3] & 0x02) != 0);
        Checks.check("unable online: CVR4 reports unable to go online",
                (r.secondAc().iad[6] & 0x01) != 0);
    }

    // --- Scenario 5b: unable to go online, Default pair approves (ARC Y3) ---

    /**
     * The terminal cannot reach the issuer and the Default pair does not
     * decline, so the second AC is a TC and the ARC is 'Y3'
     * (EMV v4.4 Book 3 §10.7, Book 4 Annex A6 Table 35).
     */
    private static void unableToGoOnlineApproved(Terminal terminal) throws Exception {
        System.out.println("--- contactless: unable to go online, approved ---");
        // No floor-limit bit, so the only TVR bit is merchant-forced online
        // (byte 4 b4); the card IAC-Default byte 4 b8 does not match it, so the
        // Default pair approves.
        TransactionRequest data = request(Long.MAX_VALUE, 0,
                new byte[] { 0, 0, 0, 0x08, 0 }, null, null, true);

        ContactlessKernel kernel = new ContactlessKernel(Reporter.to(System.out), TestKeys.caKeyStore(), new Random(29));
        TransactionResult r = kernel.run(terminal, data, (arqc, atc, result) -> null);

        Checks.check("unable online approved: first AC is an ARQC", r.firstCid() == (byte) 0x80);
        Checks.check("unable online approved: second AC is a TC", r.secondCid() == (byte) 0x40);
        Checks.check("unable online approved: transaction is approved", !r.declined());
        Checks.check("unable online approved: ARC is 'Y3'",
                Arrays.equals(r.arc(), new byte[] { 0x59, 0x33 }));
    }

    // --- Scenario 6: CDA failure declines the transaction -------------------

    /**
     * A CDA failure after an ARQC makes the terminal request an AAC at the
     * second GENERATE AC and decline the transaction (EMV v4.4 Book 4 §6.3.2.1).
     * The failure is injected by flipping a byte of the first AC's SDAD through
     * a channel wrapper.
     */
    private static void cdaFailureDeclines(CardChannel channel) throws Exception {
        System.out.println("--- contactless: CDA failure declines ---");
        TransactionRequest data = request(0, 0, tacOnline(), null, null, false);

        Terminal corrupting = new Terminal(new CorruptCdaChannel(channel));
        ContactlessKernel kernel = new ContactlessKernel(Reporter.to(System.out), TestKeys.caKeyStore(), new Random(23));
        TransactionResult r = kernel.run(corrupting, data,
                new TestIssuer(ICC_KEY, CSU_APPROVE));

        Checks.check("CDA failure: first AC is an ARQC", r.firstCid() == (byte) 0x80);
        Checks.check("CDA failure: the CDA failure is detected", r.cdaFailed());
        Checks.check("CDA failure: TVR records CDA failed",
                Tvr.isSet(r.tvr(), 0, Tvr.CDA_FAILED));
        Checks.check("CDA failure: second AC is an AAC", r.secondCid() == (byte) 0x00);
        Checks.check("CDA failure: transaction is declined", r.declined());
    }

    // --- Scenario 7: online with an issuer script ---------------------------

    /**
     * The online response carries a 72 issuer script; the kernel must forward
     * the 86 command and report 9F5B and the TVR script bit
     * (EMV v4.4 Book 3 §10.10, EMV v4.4 Book 4 §6.3.9/Annex A5).
     */
    private static void issuerScriptTransaction(Terminal terminal) throws Exception {
        System.out.println("--- contactless: issuer script ---");
        TransactionRequest data = request(0, 0, tacOnline(), null, null, false);

        ContactlessKernel kernel = new ContactlessKernel(Reporter.to(System.out), TestKeys.caKeyStore(), new Random(11));
        TransactionResult r = kernel.run(terminal, data,
                new TestIssuer(ICC_KEY, CSU_APPROVE, true));

        Checks.check("issuer script was processed", r.issuerScriptResults() != null);
        Checks.check("issuer script succeeded",
                r.issuerScriptResults() != null && (r.issuerScriptResults()[0] & 0xF0) == 0x20);
        Checks.check("no script failure in the TVR",
                r.tvr() != null && (r.tvr()[4] & 0x30) == 0);
        Checks.check("script processing TSI bit is set",
                Tsi.isSet(r.tsi(), Tsi.SCRIPT_PROCESSING_PERFORMED));
    }

    /**
     * A tag '71' script is processed before the final GENERATE AC (EMV v4.4
     * Book 3 §10.10); a failure is therefore classified 'before final AC'
     * (TVR byte 5 b6) rather than 'after' (b5).
     */
    private static void issuerScriptBeforeFinalAcFailure(Terminal terminal) throws Exception {
        System.out.println("--- contactless: 71 issuer script fails before the final AC ---");
        TransactionRequest data = request(0, 0, tacOnline(), null, null, false);

        ContactlessKernel kernel = new ContactlessKernel(Reporter.to(System.out),
                TestKeys.caKeyStore(), new Random(13));
        TransactionResult r = kernel.run(terminal, data,
                new TestIssuer(ICC_KEY, CSU_APPROVE, true, Hex.parse("3030"), 0x71, true));

        Checks.check("71 script failure is classified before the final AC",
                r.issuerScriptFailedBeforeFinalAc() && !r.issuerScriptFailedAfterFinalAc());
        Checks.check("71 script failure sets TVR byte 5 b6",
                r.tvr() != null && (r.tvr()[4] & 0x20) != 0);
        Checks.check("71 script processing sets the TSI script bit",
                Tsi.isSet(r.tsi(), Tsi.SCRIPT_PROCESSING_PERFORMED));
    }

    // --- Issuer -------------------------------------------------------------

    /**
     * A {@link CardChannel} that flips one byte of the SDAD ('9F4B') in every
     * CDA GENERATE AC response, so the terminal's CDA verification fails.  Used
     * only to exercise the CDA-failure path (EMV v4.4 Book 4 §6.3.2.1).
     */
    private static final class CorruptCdaChannel extends CardChannel {
        private final CardChannel delegate;

        CorruptCdaChannel(CardChannel delegate) {
            this.delegate = delegate;
        }

        @Override
        public Card getCard() {
            return delegate.getCard();
        }

        @Override
        public int getChannelNumber() {
            return delegate.getChannelNumber();
        }

        @Override
        public ResponseAPDU transmit(CommandAPDU command) throws javax.smartcardio.CardException {
            ResponseAPDU r = delegate.transmit(command);
            if (command.getINS() == 0xAE && (command.getP1() & 0x10) != 0
                    && r.getSW() == 0x9000) {
                byte[] data = r.getData().clone();
                int off = tlvValueOffset(data, 0x9F4B);
                if (off >= 0 && off < data.length) {
                    data[off] ^= (byte) 0x01; // corrupt the SDAD
                    byte[] full = new byte[data.length + 2];
                    System.arraycopy(data, 0, full, 0, data.length);
                    full[data.length] = (byte) (r.getSW() >> 8);
                    full[data.length + 1] = (byte) r.getSW();
                    return new ResponseAPDU(full);
                }
            }
            return r;
        }

        @Override
        public int transmit(ByteBuffer command, ByteBuffer response)
                throws javax.smartcardio.CardException {
            return delegate.transmit(command, response);
        }

        @Override
        public void close() throws javax.smartcardio.CardException {
            delegate.close();
        }
    }

    /** The value offset of a 2-byte tag in a TLV buffer, or -1. */
    private static int tlvValueOffset(byte[] buf, int tag) {
        for (int i = 0; i + 2 < buf.length; i++) {
            if ((buf[i] & 0xFF) == ((tag >> 8) & 0xFF)
                    && (buf[i + 1] & 0xFF) == (tag & 0xFF)) {
                int lb = buf[i + 2] & 0xFF;
                int n = (lb & 0x80) != 0 ? (lb & 0x7F) : 0;
                if (i + 3 + n <= buf.length) {
                    return i + 3 + n;
                }
            }
        }
        return -1;
    }

    /** A closed-loop issuer that knows the ICC master key (test only). */
    private static final class TestIssuer implements Issuer {
        private final byte[] iccKey;
        private final byte[] csu;
        private final boolean withScript;
        private final byte[] arc;
        /** Tag of the issued script ('71' before, '72' after the final AC). */
        private final int scriptTag;
        /** True to corrupt the script command's MAC so the card rejects it. */
        private final boolean failScript;

        TestIssuer(byte[] iccKey, byte[] csu) {
            this(iccKey, csu, false, Hex.parse("3030"), 0x72, false);
        }

        TestIssuer(byte[] iccKey, byte[] csu, boolean withScript) {
            this(iccKey, csu, withScript, Hex.parse("3030"), 0x72, false);
        }

        TestIssuer(byte[] iccKey, byte[] csu, boolean withScript, byte[] arc) {
            this(iccKey, csu, withScript, arc, 0x72, false);
        }

        TestIssuer(byte[] iccKey, byte[] csu, boolean withScript, byte[] arc,
                   int scriptTag, boolean failScript) {
            this.iccKey = iccKey;
            this.csu = csu;
            this.withScript = withScript;
            this.arc = arc;
            this.scriptTag = scriptTag;
            this.failScript = failScript;
        }

        public Authorization authorize(byte[] arqc, int atc, TransactionResult result) {
            try {
                byte[] sk = AcCrypto.sessionKey(iccKey, atc);
                byte[] arpc = AcCrypto.computeArpcMethod2(sk, arqc, csu, new byte[0]);
                byte[] auth = new byte[8];
                System.arraycopy(arpc, 0, auth, 0, 4);
                System.arraycopy(csu, 0, auth, 4, 4);
                byte[][] scripts = null;
                if (withScript) {
                    SmCrypto.ScriptSession session =
                            new SmCrypto.ScriptSession(SM_MAC_KEY, SM_ENC_KEY);
                    session.start(arqc);
                    byte[] command = session.command(0x18, 0x00, 0x00).getBytes();
                    if (failScript) {
                        command = command.clone();
                        command[command.length - 1] ^= (byte) 0xFF; // corrupt the MAC
                    }
                    scripts = new byte[][] { IssuerHost.script(scriptTag, "00A1B2C3", command) };
                }
                return new Authorization(arc, auth, scripts);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
    }
}
