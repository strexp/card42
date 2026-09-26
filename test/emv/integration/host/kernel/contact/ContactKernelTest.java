package card42.test;

import java.util.Arrays;
import java.util.Random;

import javax.smartcardio.Card;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.ResponseAPDU;

import card42.host.emv.crypto.AcCrypto;
import card42.host.emv.kernel.ContactKernel;
import card42.host.emv.kernel.core.Authorization;
import card42.host.emv.kernel.core.Issuer;
import card42.host.emv.kernel.core.KernelListener;
import card42.host.emv.kernel.core.PinProvider;
import card42.host.emv.kernel.core.TransactionResult;
import card42.host.common.util.Bcd;
import card42.host.emv.kernel.data.ReferralHandler;
import card42.host.emv.kernel.data.TerminalConfig;
import card42.host.emv.kernel.data.TransactionRequest;
import card42.host.emv.kernel.data.Tsi;
import card42.host.emv.kernel.data.Tvr;
import card42.host.common.util.Args;
import card42.host.emv.lib.Terminal;
import card42.host.common.util.Hex;
import card42.host.common.util.Reporter;

/**
 * End-to-end contact kernel test (docs/specs/emv/contact-kernel.md,
 * docs/specs/common/toolchain.md §6).
 *
 * <p>It runs the {@link ContactKernel} over the contact payment instance
 * (AID 43415244420101):
 *
 * <pre>
 *   SELECT PSE -&gt; directory records -&gt; SELECT ADF -&gt; GPO -&gt; READ RECORD
 *     -&gt; RSA ODA -&gt; restrictions -&gt; offline PIN CVM -&gt; TRM -&gt; TAA
 *     -&gt; GENERATE AC -&gt; online -&gt; second GENERATE AC
 * </pre>
 *
 * <p>Four transactions are exercised: an offline ODA transaction (CDA where the
 * card advertises it, SDA otherwise) with a successful plaintext offline PIN,
 * an online transaction (ARQC then TC), a transaction the terminal declines
 * through TAC-Denial (AAC), and a wrong PIN (CVM failed) followed by a correct
 * PIN that restores the try counter.  The AC cryptograms are independently
 * recomputed from the ICC master key.
 */
public class ContactKernelTest {

    private static final String CONTACT_AID = "43415244420101";
    private static final byte[] ICC_KEY = Hex.parse("343864C2E085AB3E433D2F982945E61F");

    /** CSU: Issuer Approves Online Transaction (EMV v4.4 Book 3 Annex C §C10). */
    private static final byte[] CSU_APPROVE = { 0x00, (byte) 0x80, 0x00, 0x00 };

    /** CSU: Approve + Reset the offline counters (EMV v4.4 Book 3 Annex C §C10). */
    private static final byte[] CSU_RESET = { 0x00, (byte) 0x82, 0x00, 0x00 };

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
            System.out.println("FAILED: " + Checks.failures() + " contact kernel check(s)");
            System.exit(1);
        }
        System.out.println("ALL CONTACT KERNEL CHECKS PASSED");
    }

    static void run(Terminal terminal) throws Exception {
        // The card's offline risk accumulators are persistent; reset them so the
        // offline scenarios below are deterministic regardless of earlier suites
        // (the same CSU reset EmvFlowTest uses).
        resetCounters(terminal);
        offlinePinTransaction(terminal);
        onlineTransaction(terminal);
        terminalDeclinesAac(terminal);
        referralTransaction(terminal);
        referralDeclined(terminal);
        captureCardTransaction(terminal);
        exceptionFileTransaction(terminal);
        wrongPinThenRecover(terminal);
        listenerReportsSteps(terminal);
    }

    // --- Scenario 8: the progress listener (KernelListener) ------------------

    private static void listenerReportsSteps(Terminal terminal) throws Exception {
        System.out.println("--- contact kernel: progress listener ---");
        final java.util.List<KernelListener.Step> steps =
                new java.util.ArrayList<KernelListener.Step>();
        kernel(new Random(41), "1234")
                .listener((step, result) -> steps.add(step))
                .run(terminal, request(Long.MAX_VALUE, 0, null, null, null, null),
                        issuer(CSU_APPROVE));
        Checks.check("listener reports application selection",
                steps.contains(KernelListener.Step.APPLICATION_SELECTION));
        Checks.check("listener reports initiate application processing",
                steps.contains(KernelListener.Step.INITIATE_APPLICATION_PROCESSING));
        Checks.check("listener reports read application data",
                steps.contains(KernelListener.Step.READ_APPLICATION_DATA));
        Checks.check("listener reports offline data authentication",
                steps.contains(KernelListener.Step.OFFLINE_DATA_AUTHENTICATION));
        Checks.check("listener reports processing restrictions",
                steps.contains(KernelListener.Step.PROCESSING_RESTRICTIONS));
        Checks.check("listener reports cardholder verification",
                steps.contains(KernelListener.Step.CARDHOLDER_VERIFICATION));
        Checks.check("listener reports terminal risk management",
                steps.contains(KernelListener.Step.TERMINAL_RISK_MANAGEMENT));
        Checks.check("listener reports terminal action analysis",
                steps.contains(KernelListener.Step.TERMINAL_ACTION_ANALYSIS));
        Checks.check("listener reports card action analysis",
                steps.contains(KernelListener.Step.CARD_ACTION_ANALYSIS));
        Checks.check("listener reports completion",
                steps.contains(KernelListener.Step.COMPLETION));
    }

    /**
     * A contact transaction request with the common scenario settings: EUR 5.00,
     * the given floor limit and CVM required limit, and optional TAC-Online /
     * TAC-Denial overrides (bytes 3 b8), referral handler and exception PAN.
     */
    private static TransactionRequest request(long floorLimit, long cvmRequiredLimit,
            byte[] tacOnline, byte[] tacDenial, ReferralHandler referral, byte[] exceptionPan) {
        TerminalConfig.Builder builder = TerminalConfig.forContact()
                .floorLimit(floorLimit)
                .cvmRequiredLimit(cvmRequiredLimit);
        if (tacOnline != null) {
            builder.tacOnline(tacOnline);
        }
        if (tacDenial != null) {
            builder.tacDenial(tacDenial);
        }
        if (referral != null) {
            builder.referralHandler(referral);
        }
        if (exceptionPan != null) {
            builder.addException(exceptionPan, null);
        }
        TransactionRequest request = new TransactionRequest(builder.build());
        request.amountAuthorised = Bcd.longToBcd(500, 6);
        return request;
    }

    /** A TAC-Online that forces the floor-limit transaction online. */
    private static byte[] tacOnline() {
        byte[] tac = new byte[5];
        tac[3] = (byte) 0x80;
        return tac;
    }

    /** Runs an online transaction whose CSU resets the offline counters. */
    private static void resetCounters(Terminal terminal) throws Exception {
        TransactionResult r = kernel(new Random(1), "1234")
                .run(terminal, request(0, 0, tacOnline(), null, null, null), issuer(CSU_RESET));
        Checks.check("counter reset transaction completes online",
                r.firstCid() == (byte) 0x80 && r.secondCid() == (byte) 0x40);
    }

    // --- Scenario 1: offline CDA transaction with a successful offline PIN ---

    private static void offlinePinTransaction(Terminal terminal) throws Exception {
        System.out.println("--- contact kernel: offline CDA + offline PIN ---");
        TransactionResult r = kernel(new Random(3), "1234")
                .run(terminal, request(Long.MAX_VALUE, 0, null, null, null, null),
                        issuer(CSU_APPROVE));

        Checks.check("kernel selects the contact AID", CONTACT_AID.equals(r.aidHex()));
        // The contact RSA profile advertises SDA and CVM (AIP 0x7900 on the
        // simulator; 0x5800 on an SDA-only card such as the J3R180).
        Checks.check("AIP is the contact RSA profile (SDA + CVM)",
                (r.aip() & 0x4000) != 0 && (r.aip() & 0x1000) != 0);
        if (r.cdaSelected()) {
            Checks.check("CDA selected and performed", r.cdaPerformed() && !r.cdaFailed());
            Checks.check("CDA recovers the ICC Dynamic Number (9F4C)",
                    r.iccDynamicNumber() != null && r.iccDynamicNumber().length >= 2
                            && r.iccDynamicNumber().length <= 8);
            // EMV v4.4 Book 3 §10.3: the terminal selects a single ODA method
            // (XDA > CDA > DDA > SDA), so SDA/DDA are not performed when CDA wins.
            Checks.check("SDA not performed when CDA is selected", !r.sdaPerformed());
            Checks.check("DDA not performed when CDA is selected", !r.ddaPerformed());
        } else {
            Checks.check("SDA selected and performed", r.sdaPerformed() && !r.sdaFailed());
            Checks.check("CDA not performed when SDA is selected", !r.cdaPerformed());
            Checks.check("DDA not performed when SDA is selected", !r.ddaPerformed());
        }
        Checks.check("offline PIN CVM Results (01 00 02)",
                Arrays.equals(r.cvmResults(), Hex.parse("010002")));
        Checks.check("TSI records CVM performed", Tsi.isSet(r.tsi(), Tsi.CVM_PERFORMED));
        Checks.check("offline first AC is a TC", r.firstCid() == (byte) 0x40);
        Checks.check("offline transaction does not go online", !r.wentOnline());
        Checks.check("offline transaction is not declined", !r.declined());

        byte[] expected = AcCrypto.expectedAc(ICC_KEY, r.aip(), r.firstAc().atc,
                r.cdol1Data(), r.firstAc().iad);
        Checks.bytes(expected, r.firstAc().ac, "offline first AC cryptogram");
    }

    // --- Scenario 2: online CDA transaction (ARQC -> TC) ---------------------

    private static void onlineTransaction(Terminal terminal) throws Exception {
        System.out.println("--- contact kernel: online CDA ---");
        TransactionResult r = kernel(new Random(5), "1234")
                .run(terminal, request(0, 0, tacOnline(), null, null, null), issuer(CSU_APPROVE));

        Checks.check("online CVM offline PIN successful",
                Arrays.equals(r.cvmResults(), Hex.parse("010002")));
        Checks.check("TAA requests an ARQC", r.requestedFirstAc() == (byte) 0x80);
        Checks.check("first AC is an ARQC", r.firstCid() == (byte) 0x80);
        Checks.check("second AC is a TC", r.secondCid() == (byte) 0x40);
        Checks.check("transaction went online", r.wentOnline() && r.issuerAuthPerformed());
        Checks.check("online transaction is not declined", !r.declined());
        Checks.check("TSI records issuer authentication",
                Tsi.isSet(r.tsi(), Tsi.ISSUER_AUTH_PERFORMED));

        int lastOnline = readLastOnlineAtc(terminal);
        Checks.check("9F13 records the completed online ATC",
                lastOnline == r.firstAc().atc);

        byte[] expectedFirst = AcCrypto.expectedAc(ICC_KEY, r.aip(), r.firstAc().atc,
                r.cdol1Data(), r.firstAc().iad);
        Checks.bytes(expectedFirst, r.firstAc().ac, "online first AC cryptogram");
        byte[] expectedSecond = AcCrypto.expectedAc(ICC_KEY, r.aip(), r.firstAc().atc,
                r.cdol2Data(), r.secondAc().iad);
        Checks.bytes(expectedSecond, r.secondAc().ac, "online second AC cryptogram");
    }

    // --- Scenario 3: terminal declines through TAC-Denial --------------------

    private static void terminalDeclinesAac(Terminal terminal) throws Exception {
        System.out.println("--- contact kernel: terminal declines (TAC-Denial) ---");
        // The floor-limit TVR bit (set by Terminal Risk Management) makes
        // TAC-Denial trigger (EMV v4.4 Book 3 §10.7).
        byte[] tacDenial = new byte[5];
        tacDenial[3] = (byte) 0x80;
        TransactionResult r = kernel(new Random(7), "1234")
                .run(terminal, request(0, 0, null, tacDenial, null, null), issuer(CSU_APPROVE));

        Checks.check("TAA requests an AAC", r.requestedFirstAc() == (byte) 0x00);
        Checks.check("first AC is an AAC", r.firstCid() == (byte) 0x00);
        Checks.check("AAC has no CDA SDAD", !r.cdaPerformed());
        Checks.check("declined transaction has no second AC", r.secondResponse() == null);
        Checks.check("declined transaction is marked declined", r.declined());
    }

    // --- Scenario 4: issuer referral accepted by the attendant (ARC '01') ----

    private static void referralTransaction(Terminal terminal) throws Exception {
        System.out.println("--- contact kernel: issuer referral (attendant accepts) ---");
        // The attendant accepts the referred transaction (Book 4 §6.5.2.2).
        TransactionResult r = kernel(new Random(23), "1234")
                .run(terminal, request(0, 0, tacOnline(), null, arc -> true, null),
                        issuer(CSU_APPROVE, "3031"));

        Checks.check("referral is recorded", r.referralRequested());
        Checks.check("attendant acceptance is recorded", r.attendantForcedAcceptance());
        Checks.check("referred transaction is approved", !r.declined());
        Checks.check("referred second AC is a TC", r.secondCid() == (byte) 0x40);
    }

    private static void referralDeclined(Terminal terminal) throws Exception {
        System.out.println("--- contact kernel: issuer referral (declined) ---");
        // No referral handler: the terminal cannot perform the referral.
        TransactionResult r = kernel(new Random(29), "1234")
                .run(terminal, request(0, 0, tacOnline(), null, null, null),
                        issuer(CSU_APPROVE, "3031"));

        Checks.check("referral is recorded", r.referralRequested());
        Checks.check("no attendant acceptance", !r.attendantForcedAcceptance());
        Checks.check("declined referral is declined", r.declined());
        Checks.check("declined referral second AC is an AAC", r.secondCid() == (byte) 0x00);
    }

    // --- Scenario 5: issuer asks to capture the card (ARC '02') --------------

    private static void captureCardTransaction(Terminal terminal) throws Exception {
        System.out.println("--- contact kernel: issuer asks to capture the card ---");
        TransactionResult r = kernel(new Random(31), "1234")
                .run(terminal, request(0, 0, tacOnline(), null, null, null),
                        issuer(CSU_APPROVE, "3032"));

        Checks.check("card capture is recorded", r.cardCaptureRequested());
        Checks.check("capture transaction is declined", r.declined());
    }

    // --- Scenario 6: exception file (Book 4 §6.3.5) --------------------------

    private static void exceptionFileTransaction(Terminal terminal) throws Exception {
        System.out.println("--- contact kernel: terminal exception file ---");
        // The card's default PAN is 1234567890 (Defaults.PAN).
        TransactionResult r = kernel(new Random(37), "1234")
                .run(terminal, request(0, 0, tacOnline(), null, null, Hex.parse("1234567890")),
                        issuer(CSU_APPROVE));

        Checks.check("exception-file match sets the TVR bit",
                Tvr.isSet(r.tvr(), 0, Tvr.CARD_ON_EXCEPTION_FILE));
    }

    // --- Scenario 7: wrong PIN fails the CVM, correct PIN recovers -----------

    private static void wrongPinThenRecover(Terminal terminal) throws Exception {
        System.out.println("--- contact kernel: wrong offline PIN ---");
        TransactionResult r = kernel(new Random(11), "0000")
                .run(terminal, request(0, 0, tacOnline(), null, null, null), issuer(CSU_APPROVE));

        Checks.check("wrong PIN CVM Results (01 00 01)",
                Arrays.equals(r.cvmResults(), Hex.parse("010001")));
        Checks.check("wrong PIN sets CVM not successful",
                Tvr.isSet(r.tvr(), 2, Tvr.CVM_NOT_SUCCESSFUL));

        // A correct PIN resets the card's PIN try counter (EMV v4.4 Book 3 §6.5.12).
        // This transaction is forced online with a CSU reset so it also leaves the
        // card's offline accumulators clean for the later suites.
        TransactionResult r2 = kernel(new Random(13), "1234")
                .run(terminal, request(0, 0, tacOnline(), null, null, null), issuer(CSU_RESET));
        Checks.check("correct PIN restores the CVM Results",
                Arrays.equals(r2.cvmResults(), Hex.parse("010002")));
        Checks.check("correct PIN transaction completes", !r2.declined());
    }

    // --- Helpers -------------------------------------------------------------

    private static ContactKernel kernel(Random random, final String pin) {
        PinProvider pinProvider = new PinProvider() {
            @Override
            public String pin() {
                return pin;
            }
        };
        return new ContactKernel(Reporter.to(System.out), TestKeys.caKeyStore(), random,
                pinProvider);
    }

    /** A closed-loop issuer that knows the ICC master key (test only). */
    private static Issuer issuer(final byte[] csu) {
        return issuer(csu, "3030");
    }

    /** A closed-loop issuer returning the given Authorisation Response Code. */
    private static Issuer issuer(final byte[] csu, final String arcHex) {
        return new Issuer() {
            @Override
            public Authorization authorize(byte[] arqc, int atc, TransactionResult result) {
                try {
                    byte[] sk = AcCrypto.sessionKey(ICC_KEY, atc);
                    byte[] arpc = AcCrypto.computeArpcMethod2(sk, arqc, csu, new byte[0]);
                    byte[] auth = new byte[8];
                    System.arraycopy(arpc, 0, auth, 0, 4);
                    System.arraycopy(csu, 0, auth, 4, 4);
                    return new Authorization(Hex.parse(arcHex), auth);
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }
        };
    }

    /** Reads the Last Online ATC Register (9F13), or -1. */
    private static int readLastOnlineAtc(Terminal terminal) throws Exception {
        ResponseAPDU r = terminal.getData(0x9F, 0x13);
        if (r.getSW() != 0x9000) {
            return -1;
        }
        byte[] value = card42.host.common.codec.Tags.find(r.getData(), 0x9F13);
        return value != null && value.length == 2
                ? (((value[0] & 0xFF) << 8) | (value[1] & 0xFF)) : -1;
    }
}
