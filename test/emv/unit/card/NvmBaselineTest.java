package card42.test;

import java.lang.reflect.Array;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javacard.framework.APDU;
import javacard.framework.NvmWrite;

import card42.emrtd.AaCrypto;
import card42.emrtd.EmrtdApplet;
import card42.emrtd.EmrtdInstallParameters;
import card42.emrtd.EmrtdTags;
import card42.emrtd.ExternalAuthenticate;
import card42.emrtd.LdsCatalog;
import card42.emrtd.LdsFile;
import card42.emrtd.LdsMfStore;
import card42.emrtd.LdsPerso;
import card42.emrtd.Mse;

import card42.emv.CardRiskManagement;
import card42.emv.DolReader;
import card42.emv.EMVCodes;
import card42.emv.EMVProtocolState;
import card42.emv.EMVRoles;
import card42.emv.EMVStaticData;
import card42.emv.FciBuilder;
import card42.emv.OfflineRisk;
import card42.emv.RecordBuilder;
import card42.emv.TransactionLog;
import card42.emv.TlvTags;

import card42.host.common.crypto.Iso9797;
import card42.host.common.util.Hex;
import card42.host.emrtd.access.Bac;
import card42.host.emrtd.access.Iso7816Sm;

/**
 * EEPROM write baselines: three scenarios reported as persistent bytes / write
 * operations per step (docs/specs/common/risks.md §2).
 *
 * <p>The baselines are:
 * <ol>
 *   <li><b>{@code emrtd-bac-session-read5}</b> — SELECT, GET CHALLENGE, the BAC
 *       handshake, a full read of EF.COM / DG1 / DG2 / DG5 / EF.SOD over
 *       established secure messaging, then a deselect.  This is the reference
 *       for the eMRTD session cost.  The response buffers
 *       ({@code EmrtdScratch.io}/{@code response}) and the SM scratch are
 *       transient ({@code CLEAR_ON_DESELECT}) since the buffer rework, so this
 *       baseline now counts only the remaining persistent writers
 *       (session-key caches, {@code resetSession}).</li>
 *   <li><b>{@code emv-gpo-two-ac}</b> — the EMV online transaction: SELECT,
 *       GET PROCESSING OPTIONS (which builds the GPO response twice today), the
 *       CDOL1 / CDOL2 traversals of the first and second GENERATE AC, and the
 *       transaction-log write.</li>
 *   <li><b>{@code emrtd-aa-inside-sm}</b> — one ACTIVE AUTHENTICATION
 *       (INTERNAL AUTHENTICATE) inside secure messaging, the largest single
 *       eMRTD response.</li>
 * </ol>
 *
 * <p><b>What is and is not modelled.</b> The counters come from
 * {@link NvmWrite} (bulk writes through {@code javacard.framework.Util}) and
 * {@link NvmProbe} (persistent state that actually changed); neither can see a
 * same-value field write, and the two overlap on copies that do change the
 * destination, so they are always reported side by side and never summed.  A
 * plain JVM has no EEPROM programming cycles either: these numbers are a stable
 * model of write traffic for comparing steps and for tracking changes, not an
 * endurance figure.
 *
 * <p><b>Scenario 2 is component level.</b> {@code PaymentApplet} and
 * {@code AcProcessor} are not linked into the pure-JVM build (test/rules.mk
 * {@code UNIT_CARD_SRC}), so the EMV scenario replays their persistent-state
 * effects call by call against the real card classes instead of driving the
 * applet: the GPO step mirrors the GET PROCESSING OPTIONS branch of
 * {@code PaymentApplet.processCommand}, the two AC steps mirror the DOL
 * traversals and decision logic of {@code AcProcessor} (lines 134, 164, 182,
 * 201-202, 256, 264, 324, 337) and {@code TransactionFinalizer} (lines
 * 119-120, 135-136, 146).  The AC cryptography ({@code EMVCrypto},
 * {@code DdaCrypto}) and the CVR/IAD aggregation ({@code CvrBuilder}) are not
 * linked and are therefore not counted; every DOL traversal, card decision and
 * state transition that does write EEPROM is.
 *
 * <p><b>PACE is not in the baselines.</b> The pure-JVM build links
 * {@code EmrtdApplet} against a no-op {@code Pace} stand-in on purpose
 * ({@code test/emrtd/unit/card/Pace.java}): the real PACE path needs
 * {@code KeyAgreement.ALG_EC_PACE_GM}, which the security stub does not
 * implement.  A PACE baseline has to come from the simulator side of the
 * toolchain; it is registered as a follow-up in TODO.emrtd.md.
 *
 * @author card42
 */
final class NvmBaselineTest {

    /** Fixed BAC material so every run reports the same numbers. */
    private static final byte[] BAC_SEED = Hex.parse("00112233445566778899AABBCCDDEEFF");
    private static final byte[] RND_IFD = Hex.parse("0102030405060708");
    private static final byte[] K_IFD = Hex.parse("11223344556677889900AABBCCDDEEFF");

    /** A PDOL, so the GET PROCESSING OPTIONS step writes a real PDOL payload. */
    private static final byte[] PDOL_CONFIG = Hex.parse(
            "9F38 15 9F02 06 9F03 06 9F1A 02 95 05 5F2A 02 9A 03 9C 01 9F37 04");

    /** Data groups read in baseline 1, and their personalization sizes. */
    private static final short[] DG_FIDS = {
        EmrtdTags.FID_COM, EmrtdTags.FID_DG1, EmrtdTags.FID_DG2,
        EmrtdTags.FID_DG5, EmrtdTags.FID_SOD,
    };
    private static final int[] DG_SIZES = { 32, 40, 1024, 200, 512 };

    /** Largest READ BINARY window whose SM envelope still fits a short APDU. */
    private static final short READ_WINDOW = (short) 231;

    /** Card classes that are all static scratch and never instantiated. */
    private static Class<?>[] emrtdSeeds() throws ClassNotFoundException {
        // SmScratch is package-private, so it is named rather than imported.
        return new Class<?>[] {
            EmrtdApplet.class, Class.forName("card42.emrtd.SmScratch"),
            ExternalAuthenticate.class, Mse.class, LdsMfStore.class,
        };
    }

    private static final Class<?>[] EMV_SEEDS = {
        DolReader.class, RecordBuilder.class, FciBuilder.class,
    };

    private static final List<NvmReport> REPORTS = new ArrayList<NvmReport>();

    private static Method processCommand;
    private static Method onSelect;
    private static Method onDeselect;

    private NvmBaselineTest() {
    }

    static void run() throws Exception {
        System.out.println("NvmBaseline");
        processCommand = EmrtdApplet.class.getDeclaredMethod(
                "processCommand", APDU.class, byte[].class);
        processCommand.setAccessible(true);
        onSelect = EmrtdApplet.class.getDeclaredMethod("onSelect", APDU.class, byte[].class);
        onSelect.setAccessible(true);
        onDeselect = EmrtdApplet.class.getDeclaredMethod("onDeselect");
        onDeselect.setAccessible(true);

        emrtdBacSession();
        emvGpoAndTwoAc();
        emrtdActiveAuthentication();
        transientBudget();

        System.out.println();
        System.out.println("  EEPROM write baseline summary (persistent model):");
        for (NvmReport r : REPORTS) {
            r.printSummary();
        }
        System.out.println("    state = bytes whose value changed (NvmProbe);"
                + "  util = bytes written through Util (NvmWrite); never summed.");
    }

    // --- baseline 1: eMRTD BAC + a full read of five data groups ------------

    /**
     * Reports and bounds the package-shared transient footprint.  The EMV and
     * eMRTD shared holders plus the eMRTD SM scratch are the whole per-context
     * transient budget; this is the J3R180 budget check of
     * docs/specs/common/risks.md §2.
     */
    private static void transientBudget() throws Exception {
        new EMVProtocolState(); // allocates EmvScratch
        newApplet(EmrtdInstallParameters.ROLE_LDS1, EmrtdTags.DF_NAME_LDS1); // EmrtdScratch + SmScratch
        long emv = staticArrayBytes("card42.emv.EmvScratch");
        long emrtd = staticArrayBytes("card42.emrtd.EmrtdScratch")
                + staticArrayBytes("card42.emrtd.SmScratch");
        long total = emv + emrtd;
        System.out.println();
        System.out.println("  shared transient footprint (allocated at install):");
        System.out.println(String.format("    emv %,d B + emrtd %,d B = %,d B", emv, emrtd, total));
        Asserts.check(total <= 4096, "shared transient footprint fits the J3R180 budget");
        Asserts.check(NvmWrite.transientAllocations() > 0, "shared buffers are transient");
    }

    /** Sum of the lengths of the static array fields of a class. */
    private static long staticArrayBytes(String className) throws Exception {
        Class<?> c = Class.forName(className);
        long n = 0;
        Field[] fields = c.getDeclaredFields();
        for (int i = 0; i < fields.length; i++) {
            if (!Modifier.isStatic(fields[i].getModifiers())) {
                continue;
            }
            fields[i].setAccessible(true);
            Object v = fields[i].get(null);
            if (v != null && v.getClass().isArray()) {
                n += (long) Array.getLength(v) * elementBytes(v.getClass().getComponentType());
            }
        }
        return n;
    }

    private static long elementBytes(Class<?> component) {
        if (component == short.class || component == char.class) {
            return 2;
        }
        if (component == int.class || component == float.class) {
            return 4;
        }
        if (component == long.class || component == double.class) {
            return 8;
        }
        return 1;
    }

    private static void emrtdBacSession() throws Exception {
        final EmrtdApplet applet = preparePassport();
        final APDU apdu = APDU.getInstance();
        final Session session = new Session();

        NvmReport report = new NvmReport("emrtd-bac-session-read5",
                new Object[] { applet }, emrtdSeeds());
        report.step("SELECT", new NvmReport.Step() {
            public void run() throws Exception {
                apdu.loadCommand(header((byte) 0x00, EmrtdTags.INS_SELECT_FILE,
                        (short) 0x04, (short) 0x00), EmrtdTags.DF_NAME_LDS1, (short) 0);
                invoke(applet, onSelect, apdu, apdu.getBuffer());
                Asserts.check(apdu.lastOutgoingLength() > 0, "SELECT returned an FCI");
            }
        });
        report.step("GET CHALLENGE", new NvmReport.Step() {
            public void run() throws Exception {
                plain(applet, apdu, EmrtdTags.INS_GET_CHALLENGE, (short) 0, (short) 0,
                        null, (short) 8);
                Asserts.eq(8, apdu.lastOutgoingLength(), "GET CHALLENGE returns 8 bytes");
            }
        });
        report.step("EXTERNAL AUTHENTICATE (BAC)", new NvmReport.Step() {
            public void run() throws Exception {
                byte[] rndIcc = challenge(applet);
                byte[] command = session.handshake(rndIcc);
                plain(applet, apdu, EmrtdTags.INS_EXTERNAL_AUTHENTICATE,
                        (short) 0, (short) 0, command, (short) 0);
                Asserts.eq(40, apdu.lastResponse().length, "BAC response is E_IC || M_IC");
                session.verifyResponse(apdu.lastResponse(), rndIcc);
                Asserts.check(smEstablished(applet), "secure messaging established");
            }
        });

        for (int i = 0; i < DG_FIDS.length; i++) {
            final short fid = DG_FIDS[i];
            final int total = DG_SIZES[i];
            short sfiBits = (short) (fid & EmrtdTags.SFI_MASK);
            int offset = 0;
            boolean prefix = true;
            while (offset < total) {
                final short want = (short) Math.min(READ_WINDOW, total - offset);
                final int at = offset;
                final short p1 = prefix ? (short) (EmrtdTags.READ_P1_SFI | sfiBits)
                        : (short) ((offset >> 8) & 0x7F);
                final short p2 = prefix ? 0 : (short) (offset & 0xFF);
                report.step(String.format("READ BINARY %04X @%d", fid & 0xFFFF, at),
                        new NvmReport.Step() {
                            public void run() throws Exception {
                                session.readBinary(applet, apdu, p1, p2, want);
                                Asserts.check(apdu.lastOutgoingLength() > 0,
                                        "SM READ BINARY " + Integer.toHexString(fid & 0xFFFF)
                                        + " responded");
                            }
                        });
                offset += want;
                prefix = false;
            }
        }

        report.step("DESELECT (resetSession)", new NvmReport.Step() {
            public void run() throws Exception {
                invoke(applet, onDeselect);
                Asserts.check(!smEstablished(applet), "deselect tore the session down");
            }
        });
        REPORTS.add(report);
        report.print();
    }

    // --- baseline 2: EMV online transaction (component level) ---------------

    private static void emvGpoAndTwoAc() throws Exception {
        final EMVProtocolState state = new EMVProtocolState();
        final EMVStaticData data = new EMVStaticData();
        final OfflineRisk risk = new OfflineRisk();
        final TransactionLog log = new TransactionLog();
        data.applyPaymentConfig(PDOL_CONFIG, (short) 0, (short) PDOL_CONFIG.length);
        risk.setCountLimits((byte) 1, (byte) 3);
        state.setRole(EMVRoles.ROLE_CONTACT);

        final byte[] pdol = new byte[data.getPdolDataLength()];
        Arrays.fill(pdol, (byte) 0x5A);
        // The terminal's first GENERATE AC CDOL1 data, sized from the DOL.
        final byte[] cdol1 = new byte[data.getCDOL1DataLength()];
        for (int i = 0; i < cdol1.length; i++) {
            cdol1[i] = (byte) (i + 1);
        }
        short tvrOffset = data.getCDOL1ValueOffset(TlvTags.TAG_TVR);
        Asserts.check(tvrOffset >= 0, "default CDOL1 carries a TVR");
        // Any TVR bit forces the transaction online: the default IAC-Online is
        // all ones (Defaults.IAC_ONLINE), IAC-Denial all zeroes.
        cdol1[tvrOffset] = (byte) 0x80;
        Asserts.check(pdol.length > 0, "PDOL personalized");

        // Tail of earlier sessions, outside the measurement window: a completed
        // GET PROCESSING OPTIONS, so the in-window SELECT has a session to
        // clear, and offline velocity counters from earlier offline
        // transactions, so the in-window recordOnline() has something to reset
        // (EMV v4.4 Book 3 §10.8).
        short amountOffset = data.getCDOL1ValueOffset(TlvTags.TAG_AMOUNT_AUTHORISED);
        short amountLength = data.getCDOL1ValueLength(TlvTags.TAG_AMOUNT_AUTHORISED);
        state.startNewSession();
        state.setPdolData(pdol, (short) 0, (short) pdol.length);
        state.setGpoDone();
        state.advanceATC();
        risk.recordOffline(cdol1, amountOffset, amountLength);

        NvmReport report = new NvmReport("emv-gpo-two-ac",
                new Object[] { state, data, risk, log }, EMV_SEEDS);

        report.step("SELECT (startNewSession)", new NvmReport.Step() {
            public void run() throws Exception {
                // EMVAppletBase records the interface media on every SELECT;
                // on a contact reader it is already the default and no Util.*
                // call is involved, so this write is invisible to both counters.
                state.setMedia((byte) (APDU.getProtocol() & EMVRoles.MEDIA_MASK));
                state.startNewSession();
                Asserts.check(!state.isGpoDone(), "new session has not done GPO");
            }
        });

        report.step("GET PROCESSING OPTIONS", new NvmReport.Step() {
            public void run() throws Exception {
                // PaymentApplet.processCommand, GET PROCESSING OPTIONS branch.
                short expected = data.getPdolDataLength();
                Asserts.check(state.pdolFits(expected), "PDOL fits the session buffer");
                state.setPdolData(pdol, (short) 0, (short) pdol.length);
                if (!state.isGpoDone()) {
                    state.setGpoDone();
                    state.advanceATC();
                }
                // PaymentApplet calls getGpo() then getGpoLength(); the GPO is
                // cached by (content, role), so the second call must not
                // rebuild the same bytes again.
                byte[] gpo = data.getGpo(state.getRole());
                short gpoLength = data.getGpoLength(state.getRole());
                Asserts.check(gpo != null && gpoLength > 0, "GPO response built");
                Asserts.eq(cdol1.length, data.getCDOL1DataLength(), "CDOL1 data length");
            }
        });

        report.step("GENERATE AC (first, CDOL1 + card decision)", new NvmReport.Step() {
            public void run() throws Exception {
                // AcProcessor.generateFirstAC / cardDecision.
                data.getCDOL1DataLength();
                short offset = data.getCDOL1ValueOffset(TlvTags.TAG_TVR);
                short length = data.getCDOL1ValueLength(TlvTags.TAG_TVR);
                if (offset < 0 || length <= 0) {
                    offset = 0;
                    length = 0;
                }
                byte decided = CardRiskManagement.decide(cdol1, offset, length,
                        data.getIacDenial(), data.getIacDenialLength(),
                        data.getIacOnline(), data.getIacOnlineLength(),
                        data.getIacDefault(), data.getIacDefaultLength());
                if (decided != EMVCodes.AAC_CODE
                        && (risk.forceOnline() || state.isLastOnlineNotCompleted())) {
                    decided = EMVCodes.ARQC_CODE;
                }
                // AcProcessor picks the AC response coding (EMV v4.4 Book 2
                // §5.3.4) from this flag; AcResponseBuilder/EMVCrypto are not
                // linked into the pure-JVM build, so only the flag read is
                // counted here.
                data.isCcdFormat();
                state.setLastOnlineNotCompleted(decided == EMVCodes.ARQC_CODE);
                state.setArqc(cdol1, (short) 0);
                state.setFirstACGenerated(decided);
                Asserts.eq(EMVCodes.ARQC_CODE, state.getFirstACGenerated(),
                        "the transaction is forced online");
                Asserts.eq(2, state.getATC(), "GPO advanced the ATC once");
            }
        });

        report.step("GENERATE AC (second, CDOL2 + log write)", new NvmReport.Step() {
            public void run() throws Exception {
                // AcProcessor.generateSecondAC.
                short cdol2Length = data.getCDOL2DataLength();
                short arcOffset = data.getCDOL2ValueOffset(
                        TlvTags.TAG_AUTHORISATION_RESPONSE_CODE);
                Asserts.check(arcOffset >= 0 && (short) (arcOffset + 2) <= cdol2Length,
                        "the default CDOL2 carries an ARC");
                data.externalAuthenticateSupported(state.getRole());
                state.isIssuerAuthFailed();
                state.isCsuApplied();
                risk.upperExceeded();
                data.isCcdFormat();
                state.setLastOnlineNotCompleted(false);
                state.setSecondACGenerated(EMVCodes.AAC_CODE);
                // TransactionFinalizer.updateOdaFailedPrevious (lines 119-120).
                short offset = data.getCDOL1ValueOffset(TlvTags.TAG_TVR);
                short length = data.getCDOL1ValueLength(TlvTags.TAG_TVR);
                state.setOdaFailedPrevious(false);
                Asserts.check(offset >= 0 && length >= 1, "TVR still addressable");
                // TransactionFinalizer.writeLog (line 146).
                log.write(EMVCodes.AAC_CODE, state, data, cdol1, (short) cdol1.length);
                Asserts.eq(1, log.count(), "one transaction-log record stored");
            }
        });

        report.step("record online (velocity reset)", new NvmReport.Step() {
            public void run() throws Exception {
                // TransactionFinalizer.completeOnlineSession.
                risk.recordOnline();
                Asserts.check(!risk.forceOnline(), "velocity counters reset");
            }
        });

        REPORTS.add(report);
        report.print();
    }

    // --- baseline 3: eMRTD Active Authentication inside SM ------------------

    private static void emrtdActiveAuthentication() throws Exception {
        final EmrtdApplet applet = preparePassport();
        giveActiveAuthenticationKey(applet);
        final APDU apdu = APDU.getInstance();
        final Session session = new Session();

        // The session is established outside the measurement window: this
        // baseline is the cost of one AA command, not of BAC.
        apdu.loadCommand(header((byte) 0x00, EmrtdTags.INS_SELECT_FILE,
                (short) 0x04, (short) 0x00), EmrtdTags.DF_NAME_LDS1, (short) 0);
        invoke(applet, onSelect, apdu, apdu.getBuffer());
        plain(applet, apdu, EmrtdTags.INS_GET_CHALLENGE, (short) 0, (short) 0, null, (short) 8);
        byte[] rndIcc = challenge(applet);
        plain(applet, apdu, EmrtdTags.INS_EXTERNAL_AUTHENTICATE, (short) 0, (short) 0,
                session.handshake(rndIcc), (short) 0);
        session.verifyResponse(apdu.lastResponse(), rndIcc);
        Asserts.check(smEstablished(applet), "secure messaging established for AA");

        final byte[] aaChallenge = Hex.parse("FEDCBA9876543210");
        NvmReport report = new NvmReport("emrtd-aa-inside-sm",
                new Object[] { applet }, emrtdSeeds());
        report.step("INTERNAL AUTHENTICATE (SM, 2048-bit AA)", new NvmReport.Step() {
            public void run() throws Exception {
                session.command(applet, apdu, EmrtdTags.INS_INTERNAL_AUTHENTICATE,
                        (short) 0, (short) 0, aaChallenge, (short) 0);
                // The SM envelope of a 256-byte signature (DO87 + DO99 + DO8E).
                Asserts.check(apdu.lastOutgoingLength() > 256,
                        "the wrapped AA signature is larger than its plaintext");
            }
        });
        REPORTS.add(report);
        report.print();
    }

    // --- passport fixture ---------------------------------------------------

    /**
     * A personalized LDS1 passport: the BAC K_seed and the five data groups of
     * baseline 1.  This is setup, so it runs before a report is constructed and
     * is not part of any measurement.
     */
    private static EmrtdApplet preparePassport() throws Exception {
        EmrtdApplet applet = newApplet(EmrtdInstallParameters.ROLE_LDS1,
                EmrtdTags.DF_NAME_LDS1);
        LdsPerso perso = (LdsPerso) field(applet, EmrtdApplet.class, "perso").get(applet);
        Field seed = LdsPerso.class.getDeclaredField("seed");
        seed.setAccessible(true);
        System.arraycopy(BAC_SEED, 0, (byte[]) seed.get(perso), 0, BAC_SEED.length);
        Field seedSet = LdsPerso.class.getDeclaredField("seedSet");
        seedSet.setAccessible(true);
        seedSet.setBoolean(perso, true);

        LdsCatalog catalog = (LdsCatalog) field(applet, EmrtdApplet.class, "catalog").get(applet);
        for (int i = 0; i < DG_FIDS.length; i++) {
            byte[] content = filler(DG_SIZES[i], (byte) (0xA0 + i));
            catalog.store(DG_FIDS[i], content, (short) 0, (short) content.length);
            LdsFile file = catalog.getBySfi((short) (DG_FIDS[i] & EmrtdTags.SFI_MASK));
            Asserts.check(file != null && file.getLength() == DG_SIZES[i],
                    "EF " + Integer.toHexString(DG_FIDS[i] & 0xFFFF) + " personalized");
        }
        return applet;
    }

    private static void giveActiveAuthenticationKey(EmrtdApplet applet) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair pair = generator.generateKeyPair();
        RSAPrivateKey privateKey = (RSAPrivateKey) pair.getPrivate();
        byte[] modulus = unsigned(privateKey.getModulus());
        byte[] exponent = unsigned(privateKey.getPrivateExponent());
        AaCrypto aa = (AaCrypto) field(applet, EmrtdApplet.class, "aa").get(applet);
        aa.setPrivateKey(modulus, (short) 0, (short) modulus.length,
                exponent, (short) 0, (short) exponent.length);
        Asserts.check(aa.isInitialized(), "AA private key installed");
    }

    // --- BAC / secure messaging on the host side ----------------------------

    /** Host-side view of one BAC session: session keys, SSC and the SM wrapper. */
    private static final class Session {

        private byte[] kEnc;
        private byte[] kMac;
        private Iso7816Sm sm;

        /**
         * Builds E_IFD || M_IFD for the handshake (ICAO Doc 9303-11 §4.3.1
         * steps 2-4); the card's RND.ICC comes from the GET CHALLENGE that
         * opened the window.
         */
        byte[] handshake(byte[] rndIcc) throws Exception {
            kEnc = Bac.deriveKey(BAC_SEED, 1);
            kMac = Bac.deriveKey(BAC_SEED, 2);
            byte[] s = new byte[32];
            System.arraycopy(RND_IFD, 0, s, 0, 8);
            System.arraycopy(rndIcc, 0, s, 8, 8);
            System.arraycopy(K_IFD, 0, s, 16, 16);
            byte[] eIfd = Iso9797.des3CbcEncrypt(kEnc, s);
            byte[] mIfd = Iso9797.mac(kMac, eIfd);
            byte[] command = Arrays.copyOf(eIfd, 40);
            System.arraycopy(mIfd, 0, command, 32, 8);
            return command;
        }

        /** Checks E_IC/M_IC and derives the session keys and initial SSC. */
        void verifyResponse(byte[] response, byte[] rndIcc) throws Exception {
            byte[] eIc = Arrays.copyOf(response, 32);
            Asserts.bytes(Iso9797.mac(kMac, eIc),
                    Arrays.copyOfRange(response, 32, 40), "M_IC verifies");
            byte[] s2 = Iso9797.des3CbcDecrypt(kEnc, new byte[8], eIc);
            byte[] kIc = Arrays.copyOfRange(s2, 16, 32);
            byte[] sessionSeed = Bac.sessionSeed(K_IFD, kIc);
            long ssc = (uint32(rndIcc, 4) << 32) | uint32(RND_IFD, 4);
            sm = new Iso7816Sm(Bac.deriveKey(sessionSeed, 1),
                    Bac.deriveKey(sessionSeed, 2), ssc);
        }

        /** One SM-wrapped READ BINARY (ICAO Doc 9303-11 §9.8). */
        void readBinary(EmrtdApplet applet, APDU apdu, short p1, short p2, short le)
                throws Exception {
            command(applet, apdu, EmrtdTags.INS_READ_BINARY, p1, p2, null, le);
        }

        /** One SM-wrapped command with the given data field and Le. */
        void command(EmrtdApplet applet, APDU apdu, byte ins, short p1, short p2,
                byte[] data, short le) throws Exception {
            byte[] dataField = sm.wrapCommand(0x00, ins, p1, p2, data, le);
            apdu.loadCommand(header((byte) 0x0C, ins, p1, p2), dataField, (short) 0);
            invoke(applet, processCommand, apdu, apdu.getBuffer());
            // A real reader unwraps every response, which also advances its copy
            // of the send sequence counter (ICAO Doc 9303-11 §9.8.2).  Skipping
            // it here would leave the host one counter behind, and the next
            // command's MAC would not verify.
            sm.unwrapResponse(apdu.lastResponse(), null);
        }
    }

    // --- small helpers ------------------------------------------------------

    private static byte[] challenge(EmrtdApplet applet) throws Exception {
        return (byte[]) field(applet, EmrtdApplet.class, "challenge").get(applet);
    }

    private static boolean smEstablished(EmrtdApplet applet) throws Exception {
        return field(applet, EmrtdApplet.class, "smEstablished").getBoolean(applet);
    }

    private static void plain(EmrtdApplet applet, APDU apdu, byte ins, short p1, short p2,
            byte[] data, short le) throws Exception {
        apdu.loadCommand(header((byte) 0x00, ins, p1, p2), data, le);
        invoke(applet, processCommand, apdu, apdu.getBuffer());
    }

    private static byte[] header(byte cla, byte ins, short p1, short p2) {
        return new byte[] { cla, ins, (byte) p1, (byte) p2 };
    }

    private static byte[] filler(int length, byte tag) {
        byte[] b = new byte[length];
        for (int i = 0; i < length; i++) {
            b[i] = (byte) (tag + i);
        }
        return b;
    }

    private static long uint32(byte[] buf, int off) {
        return ((long) (buf[off] & 0xFF) << 24) | ((long) (buf[off + 1] & 0xFF) << 16)
                | ((long) (buf[off + 2] & 0xFF) << 8) | (buf[off + 3] & 0xFF);
    }

    private static byte[] unsigned(BigInteger value) {
        byte[] raw = value.toByteArray();
        if (raw.length > 1 && raw[0] == 0) {
            byte[] trimmed = new byte[raw.length - 1];
            System.arraycopy(raw, 1, trimmed, 0, trimmed.length);
            return trimmed;
        }
        return raw;
    }

    private static EmrtdApplet newApplet(byte role, byte[] dfName) throws Exception {
        Constructor<EmrtdApplet> ctor = EmrtdApplet.class.getDeclaredConstructor(
                byte.class, byte[].class, short.class);
        ctor.setAccessible(true);
        return ctor.newInstance(role, dfName, (short) dfName.length);
    }

    private static Field field(Object target, Class<?> owner, String name) throws Exception {
        Field f = owner.getDeclaredField(name);
        f.setAccessible(true);
        return f;
    }

    /** Invokes a card method, unwrapping the ISOException the card threw. */
    private static Object invoke(Object target, Method method, Object... args) throws Exception {
        try {
            return method.invoke(target, args);
        } catch (InvocationTargetException e) {
            Throwable cause = e.getCause();
            if (cause instanceof Exception) {
                throw (Exception) cause;
            }
            if (cause instanceof Error) {
                throw (Error) cause;
            }
            throw e;
        }
    }
}
