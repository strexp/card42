package card42.emrtd;

import card42.common.ApduIo;
import card42.common.AppletBase;

import javacard.framework.APDU;
import javacard.framework.APDUException;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;
import javacard.security.RandomData;

import javacardx.apdu.ExtendedLength;

import org.globalplatform.Personalization;

/* card42-emrtd LDS1/LDS2 application (ICAO Doc 9303-10/-11).
 *
 * The instance AID selects the role (EmrtdInstallParameters): the LDS1 DF name
 * is the first-phase eMRTD application (LDS1 file system, BAC, ISO/IEC 7816-4
 * secure messaging, Active Authentication) and the LDS2 DF names are the
 * Travel Records, Visa Records and Additional Biometrics applications
 * (record EFs, APPEND/READ/SEARCH RECORD, FMM).  Chip Authentication (ECDH)
 * re-keys the secure-messaging session for either role.
 *
 * Before BAC the commands are served in the clear; once BAC has succeeded the
 * terminal wraps every command with SM (CLA | 0x0C) and the applet wraps every
 * response.
 *
 * @author card42
 */

public final class EmrtdApplet extends AppletBase
        implements Personalization, ExtendedLength {

    /* Session state, accessed by the command classes in this package. */
    final byte role;
    final byte[] dfName;
    final short dfNameLength;
    final LdsCatalog catalog;
    final Lds2FileSystem lds2;
    final RandomData random;
    final BacCrypto bac;
    final AaCrypto aa;
    /** 3DES/BAC secure-messaging wrapper; also the default before PACE. */
    final SecureMessaging sm3des;
    /** AES/PACE secure-messaging wrapper. */
    final SecureMessaging smAes;
    /** The wrapper of the active session: 3DES unless PACE negotiated AES. */
    SecureMessaging sm;
    final LdsPerso perso;
    final Lds2Perso lds2Perso;
    final ChipAuth chipAuth;
    final Pace pace;
    /** Terminal Authentication state; created for every eMRTD role. */
    final TaContext ta;

    /* Session keys, counters and the challenge are the package-shared
     * CLEAR_ON_DESELECT buffers of {@link EmrtdScratch}: they were per-instance
     * persistent arrays, so every session re-derived them into EEPROM and every
     * deselection zero-filled them back (docs/specs/common/risks.md §2). */
    final byte[] challenge;
    boolean challengeValid;

    final byte[] kenc;
    final byte[] kmac;
    final byte[] ksEnc;
    final byte[] ksMac;
    final byte[] ssc;
    /** True once BAC or Chip Authentication has established secure messaging. */
    boolean smEstablished;
    /**
     * True once PACE has completed on this session.  LDS2 applications and
     * EF.CardSecurity require PACE (ICAO Doc 9303-11 §1.2 Note 2 / §4.2 step 3,
     * Doc 9303-10 §3.11.4 Table 34); BAC alone is not enough.
     */
    boolean paceDone;
    /**
     * The current master-file EF (EF.CardAccess/EF.CardSecurity) selected in an
     * LDS2 session, or null when a DF file is current.  The MF files live in
     * {@link LdsMfStore}, not in the DF (Doc 9303-10 §3.11.3/§3.11.4).
     */
    Lds2TransparentFile selectedMf;
    /**
     * True when the last SELECT selected the master file in the LDS1 role.  A
     * following SELECT FILE of FID {@code 011D} then resolves to the
     * master-file EF.CardSecurity rather than the DF's EF.SOD: both share FID
     * {@code 011D}, but EF.CardSecurity lives in the MF (Doc 9303-10 §3.11.4)
     * while EF.SOD lives in the LDS1 DF (Doc 9303-10 §4.6.2).
     */
    boolean atMf;

    /* Chip Authentication: the new session keys are applied after the response
     * to the authenticating command has been wrapped with the old keys. */
    final byte[] caEnc;
    final byte[] caMac;
    boolean caPending;
    /** True when the pending CA profile is AES-128 (SM switches to the AES wrapper). */
    boolean caAes;

    /* Plaintext command data and response data (SM unwrap/wrap).  Package-shared
     * transient buffers (CLEAR_ON_DESELECT, allocated once at install), so no
     * command allocates a transient array and the repeated READ BINARY path no
     * longer writes hundreds of bytes to EEPROM (docs/specs/common/risks.md).
     * {@link EmrtdScratch#io} doubles as the wrapped SM response buffer: a
     * 256-byte AA signature wrapped by SM is ~290 bytes and does not fit the
     * JCRE APDU buffer, and it cannot share with {@code response} (which wrap
     * reads while writing the envelope).  The command data is consumed by
     * dispatch before wrap writes io, so the two uses of io do not overlap. */
    final byte[] plain;
    final byte[] response;

    /* Personalization.  The DGI sequence is applied incrementally as each
     * STORE DATA block arrives (a per-instance DgiStream drives LdsPerso /
     * Lds2Perso), so there is no whole-sequence buffer: peak memory is one
     * STORE DATA payload and a large DG2 face image costs only the persistent
     * pages it actually uses. */
    private short expectedBlock;

    private EmrtdApplet(byte role, byte[] dfName, short dfNameLength) {
        this.role = role;
        this.dfName = new byte[(short) 16];
        Util.arrayCopyNonAtomic(dfName, (short) 0, this.dfName, (short) 0, dfNameLength);
        this.dfNameLength = dfNameLength;
        // Allocate the package-shared transient session buffers and the SM
        // scratch once, at install: no command path allocates a transient array
        // (docs/specs/common/risks.md).  Order: io/response then SmScratch
        // (used by every secure-messaging command) get the transient budget
        // first, then the session state.  raw is persistent (see EmrtdScratch).
        EmrtdScratch.init();
        SmScratch.init();
        MacEngines.init();
        KdfEngines.init();
        EmrtdScratch.initSession();
        EmrtdScratch.initExtended();
        plain = EmrtdScratch.io;
        response = EmrtdScratch.response;
        challenge = EmrtdScratch.challenge;
        kenc = EmrtdScratch.kenc;
        kmac = EmrtdScratch.kmac;
        ksEnc = EmrtdScratch.ksEnc;
        ksMac = EmrtdScratch.ksMac;
        ssc = EmrtdScratch.ssc;
        caEnc = EmrtdScratch.caEnc;
        caMac = EmrtdScratch.caMac;
        boolean lds1Role = role == EmrtdInstallParameters.ROLE_LDS1;
        // Only the LDS1 instance uses the LDS1 catalog, BAC and AA crypto; an
        // LDS2 instance (Travel/Visa/Biometrics) would otherwise pay ~1.5 KB of
        // persistent heap it never touches (LdsFileSystem's 19 LdsFile objects,
        // LdsPerso's 536-byte key scratch and the 2048-bit AA key), which is
        // exactly the margin four eMRTD instances need on a J3R180
        // (docs/specs/common/risks.md §2).
        catalog = lds1Role ? new LdsCatalog() : null;
        lds2 = role == EmrtdInstallParameters.ROLE_LDS2_TRAVEL ? Lds2FileSystem.travel()
                : role == EmrtdInstallParameters.ROLE_LDS2_VISA ? Lds2FileSystem.visa()
                : role == EmrtdInstallParameters.ROLE_LDS2_BIOMETRICS ? Lds2FileSystem.biometrics()
                : null;
        random = KdfEngines.random();
        bac = lds1Role ? new BacCrypto() : null;
        aa = lds1Role ? new AaCrypto((short) 2048, AaCrypto.AA_SHA1) : null;
        sm3des = new Iso7816Sm();
        smAes = new Iso7816SmAes();
        sm = sm3des;
        chipAuth = new ChipAuth();
        pace = new Pace();
        ta = new TaContext();
        // Build the TA verification engines at install (not inside the Security
        // Domain's personalization transaction, see docs/specs/common/risks.md §4).
        TaContext.ensureKeys();
        perso = lds1Role ? new LdsPerso(catalog, aa, chipAuth, pace, ta) : null;
        lds2Perso = lds2 == null ? null : new Lds2Perso(lds2, chipAuth, pace, ta);
        expectedBlock = 0;
        // EF.DIR lists every application the card hosts (Doc 9303-10 §3.11.2).
        LdsMfStore.addDirectoryEntry(dfName, dfNameLength);
    }

    public static void install(byte[] buffer, short offset, byte length) {
        EmrtdInstallParameters params = new EmrtdInstallParameters();
        params.capture(buffer, offset, length);
        byte role = params.role();
        EmrtdApplet applet = new EmrtdApplet(role, params.aid(), params.aidLength());
        applet.register(buffer, (short) (offset + 1), buffer[offset]);
    }

    // --- SELECT / dispatch ---------------------------------------------------

    protected void onSelect(APDU apdu, byte[] apduBuffer) {
        // Selecting the application resets the secure-messaging session (ISO/IEC
        // 7816-4, Doc 9303-11): a prior BAC/PACE must not leak into the next one.
        resetSession();
        // FCI: 6F { 84 <DF name> } (Doc 9303-10 §3.6.1.2).
        short p = writeFci(apduBuffer, (short) 0);
        ApduIo.send(apdu, apduBuffer, (short) 0, p);
    }

    /** Writes {@code 6F { 84 <DF name> }} into buf[off..); returns the new offset. */
    private short writeFci(byte[] buf, short off) {
        buf[off++] = (byte) 0x6F;
        buf[off++] = (byte) (dfNameLength + 2);
        buf[off++] = (byte) 0x84;
        buf[off++] = (byte) dfNameLength;
        Util.arrayCopyNonAtomic(dfName, (short) 0, buf, off, dfNameLength);
        return (short) (off + dfNameLength);
    }

    /** eMRTD uses INS=A4 for SELECT FILE, so it must reach processCommand. */
    protected boolean rejectUnmatchedSelect() {
        return false;
    }

    /**
     * Handles a SELECT by DF name that arrives inside secure messaging.
     *
     * <p>A JCRE matches a SELECT-by-name against the applet AID before the
     * applet runs, but it cannot match a SELECT whose data field is an SM
     * envelope.  A conformant reader (JMRTD's {@code sendSelectApplet(true)})
     * performs PACE first and then wraps the SELECT of the application; the
     * unwrapped name reaches here.  A matching name returns the FCI and keeps
     * the established SM session, a different name is 6A82.
     */
    short selectByName(byte[] data, short off, short len) {
        if (len != dfNameLength
                || Util.arrayCompare(data, off, dfName, (short) 0, dfNameLength) != 0) {
            ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
        }
        // FCI: 6F { 84 <DF name> } (Doc 9303-10 §3.6.1.2).
        return writeFci(response, (short) 0);
    }

    /** Clears the secure-messaging session state on application selection. */
    private void resetSession() {
        smEstablished = false;
        paceDone = false;
        selectedMf = null;
        atMf = false;
        if (lds2 != null) {
            lds2.clearSelection();
        }
        challengeValid = false;
        caPending = false;
        caAes = false;
        Util.arrayFillNonAtomic(kenc, (short) 0, (short) 16, (byte) 0);
        Util.arrayFillNonAtomic(kmac, (short) 0, (short) 16, (byte) 0);
        Util.arrayFillNonAtomic(ksEnc, (short) 0, (short) 16, (byte) 0);
        Util.arrayFillNonAtomic(ksMac, (short) 0, (short) 16, (byte) 0);
        Util.arrayFillNonAtomic(ssc, (short) 0, (short) 8, (byte) 0);
        // Chip Authentication staged keys (applied after the authenticating
        // response): clear them too so no session key survives.
        Util.arrayFillNonAtomic(caEnc, (short) 0, (short) 16, (byte) 0);
        Util.arrayFillNonAtomic(caMac, (short) 0, (short) 16, (byte) 0);
        sm3des.reset();
        smAes.reset();
        sm = sm3des;
        pace.reset();
        chipAuth.reset();
        if (ta != null) {
            ta.clearSession();
        }
    }

    /**
     * Selects the secure-messaging wrapper of the session: the AES profile after
     * a PACE negotiation that chose it, the 3DES profile otherwise (BAC, PACE
     * 3DES or Chip Authentication).  Called by the MSE handler and BAC.
     */
    void useSecureMessaging(boolean aes) {
        sm = aes ? smAes : sm3des;
    }

    /**
     * Zeroizes the session-derived material when the applet is deselected, so no
     * BAC/PACE/Chip Authentication key persists in EEPROM between sessions
     * (Doc 9303-11 §9.8).  The personalized files and keys are untouched.
     */
    protected void onDeselect() {
        resetSession();
    }

    protected void processCommand(APDU apdu, byte[] apduBuffer) {
        byte ins = apduBuffer[ISO7816.OFFSET_INS];
        boolean smActive = smEstablished
                && (apduBuffer[ISO7816.OFFSET_CLA] & SecureMessaging.SM_CLA_MASK) != 0;
        if (smEstablished && !smActive) {
            // A command APDU without secure messaging releases the session
            // (BSI TR-03110-3 F.6 Secure Messaging Termination /
            // Doc 9303-11 §9.8.3): the card aborts SM and
            // refuses the plaintext command with 6982.
            resetSession();
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
        short incoming = apdu.setIncomingAndReceive();
        // 5 for a short APDU, 7 for an extended one (the applet implements
        // ExtendedLength so the JCRE delivers extended APDUs).
        short cdataOff = apdu.getOffsetCdata();
        short rawLen = apdu.getIncomingLength();

        // The READ BINARY / READ RECORD hot path uses the JCRE buffer in place:
        // a command whose data (header included) fits the buffer is already
        // complete there, exactly as before extended-command support, so no RAM
        // scratch is touched per chunk.  Only an extended-length command whose
        // secure-messaging envelope exceeds the JCRE buffer is assembled in
        // several chunks into EmrtdScratch.raw; the 4 header bytes stay at
        // offset 0 (the SM unwrap reads CLA/INS/P1/P2 there) and the data
        // starts at offset 4.
        // (APDU.waitExtension must come after the last receiveBytes: the J3R180
        // rejects receiveBytes once a wait-extension has been requested.)
        byte[] cmd;
        short cmdOff;
        if (rawLen <= (short) (apduBuffer.length - cdataOff) && incoming >= rawLen) {
            cmd = apduBuffer;
            cmdOff = cdataOff;
        } else {
            cmd = receiveExtended(apdu, apduBuffer, cdataOff, incoming, rawLen);
            cmdOff = (short) 4;
        }
        requestMoreTime(ins);

        byte[] data;
        short dataOff;
        short dataLen;
        short le;
        if (smActive) {
            data = plain;
            dataOff = 0;
            dataLen = sm.unwrap(ksEnc, ksMac, ssc, cmd, cmdOff, rawLen, plain, (short) 0);
            le = sm.getLe();
        } else {
            data = cmd;
            dataOff = cmdOff;
            dataLen = rawLen;
            le = rawLen == 0 ? readLe(apduBuffer, cdataOff) : -1;
        }

        short respLen;
        try {
            respLen = dispatch(ins, data, dataOff, dataLen, le, apduBuffer);
        } catch (ISOException e) {
            if (!smActive) {
                throw e;
            }
            // An error status word is part of the response and must be
            // protected by secure messaging like any other (Doc 9303-11 §9.8).
            short n = sm.wrap(ksEnc, ksMac, ssc, response, (short) 0,
                    e.getReason(), plain, (short) 0);
            ApduIo.send(apdu, plain, (short) 0, n);
            return;
        }

        if (smActive) {
            short n = sm.wrap(ksEnc, ksMac, ssc, response, respLen,
                    (short) 0x9000, plain, (short) 0);
            ApduIo.send(apdu, plain, (short) 0, n);
        } else {
            ApduIo.send(apdu, response, (short) 0, respLen);
        }
        if (caPending) {
            // Chip Authentication: switch the SM session keys for the next
            // command, after this response was wrapped with the old ones.  The
            // profile is ECDH-3DES (MSE:Set KAT) or ECDH-AES-128 (MSE:Set AT +
            // GENERAL AUTHENTICATE); the wrapper follows the negotiated cipher.
            Util.arrayCopyNonAtomic(caEnc, (short) 0, ksEnc, (short) 0, (short) 16);
            Util.arrayCopyNonAtomic(caMac, (short) 0, ksMac, (short) 0, (short) 16);
            Util.arrayFillNonAtomic(ssc, (short) 0, (short) 8, (byte) 0);
            sm = caAes ? smAes : sm3des;
            smEstablished = true;
            caPending = false;
        }
    }

    /**
     * Asks the card access device for more processing time before a command
     * whose cryptography can exceed the contactless block waiting time: the
     * PACE / Chip Authentication EC operations, the RSA Active Authentication
     * signature and the BAC handshake.  READ BINARY is deliberately excluded
     * (the native MAC and the shared transient scratch keep it well under the
     * timeout); a WTX on every read would add a radio round trip per chunk.
     */
    private static void requestMoreTime(byte ins) {
        switch (ins) {
        case EmrtdTags.INS_GENERAL_AUTHENTICATE:
        case EmrtdTags.INS_INTERNAL_AUTHENTICATE:
        case EmrtdTags.INS_EXTERNAL_AUTHENTICATE:
        case EmrtdTags.INS_MANAGE_SECURITY_ENVIRONMENT:
        case EmrtdTags.INS_PSO:
            try {
                APDU.waitExtension();
            } catch (APDUException e) {
                // The CAD may not need or support the extension; the command
                // still runs, it is just not given extra waiting time.
            }
            break;
        default:
            break;
        }
    }

    /**
     * The Le field of a case-2 APDU: the short form byte at
     * {@code OFFSET_LC}, or the two extended length bytes after the
     * {@code 0x00} marker when {@code cdataOff} is the extended offset.
     */
    private static short readLe(byte[] apduBuffer, short cdataOff) {
        if (cdataOff == ISO7816.OFFSET_CDATA) {
            return (short) (apduBuffer[ISO7816.OFFSET_LC] & 0xFF);
        }
        return (short) (((apduBuffer[ISO7816.OFFSET_LC + 1] & 0xFF) << 8)
                | (apduBuffer[ISO7816.OFFSET_LC + 2] & 0xFF));
    }

    /**
     * Receives an extended-length command into the shared scratch
     * ({@link EmrtdScratch#raw}) and returns it.  The first
     * {@code getIncomingLength()} bytes after the 4 header bytes are the data.
     * Called only when the command does not fit the JCRE buffer (e.g. a command
     * whose secure-messaging envelope exceeds it); the remainder is pulled with
     * {@code receiveBytes}.
     */
    private static byte[] receiveExtended(APDU apdu, byte[] apduBuffer, short cdataOff,
                                          short firstChunk, short lc) {
        byte[] target = EmrtdScratch.raw;
        if (target == null || lc < 0 || (short) (lc + 4) > (short) target.length) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        // Keep the 4 header bytes at offset 0 (the SM unwrap reads CLA/INS/P1/P2
        // from there); the command data follows at offset 4.
        Util.arrayCopyNonAtomic(apduBuffer, (short) 0, target, (short) 0, (short) 4);
        short received = firstChunk > lc ? lc : firstChunk;
        if (received > 0) {
            Util.arrayCopyNonAtomic(apduBuffer, cdataOff, target, (short) 4, received);
        }
        while (received < lc) {
            short more = apdu.receiveBytes(cdataOff);
            if (more <= 0) {
                break;
            }
            if ((short) (received + more) > lc) {
                more = (short) (lc - received);
            }
            Util.arrayCopyNonAtomic(apduBuffer, cdataOff, target, (short) (4 + received), more);
            received += more;
        }
        if (received < lc) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        return target;
    }

    /** Runs one command, writing its response data to {@link #response}. */
    private short dispatch(byte ins, byte[] data, short off, short len, short le,
                           byte[] apduBuffer) {
        if (role != EmrtdInstallParameters.ROLE_LDS1) {
            switch (ins) {
            case EmrtdTags.INS_SELECT_FILE:
                return Lds2File.select(this, data, off, len, apduBuffer);
            case EmrtdTags.INS_READ_BINARY:
                return Lds2File.readBinary(this, le, apduBuffer);
            case EmrtdTags.INS_READ_RECORD:
                return Lds2Record.readRecord(this, apduBuffer[ISO7816.OFFSET_P1],
                        apduBuffer[ISO7816.OFFSET_P2], le);
            case EmrtdTags.INS_APPEND_RECORD:
                return Lds2Record.appendRecord(this, apduBuffer[ISO7816.OFFSET_P1],
                        apduBuffer[ISO7816.OFFSET_P2], data, off, len);
            case EmrtdTags.INS_SEARCH_RECORD:
                return Lds2Record.searchRecord(this, apduBuffer[ISO7816.OFFSET_P2],
                        data, off, len);
            case EmrtdTags.INS_FILE_MEMORY_MANAGEMENT:
                return Lds2Record.fileMemoryManagement(this, apduBuffer[ISO7816.OFFSET_P1],
                        apduBuffer[ISO7816.OFFSET_P2], data, off, len);
            case EmrtdTags.INS_UPDATE_BINARY_ODD:
                return Lds2Record.updateBinary(this, data, off, len);
            case EmrtdTags.INS_ACTIVATE:
                return Lds2Record.activate(this, apduBuffer[ISO7816.OFFSET_P1],
                        apduBuffer[ISO7816.OFFSET_P2]);
            case EmrtdTags.INS_MANAGE_SECURITY_ENVIRONMENT:
                return Mse.process(this, apduBuffer[ISO7816.OFFSET_P1],
                        apduBuffer[ISO7816.OFFSET_P2], data, off, len);
            case EmrtdTags.INS_GENERAL_AUTHENTICATE:
                return Mse.generalAuthenticate(this, data, off, len);
            case EmrtdTags.INS_GET_CHALLENGE:
                return GetChallenge.process(this);
            case EmrtdTags.INS_EXTERNAL_AUTHENTICATE:
                return ExternalAuthenticate.process(this, data, off, len);
            case EmrtdTags.INS_PSO:
                return PsoVerifyCertificate.process(this, data, off, len);
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
                return 0; // unreachable
            }
        }
        switch (ins) {
        case EmrtdTags.INS_SELECT_FILE:
            return SelectFile.process(this, data, off, len, apduBuffer);
        case EmrtdTags.INS_READ_BINARY:
            return ReadBinary.process(this, le, apduBuffer);
        case EmrtdTags.INS_GET_CHALLENGE:
            return GetChallenge.process(this);
        case EmrtdTags.INS_EXTERNAL_AUTHENTICATE:
            return ExternalAuthenticate.process(this, data, off, len);
        case EmrtdTags.INS_INTERNAL_AUTHENTICATE:
            return InternalAuthenticate.process(this, data, off, len);
        case EmrtdTags.INS_MANAGE_SECURITY_ENVIRONMENT:
            return Mse.process(this, apduBuffer[ISO7816.OFFSET_P1],
                    apduBuffer[ISO7816.OFFSET_P2], data, off, len);
        case EmrtdTags.INS_PSO:
            return PsoVerifyCertificate.process(this, data, off, len);
        case EmrtdTags.INS_GENERAL_AUTHENTICATE:
            return Mse.generalAuthenticate(this, data, off, len);
        default:
            ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
            return 0; // unreachable
        }
    }

    /**
     * LDS2 access control (ICAO Doc 9303-11 §1.2 Note 2 / §4.2 step 3): the
     * card MUST require PACE for LDS2 applications and for EF.CardSecurity
     * (Doc 9303-10 §3.11.4 Table 34).  Without PACE the command is refused with
     * 6982.
     */
    void requirePace() {
        if (!paceDone) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
    }

    /** LDS2 read authorization bit (b1 of the application authorization byte). */
    static final byte LDS2_READ_BIT = 0;
    /** LDS2 append authorization bit (b2 of the application authorization byte). */
    static final byte LDS2_APPEND_BIT = 1;
    /** Travel/Visa EF.Certificates read authorization bit (b3, Doc 9303-10 Table 96/97). */
    static final byte LDS2_CERT_READ_BIT = 2;
    /** Travel/Visa EF.Certificates append authorization bit (b4). */
    static final byte LDS2_CERT_APPEND_BIT = 3;
    /** ePassport CHAT bit b1: read EF.DG3 (fingerprints). */
    static final byte EPASS_DG3_BIT = 0;
    /** ePassport CHAT bit b2: read EF.DG4 (irises). */
    static final byte EPASS_DG4_BIT = 1;

    /**
     * The LDS2 read authorization bit of a DF file: the Travel/Visa
     * EF.Certificates use b3 while EF.EntryRecords/ExitRecords/VisaRecords and
     * the Additional Biometrics files use b1 (Doc 9303-10 §5.4.2 Table 96/97/98).
     */
    byte lds2ReadBit(short fid) {
        return lds2Certificates(fid) ? LDS2_CERT_READ_BIT : LDS2_READ_BIT;
    }

    /** The LDS2 append authorization bit of a DF file (b4 for Travel/Visa EF.Certificates). */
    byte lds2AppendBit(short fid) {
        return lds2Certificates(fid) ? LDS2_CERT_APPEND_BIT : LDS2_APPEND_BIT;
    }

    /** True for the Travel/Visa EF.Certificates (011A), whose bits are b3/b4. */
    private boolean lds2Certificates(short fid) {
        return fid == EmrtdTags.FID_CERTIFICATES
                && (role == EmrtdInstallParameters.ROLE_LDS2_TRAVEL
                        || role == EmrtdInstallParameters.ROLE_LDS2_VISA);
    }

    /**
     * LDS1 DG3/DG4 access control (ICAO Doc 9303-10 §5.4.2 Table 96/97): once a
     * Terminal Authentication trust point is personalized, reading EF.DG3/DG4
     * requires a successful Terminal Authentication holding the matching
     * ePassport CHAT bit; a card without a trust point keeps the PACE-only
     * (development) behaviour.  Other data groups stay PACE-only.
     */
    void requireLds1ChatAccess(short fid) {
        if (ta == null || !ta.hasTrustPoint()) {
            return;
        }
        byte bit;
        if (fid == EmrtdTags.FID_DG3) {
            bit = EPASS_DG3_BIT;
        } else if (fid == EmrtdTags.FID_DG4) {
            bit = EPASS_DG4_BIT;
        } else {
            return;
        }
        if (!ta.granted((short) 0, bit)) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
    }

    /** The application authorization index for this LDS2 instance (1..3). */
    private short lds2ApplicationIndex() {
        switch (role) {
        case EmrtdInstallParameters.ROLE_LDS2_TRAVEL:
            return (short) 1;
        case EmrtdInstallParameters.ROLE_LDS2_VISA:
            return (short) 2;
        case EmrtdInstallParameters.ROLE_LDS2_BIOMETRICS:
            return (short) 3;
        default:
            return (short) 0;
        }
    }

    /**
     * LDS2 access control (ICAO Doc 9303-11 §1.2 Note 2 / Doc 9303-10 §5.4):
     * PACE is required, and once a Terminal Authentication trust point is
     * personalized the terminal must hold the requested authorization bit for
     * this application.  A card without a trust point enforces PACE only
     * (development configuration).
     */
    void requireLds2Access(byte bit) {
        requirePace();
        if (ta != null && ta.hasTrustPoint() && !ta.granted(lds2ApplicationIndex(), bit)) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
    }

    // --- GP personalization (STORE DATA forwarded by the Security Domain) ----

    public short processData(byte[] inBuf, short inOff, short inLen,
                             byte[] outBuf, short outOff) {
        short p1 = (short) (inBuf[(short) (inOff + ISO7816.OFFSET_P1)] & 0xFF);
        short p2 = (short) (inBuf[(short) (inOff + ISO7816.OFFSET_P2)] & 0xFF);
        short lc = (short) (inBuf[(short) (inOff + ISO7816.OFFSET_LC)] & 0xFF);
        short dataOff = (short) (inOff + ISO7816.OFFSET_CDATA);
        if (inLen < (short) (dataOff - inOff + lc)) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        if (p2 == 0) {
            expectedBlock = 0;
            if (role == EmrtdInstallParameters.ROLE_LDS1) {
                perso.reset();
            } else {
                lds2Perso.reset();
            }
        }
        if (p2 != expectedBlock) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        // Apply the block straight away: a DGI value (a DG2 face image in
        // particular) may span many STORE DATA blocks, and streaming it into
        // its target file keeps memory bounded by the block instead of the
        // whole sequence (see LdsPerso / Lds2Perso / DgiStream).
        if (role == EmrtdInstallParameters.ROLE_LDS1) {
            perso.feed(inBuf, dataOff, lc);
        } else {
            lds2Perso.feed(inBuf, dataOff, lc);
        }
        if ((p1 & 0x80) == 0) {
            expectedBlock++;
            return 0;
        }
        if (role == EmrtdInstallParameters.ROLE_LDS1) {
            perso.finish();
        } else {
            lds2Perso.finish();
        }
        return 0;
    }
}
