package card42.emrtd;

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

    final byte[] challenge = new byte[8];
    boolean challengeValid;

    final byte[] kenc = new byte[16];
    final byte[] kmac = new byte[16];
    final byte[] ksEnc = new byte[16];
    final byte[] ksMac = new byte[16];
    final byte[] ssc = new byte[8];
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

    /* Chip Authentication: the new session keys are applied after the response
     * to the authenticating command has been wrapped with the old keys. */
    final byte[] caEnc = new byte[16];
    final byte[] caMac = new byte[16];
    boolean caPending;

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
        // (docs/specs/common/risks.md).
        EmrtdScratch.init();
        SmScratch.init();
        plain = EmrtdScratch.io;
        response = EmrtdScratch.response;
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
        random = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        bac = lds1Role ? new BacCrypto() : null;
        aa = lds1Role ? new AaCrypto((short) 2048, AaCrypto.AA_SHA1) : null;
        sm3des = new Iso7816Sm();
        smAes = new Iso7816SmAes();
        sm = sm3des;
        chipAuth = new ChipAuth();
        pace = new Pace();
        perso = lds1Role ? new LdsPerso(catalog, aa, chipAuth, pace) : null;
        lds2Perso = lds2 == null ? null : new Lds2Perso(lds2, chipAuth, pace);
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
        byte[] fci = apduBuffer;
        short p = 0;
        fci[p++] = (byte) 0x6F;
        fci[p++] = (byte) (dfNameLength + 2);
        fci[p++] = (byte) 0x84;
        fci[p++] = (byte) dfNameLength;
        Util.arrayCopyNonAtomic(dfName, (short) 0, fci, p, dfNameLength);
        p += dfNameLength;
        apdu.setOutgoing();
        apdu.setOutgoingLength(p);
        apdu.sendBytes((short) 0, p);
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
        if (len != dfNameLength) {
            ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
        }
        for (short i = 0; i < dfNameLength; i++) {
            if (data[(short) (off + i)] != dfName[i]) {
                ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
            }
        }
        // FCI: 6F { 84 <DF name> } (Doc 9303-10 §3.6.1.2).
        short p = 0;
        response[p++] = (byte) 0x6F;
        response[p++] = (byte) (dfNameLength + 2);
        response[p++] = (byte) 0x84;
        response[p++] = (byte) dfNameLength;
        Util.arrayCopyNonAtomic(dfName, (short) 0, response, p, dfNameLength);
        p += dfNameLength;
        return p;
    }

    /** Clears the secure-messaging session state on application selection. */
    private void resetSession() {
        smEstablished = false;
        paceDone = false;
        selectedMf = null;
        if (lds2 != null) {
            lds2.clearSelection();
        }
        challengeValid = false;
        caPending = false;
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
        requestMoreTime(ins);

        byte[] data;
        short dataOff;
        short dataLen;
        short le;
        if (smActive) {
            data = plain;
            dataOff = 0;
            dataLen = sm.unwrap(ksEnc, ksMac, ssc, apduBuffer,
                    cdataOff, incoming, plain, (short) 0);
            le = sm.getLe();
        } else {
            data = apduBuffer;
            dataOff = cdataOff;
            dataLen = incoming;
            le = incoming == 0 ? readLe(apduBuffer, cdataOff) : -1;
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
            apdu.setOutgoing();
            apdu.setOutgoingLength(n);
            apdu.sendBytesLong(plain, (short) 0, n);
            return;
        }

        if (smActive) {
            short n = sm.wrap(ksEnc, ksMac, ssc, response, respLen,
                    (short) 0x9000, plain, (short) 0);
            apdu.setOutgoing();
            apdu.setOutgoingLength(n);
            apdu.sendBytesLong(plain, (short) 0, n);
        } else {
            apdu.setOutgoing();
            apdu.setOutgoingLength(respLen);
            apdu.sendBytesLong(response, (short) 0, respLen);
        }
        if (caPending) {
            // Chip Authentication: switch the SM session keys for the next
            // command, after this response was wrapped with the old ones.  The
            // CA profile implemented here is ECDH-3DES, so SM falls back to the
            // retail-MAC wrapper even if PACE had negotiated AES.
            Util.arrayCopyNonAtomic(caEnc, (short) 0, ksEnc, (short) 0, (short) 16);
            Util.arrayCopyNonAtomic(caMac, (short) 0, ksMac, (short) 0, (short) 16);
            for (short i = 0; i < 8; i++) {
                ssc[i] = 0;
            }
            sm = sm3des;
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

    /** Runs one command, writing its response data to {@link #response}. */
    private short dispatch(byte ins, byte[] data, short off, short len, short le,
                           byte[] apduBuffer) {
        if (role != EmrtdInstallParameters.ROLE_LDS1) {
            switch (ins) {
            case EmrtdTags.INS_SELECT_FILE:
                return selectLds2(data, off, len, apduBuffer);
            case EmrtdTags.INS_READ_BINARY:
                return readBinaryLds2(le, apduBuffer);
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
        case EmrtdTags.INS_GENERAL_AUTHENTICATE:
            return Mse.generalAuthenticate(this, data, off, len);
        default:
            ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
            return 0; // unreachable
        }
    }

    private short selectLds2(byte[] data, short off, short len, byte[] apduBuffer) {
        if (apduBuffer[ISO7816.OFFSET_P1] == 0x04) {
            // SELECT by DF name inside secure messaging (see EmrtdApplet.selectByName).
            return selectByName(data, off, len);
        }
        if (len != 2) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        short fid = Util.getShort(data, off);
        Lds2TransparentFile mf = LdsMfStore.file(fid);
        if (mf != null) {
            // EF.CardAccess, EF.ATR/INFO and EF.DIR are selectable/readable
            // before PACE (ALWAYS, Doc 9303-10 §3.11.3 Table 32 / §3.11.1/2);
            // EF.CardSecurity needs PACE (§3.11.4 Table 34).
            if (!isPublicMf(fid)) {
                requirePace();
            }
            selectedMf = mf;
            lds2.clearSelection();
            return 0;
        }
        // Every DF file needs PACE.
        requirePace();
        selectedMf = null;
        lds2.select(fid);
        return 0;
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

    /** True for the master-file EFs readable before PACE (ALWAYS). */
    private static boolean isPublicMf(short fid) {
        return fid == EmrtdTags.FID_CARD_ACCESS
                || fid == EmrtdTags.FID_ATR_INFO
                || fid == EmrtdTags.FID_DIR;
    }

    private short readBinaryLds2(short le, byte[] apduBuffer) {
        short p1 = (short) (apduBuffer[ISO7816.OFFSET_P1] & 0xFF);
        short p2 = (short) (apduBuffer[ISO7816.OFFSET_P2] & 0xFF);
        Lds2TransparentFile file;
        short offset;
        if ((p1 & EmrtdTags.READ_P1_SFI) != 0) {
            // Short EF identifier form (Doc 9303-10 §3.6.3.2 Table 5); a valid
            // SFI also sets that EF as current (ISO/IEC 7816-4 §6.1.2).
            short sfi = (short) (p1 & EmrtdTags.SFI_MASK);
            file = lds2.transparentBySfi(sfi);
            if (file != null) {
                selectedMf = null;
                lds2.selectTransparent(file);
            } else {
                file = LdsMfStore.fileBySfi(sfi);
                if (file != null) {
                    selectedMf = file;
                    lds2.clearSelection();
                }
            }
            offset = p2;
            if (file == null) {
                ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND); // 6A82
            }
        } else {
            file = selectedMf != null ? selectedMf : lds2.getSelectedTransparent();
            offset = (short) (((p1 & 0x7F) << 8) | p2);
            if (file == null) {
                // 6986: command not allowed, no current EF (ISO/IEC 7816-4 §6.1.5).
                ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
            }
        }
        // EF.CardAccess, EF.ATR/INFO and EF.DIR are readable before PACE;
        // EF.CardSecurity and the record EFs need PACE (Doc 9303-10 §3.11.4
        // Table 34, §5.4).
        if (!isPublicMf(file.getFid())) {
            requirePace();
        }
        short want = le <= 0 ? (short) 256 : le;
        if (want > ReadBinary.SM_RESPONSE_MAX) {
            want = ReadBinary.SM_RESPONSE_MAX;
        }
        short available = (short) (file.getLength() - offset);
        if (available < 0) {
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
        }
        short n = want < available ? want : available;
        file.read(offset, n, response, (short) 0);
        return n;
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
