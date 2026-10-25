package card42.host.emrtd.transport;

import java.util.Arrays;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import card42.host.common.transport.Terminal;
import card42.host.common.util.Sw;
import card42.host.emrtd.access.SecureMessaging;

/**
 * ICAO 9303 APDU layer over the generic card terminal (H0.1).
 *
 * <p>It builds the LDS1 commands (SELECT DF, SELECT FILE, READ BINARY, GET
 * CHALLENGE, EXTERNAL AUTHENTICATE, INTERNAL AUTHENTICATE) and, once BAC has
 * installed an {@link SecureMessaging}, wraps every command and unwraps every
 * response transparently.
 */
public final class EmrtdTerminal {

    /** LDS1 DF name / instance AID (Doc 9303-10 §4.1). */
    public static final String LDS1_AID = "A0000002471001";

    private final Terminal base;
    private SecureMessaging sm;

    public EmrtdTerminal(Terminal base) {
        this.base = base;
    }

    public Terminal base() {
        return base;
    }

    public void setSecureMessaging(SecureMessaging sm) {
        this.sm = sm;
    }

    public boolean hasSecureMessaging() {
        return sm != null;
    }

    /** SELECT the LDS1 application by DF name. */
    public ResponseAPDU selectLds1() throws Exception {
        return base.select(LDS1_AID);
    }

    /** SELECT an application by DF name (LDS1 or an LDS2 application). */
    public ResponseAPDU selectApplication(String aidHex) throws Exception {
        return base.select(aidHex);
    }

    /** READ RECORD (B2): P1 = record number, P2 = SFI<<3 | 4 (single) / 5 (all). */
    public ResponseAPDU readRecord(int sfi, int record, boolean all, int le) throws Exception {
        int p2 = (sfi << 3) | (all ? 0x05 : 0x04);
        return transmit(0x00, 0xB2, record & 0xFF, p2, null, le);
    }

    /** APPEND RECORD (E2): P2 = SFI<<3 (Doc 9303-10 §3.7.1 Table 10). */
    public ResponseAPDU appendRecord(int sfi, byte[] record) throws Exception {
        return transmit(0x00, 0xE2, 0x00, sfi << 3, record, 0);
    }

    /**
     * SEARCH RECORD (A2): P1='00', P2='F8' (search through multiple EFs); the
     * data field is the Record handling DO'7F76' (Doc 9303-10 §3.7.3 Table 14/
     * 16/17).
     */
    public ResponseAPDU searchRecord(byte[] data) throws Exception {
        return transmit(0x00, 0xA2, 0x00, 0xF8, data, 0);
    }

    /**
     * UPDATE BINARY for an LDS2 Additional Biometrics transparent EF
     * (Doc 9303-10 §3.8): the command data is {@code 54 offset || 53 data
     * [|| C0 size]}.  The caller selects the EF first.
     */
    public ResponseAPDU updateBinary(byte[] data) throws Exception {
        return transmit(0x00, 0xD7, 0x00, 0x00, data, 0);
    }

    /**
     * UPDATE BINARY with the proprietary File Size DO'C0'.  Doc 9303-10
     * §3.8.1 Table 18 requires CLA bit 8 set ('8C') when DO'C0' is present;
     * the secure-messaging layer ORs its own bits into the class byte.
     */
    public ResponseAPDU updateBinaryWithSize(byte[] data) throws Exception {
        return transmit(0x80, 0xD7, 0x00, 0x00, data, 0);
    }

    /** ACTIVATE (44) an LDS2 Additional Biometrics transparent EF. */
    public ResponseAPDU activate() throws Exception {
        return transmit(0x00, 0x44, 0x00, 0x00, null, 0);
    }

    /** FILE AND MEMORY MANAGEMENT (5F). */
    public ResponseAPDU fileMemoryManagement(int p1, int p2, byte[] data) throws Exception {
        return transmit(0x00, 0x5F, p1, p2, data, 0);
    }

    /** SELECT FILE by FID (P1=02 select EF, P2=0C). */
    public ResponseAPDU selectFile(int fid) throws Exception {
        return transmit(0x00, 0xA4, 0x02, 0x0C,
                new byte[] { (byte) (fid >> 8), (byte) fid }, 0);
    }

    /**
     * SELECT MF (ISO/IEC 7816-4 §7.1.1): P1=00, P2=0C, FID 3F00.  A reader uses
     * this to read EF.CardAccess at the MF level (Doc 9303-10 §3.11.3) before
     * selecting the eMRTD application.
     *
     * <p>The P2=0C (no FCI) form is the one JMRTD and our applet use.  Do not
     * probe P2=00 as a fallback here: the only observed chip that rejects
     * P2=0C is a BAC-only passport that has no MF EF to read in the first
     * place, and the read path must not select MF for such a document.
     */
    public ResponseAPDU selectMf() throws Exception {
        return transmit(0x00, 0xA4, 0x00, 0x0C, new byte[] { 0x3F, 0x00 }, 0);
    }

    /** READ BINARY at offset with the requested length (0 = 256). */
    public ResponseAPDU readBinary(int offset, int le) throws Exception {
        return transmit(0x00, 0xB0, (offset >> 8) & 0xFF, offset & 0xFF, null, le);
    }

    /**
     * READ BINARY with the short EF identifier form (ISO/IEC 7816-4 §6.1.1,
     * Doc 9303-10 §3.6.3.2 Table 5): P1 b8=1 and b5..b1 carry the SFI, P2 is
     * the 8-bit offset.  This form is mandatory for the eMRTD and needs no
     * preceding SELECT FILE.
     */
    public ResponseAPDU readBinarySfi(int sfi, int offset, int le) throws Exception {
        return transmit(0x00, 0xB0, 0x80 | (sfi & 0x1F), offset & 0xFF, null, le);
    }

    /** GET CHALLENGE: an 8-byte RND.ICC. */
    public byte[] getChallenge() throws Exception {
        ResponseAPDU r = transmit(0x00, 0x84, 0x00, 0x00, null, 8);
        if (r.getSW() != 0x9000 || r.getData().length != 8) {
            throw new IllegalStateException("GET CHALLENGE failed: "
                    + Sw.format(r.getSW()));
        }
        return r.getData();
    }

    /** EXTERNAL AUTHENTICATE with E_IFD || M_IFD. */
    public ResponseAPDU externalAuthenticate(byte[] data) throws Exception {
        return transmit(0x00, 0x82, 0x00, 0x00, data, 0);
    }

    /**
     * MSE:Set DST (P1/P2=0x81B6): the DO'83' reference of the public key used to
     * verify a CV certificate (ICAO Doc 9303-11 §7.1.5.1).
     */
    public ResponseAPDU mseSetDst(byte[] reference) throws Exception {
        return transmit(0x00, 0x22, 0x81, 0xB6, doTag(0x83, reference), 0);
    }

    /**
     * PSO:Verify Certificate (P1/P2=0x00BE): the certificate body TLV (7F4E...)
     * followed by the signature TLV (5F37...) (ICAO Doc 9303-11 §7.1.5.2).
     */
    public ResponseAPDU psoVerifyCertificate(byte[] bodyTlv, byte[] signatureTlv) throws Exception {
        return transmit(0x00, 0x2A, 0x00, 0xBE,
                card42.host.common.util.Bytes.concat(bodyTlv, signatureTlv), 0);
    }

    /**
     * MSE:Set AT (P1/P2=0x81A4): the DO'83' reference of the terminal public key
     * for Terminal Authentication (ICAO Doc 9303-11 §7.1.5.3).
     */
    public ResponseAPDU mseSetAt(byte[] reference) throws Exception {
        return transmit(0x00, 0x22, 0x81, 0xA4, doTag(0x83, reference), 0);
    }

    /** A single data object {@code tag len value} (short length). */
    private static byte[] doTag(int tag, byte[] value) {
        byte[] out = new byte[2 + value.length];
        out[0] = (byte) tag;
        out[1] = (byte) value.length;
        System.arraycopy(value, 0, out, 2, value.length);
        return out;
    }

    /** INTERNAL AUTHENTICATE with the 8-byte challenge. */
    public ResponseAPDU internalAuthenticate(byte[] challenge) throws Exception {
        return transmit(0x00, 0x88, 0x00, 0x00, challenge, 0);
    }

    /**
     * Sends one command, wrapping/unwrapping with SM when it is active.  The
     * returned APDU carries the plaintext response data and the real status
     * word.
     */
    public ResponseAPDU transmit(int cla, int ins, int p1, int p2, byte[] data, int le)
            throws Exception {
        // The outer Le of an SM command must cover the wrapped response, which
        // is larger than the plaintext Le.  For an extended plaintext Le use
        // the extended outer Le (65536) instead of truncating the response to
        // the short-APDU maximum.
        int outerLe = le > 256 ? 65536 : (le > 0 ? le : 256);
        if (sm == null) {
            CommandAPDU command = data != null && data.length > 0
                    ? new CommandAPDU(cla, ins, p1, p2, data, outerLe)
                    : new CommandAPDU(cla, ins, p1, p2, outerLe);
            return base.transmit(command);
        }
        byte[] wrapped = sm.wrapCommand(cla, ins, p1, p2, data, le);
        // The card recomputes the MAC over CLA | 0x0C.  The outer header must
        // carry the same class byte, including the proprietary bit 8 used by
        // UPDATE BINARY with DO'C0' (Doc 9303-10 §3.8.1 Table 18: CLA '8C').
        int smCla = (cla | 0x0C) & 0xFF;
        CommandAPDU command = new CommandAPDU(smCla, ins, p1, p2, wrapped, outerLe);
        ResponseAPDU raw = base.transmit(command);
        short[] sw = new short[1];
        byte[] plain;
        try {
            plain = sm.unwrapResponse(raw.getData(), sw);
        } catch (RuntimeException e) {
            throw new IllegalStateException("SM unwrap failed (SW="
                    + Sw.format(raw.getSW()) + ", data="
                    + card42.host.common.util.Hex.format(raw.getData()) + ")", e);
        }
        byte[] out = Arrays.copyOf(plain, plain.length + 2);
        out[plain.length] = (byte) (sw[0] >> 8);
        out[plain.length + 1] = (byte) sw[0];
        return new ResponseAPDU(out);
    }
}
