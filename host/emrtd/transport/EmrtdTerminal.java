package card42.host.emrtd.transport;

import java.util.Arrays;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import card42.host.common.transport.Terminal;
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
                    + Integer.toHexString(r.getSW()));
        }
        return r.getData();
    }

    /** EXTERNAL AUTHENTICATE with E_IFD || M_IFD. */
    public ResponseAPDU externalAuthenticate(byte[] data) throws Exception {
        return transmit(0x00, 0x82, 0x00, 0x00, data, 0);
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
        if (sm == null) {
            CommandAPDU command = data != null && data.length > 0
                    ? new CommandAPDU(cla, ins, p1, p2, data, le > 0 ? le : 256)
                    : new CommandAPDU(cla, ins, p1, p2, le > 0 ? le : 256);
            return base.transmit(command);
        }
        byte[] wrapped = sm.wrapCommand(cla, ins, p1, p2, data, le);
        CommandAPDU command = new CommandAPDU(0x0C, ins, p1, p2, wrapped,
                le > 0 ? le : 256);
        ResponseAPDU raw = base.transmit(command);
        short[] sw = new short[1];
        byte[] plain;
        try {
            plain = sm.unwrapResponse(raw.getData(), sw);
        } catch (RuntimeException e) {
            throw new IllegalStateException("SM unwrap failed (SW="
                    + Integer.toHexString(raw.getSW()) + ", data="
                    + card42.host.common.util.Hex.format(raw.getData()) + ")", e);
        }
        byte[] out = Arrays.copyOf(plain, plain.length + 2);
        out[plain.length] = (byte) (sw[0] >> 8);
        out[plain.length + 1] = (byte) sw[0];
        return new ResponseAPDU(out);
    }
}
