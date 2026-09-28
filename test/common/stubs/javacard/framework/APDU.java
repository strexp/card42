package javacard.framework;

/**
 * Plain-JVM stand-in for the Java Card {@code APDU} (docs/specs/common/toolchain.md
 * §6), so the command-level unit suites can drive the real
 * {@code processCommand}/{@code onSelect} entry points instead of re-implementing
 * their APDU orchestration next to it.
 *
 * <p>Only the surface the linked card classes use is provided: the command
 * buffer, short-APDU data reception and the outgoing calls.  The class carries
 * a few extra helpers ({@link #loadCommand}, {@link #lastResponse},
 * {@link #lastLe}) that a real JCRE would provide by other means; they are
 * test scaffolding, not Java Card API.
 *
 * <p>Deliberately self-contained: this file is also compiled into the
 * host/integration classpath, which has no {@code api_classic} jar, so it must
 * not reference {@code ISO7816} or any other Java Card type.
 */
public class APDU {

    /** ISO/IEC 7816-4 offset of the command data field of a short APDU. */
    private static final short OFFSET_CDATA = (short) 5;
    /** ISO/IEC 7816-4 offset of Lc (and of Le in a case-2 short APDU). */
    private static final short OFFSET_LC = (short) 4;

    // Transport constants of the real javacard.framework.APDU; EMVRoles folds
    // PROTOCOL_MEDIA_MASK into MEDIA_MASK at class-init time, so the card code
    // needs them even though no test ever calls getProtocol().
    public static final byte PROTOCOL_MEDIA_MASK = (byte) 0xF0;
    public static final byte PROTOCOL_TYPE_MASK = (byte) 0x0F;
    public static final byte PROTOCOL_T0 = (byte) 0x00;
    public static final byte PROTOCOL_T1 = (byte) 0x01;
    public static final byte PROTOCOL_MEDIA_DEFAULT = (byte) 0x00;
    public static final byte PROTOCOL_MEDIA_CONTACTLESS_TYPE_A = (byte) 0x80;
    public static final byte PROTOCOL_MEDIA_CONTACTLESS_TYPE_B = (byte) 0x90;
    public static final byte PROTOCOL_MEDIA_USB = (byte) 0xA0;
    public static final byte PROTOCOL_MEDIA_HCI_APDU_GATE = (byte) 0xB0;
    public static final byte PROTOCOL_MEDIA_CONTACTLESS_TYPE_F = (byte) 0xB0;

    private final byte[] buffer = new byte[300];

    /** Command data length (Lc) of the command in {@link #buffer}. */
    private short lc;
    /** Le of a case-2/4 command, or 0 when the command carries no Le. */
    private short le;

    private short outgoingLength;
    private byte[] sent = new byte[0];

    private APDU() {
    }

    /** A fresh APDU with an empty command buffer. */
    public static APDU getInstance() {
        return new APDU();
    }

    public byte[] getBuffer() {
        return buffer;
    }

    /** Short-APDU case 4 / case 3 reception: the data field is already in the buffer. */
    public short setIncomingAndReceive() {
        return lc;
    }

    /** Remaining bytes of an already-received data field: nothing to pull. */
    public short receiveBytes(short off) {
        return 0;
    }

    public short getOffsetCdata() {
        return OFFSET_CDATA;
    }

    public void setOutgoing() {
    }

    public void setOutgoingLength(short len) {
        outgoingLength = len;
    }

    public void sendBytes(short off, short len) {
        record(buffer, off, len);
    }

    public void sendBytesLong(byte[] src, short off, short len) {
        record(src, off, len);
    }

    /** The CAD may not support the extension; the card code catches the throw. */
    public static void waitExtension() {
    }

    /**
     * Contact transport, like the JCRE on a T=0/T=1 reader.  The EMV applet
     * records it into {@code EMVProtocolState.media} on SELECT; it is not
     * reliable on the simulator either (docs/specs/common/architecture.md §1).
     */
    public static byte getProtocol() {
        return PROTOCOL_MEDIA_DEFAULT;
    }

    // --- test scaffolding ----------------------------------------------------

    /**
     * Loads {@code header[0..3]} plus {@code dataField} as the current command.
     * {@code dataField} may be null (case 1/2).  Returns this APDU.
     */
    public APDU loadCommand(byte[] header, byte[] dataField, short leValue) {
        System.arraycopy(header, 0, buffer, 0, 4);
        lc = 0;
        if (dataField != null && dataField.length > 0) {
            // Short APDU: CLA INS P1 P2 Lc=4 Data=5.. (ISO/IEC 7816-4 §5.1).
            buffer[OFFSET_LC] = (byte) dataField.length;
            System.arraycopy(dataField, 0, buffer, OFFSET_CDATA, dataField.length);
            lc = (short) dataField.length;
        } else if (leValue > 0) {
            // Case 2: no command data, so the Le lives where Lc would
            // (ISO/IEC 7816-4 §5.1); the card code reads it with readLe().
            buffer[OFFSET_LC] = (byte) leValue;
        }
        le = leValue;
        outgoingLength = 0;
        sent = new byte[0];
        return this;
    }

    /** The bytes the command sent back, or an empty array when it sent none. */
    public byte[] lastResponse() {
        return sent;
    }

    /** The data-field length the command declared with {@code setOutgoingLength}. */
    public short lastOutgoingLength() {
        return outgoingLength;
    }

    /** Le of the command currently loaded. */
    public short lastLe() {
        return le;
    }

    private void record(byte[] src, short off, short len) {
        if (src == null || len <= 0 || off < 0 || (short) (off + len) > src.length) {
            return;
        }
        byte[] out = new byte[len];
        System.arraycopy(src, off, out, 0, len);
        sent = out;
    }
}
