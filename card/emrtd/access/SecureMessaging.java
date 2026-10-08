package card42.emrtd;

/* The secure-messaging wrapper of an eMRTD session (ISO/IEC 7816-4 §5.6,
 * ICAO Doc 9303-11 §9.8): it unwraps a command data field and wraps a response
 * data field.  Two profiles implement it, selected when the session is
 * established: {@link Iso7816Sm} (BAC/3DES, retail MAC) and
 * {@link Iso7816SmAes} (PACE/AES-128, CMAC).
 *
 * The applet holds one active reference, so the command path no longer branches
 * on the negotiated profile.
 *
 * @author card42
 */

public interface SecureMessaging {

    /** The SM class byte is CLA | 0x0C (ISO/IEC 7816-4 §5.6.1). */
    byte SM_CLA_MASK = (byte) 0x0C;

    /** Le of the last unwrapped command, or -1 when it carried none. */
    short getLe();

    /**
     * The largest plaintext response data field this profile can wrap so the
     * secure-messaging envelope still fits a 256-byte short APDU.  Depends on
     * the block size: a 231-byte window is the 3DES maximum (8-byte blocks,
     * envelope 250 B) while AES (16-byte blocks) tops out at 223 B
     * (envelope 242 B); a 232/224-byte window would jump to 258 B and the
     * transport refuses the response with 6700.
     */
    short maxResponseData();

    /**
     * Releases the cached session key when the secure-messaging session ends
     * (application selection), so the cipher does not keep the previous session
     * key material beyond its lifetime.
     */
    void reset();

    /**
     * Unwraps the command data field {@code apdu[dataOff..dataOff+dataLen)}
     * using the command header ({@code CLA/INS/P1/P2}).  Returns the plaintext
     * length written to {@code out} and sets {@link #getLe()}.  Throws 6982 on a
     * MAC failure or malformed data.
     */
    short unwrap(byte[] ksEnc, byte[] ksMac, byte[] ssc,
                 byte[] apdu, short dataOff, short dataLen,
                 byte[] out, short outOff);

    /**
     * Wraps the response data {@code response[0..respLen)} and status word
     * {@code sw} into {@code out}, returning the response data-field length.
     */
    short wrap(byte[] ksEnc, byte[] ksMac, byte[] ssc,
               byte[] response, short respLen, short sw,
               byte[] out, short outOff);
}
