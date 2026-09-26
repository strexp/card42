package card42.emv;

/* Cryptogram, AC-type and CVM-type codes, split out of the former EMVConstants
 * constant interface so a class depends only on the codes it handles.
 *
 * @author card42
 */

public final class EMVCodes {

    private EMVCodes() {
    }

    /* codes for cryptogram types used in P1 */
    public static final byte ARQC_CODE = (byte) 0x80;
    public static final byte TC_CODE = (byte) 0x40;
    public static final byte AAC_CODE = (byte) 0x00;
    public static final byte RFU_CODE = (byte) 0xC0;

    /* types of AC */
    public static final byte NONE = (byte) 0x00;
    public static final byte ARQC = (byte) 0x01;
    public static final byte TC = (byte) 0x02;
    public static final byte AAC = (byte) 0x03;

    // types of CVM performed; NONE for none.
    public static final byte PLAINTEXT_PIN = (byte) 0x01;
    public static final byte ENCRYPTED_PIN = (byte) 0x02;
}
