package card42.host.emv.crypto;

import java.security.GeneralSecurityException;

/**
 * Terminal-side EMV Format&nbsp;1 secure-messaging primitives (EMV v4.4 Book 2
 * §9.2/§9.3): the secured CLA and the ISO/IEC 7816-4 padding/encipherment used
 * for a confidentiality object.
 *
 * <p>The MAC-chained command builder is {@link ScriptSession}; the Issuer Script
 * (tag '71'/'72') parse and its result encoding (tag '9F5B', TVR bits) live in
 * {@code card42.host.emv.kernel.script}.
 */
public final class SmCrypto {

    /** Format 1 secure-messaging CLA (low nibble C) for the post-issuance set. */
    public static final int CLA_FORMAT1 = 0x8C;
    /** Format 1 CLA with the command-chaining bit (b5) set (EMV v4.4 Book 3 §6.5.13). */
    public static final int CLA_FORMAT1_CHAINED = 0x9C;

    private SmCrypto() {
    }

    /** Enciphers a PIN block for a Format 1 confidentiality object. */
    public static byte[] encipher(byte[] encKey16, byte[] plaintext)
            throws GeneralSecurityException {
        // ISO/IEC 7816-4 padding always takes place, even when the data field is
        // already a multiple of 8 (EMV v4.4 Book 2 Annex D2.2), so an 8-byte PIN block
        // enciphers to 16 bytes.
        byte[] cryptogram = AcCrypto.des3CbcEncrypt(encKey16, padIso7816(plaintext));
        byte[] out = new byte[cryptogram.length + 1];
        out[0] = 0x01; // padding indicator
        System.arraycopy(cryptogram, 0, out, 1, cryptogram.length);
        return out;
    }

    /** ISO/IEC 7816-4 padding: a mandatory 0x80 then 0x00 to a multiple of 8. */
    public static byte[] padIso7816(byte[] data) {
        int pad = 8 - (data.length % 8);
        byte[] padded = new byte[data.length + pad];
        System.arraycopy(data, 0, padded, 0, data.length);
        padded[data.length] = (byte) 0x80;
        return padded;
    }
}
