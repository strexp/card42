package card42.host.emrtd.access;

import java.security.GeneralSecurityException;

import card42.host.common.crypto.Iso9797;

/**
 * Terminal-side ISO/IEC 7816-4 secure messaging for BAC (ICAO Doc 9303-11
 * §9.8), the mirror of the card-side {@code card42.emrtd.Iso7816Sm}.
 *
 * <p>Encryption is 3DES-CBC with a zero IV; the checksum is the ISO/IEC 9797-1
 * algorithm 3 (retail) MAC truncated to 8 bytes.  The framing and the 64-bit
 * big-endian send sequence counter live in {@link AbstractSecureMessaging}.
 */
public final class Iso7816Sm extends AbstractSecureMessaging {

    private static final byte[] ZERO_IV = new byte[8];

    public Iso7816Sm(byte[] ksEnc, byte[] ksMac, long ssc) {
        super(ksEnc, ksMac, ssc);
    }

    @Override
    int blockSize() {
        return 8;
    }

    @Override
    byte[] encodedSsc() {
        long ssc = getSendSequenceCounter();
        byte[] out = new byte[8];
        for (int i = 0; i < 8; i++) {
            out[i] = (byte) (ssc >>> (8 * (7 - i)));
        }
        return out;
    }

    @Override
    byte[] mac(byte[] key, byte[] padded) throws GeneralSecurityException {
        return Iso9797.macPadded(key, padded, 8);
    }

    @Override
    byte[] encrypt(byte[] key, byte[] padded) throws GeneralSecurityException {
        return Iso9797.des3CbcEncrypt(key, padded);
    }

    @Override
    byte[] decrypt(byte[] key, byte[] cipher) throws GeneralSecurityException {
        return Iso9797.des3CbcDecrypt(key, ZERO_IV, cipher);
    }
}
