package card42.emv;

import card42.common.*;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.security.PrivateKey;
import javacardx.crypto.Cipher;

/* The ICC PIN encipherment private key and the RSA Signing Function applied to
 * an enciphered offline PIN (EMV v4.4 Book 2 §7.2).
 *
 * The terminal obtains the ICC Unpredictable Number with GET CHALLENGE, builds
 * the block '7F' || PIN Block(8) || ICC UN(8) || random padding (Table 25) and
 * applies the RSA Recovery Function (EMV v4.4 Book 2 Annex B2.1.3, a public-key
 * operation) to it.  The card applies the RSA Signing Function (B2.1.2, a
 * private-key operation) to recover that plaintext; this class performs the raw
 * modular exponentiation (Cipher.ALG_RSA_NOPAD) and returns the whole recovered
 * modulus-length block.  OfflinePin validates the header, the ICC UN and the PIN
 * block (EMV v4.4 Book 2 §7.2 steps 6-9).
 *
 * The key is injected by personalization as the EMV CPS v2.0 Annex A DGI '8102'/'8104'
 * modulus/exponent pair, assembled into the BER-TLV container of RsaKey
 * (86 n, 87 d) or the CRT form.  The key is built lazily when the DGI arrives,
 * so a card without RSA support can still install and serve the plaintext PIN
 * path.
 *
 * @author card42
 */

public class PinCrypto implements ISO7816 {

    private PrivateKey pinKey;
    private Cipher pinCipher;

    public PinCrypto() {
    }

    /** True once a usable private key and cipher have been injected. */
    public boolean isAvailable() {
        return pinKey != null && pinCipher != null;
    }

    /** Modulus length in bytes of the injected key (0 when absent). */
    public short getKeyLength() {
        if (pinKey == null) {
            return 0;
        }
        try {
            return (short) (pinKey.getSize() / 8);
        } catch (Exception e) {
            return 0;
        }
    }

    /**
     * Stores the ICC PIN encipherment private key assembled from the EMV CPS v2.0
     * '8104'/'8102' DGIs.  Called inside the personalization transaction.
     */
    public void setPrivateKey(byte[] buf, short off, short len) {
        try {
            pinKey = RsaKey.parse(buf, off, len);
            pinCipher = Cipher.getInstance(Cipher.ALG_RSA_NOPAD, false);
        } catch (ISOException e) {
            throw e;
        } catch (Exception e) {
            // Unsupported key size or RSA not available on this platform.
            pinKey = null;
            pinCipher = null;
            ISOException.throwIt(SW_WRONG_DATA);
        }
    }

    /**
     * Applies the RSA Signing Function (EMV v4.4 Book 2 Annex B2.1.2) to the Enciphered
     * PIN Data and writes the recovered modulus-length block to out/outOff.
     * Returns the recovered block length (the modulus length), or -1 when there
     * is no key or the ciphertext length is not the modulus length.
     */
    public short recover(byte[] in, short inOff, short inLen,
                         byte[] out, short outOff) {
        if (pinKey == null || pinCipher == null) {
            return -1;
        }
        short keyLength = getKeyLength();
        if (keyLength <= 0 || inLen != keyLength || (short) (outOff + keyLength) > out.length) {
            return -1;
        }
        try {
            pinCipher.init(pinKey, Cipher.MODE_DECRYPT);
            return pinCipher.doFinal(in, inOff, inLen, out, outOff);
        } catch (Exception e) {
            return -1;
        }
    }
}
