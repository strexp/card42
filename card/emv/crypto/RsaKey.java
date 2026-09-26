package card42.emv;

import card42.common.*;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.security.KeyBuilder;
import javacard.security.PrivateKey;
import javacard.security.RSAPrivateCrtKey;
import javacard.security.RSAPrivateKey;

/* Builds a Java Card RSA private key from the BER-TLV container used by the
 * personalization DGIs: the EMV CPS v2.0 Annex A DGI '8103'/'8101' (ICC DDA/CDA) and '8104'/'8102'
 * (ICC PIN) modulus/exponent pairs are assembled into this container.
 *
 * The container carries either the five CRT components
 * (81 p, 82 q, 83 dp, 84 dq, 85 pq) or the plain modulus and private exponent
 * (86 n, 87 d).  The key is built lazily when the DGI arrives, so a card
 * without RSA support can still install and serve the paths that do not need a
 * private key (EMV v4.4 Book 2 §6.5, §7.2).
 *
 * @author card42
 */

public final class RsaKey {

    /** Key container tags (private to the key DGIs). */
    private static final short KEY_TAG_P = (short) 0x81;
    private static final short KEY_TAG_Q = (short) 0x82;
    private static final short KEY_TAG_DP = (short) 0x83;
    private static final short KEY_TAG_DQ = (short) 0x84;
    private static final short KEY_TAG_PQ = (short) 0x85;
    private static final short KEY_TAG_N = (short) 0x86;
    private static final short KEY_TAG_D = (short) 0x87;

    private RsaKey() {
    }

    /**
     * Parses one key container.  Throws 6A80 when neither a complete CRT set
     * nor a modulus/exponent pair is present.
     */
    public static PrivateKey parse(byte[] buf, short off, short len) {
        byte[] p = null;
        short pOff = 0;
        short pLen = 0;
        byte[] q = null;
        short qOff = 0;
        short qLen = 0;
        byte[] dp = null;
        short dpOff = 0;
        short dpLen = 0;
        byte[] dq = null;
        short dqOff = 0;
        short dqLen = 0;
        byte[] pq = null;
        short pqOff = 0;
        short pqLen = 0;
        byte[] n = null;
        short nOff = 0;
        short nLen = 0;
        byte[] d = null;
        short dOff = 0;
        short dLen = 0;

        TlvReader reader = new TlvReader(buf, off, len);
        while (reader.hasNext()) {
            reader.next();
            short tag = reader.tag();
            short vOff = reader.valueOffset();
            short vLen = reader.valueLength();
            if (tag == KEY_TAG_P) {
                p = buf; pOff = vOff; pLen = vLen;
            } else if (tag == KEY_TAG_Q) {
                q = buf; qOff = vOff; qLen = vLen;
            } else if (tag == KEY_TAG_DP) {
                dp = buf; dpOff = vOff; dpLen = vLen;
            } else if (tag == KEY_TAG_DQ) {
                dq = buf; dqOff = vOff; dqLen = vLen;
            } else if (tag == KEY_TAG_PQ) {
                pq = buf; pqOff = vOff; pqLen = vLen;
            } else if (tag == KEY_TAG_N) {
                n = buf; nOff = vOff; nLen = vLen;
            } else if (tag == KEY_TAG_D) {
                d = buf; dOff = vOff; dLen = vLen;
            }
        }

        if (p != null && q != null && dp != null && dq != null && pq != null) {
            // EMV v4.4 Book 2 Table 43: the ICC modulus is at most 247 bytes.  The
            // container carries only the prime factors, and n = p*q needs at
            // most pLen + qLen bytes.  Bounding each prime at 124 bytes is a
            // deliberately conservative approximation: it rejects a legal
            // 247-byte n built from e.g. a 125-byte and a 122-byte prime.
            // Computing n exactly would need a big-integer multiply on the card;
            // the CRT container is not produced by the personalization scripts,
            // so the conservative bound is kept (docs/specs/common/cryptography.md §6).
            if (pLen > 124 || qLen > 124
                    || (short) (pLen + qLen) > EMVStatus.RSA_MAX_ICC_MODULUS) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }
            short bits = (short) (pLen * 2 * 8);
            RSAPrivateCrtKey crt = (RSAPrivateCrtKey) KeyBuilder.buildKey(
                    KeyBuilder.TYPE_RSA_CRT_PRIVATE, bits, false);
            crt.setP(p, pOff, pLen);
            crt.setQ(q, qOff, qLen);
            crt.setDP1(dp, dpOff, dpLen);
            crt.setDQ1(dq, dqOff, dqLen);
            crt.setPQ(pq, pqOff, pqLen);
            return crt;
        }
        if (n != null && d != null) {
            // EMV v4.4 Book 2 Table 43: the ICC DDA/CDA and PIN encipherment modulus is
            // at most 247 bytes.
            if (nLen > EMVStatus.RSA_MAX_ICC_MODULUS) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }
            short bits = (short) (nLen * 8);
            RSAPrivateKey key = (RSAPrivateKey) KeyBuilder.buildKey(
                    KeyBuilder.TYPE_RSA_PRIVATE, bits, false);
            key.setModulus(n, nOff, nLen);
            key.setExponent(d, dOff, dLen);
            return key;
        }
        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        return null; // unreachable
    }
}
