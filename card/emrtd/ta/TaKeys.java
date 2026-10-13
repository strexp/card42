package card42.emrtd;

import javacard.security.ECPublicKey;
import javacard.security.KeyBuilder;
import javacard.security.MessageDigest;
import javacard.security.RSAPublicKey;
import javacard.security.Signature;
import javacardx.crypto.Cipher;

/* Shared Terminal Authentication verification engines (ICAO Doc 9303-11 §7.1,
 * BSI TR-03110-3 A.7).
 *
 * The certificate-verification and terminal-signature algorithms are selected
 * per key from its kind: ECDSA-SHA-256 (TR-03111 plain r||s, verified directly
 * with SIG_CIPHER_ECDSA_PLAIN) or RSA-PSS-SHA-256
 * (Signature.ALG_RSA_SHA_256_PKCS1_PSS, salt = SHA-256 length).
 *
 * The EC/RSA public keys and the two Signature objects are built once, at first
 * use during personalization (never on a command path, docs/specs/common/risks.md §4),
 * and shared by every eMRTD instance of the package context exactly like the
 * former TaContext fields.  This class owns no per-session state; it is a
 * stateless helper, so splitting it out of TaContext adds no persistent or
 * transient heap.
 *
 * @author card42
 */

final class TaKeys {

    /** Uncompressed P-256 public point length (0x04 || X || Y). */
    static final short EC_KEY_LENGTH = (short) 65;
    /** RSA-2048 maximum modulus length. */
    static final short MAX_MODULUS = (short) 256;
    /** RSA public exponent maximum length. */
    static final short MAX_EXPONENT = (short) 8;

    /** Key-kind discriminators shared with the trust store and the parser. */
    static final byte KIND_NONE = 0;
    static final byte KIND_EC = 1;
    static final byte KIND_RSA = 2;

    private static ECPublicKey ecKey;
    private static RSAPublicKey rsaKey1024;
    private static RSAPublicKey rsaKey2048;
    private static Signature ecSig;
    private static Signature rsaSig;

    private TaKeys() {
    }

    /**
     * Builds the shared verification keys and Signatures once, at first use
     * (personalization, so no persistent allocation happens on a command path).
     * Failures are left to the platform: a card without the algorithm simply
     * cannot verify that profile.
     */
    static void ensureKeys() {
        if (ecKey == null) {
            ecKey = (ECPublicKey) KeyBuilder.buildKey(
                    KeyBuilder.TYPE_EC_FP_PUBLIC, KeyBuilder.LENGTH_EC_FP_256, false);
            P256.setCurve(ecKey);
        }
        if (ecSig == null) {
            ecSig = Signature.getInstance(MessageDigest.ALG_SHA_256,
                    Signature.SIG_CIPHER_ECDSA_PLAIN, Cipher.PAD_NULL, false);
        }
    }

    private static void ensureRsa() {
        if (rsaKey2048 == null) {
            rsaKey1024 = (RSAPublicKey) KeyBuilder.buildKey(
                    KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_1024, false);
            rsaKey2048 = (RSAPublicKey) KeyBuilder.buildKey(
                    KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_2048, false);
            rsaSig = Signature.getInstance(Signature.ALG_RSA_SHA_256_PKCS1_PSS, false);
        }
    }

    /**
     * Verifies {@code message} against an explicit key with the algorithm
     * selected by the key kind (ECDSA-SHA-256 plain, RSA-PSS-SHA-256; BSI
     * TR-03110-3 Table 27).  The key is passed in rather than read from a
     * staging buffer so the caller can reuse that buffer for the message
     * (terminal authentication, BSI TR-03110-3 A.7.2).
     */
    static boolean verifyKey(byte kind, byte[] key, short keyLen,
                             byte[] exp, short expLen,
                             byte[] message, short messageOff, short messageLength,
                             byte[] signature, short signatureOff, short signatureLength) {
        try {
            if (kind == KIND_EC) {
                ensureKeys();
                ecKey.setW(key, (short) 0, EC_KEY_LENGTH);
                ecSig.init(ecKey, Signature.MODE_VERIFY);
                return ecSig.verify(message, messageOff, messageLength,
                        signature, signatureOff, signatureLength);
            }
            ensureRsa();
            RSAPublicKey rsa = keyLen <= 128 ? rsaKey1024 : rsaKey2048;
            rsa.setModulus(key, (short) 0, keyLen);
            rsa.setExponent(exp, (short) 0, expLen);
            rsaSig.init(rsa, Signature.MODE_VERIFY);
            return rsaSig.verify(message, messageOff, messageLength,
                    signature, signatureOff, signatureLength);
        } catch (Exception e) {
            return false;
        }
    }
}
