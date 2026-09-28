package card42.emv;

import card42.common.*;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.security.PrivateKey;
import javacard.security.Signature;
import javacard.security.SignatureMessageRecovery;

/* The ICC RSA key pair used for Dynamic Data Authentication (DDA) and Combined
 * DDA/Application Cryptogram Generation (CDA) (EMV v4.4 Book 2 §6.5, §6.6).
 *
 * The private key is injected by personalization as the EMV CPS v2.0 Annex A DGI '8103'/'8101'
 * modulus/exponent pair (assembled into the BER-TLV container of RsaKey).  The
 * matching public key certificate (9F46/9F48/9F47) is delivered with the
 * payment records.
 *
 * Both DDA and CDA sign an ISO/IEC 9796-2 message with recovery using the same
 * key: the caller assembles the message of EMV v4.4 Book 2 tables 14/17 (Signed Data
 * Format, hash indicator, ICC Dynamic Data, pad pattern and the terminal
 * dynamic data) and this class returns the modulus-sized SDAD.  The message
 * split (the first N-22 bytes are the recoverable part) and the hash over the
 * whole message are handled by the platform's SignatureMessageRecovery.
 *
 * @author card42
 */

public class DdaCrypto implements ISO7816 {

    /** Recoverable-message length returned by sign(); transient (session). */
    private final short[] m1Length;

    private PrivateKey ddaKey;
    private SignatureMessageRecovery iso9796;

    public DdaCrypto() {
        EmvScratch.init();
        m1Length = EmvScratch.m1Length;
    }

    /** True once a usable private key and signer have been injected. */
    public boolean isAvailable() {
        return ddaKey != null && iso9796 != null;
    }

    /** Modulus length in bytes of the injected key (0 when absent). */
    public short getKeyLength() {
        if (ddaKey == null) {
            return 0;
        }
        try {
            return (short) (ddaKey.getSize() / 8);
        } catch (Exception e) {
            return 0;
        }
    }

    /**
     * Stores the ICC DDA/CDA private key assembled from the EMV CPS v2.0 Annex A DGI '8103'/'8101'
     * DGIs.  Called inside the personalization transaction.
     */
    public void setPrivateKey(byte[] buf, short off, short len) {
        boolean hadKey = ddaKey != null || iso9796 != null;
        try {
            PrivateKey key = RsaKey.parse(buf, off, len);
            SignatureMessageRecovery signer = (SignatureMessageRecovery)
                    Signature.getInstance(Signature.ALG_RSA_SHA_ISO9796_MR, false);
            ddaKey = key;
            iso9796 = signer;
        } catch (ISOException e) {
            ddaKey = null;
            iso9796 = null;
            if (hadKey) {
                JCSystem.requestObjectDeletion();
            }
            throw e;
        } catch (Exception e) {
            // Unsupported key size or ISO 9796-2 message recovery not available.
            ddaKey = null;
            iso9796 = null;
            if (hadKey) {
                JCSystem.requestObjectDeletion();
            }
            ISOException.throwIt(SW_WRONG_DATA);
        }
        if (hadKey) {
            // A re-personalization replaced the previous key and signer objects;
            // ask the platform to reclaim the persistent space now instead of
            // waiting for it (a J3R180 does not reclaim promptly on its own, see
            // docs/specs/common/risks.md §2).
            JCSystem.requestObjectDeletion();
        }
    }

    /**
     * Signs an ISO 9796-2 message with the ICC private key, writing the SDAD to
     * out/outOff.  Returns the signature length (the modulus length), or 0 when
     * no key is available.
     */
    public short sign(byte[] msg, short msgOff, short msgLen,
                      byte[] out, short outOff) {
        if (ddaKey == null || iso9796 == null) {
            return 0;
        }
        try {
            iso9796.init(ddaKey, Signature.MODE_SIGN);
            return iso9796.sign(msg, msgOff, msgLen, out, outOff, m1Length,
                    (short) 0);
        } catch (Exception e) {
            return 0;
        }
    }
}
