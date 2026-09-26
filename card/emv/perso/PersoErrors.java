package card42.emv;

import card42.common.*;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;

/* Maps a failure raised while applying a personalization sequence to the
 * status word the offline side sees (docs/specs/common/cryptography.md §9).
 *
 * The mapping is deliberately explicit and lives in its own class (rather than
 * inline in PersoHandler.applyAll) so it can be checked by a pure-JVM unit test
 * without a stub applet:
 *
 *   - ISOException  : transparently propagated (it already carries a status);
 *   - CryptoException: a condition-of-use failure (6985);
 *   - anything else : an unknown error (6F00).
 *
 * @author card42
 */

public final class PersoErrors implements ISO7816 {

    private PersoErrors() {
    }

    /**
     * Translates a failure caught while applying the DGI sequence and throws
     * the corresponding ISOException.  Always throws.
     */
    public static void throwMapped(Exception e) {
        if (e instanceof ISOException) {
            throw (ISOException) e;
        }
        if (e instanceof javacard.security.CryptoException) {
            ISOException.throwIt(SW_CONDITIONS_NOT_SATISFIED); // 6985
        }
        ISOException.throwIt((short) 0x6F00);
    }
}
