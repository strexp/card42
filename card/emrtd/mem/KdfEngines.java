package card42.emrtd;

import javacard.security.RandomData;

/* Package-shared SHA-1 KDF and secure random source for the eMRTD applets.
 *
 * BacCrypto, Pace and ChipAuth each used to build their own Sha1Kdf (a
 * MessageDigest plus its scratch), and EmrtdApplet and AaCrypto each built their
 * own RandomData.  An LDS1 instance therefore carried three KDFs and two random
 * sources, and every LDS2 instance two KDFs and one random source.  Only one
 * applet instance processes a command at a time and the KDF calls never nest, so
 * one Sha1Kdf and one RandomData for the whole package are enough; this mirrors
 * MacEngines (docs/specs/common/risks.md §2).
 *
 * <p>The objects are allocated once, from EmrtdApplet's constructor during
 * installation; the lazy getters keep the pure-JVM unit tests (which construct
 * BacCrypto / AaCrypto / ChipAuth directly) working.
 *
 * <p>They live in this applet package (not in card42.common), so they belong to
 * the eMRTD applet context.
 *
 * @author card42
 */

final class KdfEngines {

    /** SHA-1 KDF(x, counter) shared by BAC, PACE and Chip Authentication. */
    private static Sha1Kdf kdf;
    /** Unpredictable-number source (GET CHALLENGE, BAC, PACE, Active Authentication). */
    private static RandomData random;

    private KdfEngines() {
    }

    /** Allocates the shared helpers once, at install.  Idempotent. */
    static void init() {
        kdf();
        random();
    }

    static Sha1Kdf kdf() {
        if (kdf == null) {
            kdf = new Sha1Kdf();
        }
        return kdf;
    }

    static RandomData random() {
        if (random == null) {
            random = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        }
        return random;
    }
}
