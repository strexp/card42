package card42.emv;

import card42.common.AesCmac;
import card42.common.RetailMac;

import javacard.security.MessageDigest;
import javacard.security.RandomData;

/* Package-shared crypto engines and helpers for the EMV applets.
 *
 * Every payment instance used to build its own MAC engines (EMVCrypto held one
 * RetailMac and one AesCmac), its own RandomData and its own SHA-1 MessageDigest.
 * With the production contact/contactless instances plus the test instances
 * (deploy/deploy-emv-test.conf: 04/06/08) that is up to five copies of each, and
 * an AesCmac carries a 256-byte transient CBC staging array per copy
 * (docs/specs/common/risks.md §2).  Only one applet instance processes a command
 * at a time, so one engine set for the whole package is enough - exactly the
 * argument that already produced card42.emrtd's MacEngines.
 *
 * <p>The objects are allocated once, from the EMV applet constructors during
 * installation; the lazy getters keep the pure-JVM unit tests (which construct
 * EMVCrypto directly) working.  The engines' "load the key once per session key"
 * caches still short-circuit while a session key is stable and simply reload when
 * another instance presents a different key.
 *
 * <p>The shared objects live in this applet package (not in card42.common), so
 * they belong to the EMV applet context: a shared library would have put them in
 * an implementation-defined context and broken the per-context CLEAR_ON_DESELECT
 * and transient-budget accounting (docs/specs/common/architecture.md, risks.md §2).
 *
 * @author card42
 */

final class EmvEngines {

    /** 3DES ISO/IEC 9797-1 algorithm 3 MAC (CV '5', EMV v4.4 Book 2 §8.1.2). */
    private static RetailMac retailMac;
    /** AES ISO/IEC 9797-1 algorithm 5 / CMAC (CV '6', EMV v4.4 Book 2 §8.1.2). */
    private static AesCmac aesCmac;
    /** Unpredictable-number source (GET CHALLENGE, CDA, DDA). */
    private static RandomData random;
    /** SHA-1 for the CDA Transaction Data Hash Code (EMV v4.4 Book 2 §6.6). */
    private static MessageDigest sha1;

    private EmvEngines() {
    }

    /** Allocates the shared engines once, at install.  Idempotent. */
    static void init() {
        retailMac();
        aesCmac();
        random();
        sha1();
    }

    static RetailMac retailMac() {
        if (retailMac == null) {
            retailMac = new RetailMac();
        }
        return retailMac;
    }

    static AesCmac aesCmac() {
        if (aesCmac == null) {
            aesCmac = new AesCmac();
        }
        return aesCmac;
    }

    static RandomData random() {
        if (random == null) {
            random = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        }
        return random;
    }

    static MessageDigest sha1() {
        if (sha1 == null) {
            sha1 = MessageDigest.getInstance(MessageDigest.ALG_SHA, false);
        }
        return sha1;
    }
}
