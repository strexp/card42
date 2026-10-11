package card42.emrtd;

import card42.common.AesCmac;
import card42.common.RetailMac;

/* Package-shared MAC engines for the eMRTD applets.
 *
 * Every eMRTD instance used to build its own engines: BacCrypto and Iso7816Sm
 * each held a RetailMac, Iso7816SmAes an AesCmac and Pace both, so an LDS1
 * instance carried three RetailMac and two AesCmac objects (each with its key
 * objects, cipher and key-derivation cache) in persistent memory
 * (docs/specs/common/risks.md §2).  Only one applet instance processes a
 * command at a time, so one RetailMac and one AesCmac for the whole package
 * are enough; the engines' "load the key once per session key" cache still
 * short-circuits while the session key is stable and simply reloads when
 * another caller presents a different key.
 *
 * <p>The eager {@link #init()} runs from {@code EmrtdApplet}'s constructor, so
 * the engines are allocated at install time; the lazy getters keep the
 * pure-JVM unit tests (which construct BacCrypto/Pace directly) working.
 *
 * @author card42
 */

final class MacEngines {

    private static RetailMac retailMac;
    private static AesCmac aesCmac;

    private MacEngines() {
    }

    /** Allocates both engines once, at install.  Idempotent. */
    static void init() {
        retailMac();
        aesCmac();
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
}
