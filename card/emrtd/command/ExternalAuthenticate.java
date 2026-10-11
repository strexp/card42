package card42.emrtd;

import card42.common.ConstantTime;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;

/* EXTERNAL AUTHENTICATE: BAC mutual authentication (ICAO Doc 9303-11 §4.3.1 /
 * §4.3.4.2).
 * The command data is E_IFD (32) || M_IFD (8); the response is E_IC (32) ||
 * M_IC (8).  The session keys and initial SSC are derived here.
 *
 * @author card42
 */

public final class ExternalAuthenticate {

    /* The BAC scratch (E_IFD, K_IC, S2, session seed) is the package-shared
     * transient {@link EmrtdScratch}: it used to be static persistent arrays,
     * so every BAC handshake wrote 96 bytes to EEPROM for state that lives
     * only for the command (docs/specs/common/risks.md §2). */

    private ExternalAuthenticate() {
    }

    public static short process(EmrtdApplet applet, byte[] data, short off, short len) {
        if (!applet.perso.seedSet()) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        if (len != 40) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        byte[] seed = applet.perso.seed();
        applet.bac.deriveKey(seed, (short) 0, BacCrypto.DERIVE_ENC, applet.kenc, (short) 0);
        applet.bac.deriveKey(seed, (short) 0, BacCrypto.DERIVE_MAC, applet.kmac, (short) 0);

        // M_IFD covers E_IFD (Doc 9303-11 §4.3.1 step 3a).
        if (!applet.challengeValid || !applet.bac.verifyMac(applet.kmac, data, off, (short) 32,
                data, (short) (off + 32))) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        byte[] s = EmrtdScratch.bacEIfd;
        applet.bac.decrypt(applet.kenc, data, off, s, (short) 0, (short) 32);
        // RND.IC must equal the challenge (Doc 9303-11 §4.3.1 step 3c).
        if (!ConstantTime.equals(s, (short) 8, applet.challenge, (short) 0, (short) 8)) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        byte[] kic = EmrtdScratch.bacKic;
        applet.random.generateData(kic, (short) 0, (short) 16);

        byte[] s2 = EmrtdScratch.bacS2;
        Util.arrayCopyNonAtomic(s, (short) 8, s2, (short) 0, (short) 8);   // RND.ICC
        Util.arrayCopyNonAtomic(s, (short) 0, s2, (short) 8, (short) 8);   // RND.IFD
        Util.arrayCopyNonAtomic(kic, (short) 0, s2, (short) 16, (short) 16);
        applet.bac.encrypt(applet.kenc, s2, (short) 0, applet.response, (short) 0, (short) 32);
        applet.bac.computeMac(applet.kmac, applet.response, (short) 0, (short) 32,
                applet.response, (short) 32);

        byte[] sessionSeed = EmrtdScratch.bacSessionSeed;
        BacCrypto.sessionSeed(s, (short) 16, kic, (short) 0, sessionSeed, (short) 0);
        applet.bac.deriveKey(sessionSeed, (short) 0, BacCrypto.DERIVE_ENC,
                applet.ksEnc, (short) 0);
        applet.bac.deriveKey(sessionSeed, (short) 0, BacCrypto.DERIVE_MAC,
                applet.ksMac, (short) 0);
        BacCrypto.initialSsc(s, (short) 8, s, (short) 0, applet.ssc, (short) 0);
        applet.smEstablished = true;
        applet.useSecureMessaging(false); // BAC is always 3DES
        applet.challengeValid = false;
        return 40;
    }
}
