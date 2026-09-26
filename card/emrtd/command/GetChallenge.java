package card42.emrtd;

import javacard.framework.Util;

/* GET CHALLENGE (ICAO Doc 9303-11 §4.3.4.1): returns an 8-byte RND.ICC and keeps
 * it as the BAC challenge.
 *
 * @author card42
 */

public final class GetChallenge {

    private GetChallenge() {
    }

    public static short process(EmrtdApplet applet) {
        applet.random.generateData(applet.challenge, (short) 0, (short) 8);
        applet.challengeValid = true;
        Util.arrayCopyNonAtomic(applet.challenge, (short) 0, applet.response,
                (short) 0, (short) 8);
        return 8;
    }
}
