package card42.emv;

import card42.common.InstallParams;

/* The install parameters of an EMV applet instance (Java Card 3.0.5 JCRE §11.2.1).
 *
 * The shared (L,V) parsing and AID fallback live in {@link card42.common.InstallParams};
 * this subclass adds the EMV-specific role resolution from the applet data
 * (see docs/specs/common/research-notes.md §3).
 *
 * @author card42
 */

public class InstallParameters extends InstallParams {

    /**
     * Resolves a one-byte role/directory code from the applet data of the
     * install parameters (docs/specs/common/research-notes.md §3).  Returns roleA when the first
     * applet data byte is validA, roleB when it is validB, and fallback
     * otherwise (including when no applet data is present).
     */
    public byte roleFromInstallData(byte validA, byte roleA,
            byte validB, byte roleB, byte fallback) {
        if (getInstallDataLength() >= 1) {
            byte r = getInstallData()[0];
            if (r == validA) {
                return roleA;
            }
            if (r == validB) {
                return roleB;
            }
        }
        return fallback;
    }
}
