package card42.emv;

import javacard.framework.APDU;

/* The lifecycle, role, directory-type and interface-media constants of an EMV
 * instance, split out of the former EMVConstants constant interface.  They are
 * the instance's identity (docs/specs/common/architecture.md §1) rather than
 * command or status data.
 *
 * @author card42
 */

public final class EMVRoles {

    private EMVRoles() {
    }

    // constants to record the (persistent) lifecycle state
    public static final byte PERSONALISATION = (byte) 0x00;
    public static final byte READY = (byte) 0x01;
    /* Invalidated application (APPLICATION BLOCK, or the ATC overflow of
     * EMV v4.4 Book 2 Annex D3): SELECT answers 6283 and GENERATE AC only returns
     * AAC (EMV v4.4 Book 3 section 6.5.1). */
    public static final byte BLOCKED = (byte) 0x02;
    /* CARD BLOCK: every SELECT answers 6A81 (EMV v4.4 Book 3 section 6.5.3). */
    public static final byte CARD_BLOCKED = (byte) 0x03;

    // applet role: fixed per instance, see docs/specs/common/architecture.md §1
    public static final byte ROLE_CONTACT = (byte) 0x00;
    public static final byte ROLE_CONTACTLESS = (byte) 0x01;

    // directory type served by a DirectoryApplet instance
    public static final byte DIR_NONE = (byte) 0x00;
    public static final byte DIR_PSE = (byte) 0x01;
    public static final byte DIR_PPSE = (byte) 0x02;

    // interface media (apdu.getProtocol() & MEDIA_MASK), see
    // docs/specs/common/architecture.md §1.  Only the contact value is used for
    // decisions (getProtocol() is not reliable on the simulator, §1, §7).
    public static final byte MEDIA_MASK = APDU.PROTOCOL_MEDIA_MASK;
    public static final byte MEDIA_CONTACT = APDU.PROTOCOL_MEDIA_DEFAULT;
}
