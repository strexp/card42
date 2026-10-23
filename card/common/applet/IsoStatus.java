package card42.common;

/* ISO/IEC 7816-4 status words that the Java Card ISO7816 interface does not
 * expose.  The standard codes (6700, 6A80, 6A82, 6A83, 6A86, 6F00, ...) come
 * from {@link javacard.framework.ISO7816}; this class only adds the missing
 * warnings/errors so no class spells them as raw literals.
 *
 * @author card42
 */

public final class IsoStatus {

    private IsoStatus() {
    }

    /**
     * End of file reached before the expected number of data bytes, or the
     * record is not found (ISO/IEC 7816-4 Table 6); a warning.
     */
    public static final short SW_END_OF_FILE = (short) 0x6282;

    /** Selected file invalidated (EMV v4.4 Book 3 §6.5.1 / ISO/IEC 7816-4). */
    public static final short SW_SELECTED_FILE_INVALIDATED = (short) 0x6283;
    /** Authentication method blocked (ISO/IEC 7816-4); used for a blocked PIN. */
    public static final short SW_AUTH_BLOCKED = (short) 0x6983;
    /** Reference data not usable (ISO/IEC 7816-4). */
    public static final short SW_REFERENCE_DATA_NOT_USABLE = (short) 0x6984;
    /** Referenced data not found (ISO/IEC 7816-4). */
    public static final short SW_REFERENCED_DATA_NOT_FOUND = (short) 0x6A88;
    /** Authentication failed; used for issuer authentication (EMV v4.4 Book 3 §6.5.4.5). */
    public static final short SW_AUTHENTICATION_FAILED = (short) 0x6300;
    /** Command chaining failure (EMV v4.4 Book 3 §6.5.12.5). */
    public static final short SW_COMMAND_CHAINING_FAILED = (short) 0x6800;
}
