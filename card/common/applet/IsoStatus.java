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
}
