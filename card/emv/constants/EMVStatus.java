package card42.emv;

/* Status words, key-modulus bounds and issuer-authentication state that the
 * former EMVConstants constant interface exposed to every EMV class.  Split out
 * so a class depends only on the status codes it uses.
 *
 * ISO7816 already provides 6A80/6985/6A81/6A86/6A88/6A82/6A83 and 6700.
 *
 * @author card42
 */

public final class EMVStatus {

    private EMVStatus() {
    }

    // status words
    // 6283 ("selected file invalidated") is not exposed by Java Card's ISO7816
    // interface, so it is defined here (EMV v4.4 Book 3 Table 4 / §6.5.1).
    public static final short SW_SELECTED_FILE_INVALIDATED = (short) 0x6283;
    public static final short SW_PIN_BLOCKED = (short) 0x6983;
    // Enciphered PIN recovery failed (EMV v4.4 Book 2 §7.2 step 7/8 and its
    // footnote 34; EMV v4.4 Book 3 §10.5.1 allows 6983 or 6984).
    public static final short SW_REFERENCE_DATA_NOT_USABLE = (short) 0x6984;
    // GET DATA referenced data not found (EMV v4.4 Book 3 Table 5).
    public static final short SW_REFERENCED_DATA_NOT_FOUND = (short) 0x6A88;
    // Issuer authentication failed (EMV v4.4 Book 3 §6.5.4.5).
    public static final short SW_ISSUER_AUTHENTICATION_FAILED = (short) 0x6300;
    // A chained VERIFY (CLA='10') could not be processed (EMV v4.4 Book 3
    // §6.5.12.5): the failure is not one of the specific chaining errors
    // 6883/6884 of section 6.5.13.  ISO7816 does not define 6800.
    public static final short SW_COMMAND_CHAINING_FAILED = (short) 0x6800;

    /* RSA modulus upper bounds (EMV v4.4 Book 2 Table 43).  The CA key is only
     * used off-card by the terminal / certificate generator, but the issuer,
     * ICC DDA/CDA and ICC PIN encipherment bounds are enforced on the card when
     * the corresponding certificates/keys are personalized.  An SDA-only issuer
     * key may be one byte longer because the SSAD uses a 1-byte tag (EMV v4.4
     * Book 2 Table 43 note / Annex D1.1). */
    public static final short RSA_MAX_CA_MODULUS = (short) 248;
    public static final short RSA_MAX_ISSUER_MODULUS = (short) 247;
    public static final short RSA_MAX_ISSUER_MODULUS_SDA = (short) 248;
    public static final short RSA_MAX_ICC_MODULUS = (short) 247;

    // Issuer authentication state of the current transaction (EMV v4.4 Book 2 §8.2).
    public static final byte ISSUER_AUTH_NONE = (byte) 0x00;
    public static final byte ISSUER_AUTH_SUCCESS = (byte) 0x01;
    public static final byte ISSUER_AUTH_FAILED = (byte) 0x02;
}
