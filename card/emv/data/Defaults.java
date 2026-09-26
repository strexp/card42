package card42.emv;

import card42.common.*;

/* Role-dependent and role-independent default data used when personalization
 * does not supply a value (EMV CPS v2.0 Annex A, docs/specs/common/architecture.md §4).
 *
 * Keeping them in one place makes the fallbacks of the payment data, the FCI
 * and the record builders agree.
 *
 * All fields are compile-time constant arrays (the converter accepts these;
 * see the note in EMVAids about non-constant static fields).
 *
 * @author card42
 */

public final class Defaults {

    private Defaults() {
    }

    /**
     * Default AFL (one entry: SFI 1, records 1-5).  Records 4 and 5 are the
     * ICC PIN and ICC DDA/CDA public key certificates and only exist once the
     * corresponding certificates have been personalized; a missing record is
     * reported as 6A83 and skipped by the terminal (EMV v4.4 Book 2 §5, §6.5,
     * §6.6, docs/specs/common/architecture.md §2, EMV v4.4 Book 3 §6.5.11).  The sample
     * card personalized from sample.perso is self-consistent.
     */
    public static final byte[] AFL = {
            (byte) 0x08, 0x01, 0x05, 0x01 };

    /**
     * Default AIP of a contact instance: SDA + DDA + CDA + CVM supported +
     * terminal risk management.  The DDA/CDA bits only reflect the applet
     * capability; the ICC DDA/CDA key and certificate are supplied by
     * personalization (EMV v4.4 Book 2 §6.5/§6.6).
     */
    public static final byte[] AIP_CONTACT = {
            0x79, 0x00 };

    /** Default AIP of a contactless instance: SDA + DDA + CDA (no CVM). */
    public static final byte[] AIP_CONTACTLESS = {
            0x69, 0x00 };

    // CVM list: amount fields zero; only the two CV rules differ by role.
    // CONTACT: 01 00 = plaintext offline PIN by ICC, else fail.
    // CONTACTLESS: 1F 03 = No CVM required, else fail.
    public static final byte[] CVM_LIST_CONTACT = {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00 };
    public static final byte[] CVM_LIST_CONTACTLESS = {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1F, 0x03 };

    public static final byte[] LABEL_CONTACT = {
            0x45, 0x4D, 0x56, 0x34, 0x32, 0x20, 0x43, 0x4F,
            0x4E, 0x54, 0x41, 0x43, 0x54 }; // "card42 CONTACT"
    // Application Label is 1-16 bytes (EMV v4.4 Book 3 Annex A Table 37);
    // "card42 CTLS" keeps the default within that bound.
    public static final byte[] LABEL_CONTACTLESS = {
            0x45, 0x4D, 0x56, 0x34, 0x32, 0x20, 0x43, 0x54,
            0x4C, 0x53 }; // "card42 CTLS"

    /**
     * PPSE Kernel Identifier (tag 9F2A) of the default contactless Directory
     * Entry (EMV Contactless Book B v2.12 Table 3-4/3-5).  Byte 1 is 0x00:
     * b8-b7 = 00b (an international kernel) and the Short Kernel ID is
     * 000000b, i.e. "the kernel is associated with the corresponding ADF
     * Name".  card42 has no kernel, so Entry Point resolves the kernel from the
     * ADF Name (EMV Contactless Book B v2.12 §3.3.2 bullet C); a reader accepts the Combination.
     */
    public static final byte[] PPSE_KERNEL_IDENTIFIER = {
            0x00 };

    /**
     * Terminal Categories Supported List (tag 9F3E) advertised in the PPSE FCI
     * (EMV Contactless Book B v2.12 Table A-1/A-2): category 0001 (transit gate)
     * and 0002 (loyalty).  A terminal whose Terminal Category is on this list
     * sends SEND POI INFORMATION before Entry Point selection.
     */
    public static final byte[] SPI_TERMINAL_CATEGORIES = {
            0x00, 0x01, 0x00, 0x02 };

    /**
     * Supported Data Object List (tag 9F3F) advertised in the PPSE FCI
     * (EMV Contactless Book B v2.12 Table A-1): the card requests the Terminal
     * Country Code (9F1A) and Transaction Currency Code (5F2A) in the SPI
     * command data.  A tag/length pair list.
     */
    public static final byte[] SPI_SDOL = {
            (byte) 0x9F, 0x1A, 0x02, 0x5F, 0x2A, 0x02 };

    /**
     * Fallback CDOL1, used when the EMV CPS v2.0 DGIs do not supply one.  It is
     * the CCD data element set for Application Cryptogram generation in order
     * (EMV v4.4 Book 2 CCD Table CCD 3): the terminal-provided elements only,
     * since AIP/ATC/IAD come from the ICC internally.  The CDOL2 still carries
     * the CCD inline issuer authentication data (tag '91').
     */
    public static final byte[] CDOL1 = {
            (byte) 0x9F, 0x02, 0x06, (byte) 0x9F, 0x03, 0x06, (byte) 0x9F, 0x1A,
            0x02, (byte) 0x95, 0x05, 0x5F, 0x2A, 0x02, (byte) 0x9A, 0x03,
            (byte) 0x9C, 0x01, (byte) 0x9F, 0x37, 0x04 };
    public static final byte[] CDOL2 = {
            (byte) 0x91, 0x08, (byte) 0x8A, 0x02, (byte) 0x95, 0x05,
            (byte) 0x9F, 0x37, 0x04, (byte) 0x9F, 0x4C, 0x08 };
    public static final byte[] PAN = {
            0x12, 0x34, 0x56, 0x78, (byte) 0x90 };
    public static final byte[] EXPIRY = {
            0x29, 0x12, 0x31 };

    /**
     * Default Track 2 Equivalent Data (tag 57, EMV v4.4 Book 3 Annex A Table 37)
     * for the default PAN 1234567890 / expiry 2912: PAN, the 'D' separator, the
     * expiry YYMM, service code 101 and 'F' padding to the 19-byte maximum.
     */
    public static final byte[] TRACK2 = {
            0x12, 0x34, 0x56, 0x78, (byte) 0x90, (byte) 0xD2, (byte) 0x91,
            0x21, 0x01, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF };

    /**
     * Default Issuer Action Codes (EMV v4.4 Book 3 section 10.7): IAC-Denial defaults
     * to all bits 0, IAC-Online and IAC-Default to all bits 1 (EMV v4.4 Book 3 §10.8).
     * With these defaults any set TVR bit forces the transaction online.
     */
    public static final byte[] IAC_DENIAL = {
            0x00, 0x00, 0x00, 0x00, 0x00 };
    public static final byte[] IAC_ONLINE = {
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF };
    public static final byte[] IAC_DEFAULT = {
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF };

    /**
     * Default Issuer Application Data (EMV v4.4 Book 3 Annex C §C9, Format
     * Code 'A'): a fixed 32-byte template with the
     * Format Code 'A' / CV '5' CCI, a zero CVR, zero counters and zero issuer
     * discretionary data.  The card rewrites the CVR (bytes 4-8) before every
     * GENERATE AC; the DKI, counters and issuer discretionary bytes may be
     * personalized with tag 9F10.
     */
    public static final byte[] IAD = {
            Iad.LENGTH_INDICATOR, Iad.CCI_FC_A_CV_5, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, // CVR
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // counters
            Iad.LENGTH_INDICATOR,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // issuer discretionary
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

    /**
     * Default transaction log format (EMV v4.4 Book 3 Annex D4):
     * a list of (tag, length) entries whose values, concatenated in this order,
     * form one log record.  The card sources the terminal fields (9A, 5F2A,
     * 9F02, 95) from the first GENERATE AC's CDOL1 data and the card fields
     * (9F36 ATC, 9F27 CID) from its own state; see TransactionLog.
     *
     *   9A 03  Transaction Date
     *   5F2A 02 Transaction Currency Code
     *   9F02 06 Amount, Authorised
     *   9F36 02 Application Transaction Counter
     *   9F27 01 Cryptogram Information Data
     *   95 05  Terminal Verification Results
     */
    public static final byte[] LOG_FORMAT = {
            (byte) 0x9A, 0x03, 0x5F, 0x2A, 0x02, (byte) 0x9F, 0x02, 0x06,
            (byte) 0x9F, 0x36, 0x02, (byte) 0x9F, 0x27, 0x01, (byte) 0x95, 0x05 };
}
