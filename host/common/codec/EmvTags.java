package card42.host.common.codec;

/**
 * The EMV v4.4 Book 3 §5.2 BER-TLV tag constants used by the host stack, the
 * counterpart of the card-side {@code card42.emv.TlvTags}.  Only the tags the
 * host modules reference are listed; the values match EMV v4.4 Book 3 Annex A.
 *
 * <p>It lives in {@code common} because both the EMV lib/kernel and the report
 * modules need the same names, and avoids spelling tags such as {@code 0x5A} /
 * {@code 0x8C} / {@code 0x9F08} as bare literals across the tree.
 */
public final class EmvTags {

    private EmvTags() {
    }

    // Records and templates.
    public static final int RECORD_TEMPLATE = 0x70;
    public static final int RESPONSE_FORMAT_1 = 0x80;
    public static final int RESPONSE_FORMAT_2 = 0x77;
    public static final int FCI_TEMPLATE = 0x6F;
    public static final int FCI_PROPRIETARY = 0xA5;
    public static final int FCI_ISSUER_DISCRETIONARY = 0xBF0C;
    public static final int DIRECTORY_ENTRY = 0x61;
    public static final int ADF_NAME = 0x4F;
    public static final int APPLICATION_LABEL = 0x50;
    public static final int PRIORITY_INDICATOR = 0x87;
    public static final int SFI = 0x88;
    public static final int DF_NAME = 0x84;

    // Application data.
    public static final int PAN = 0x5A;
    public static final int TRACK1_DATA = 0x56;
    public static final int TRACK2_EQUIVALENT_DATA = 0x57;
    public static final int EXPIRY_DATE = 0x5F24;
    public static final int EFFECTIVE_DATE = 0x5F25;
    public static final int ISSUER_COUNTRY_CODE = 0x5F28;
    public static final int PAN_SEQUENCE_NUMBER = 0x5F34;
    public static final int AIP = 0x82;
    public static final int AFL = 0x94;
    public static final int PDOL = 0x9F38;
    public static final int CDOL1 = 0x8C;
    public static final int CDOL2 = 0x8D;
    public static final int CVM_LIST = 0x8E;
    public static final int APPLICATION_VERSION_NUMBER_ICC = 0x9F08;
    public static final int APPLICATION_USAGE_CONTROL = 0x9F07;
    public static final int APPLICATION_CURRENCY_CODE = 0x9F42;
    public static final int COMMAND_TEMPLATE = 0x83;

    // Card risk management.
    public static final int IAC_DEFAULT = 0x9F0D;
    public static final int IAC_DENIAL = 0x9F0E;
    public static final int IAC_ONLINE = 0x9F0F;
    public static final int IAD = 0x9F10;
    public static final int LAST_ONLINE_ATC = 0x9F13;
    public static final int PIN_TRY_COUNTER = 0x9F17;
    public static final int LCOL = 0x9F14;
    public static final int UCOL = 0x9F23;

    // SDA / DDA / CDA certificate chain.
    public static final int CA_PUBLIC_KEY_INDEX = 0x8F;
    public static final int ISSUER_PUBLIC_KEY_CERT = 0x90;
    public static final int ISSUER_PUBLIC_KEY_REMAINDER = 0x92;
    public static final int ISSUER_PUBLIC_KEY_EXPONENT = 0x9F32;
    public static final int SIGNED_STATIC_APPLICATION_DATA = 0x93;
    public static final int SDA_TAG_LIST = 0x9F4A;
    public static final int ICC_PUBLIC_KEY_CERT = 0x9F46;
    public static final int ICC_PUBLIC_KEY_EXPONENT = 0x9F47;
    public static final int ICC_PUBLIC_KEY_REMAINDER = 0x9F48;
    public static final int DDOL = 0x9F49;
    public static final int SIGNED_DYNAMIC_APPLICATION_DATA = 0x9F4B;

    // Cryptogram / online processing.
    public static final int CID = 0x9F27;
    public static final int AC = 0x9F26;
    public static final int ATC = 0x9F36;
    public static final int UNPREDICTABLE_NUMBER = 0x9F37;
    public static final int ARC = 0x8A;
    public static final int ISSUER_AUTH_DATA = 0x91;

    // Issuer scripts.
    public static final int ISSUER_SCRIPT_TEMPLATE_1 = 0x71;
    public static final int ISSUER_SCRIPT_TEMPLATE_2 = 0x72;
    public static final int ISSUER_SCRIPT_IDENTIFIER = 0x9F18;
    public static final int ISSUER_SCRIPT_COMMAND = 0x86;
    public static final int ISSUER_SCRIPT_RESULTS = 0x9F5B;

    // Log.
    public static final int LOG_ENTRY = 0x9F4D;
    public static final int LOG_FORMAT = 0x9F4F;

    // Contactless Entry Point / PPSE (EMV Contactless Book B v2.12 §3.3).
    public static final int KERNEL_IDENTIFIER = 0x9F2A;
    public static final int EXTENDED_SELECTION = 0x9F29;
    public static final int ASRPD = 0x9F0A;
    public static final int TERMINAL_CATEGORIES_SUPPORTED = 0x9F3E;
    public static final int SDOL = 0x9F3F;
    public static final int POI_INFORMATION = 0x8B;
}
