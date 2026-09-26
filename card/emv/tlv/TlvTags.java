package card42.emv;

import card42.common.*;

/* Constants for the personalization data model of card42.
 *
 * The DGI numbers follow EMV CPS v2.0 Annex A;
 * the EMV CPS v2.0 reserved ranges (9F60-9F6F, 00CF, 7FF0-7FFE) are deliberately avoided.
 * File records use DGI == (SFI << 8) | record.
 *
 * The BER-TLV tags are the subset listed in EMV v4.4 Book 3 §5.2, plus the
 * Entry Point / PPSE tags of EMV Contactless Book B v2.12 §3.3 (9F2A/9F29/
 * 9F0A).
 *
 * @author card42
 */

public final class TlvTags {

    private TlvTags() {
    }

    // --- DGI containers (EMV CPS v2.0 Annex A) ---------------
    //
    // The EMV CPS v2.0 (2021-08) numbering replaces the former project-specific
    // E0xx containers.  File records keep the EMV CPS v2.0 scheme where the DGI is the
    // (SFI << 8) | record key, i.e. '0101'..'1EFF' are record templates.
    // The card42-specific data uses project DGIs outside the ranges that EMV CPS v2.0
    // reserves (9F60-9F6F, 7FF0-7FFE, 8F01, 7F01, 00CF, 0062).

    /** SELECT response data (an A5 FCI proprietary template), EMV CPS v2.0 Annex A DGI '9102'. */
    public static final short DGI_FCI_RESPONSE = (short) 0x9102;
    /** GPO response data (82 AIP / 94 AFL), EMV CPS v2.0 Annex A DGI '9104'. */
    public static final short DGI_GPO_RESPONSE = (short) 0x9104;
    /** Application common internal data (9F36 ATC, 9F4F Log Format), EMV CPS v2.0 Annex A DGI '3000'. */
    public static final short DGI_APP_COMMON = (short) 0x3000;
    /** Application internal data (IAC, limits, IAD, ...), EMV CPS v2.0 Annex A DGI '3001'. */
    public static final short DGI_APP_INTERNAL = (short) 0x3001;
    /**
     * Block cipher (DES/AES) keys: CAM (ICC master) key || MAC UDK || ENC UDK,
     * each 16 bytes for the 3DES profile.  Shorter values carry only the
     * leading keys (16 = CAM, 32 = CAM+MAC, 48 = CAM+MAC+ENC), EMV CPS v2.0 Annex A DGI '8000'.
     */
    public static final short DGI_BLOCK_KEYS = (short) 0x8000;
    /** Block cipher Key Check Values; accepted and ignored, EMV CPS v2.0 Annex A DGI '9000'. */
    public static final short DGI_KCV = (short) 0x9000;
    /** Reference PIN Block (ISO 9564-1 format 1), EMV CPS v2.0 Annex A DGI '8010'. */
    public static final short DGI_OFFLINE_PIN = (short) 0x8010;
    /** PIN related data (PIN Try Counter / Limit), EMV CPS v2.0 Annex A DGI '9010'. */
    public static final short DGI_PIN_DATA = (short) 0x9010;
    /** ICC DDA/CDA private key exponent, EMV CPS v2.0 Annex A DGI '8101'. */
    public static final short DGI_ICC_DDA_EXPONENT = (short) 0x8101;
    /** ICC PIN encipherment private key exponent, EMV CPS v2.0 Annex A DGI '8102'. */
    public static final short DGI_ICC_PIN_EXPONENT = (short) 0x8102;
    /** ICC DDA/CDA key modulus, EMV CPS v2.0 Annex A DGI '8103'. */
    public static final short DGI_ICC_DDA_MODULUS = (short) 0x8103;
    /** ICC PIN encipherment key modulus, EMV CPS v2.0 Annex A DGI '8104'. */
    public static final short DGI_ICC_PIN_MODULUS = (short) 0x8104;
    /** ICC ECC secret key (XDA/ODE); accepted but not used, EMV CPS v2.0 Annex A DGI '8105'. */
    public static final short DGI_ICC_ECC_KEY = (short) 0x8105;
    /** ICC ECC offline-data secret key; accepted but not used, EMV CPS v2.0 Annex A DGI '8106'. */
    public static final short DGI_ICC_ECC_OFFLINE_KEY = (short) 0x8106;
    /** Personalization completion data (optional), EMV CPS v2.0 Annex A DGI '7FFF'. */
    public static final short DGI_COMPLETE = (short) 0x7FFF;

    // card42 extensions in project DGIs outside the EMV CPS v2.0 reserved ranges
    // (EMV CPS v2.0 §3.2).  They carry internal card data that has no standard
    // EMV CPS v2.0 DGI.
    /**
     * Cumulative offline amount limits (EMV v4.4 Book 3 Annex C §C9.3): BCD,
     * {@code LCOTA(6) || UCOTA(6)}.
     */
    public static final short DGI_OFFLINE_LIMITS = (short) 0xE002;
    /** Cryptogram algorithm selection (DGI 'E003': 9F69 CV, 9F6A AES key length). */
    public static final short DGI_ALGORITHM = (short) 0xE003;
    /** Cryptogram Version ('5' 3DES / '6' AES) inside DGI 'E003'. */
    public static final short TAG_CRYPTOGRAM_VERSION = (short) 0x9F69;
    /** AES key length in bytes (16/32) inside DGI 'E003'; default 16. */
    public static final short TAG_AES_KEY_LENGTH = (short) 0x9F6A;

    /** True when dgi is an EMV CPS v2.0 file-record container ('01xx'..'1Exx'). */
    public static boolean isRecordDgi(short dgi) {
        short high = (short) ((dgi >> 8) & 0xFF);
        return high >= 0x01 && high <= 0x1E;
    }

    // --- BER-TLV tags (EMV v4.4 Book 3 §5.2) ----------------------------------

    public static final short TAG_RECORD_TEMPLATE = (short) 0x70;
    public static final short TAG_PAN = (short) 0x5A;
    public static final short TAG_EXPIRY_DATE = (short) 0x5F24;
    public static final short TAG_APPLICATION_LABEL = (short) 0x50;
    /** Application Preferred Name in a directory entry (EMV CPS v2.0 Annex A Table A-20). */
    public static final short TAG_APPLICATION_PREFERRED_NAME = (short) 0x9F12;
    public static final short TAG_PRIORITY_INDICATOR = (short) 0x87;
    /** Processing Options Data Object List (validated by GPO, EMV v4.4 Book 3 §6.5.8). */
    public static final short TAG_PDOL = (short) 0x9F38;
    public static final short TAG_AIP = (short) 0x82;
    public static final short TAG_AFL = (short) 0x94;
    public static final short TAG_CVM_LIST = (short) 0x8E;
    public static final short TAG_CDOL1 = (short) 0x8C;
    public static final short TAG_CDOL2 = (short) 0x8D;
    /** Command Template of GET PROCESSING OPTIONS (the PDOL-related data). */
    public static final short TAG_COMMAND_TEMPLATE = (short) 0x83;
    /** Terminal Verification Results (EMV v4.4 Book 3 §10.8). */
    public static final short TAG_TVR = (short) 0x95;
    /** Amount, Authorised (numeric, BCD; CDOL1 and log field). */
    public static final short TAG_AMOUNT_AUTHORISED = (short) 0x9F02;

    // --- Optional card data objects (EMV v4.4 Book 3 Annex A Table 37) --------
    /** Issuer Identification Number Extended, in the FCI (EMV v4.4 Book 3 Annex A). */
    public static final short TAG_IINE = (short) 0x9F0C;
    /** Token Requestor ID, in a record template (EMV v4.4 Book 3 Annex A). */
    public static final short TAG_TOKEN_REQUESTOR_ID = (short) 0x9F19;
    /** Payment Account Reference (PAR), in a record template (EMV v4.4 Book 3 Annex A). */
    public static final short TAG_PAR = (short) 0x9F24;
    /** Last 4 Digits of PAN, in a record template (EMV v4.4 Book 3 Annex A). */
    public static final short TAG_LAST4_PAN = (short) 0x9F25;
    /** Track 2 Equivalent Data, in a record template (EMV v4.4 Book 3 Annex A). */
    public static final short TAG_TRACK2_EQUIVALENT_DATA = (short) 0x57;
    /** Application Usage Control, in a record template (EMV v4.4 Book 3 §10.4.2). */
    public static final short TAG_APPLICATION_USAGE_CONTROL = (short) 0x9F07;
    /** Application Version Number, in a record template (EMV v4.4 Book 3 §10.4.1). */
    public static final short TAG_APPLICATION_VERSION_NUMBER = (short) 0x9F08;

    // --- Card risk management (EMV v4.4 Book 3 §10.8) --------------------------
    /** Issuer Action Code - Default. */
    public static final short TAG_IAC_DEFAULT = (short) 0x9F0D;
    /** Issuer Action Code - Denial. */
    public static final short TAG_IAC_DENIAL = (short) 0x9F0E;
    /** Issuer Action Code - Online. */
    public static final short TAG_IAC_ONLINE = (short) 0x9F0F;
    /** Issuer Application Data. */
    public static final short TAG_IAD = (short) 0x9F10;

    // --- SDA certificate chain (EMV v4.4 Book 2 §5) -------------------------
    public static final short TAG_CA_PUBLIC_KEY_INDEX = (short) 0x8F;
    public static final short TAG_ISSUER_PUBLIC_KEY_CERT = (short) 0x90;
    public static final short TAG_ISSUER_PUBLIC_KEY_REMAINDER = (short) 0x92;
    public static final short TAG_ISSUER_PUBLIC_KEY_EXPONENT = (short) 0x9F32;
    public static final short TAG_SIGNED_STATIC_APPLICATION_DATA = (short) 0x93;
    public static final short TAG_SDA_TAG_LIST = (short) 0x9F4A;

    // --- DDA / CDA (EMV v4.4 Book 2 §6.5, §6.6) ----------------------------
    public static final short TAG_ICC_PUBLIC_KEY_CERT = (short) 0x9F46;
    public static final short TAG_ICC_PUBLIC_KEY_EXPONENT = (short) 0x9F47;
    public static final short TAG_ICC_PUBLIC_KEY_REMAINDER = (short) 0x9F48;
    /** Signed Dynamic Application Data (SDAD), the DDA/CDA signature. */
    public static final short TAG_SIGNED_DYNAMIC_APPLICATION_DATA = (short) 0x9F4B;
    /** Cryptogram Information Data (CID). */
    public static final short TAG_CID = (short) 0x9F27;
    /** Application Transaction Counter (ATC). */
    public static final short TAG_ATC = (short) 0x9F36;
    /** Application Cryptogram (AC). */
    public static final short TAG_AC = (short) 0x9F26;
    /** Unpredictable Number (terminal). */
    public static final short TAG_UNPREDICTABLE_NUMBER = (short) 0x9F37;

    // --- Issuer authentication and online processing (EMV v4.4 Book 2 §8.2) ---
    /** Issuer Authentication Data (ARPC [+ CSU]), CDOL2 / EXTERNAL AUTHENTICATE. */
    public static final short TAG_ISSUER_AUTH_DATA = (short) 0x91;
    /** Authorisation Response Code (ARC), a CDOL2 data element. */
    public static final short TAG_AUTHORISATION_RESPONSE_CODE = (short) 0x8A;

    // --- Offline velocity checking (EMV v4.4 Book 3 Annex C §C9.3) --------------------
    /** Lower Consecutive Offline Limit (LCOL). */
    public static final short TAG_LCOL = (short) 0x9F14;
    /** Upper Consecutive Offline Limit (UCOL). */
    public static final short TAG_UCOL = (short) 0x9F23;

    // --- Transaction log (EMV v4.4 Book 3 Annex D4) ------------------------------
    /** Log Entry: SFI (1 B) || maximum number of records (1 B), in the FCI. */
    public static final short TAG_LOG_ENTRY = (short) 0x9F4D;
    /** Log Format, read with GET DATA; a list of (tag, length) entries. */
    public static final short TAG_LOG_FORMAT = (short) 0x9F4F;

    // --- Issuer scripts and secure messaging (EMV v4.4 Book 2 §9.2/§9.3) -----------
    /** Secure messaging Format 1 plaintext command data object. */
    public static final short TAG_SM_PLAINTEXT = (short) 0x81;
    /** Secure messaging Format 1 MAC data object. */
    public static final short TAG_SM_MAC = (short) 0x8E;
    /** Secure messaging Format 1 confidentiality data object. */
    public static final short TAG_SM_ENCIPHERED = (short) 0x87;
    /** Padding indicator byte used by the Format 1 confidentiality object. */
    public static final byte SM_PADDING_INDICATOR = (byte) 0x01;

    // --- Enciphered offline PIN (EMV v4.4 Book 2 §7.2) ------------------------
    public static final short TAG_ICC_PIN_PUBLIC_KEY_CERT = (short) 0x9F2D;
    public static final short TAG_ICC_PIN_PUBLIC_KEY_EXPONENT = (short) 0x9F2E;
    public static final short TAG_ICC_PIN_PUBLIC_KEY_REMAINDER = (short) 0x9F2F;

    // --- FCI / directory templates (docs/specs/common/architecture.md §6) ---------------------

    public static final short TAG_FCI_TEMPLATE = (short) 0x6F;
    public static final short TAG_FCI_PROPRIETARY = (short) 0xA5;
    public static final short TAG_FCI_ISSUER_DISCRETIONARY = (short) 0xBF0C;
    /** SFI of the directory elementary file, inside the PSE FCI (EMV CPS v2.0 Table A-21). */
    public static final short TAG_SFI = (short) 0x88;
    public static final short TAG_DF_NAME = (short) 0x84;
    public static final short TAG_DIRECTORY_ENTRY = (short) 0x61;
    public static final short TAG_ADF_NAME = (short) 0x4F;

    // --- Contactless Entry Point / PPSE (EMV Contactless Book B v2.12 §3.3) ---
    /** Kernel Identifier, inside a PPSE Directory Entry (EMV Contactless Book B v2.12 Table 3-4/3-5). */
    public static final short TAG_KERNEL_IDENTIFIER = (short) 0x9F2A;
    /** Extended Selection, appended to the ADF Name in SELECT (EMV Contactless Book B v2.12 Table A-1). */
    public static final short TAG_EXTENDED_SELECTION = (short) 0x9F29;
    /** Application Selection Registered Proprietary Data (EMV Contactless Book B v2.12 §3.3.1.2). */
    public static final short TAG_ASRPD = (short) 0x9F0A;

    // --- SEND POI INFORMATION (EMV Contactless Book B v2.12 Annex C) ---------
    /** Terminal Categories Supported List, advertised in the PPSE FCI (Book B Table A-1). */
    public static final short TAG_TERMINAL_CATEGORIES_SUPPORTED = (short) 0x9F3E;
    /** Supported Data Object List, advertised in the PPSE FCI (Book B Table A-1). */
    public static final short TAG_SDOL = (short) 0x9F3F;
    /** POI Information, carried in the SPI command data (Book B Annex C). */
    public static final short TAG_POI_INFORMATION = (short) 0x8B;
    /** POI Information ID '0001': Terminal Category (Book B Table A-2). */
    public static final short POI_ID_TERMINAL_CATEGORY = (short) 0x0001;
}
