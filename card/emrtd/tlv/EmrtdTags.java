package card42.emrtd;

/* ICAO 9303 LDS1 data objects and file identifiers (Doc 9303-10 §4, §5).
 *
 * The LDS1 elementary files are addressed by a 2-byte file identifier (FID):
 * DG1..DG16 are 0101..0110, EF.SOD is 011D, EF.COM is 011E and EF.CVCA is
 * 011C.  The outer application templates are 61 (DG1), 75 (DG2), 6F (DG15),
 * 60 (COM) and 77 (SOD); the eMRTD DF name is A0 00 00 02 47 10 01.
 *
 * @author card42
 */

public final class EmrtdTags {

    /** LDS1 DF name / instance AID: A0 00 00 02 47 10 01 (Doc 9303-10 §4.1). */
    public static final byte[] DF_NAME_LDS1 = {
            (byte) 0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01 };

    // LDS2 application DF names (Doc 9303-10 §5.1–§5.3).
    /** Travel Records application: A0 00 00 02 47 20 01. */
    public static final byte[] DF_NAME_TRAVEL = {
            (byte) 0xA0, 0x00, 0x00, 0x02, 0x47, 0x20, 0x01 };
    /** Visa Records application: A0 00 00 02 47 20 02. */
    public static final byte[] DF_NAME_VISA = {
            (byte) 0xA0, 0x00, 0x00, 0x02, 0x47, 0x20, 0x02 };
    /** Additional Biometrics application: A0 00 00 02 47 20 03. */
    public static final byte[] DF_NAME_BIOMETRICS = {
            (byte) 0xA0, 0x00, 0x00, 0x02, 0x47, 0x20, 0x03 };

    // Elementary file identifiers (Doc 9303-10 §4.6).
    public static final short FID_DG1 = (short) 0x0101;
    public static final short FID_DG2 = (short) 0x0102;
    public static final short FID_DG3 = (short) 0x0103;
    public static final short FID_DG4 = (short) 0x0104;
    public static final short FID_DG5 = (short) 0x0105;
    public static final short FID_DG6 = (short) 0x0106;
    public static final short FID_DG7 = (short) 0x0107;
    public static final short FID_DG8 = (short) 0x0108;
    public static final short FID_DG9 = (short) 0x0109;
    public static final short FID_DG10 = (short) 0x010A;
    public static final short FID_DG11 = (short) 0x010B;
    public static final short FID_DG12 = (short) 0x010C;
    public static final short FID_DG13 = (short) 0x010D;
    public static final short FID_DG14 = (short) 0x010E;
    public static final short FID_DG15 = (short) 0x010F;
    public static final short FID_DG16 = (short) 0x0110;
    /**
     * EF.CVCA / EF.CardAccess (Doc 9303-10 §3.11.3, §5.1): EAC's EF.CVCA and
     * PACE's EF.CardAccess share FID {@code 011C}.  The LDS1 application serves
     * it as EF.CardAccess (EAC is out of scope); the LDS2 DFs also carry one.
     */
    public static final short FID_CVCA = (short) 0x011C;
    public static final short FID_SOD = (short) 0x011D;
    public static final short FID_COM = (short) 0x011E;

    // LDS2 elementary file identifiers (Doc 9303-10 §5.1–§5.3).
    /** EF.CardAccess in the master file / LDS2 DF: 011C (same as EF.CVCA). */
    public static final short FID_CARD_ACCESS = (short) 0x011C;
    /** EF.CardSecurity: 011D. */
    public static final short FID_CARD_SECURITY = (short) 0x011D;
    /** EF.Certificates (Travel/Visa/Biometrics): 011A. */
    public static final short FID_CERTIFICATES = (short) 0x011A;
    /** EF.EntryRecords (Travel Records application): 0101 (Doc 9303-10 §5.1.3). */
    public static final short FID_RECORDS = (short) 0x0101;
    /** EF.ExitRecords (Travel Records application): 0102 (Doc 9303-10 §5.1.4). */
    public static final short FID_EXIT_RECORDS = (short) 0x0102;
    /** EF.VisaRecords (Visa Records application): 0103 (Doc 9303-10 §5.2.3 Table 89). */
    public static final short FID_VISA_RECORDS = (short) 0x0103;
    /** EF.Biometrics1 (Additional Biometrics application): 0201 (Doc 9303-10 §5.3.3). */
    public static final short FID_BIOMETRICS = (short) 0x0201;

    // Project personalization DGIs (not ICAO files): key material for BAC, AA,
    // Chip Authentication and PACE.
    /** BAC K_seed (16 bytes). */
    public static final short DGI_BAC_SEED = (short) 0xFF01;
    /** AA RSA private key: modLen || modulus || expLen || exponent. */
    public static final short DGI_AA_KEY = (short) 0xFF02;
    /** Chip Authentication static P-256 private scalar (32 bytes). */
    public static final short DGI_CA_KEY = (short) 0xFF03;
    /** PACE key seed SHA-1(MRZ_information) (20 bytes), password reference 0x01. */
    public static final short DGI_PACE_SEED = (short) 0xFF04;
    /**
     * LDS1 master-file EF.CardSecurity (Doc 9303-10 §3.11.4) CMS SignedData.
     * FID {@code 011D} is already EF.SOD inside the LDS1 DF, so a dedicated
     * project DGI carries the master-file EF.CardSecurity content (LdsPerso
     * routes it to {@link LdsMfStore}).
     */
    public static final short DGI_CARD_SECURITY = (short) 0xFF05;
    /** PACE key seed SHA-1(CAN) (20 bytes), password reference 0x02. */
    public static final short DGI_PACE_CAN_SEED = (short) 0xFF06;

    // Application/EF outer tags.
    public static final short TAG_COM = (short) 0x60;
    public static final short TAG_DG1 = (short) 0x61;
    public static final short TAG_DG2 = (short) 0x75;
    public static final short TAG_DG15 = (short) 0x6F;
    public static final short TAG_SOD = (short) 0x77;

    // LDS2 command data objects (Doc 9303-10 §3.7/§3.8).
    /** File reference DO (FMM/SEARCH). */
    public static final short DO_FILE_REFERENCE = (short) 0x51;
    /** Offset DO of UPDATE BINARY. */
    public static final short DO_OFFSET = (short) 0x54;
    /** Discretionary data DO of UPDATE BINARY. */
    public static final short DO_DISCRETIONARY = (short) 0x53;
    /** File size DO of UPDATE BINARY. */
    public static final short DO_FILE_SIZE = (short) 0xC0;
    /** Record handling template (SEARCH RECORD). */
    public static final short DO_RECORD_HANDLING = (short) 0x7F76;
    /** File and memory management response template. */
    public static final short DO_FMM = (short) 0x7F78;

    // LDS1 command / status constants (ISO/IEC 7816-4 + Doc 9303-10 §5).
    public static final byte INS_SELECT_FILE = (byte) 0xA4;
    public static final byte INS_READ_BINARY = (byte) 0xB0;
    public static final byte INS_GET_CHALLENGE = (byte) 0x84;
    public static final byte INS_EXTERNAL_AUTHENTICATE = (byte) 0x82;
    public static final byte INS_INTERNAL_AUTHENTICATE = (byte) 0x88;

    // LDS2 / EAC commands (Doc 9303-10 §3.5, Doc 9303-11 §4/§6).
    public static final byte INS_READ_RECORD = (byte) 0xB2;
    public static final byte INS_APPEND_RECORD = (byte) 0xE2;
    public static final byte INS_SEARCH_RECORD = (byte) 0xA2;
    public static final byte INS_FILE_MEMORY_MANAGEMENT = (byte) 0x5F;
    public static final byte INS_MANAGE_SECURITY_ENVIRONMENT = (byte) 0x22;
    public static final byte INS_GENERAL_AUTHENTICATE = (byte) 0x86;
    public static final byte INS_PSO = (byte) 0x2A;
    /** UPDATE BINARY with the odd INS byte (Additional Biometrics, §3.8.1). */
    public static final byte INS_UPDATE_BINARY_ODD = (byte) 0xD7;
    /** ACTIVATE (Additional Biometrics, §3.8.2). */
    public static final byte INS_ACTIVATE = (byte) 0x44;

    // MSE P1/P2 (BSI TR-03110-3 B.14.1 MSE:Set AT): set for computation / KAT.
    public static final byte MSE_P1_SET_COMPUTATION = (byte) 0x41;
    public static final byte MSE_P2_KAT = (byte) 0xA6;
    /** MSE:Set AT (P2) for PACE (BSI TR-03110-3 B.14.1). */
    public static final byte MSE_P2_AT = (byte) 0xA4;

    // PACE GENERAL AUTHENTICATE data objects (BSI TR-03110-3 B.1, Doc 9303-11
    // §4.4): DO'80' encrypted nonce, DO'81'/DO'82' mapping public keys,
    // DO'83'/DO'84' ephemeral public keys, DO'85'/DO'86' auth tokens.
    public static final short DO_PACE_NONCE = (short) 0x80;
    public static final short DO_PACE_MAP_PCD = (short) 0x81;
    public static final short DO_PACE_MAP_PICC = (short) 0x82;
    public static final short DO_PACE_EPH_PCD = (short) 0x83;
    public static final short DO_PACE_EPH_PICC = (short) 0x84;
    public static final short DO_PACE_TOKEN_PCD = (short) 0x85;
    public static final short DO_PACE_TOKEN_PICC = (short) 0x86;
    /** DO'83' password reference (MSE:Set AT). */
    public static final short DO_PACE_PASSWORD_REF = (short) 0x83;

    // Chip Authentication private-key reference / public-key DO.
    public static final short DO_CA_PUBLIC_KEY = (short) 0x91;
    public static final short DO_KEY_ID = (short) 0x84;

    /**
     * Largest EF the card can serve.  {@code READ BINARY} addresses a 15-bit
     * offset and the personalization DGI length field is 15-bit (Doc 9303-10
     * §3.6.3.1), so a file cannot exceed 32767 bytes.  This is the sole
     * per-file bound once the fixed budgets are replaced by length-driven
     * growth (docs/specs/emrtd/emrtd.md §2).
     */
    public static final short MAX_EF_BYTES = (short) 32767;

    /** Master file identifier (ISO/IEC 7816-4 §7.1.1): 3F00. */
    public static final short FID_MF = (short) 0x3F00;
    /** EF.DIR in the master file (Doc 9303-10 §3.11.2): 2F00, SFI 1E. */
    public static final short FID_DIR = (short) 0x2F00;
    /** EF.ATR/INFO in the master file (Doc 9303-10 §3.11.1): 2F01, SFI 01. */
    public static final short FID_ATR_INFO = (short) 0x2F01;

    // SELECT FILE P1/P2 (ISO/IEC 7816-4 §7.1.1): P1 selects the MF (00), an EF
    // by FID (02) or a DF by FID (03); P2=0C requests no response data.  The
    // eMRTD reads EF.CardAccess at the MF level (Doc 9303-10 §3.11.3), so the
    // applet serves SELECT MF and the by-FID forms.
    public static final byte SELECT_P1_BY_FID = (byte) 0x00;
    public static final byte SELECT_P1_EF = (byte) 0x02;
    public static final byte SELECT_P1_DF = (byte) 0x03;
    public static final byte SELECT_P2_NO_FCI = (byte) 0x0C;

    // READ BINARY P1 (ISO/IEC 7816-4 §6.1.1): b8=1 selects the short EF
    // identifier form, b7/b6 are RFU and b5..b1 carry the SFI; P2 is the
    // 8-bit offset (Doc 9303-10 §3.6.3 Table 5).
    public static final byte READ_P1_SFI = (byte) 0x80;
    public static final byte SFI_MASK = (byte) 0x1F;

    private EmrtdTags() {
    }

    /** The FID of a data group (1-16), or 0 when out of range. */
    public static short dgFid(short dg) {
        if (dg < 1 || dg > 16) {
            return 0;
        }
        return (short) (0x0100 + dg);
    }

    /** The outer application tag of a data group (Doc 9303-10 §4.7), or 0. */
    public static short dgTag(short dg) {
        switch (dg) {
        case 1:
            return TAG_DG1;
        case 2:
            return TAG_DG2;
        case 3:
            return (short) 0x63;
        case 4:
            return (short) 0x76;
        case 5:
            return (short) 0x65;
        case 6:
            return (short) 0x66;
        case 7:
            return (short) 0x67;
        case 8:
            return (short) 0x68;
        case 9:
            return (short) 0x69;
        case 10:
            return (short) 0x6A;
        case 11:
            return (short) 0x6B;
        case 12:
            return (short) 0x6C;
        case 13:
            return (short) 0x6D;
        case 14:
            return (short) 0x6E;
        case 15:
            return TAG_DG15;
        case 16:
            return (short) 0x70;
        default:
            return 0;
        }
    }
}
