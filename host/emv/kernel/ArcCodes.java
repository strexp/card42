package card42.host.emv.kernel;

/**
 * Cryptogram Information Data (CID) and Authorisation Response Code (ARC)
 * decoding (EMV v4.4 Book 3 Table 15, Book 4 §6.5.2/Annex A6).
 *
 * <p>Split out of {@link TransactionFlow}; these are pure functions of the two
 * two-byte fields.
 */
final class ArcCodes {

    private ArcCodes() {
    }

    /** The two-digit ISO 8583 response code of an ARC, or -1 when not numeric.
     *  The Authorisation Response Code ('8A') is ISO 8583 (EMV v4.4 Book 4 Annex A6). */
    static int code(byte[] arc) {
        if (arc == null || arc.length < 2) {
            return -1;
        }
        int hi = arc[0] & 0xFF;
        int lo = arc[1] & 0xFF;
        if (hi < '0' || hi > '9' || lo < '0' || lo > '9') {
            return -1;
        }
        return (hi - '0') * 10 + (lo - '0');
    }

    /** The mnemonic of a CID's b8-b7 cryptogram type (EMV v4.4 Book 3 Table 15). */
    static String name(byte cid) {
        switch (cid & 0xC0) {
        case 0x00: return "AAC";
        case 0x40: return "TC";
        case 0x80: return "ARQC";
        default: return String.format("%02X", cid & 0xFF);
        }
    }
}
