package card42.host.common.codec;

import java.util.Arrays;

import javax.smartcardio.ResponseAPDU;

/**
 * Parsers for the card's GPO and GENERATE AC responses (docs/specs/common/toolchain.md §6).
 *
 * The card answers contact in format 1 (tag 80) and contactless in format 2
 * (tag 77), so every parser accepts both.
 */
public final class Responses {

    private Responses() {
    }

    /** The parsed fields of a format 1 or format 2 GENERATE AC response. */
    public static final class AcResponse {
        public byte cid;
        public int atc;
        public byte[] ac;
        public byte[] iad;
    }

    /**
     * Parses a format 1 (tag 80) or format 2 (tag 77) GENERATE AC response into
     * its CID, ATC, AC and IAD.  Shared by the simulator suites so their
     * response parsers cannot drift apart.
     */
    public static AcResponse parseAc(ResponseAPDU r) {
        byte[] data = r.getData();
        AcResponse out = new AcResponse();
        if (data.length > 0 && (data[0] & 0xFF) == 0x77) {
            byte[] cid = Tags.find(data, 0x9F27);
            byte[] atc = Tags.find(data, 0x9F36);
            out.ac = Tags.find(data, 0x9F26);
            out.iad = Tags.find(data, 0x9F10);
            out.cid = cid != null ? cid[0] : 0;
            out.atc = atc != null ? (((atc[0] & 0xFF) << 8) | (atc[1] & 0xFF)) : 0;
        } else {
            // Format 1: 80 LL CID ATC AC IAD.
            out.cid = data[2];
            out.atc = ((data[3] & 0xFF) << 8) | (data[4] & 0xFF);
            out.ac = Arrays.copyOfRange(data, 5, Math.min(13, data.length));
            out.iad = Arrays.copyOfRange(data, 13, data.length);
        }
        return out;
    }

    /** The CID of a format 1 or format 2 GENERATE AC response. */
    public static byte parseCid(ResponseAPDU r) {
        return parseAc(r).cid;
    }

    // --- Cryptogram Information Data (EMV v4.4 Book 3 Table 15). -------------

    /** CID reason/advice code: Service not allowed. */
    public static final int CID_SERVICE_NOT_ALLOWED = 0x01;
    /** CID reason/advice code: PIN Try Limit exceeded. */
    public static final int CID_PIN_TRY_LIMIT_EXCEEDED = 0x02;
    /** CID reason/advice code: Issuer authentication failed. */
    public static final int CID_ISSUER_AUTH_FAILED = 0x03;

    /** True when the CID advice bit (b4) is set (EMV v4.4 Book 3 Table 15). */
    public static boolean adviceRequired(byte cid) {
        return (cid & 0x08) != 0;
    }

    /** The CID reason/advice code (b3-b1) (EMV v4.4 Book 3 Table 15). */
    public static int adviceReason(byte cid) {
        return cid & 0x07;
    }

    /** The AIP of a format 1 or format 2 GPO response. */
    public static byte[] gpoAip(byte[] gpo) {
        if ((gpo[0] & 0xFF) == 0x77) {
            return Tags.find(gpo, 0x82);
        }
        return Arrays.copyOfRange(gpo, 2, 4);
    }

    /** The AFL of a format 1 or format 2 GPO response. */
    public static byte[] gpoAfl(byte[] gpo) {
        if ((gpo[0] & 0xFF) == 0x77) {
            return Tags.find(gpo, 0x94);
        }
        return Arrays.copyOfRange(gpo, 4, gpo.length);
    }
}
