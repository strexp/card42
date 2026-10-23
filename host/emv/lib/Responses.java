package card42.host.emv.lib;

import java.util.Arrays;

import javax.smartcardio.ResponseAPDU;

import card42.host.common.codec.Tags;

/**
 * Parsers for the card's GPO and GENERATE AC responses (docs/specs/common/toolchain.md §6).
 *
 * The card answers contact in format 1 (tag 80) and contactless in format 2
 * (tag 77), so every parser accepts both.
 */
public final class Responses {

    private Responses() {
    }

    /** Immutable parsed fields of a format 1 or format 2 GENERATE AC response. */
    public static final class AcResponse {
        public final byte cid;
        public final int atc;
        public final byte[] ac;
        public final byte[] iad;

        public AcResponse(byte cid, int atc, byte[] ac, byte[] iad) {
            this.cid = cid;
            this.atc = atc;
            this.ac = ac == null ? null : ac.clone();
            this.iad = iad == null ? null : iad.clone();
        }
    }

    /**
     * Parses a format 1 (tag 80) or format 2 (tag 77) GENERATE AC response into
     * its CID, ATC, AC and IAD.  Shared by the simulator suites so their
     * response parsers cannot drift apart.
     */
    public static AcResponse parseAc(ResponseAPDU r) {
        byte[] data = r.getData();
        if (data.length > 0 && (data[0] & 0xFF) == 0x77) {
            byte[] cid = Tags.find(data, 0x9F27);
            byte[] atc = Tags.find(data, 0x9F36);
            byte cidValue = cid != null ? cid[0] : 0;
            int atcValue = atc != null
                    ? (((atc[0] & 0xFF) << 8) | (atc[1] & 0xFF)) : 0;
            return new AcResponse(cidValue, atcValue,
                    Tags.find(data, 0x9F26), Tags.find(data, 0x9F10));
        }
        // Format 1: 80 LL CID ATC AC IAD.
        return new AcResponse(data[2], ((data[3] & 0xFF) << 8) | (data[4] & 0xFF),
                Arrays.copyOfRange(data, 5, Math.min(13, data.length)),
                Arrays.copyOfRange(data, 13, data.length));
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
