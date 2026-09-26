package card42.host.emv.oda;

import java.io.ByteArrayOutputStream;
import java.util.Arrays;

import card42.host.common.util.Bytes;
import card42.host.common.util.Digests;
import card42.host.common.codec.Tags;
import card42.host.emv.lib.IssuerKey;

/**
 * Terminal-side Dynamic Data Authentication (DDA) and Combined DDA/Application
 * Cryptogram Generation (CDA) verification (EMV v4.4 Book 2 §6.5, §6.6).
 *
 * <p>Both use the ICC public key recovered from the certificate in record 5
 * ({@link SdaVerifier#recoverIccKey}) and the ISO/IEC 9796-2 recovery function
 * of EMV v4.4 Book 2 Annex A2.1: the recovered block is 6A || MSG1 || H || BC and
 * the hash H covers MSG1 followed by the terminal dynamic data.
 *
 * <p>The verifier never reports to stdout: every method returns a {@link Result}
 * the caller interprets.
 */
public final class CamVerifier {

    /** The outcome of one DDA/CDA verification. */
    public static final class Result {
        /** True when every check passed. */
        public final boolean ok;
        /** A short failure description, or null when {@link #ok}. */
        public final String reason;
        /**
         * On success: the ICC Dynamic Number for DDA, or the recovered
         * Application Cryptogram for CDA; null on failure.
         */
        public final byte[] value;
        /**
         * The ICC Dynamic Number recovered from the ICC Dynamic Data on success
         * (tag '9F4C', EMV v4.4 Book 2 §6.5.2/§6.6.2), or null.
         */
        public final byte[] iccDynamicNumber;

        Result(boolean ok, String reason, byte[] value) {
            this(ok, reason, value, null);
        }

        Result(boolean ok, String reason, byte[] value, byte[] iccDynamicNumber) {
            this.ok = ok;
            this.reason = reason;
            this.value = value;
            this.iccDynamicNumber = iccDynamicNumber;
        }

        /** A failed result with the given reason. */
        public static Result failure(String reason) {
            return new Result(false, reason, null);
        }
    }

    private CamVerifier() {
    }

    /**
     * Verifies a DDA Signed Dynamic Application Data (EMV v4.4 Book 2 tables 14/16).
     * The DDOL data is the terminal dynamic data sent in INTERNAL AUTHENTICATE.
     * On success {@link Result#value} is the ICC Dynamic Number.
     */
    public static Result verifyDda(byte[] sdad, byte[] ddolData,
                                   IssuerKey iccKey) {
        if (iccKey == null) {
            return new Result(false, "DDA: ICC public key unavailable", null);
        }
        byte[] rec = Sda.recover(sdad, iccKey.modulus, iccKey.exponent);
        if (rec.length != sdad.length) {
            return new Result(false, "DDA SDAD length", null);
        }
        boolean structure = rec[0] == 0x6A && rec[1] == 0x05
                && rec[rec.length - 1] == (byte) 0xBC;
        byte[] hashInput = Bytes.concat(
                Arrays.copyOfRange(rec, 1, rec.length - 21), ddolData);
        boolean hash = Arrays.equals(Digests.sha1(hashInput),
                Arrays.copyOfRange(rec, rec.length - 21, rec.length - 1));
        if (!(structure && hash)) {
            return new Result(false, "DDA signed dynamic application data", null);
        }
        // ICC Dynamic Data: 1-byte length of the ICC Dynamic Number + number.
        // The recovered block is 6A || 05 || 01 || LDD || ICC Dynamic Data ...
        int ldd = rec[3] & 0xFF;
        int dynLength = rec[4] & 0xFF;
        if (dynLength < 2 || dynLength > 8 || 4 + ldd > rec.length) {
            return new Result(false, "DDA ICC dynamic data", null);
        }
        byte[] dyn = Arrays.copyOfRange(rec, 5, 5 + dynLength);
        return new Result(true, null, dyn, dyn);
    }

    /**
     * Verifies a CDA format 2 GENERATE AC response (EMV v4.4 Book 2 tables 17-21):
     * recovers the SDAD, checks the signature hash, the ICC Dynamic Data
     * (CID, AC, Transaction Data Hash Code) and the response CID.  On success
     * {@link Result#value} is the recovered AC.
     */
    public static Result verifyCda(byte[] responseData, byte[] cdol1Data,
                                   byte[] cdol2Data, byte[] pdolData,
                                   byte[] unpredictableNumber,
                                   IssuerKey iccKey, byte[] expectedAc,
                                   int expectedCid) {
        if (iccKey == null) {
            return new Result(false, "CDA: ICC public key unavailable", null);
        }
        byte[] sdad = Tags.find(responseData, 0x9F4B);
        byte[] cidTag = Tags.find(responseData, 0x9F27);
        byte[] atcTag = Tags.find(responseData, 0x9F36);
        byte[] iadTag = Tags.find(responseData, 0x9F10);
        if (sdad == null || cidTag == null || atcTag == null || iadTag == null) {
            return new Result(false, "CDA response 9F27/9F36/9F4B/9F10", null);
        }
        int cid = cidTag[0] & 0xFF;
        if (cid != expectedCid) {
            return new Result(false, "CDA response CID", null);
        }

        byte[] rec = Sda.recover(sdad, iccKey.modulus, iccKey.exponent);
        if (rec.length != sdad.length) {
            return new Result(false, "CDA SDAD length", null);
        }
        boolean structure = rec[0] == 0x6A && rec[1] == 0x05
                && rec[rec.length - 1] == (byte) 0xBC;
        byte[] hashInput = Bytes.concat(
                Arrays.copyOfRange(rec, 1, rec.length - 21), unpredictableNumber);
        boolean hash = Arrays.equals(Digests.sha1(hashInput),
                Arrays.copyOfRange(rec, rec.length - 21, rec.length - 1));
        if (!(structure && hash)) {
            return new Result(false, "CDA signed dynamic application data", null);
        }

        // ICC Dynamic Data (EMV v4.4 Book 2 table 18): dynamic number, CID, AC, hash.
        // The recovered block is 6A || 05 || 01 || LDD || ICC Dynamic Data ...
        int ldd = rec[3] & 0xFF;
        int dynLength = rec[4] & 0xFF;
        int o = 5 + dynLength;
        if (dynLength < 2 || dynLength > 8 || o + 29 > 4 + ldd) {
            return new Result(false, "CDA ICC dynamic data", null);
        }
        int dynamicCid = rec[o] & 0xFF;
        byte[] dynamicNumber = Arrays.copyOfRange(rec, 5, 5 + dynLength);
        byte[] ac = Arrays.copyOfRange(rec, o + 1, o + 9);
        byte[] txHash = Arrays.copyOfRange(rec, o + 9, o + 29);
        if (dynamicCid != expectedCid) {
            return new Result(false, "CDA ICC dynamic data CID", null);
        }
        // The AC equality against an independently recomputed cryptogram is only
        // possible when the caller knows the ICC master key (closed-loop test);
        // the SDAD signature and the transaction data hash code below already
        // authenticate the returned AC.
        if (expectedAc != null && !Arrays.equals(ac, expectedAc)) {
            return new Result(false, "CDA cryptogram", null);
        }

        // Transaction Data Hash Code: CDOL data followed by the tags, lengths
        // and values of the data elements returned in the response, in the
        // order returned, except the SDAD (EMV v4.4 Book 2 §6.6.1 step 2b).
        byte[] elements = responseElements(responseData, 0x9F4B);
        byte[] txInput = cdol2Data == null
                ? Bytes.concat(pdolData, cdol1Data, elements)
                : Bytes.concat(pdolData, cdol1Data, cdol2Data, elements);
        if (!Arrays.equals(Digests.sha1(txInput), txHash)) {
            return new Result(false, "CDA transaction data hash code", null);
        }
        return new Result(true, null, ac, dynamicNumber);
    }

    /**
     * Concatenates the tag/length/value encodings of the data objects returned
     * in the GENERATE AC response, in the order returned, excluding the given
     * tag (the Signed Dynamic Application Data) (EMV v4.4 Book 2 §6.6.1 step 2b).
     * A Format 2 response is a '77' template; its immediate children are used.
     * The '9F4B' SDAD is the only element excluded.
     */
    private static byte[] responseElements(byte[] responseData, int excludeTag) {
        byte[] body = Tags.find(responseData, 0x77);
        byte[] buf = body != null ? body : responseData;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int p = 0;
        while (p < buf.length) {
            int start = p;
            int b = buf[p] & 0xFF;
            int tag;
            int tagLen;
            if ((b & 0x1F) == 0x1F) {
                if (p + 2 > buf.length) {
                    break;
                }
                tag = (b << 8) | (buf[p + 1] & 0xFF);
                tagLen = 2;
            } else {
                tag = b;
                tagLen = 1;
            }
            int lOff = p + tagLen;
            if (lOff >= buf.length) {
                break;
            }
            int lb = buf[lOff] & 0xFF;
            int lLen;
            int vLen;
            if ((lb & 0x80) == 0) {
                lLen = 1;
                vLen = lb;
            } else {
                int n = lb & 0x7F;
                if (n == 0 || lOff + 1 + n > buf.length) {
                    break;
                }
                lLen = 1 + n;
                vLen = 0;
                for (int i = 0; i < n; i++) {
                    vLen = (vLen << 8) | (buf[lOff + 1 + i] & 0xFF);
                }
            }
            int end = lOff + lLen + vLen;
            if (end > buf.length) {
                break;
            }
            if (tag != excludeTag) {
                out.write(buf, start, end - start);
            }
            p = end;
        }
        return out.toByteArray();
    }
}
