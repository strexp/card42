package card42.emv;

import card42.common.*;

import javacard.framework.Util;

/* Frames a computed Application Cryptogram into the GENERATE AC response:
 * format 1 (tag '80' CID || ATC || AC || IAD, EMV v4.4 Book 3 Table 13) for the
 * generic contact profile and format 2 (77 { 9F27, 9F36, 9F26, 9F10 },
 * EMV v4.4 Book 3 Table CCD 2) for the contactless and CCD profiles.
 *
 * Pure static formatting with no state; the AC is computed by EMVCrypto and
 * passed in.
 *
 * @author card42
 */

public final class AcResponseBuilder {

    private AcResponseBuilder() {
    }

    /** Writes the response for a precomputed 8-byte AC. */
    static void build(boolean format2, byte cid, short atc, byte[] iad,
                      short iadLength, byte[] ac, byte[] response, short offset) {
        if (format2) {
            buildFormat2(cid, atc, iad, iadLength, ac, response, offset);
        } else {
            buildFormat1(cid, atc, iad, iadLength, ac, response, offset);
        }
    }

    /**
     * Format 1 response: the concatenation without delimiters of the CID, the
     * ATC, the AC and the IAD (EMV v4.4 Book 3 Table 13).
     */
    private static void buildFormat1(byte cid, short atc, byte[] iad,
                                     short iadLength, byte[] ac, byte[] response,
                                     short offset) {
        response[offset] = (byte) 0x80; // Tag for Format 1 cryptogram
        // Length: CID (1) + ATC (2) + AC (8) + IAD
        response[(short) (offset + 1)] = (byte) (11 + iadLength);
        response[(short) (offset + 2)] = cid;
        Util.setShort(response, (short) (offset + 3), atc);
        Util.arrayCopyNonAtomic(ac, (short) 0, response, (short) (offset + 5), (short) 8);
        Util.arrayCopyNonAtomic(iad, (short) 0, response,
                (short) (offset + 13), iadLength);
    }

    /**
     * Format 2 response: 77 { 9F27 CID, 9F36 ATC, 9F26 AC, 9F10 IAD }
     * (EMV v4.4 Book 3 Table CCD 2).
     */
    private static void buildFormat2(byte cid, short atc, byte[] iad,
                                     short iadLength, byte[] ac, byte[] response,
                                     short offset) {
        // 9F27(3) + 9F36(5) + 9F26(2+1+8) + 9F10(2+1+iadLength)
        short body = (short) (4 + 5 + 11 + 3 + iadLength);
        short p = format2Start(cid, atc, body, response, offset);
        p = Tlv.append(TlvTags.TAG_AC, ac, (short) 0, (short) 8, response, p);
        appendIad(iad, iadLength, response, p);
    }

    /**
     * Writes the common Format-2 prefix {@code 77 { length, 9F27 CID, 9F36 ATC }}
     * and returns the first free offset.  The caller appends either 9F26 (AC)
     * or 9F4B (CDA SDAD), then calls {@link #appendIad}.
     */
    static short format2Start(byte cid, short atc, short bodyLength,
                              byte[] response, short offset) {
        short p = offset;
        response[p++] = (byte) 0x77;
        p = Tlv.appendLength(bodyLength, response, p);
        p = Tlv.appendTag(TlvTags.TAG_CID, response, p);
        response[p++] = 0x01;
        response[p++] = cid;
        p = Tlv.appendTag(TlvTags.TAG_ATC, response, p);
        response[p++] = 0x02;
        Util.setShort(response, p, atc);
        return (short) (p + 2);
    }

    /** Appends {@code 9F10 IAD} and returns the new offset. */
    static short appendIad(byte[] iad, short iadLength, byte[] response, short offset) {
        short p = Tlv.append(TlvTags.TAG_IAD, iad, (short) 0, iadLength, response, offset);
        return p;
    }
}
