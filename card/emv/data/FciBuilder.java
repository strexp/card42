package card42.emv;

import card42.common.*;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;

/* Builds the SELECT (FCI) and GET PROCESSING OPTIONS (GPO) responses of a
 * payment instance from its personalized PaymentData.
 *
 * The FCI is either the EMV CPS v2.0 Annex A DGI '9102' A5 override or a default built from the
 * structured fields.  In both cases the Log Entry (9F4D) is placed inside the
 * A5 FCI Proprietary Template as a BF0C FCI Issuer Discretionary Data template
 * (EMV v4.4 Book 1 Table 10, EMV v4.4 Book 3 Annex D4).  The GPO response is format 1
 * ('80' AIP || AFL) for a generic contact instance and format 2
 * ('77' { 82, 94 }) for a CCD or contactless instance (EMV v4.4 Book 3 §6.5.8,
 * CCD §6.5.8.4).
 *
 * All methods are static and write into caller-supplied buffers, so no object
 * is allocated on the SELECT / GPO path.
 *
 * @author card42
 */

public final class FciBuilder implements ISO7816 {

    private FciBuilder() {
    }

    /**
     * Encoded size of the FCI Issuer Discretionary Data (BF0C): the Log Entry
     * (9F4D) plus the optional IINE (9F0C) and ASRPD (9F0A) data objects
     * (EMV v4.4 Book 1 Table 10, EMV v4.4 Book 3 Annex A Table 37).
     */
    private static short discretionarySize(PaymentData data) {
        short inner = discretionaryInnerSize(data);
        return (short) (2 + Tlv.lengthSize(inner) + inner);
    }

    /** Encoded size of the BF0C inner content: the Log Entry and optionals. */
    private static short discretionaryInnerSize(PaymentData data) {
        short inner = (short) 5; // 9F4D 02 sfi cap
        if (data.getIineLength() > 0) {
            inner += (short) (3 + data.getIineLength());
        }
        if (data.getAsrpdLength() > 0) {
            inner += (short) (3 + data.getAsrpdLength());
        }
        return inner;
    }

    /**
     * Builds the FCI of this instance into fci and returns its length.  scratch
     * is a caller-supplied working buffer of at least the FCI content size.
     */
    public static short buildFci(byte role, byte[] aid, short aidLength, PaymentData data,
                                 byte[] scratch, byte[] fci) {
        short contentLength;
        if (data.getFciOverrideLength() > 0) {
            // The override is a complete A5 template; the Log Entry is appended
            // inside the A5 FCI Proprietary Template (EMV v4.4 Book 1 Table 10).
            short overrideLength = data.getFciOverrideLength();
            if ((short) (overrideLength + discretionarySize(data)) > scratch.length) {
                ISOException.throwIt(SW_WRONG_DATA);
            }
            Util.arrayCopyNonAtomic(data.getFciOverride(), (short) 0, scratch,
                    (short) 0, overrideLength);
            contentLength = appendDiscretionaryInA5(scratch, overrideLength, data);
        } else {
            contentLength = buildDefaultA5(role, data, scratch);
        }
        return Tlv.appendFci(aid, (short) 0, aidLength,
                scratch, (short) 0, contentLength, fci, (short) 0);
    }

    /**
     * The GPO response.  A CCD application and any contactless instance return
     * a Format 2 response (77 { 82 AIP, 94 AFL }, EMV v4.4 Book 3 CCD §6.5.8.4
     * / Table CCD 4); a generic contact instance returns Format 1 (80 AIP ||
     * AFL, EMV v4.4 Book 3 §6.5.8.4).  The CCD data format, not the AIP
     * EXTERNAL AUTHENTICATE capability bit, selects it.  The AIP and AFL come
     * from the EMV CPS v2.0 Annex A DGI '9104' or the structured tags.
     */
    public static short buildGpo(byte role, PaymentData data, byte[] gpo) {
        byte[] aflBytes = data.getAFL();
        short aflLen = data.getAFLLength();
        short aipValue = data.getAIP(role);
        boolean format2 = role == EMVRoles.ROLE_CONTACTLESS || data.isCcdFormat();
        short p = 0;
        if (format2) {
            // Body: 82 (tag+len+AIP) + 94 (tag+len+AFL).
            short body = (short) (5 + Tlv.lengthSize(aflLen) + aflLen);
            gpo[p++] = (byte) 0x77;
            p = Tlv.appendLength(body, gpo, p);
            p = Tlv.appendTag(TlvTags.TAG_AIP, gpo, p);
            gpo[p++] = 0x02;
            gpo[p++] = (byte) (aipValue >> 8);
            gpo[p++] = (byte) aipValue;
            p = Tlv.appendTag(TlvTags.TAG_AFL, gpo, p);
            p = Tlv.appendLength(aflLen, gpo, p);
        } else {
            gpo[p++] = (byte) 0x80;
            gpo[p++] = (byte) (2 + aflLen);
            gpo[p++] = (byte) (aipValue >> 8);
            gpo[p++] = (byte) aipValue;
        }
        Util.arrayCopyNonAtomic(aflBytes, (short) 0, gpo, p, aflLen);
        p += aflLen;
        return p;
    }

    /**
     * Builds the default FCI content as the A5 FCI Proprietary Template
     * (EMV v4.4 Book 1 Table 10): the label (50), priority (87), language
     * (5F2D), optional PDOL (9F38) and the Log Entry inside BF0C.  The A5
     * template is assembled in out and its length returned.
     */
    private static short buildDefaultA5(byte role, PaymentData data, byte[] out) {
        byte[] label = data.getLabel();
        short labelLength;
        if (label == null) {
            label = role == EMVRoles.ROLE_CONTACTLESS
                    ? Defaults.LABEL_CONTACTLESS : Defaults.LABEL_CONTACT;
            labelLength = (short) label.length;
        } else {
            labelLength = data.getLabelLength();
        }

        // Build the A5 value first, then prefix the tag and length.
        short p = 0;
        p = Tlv.append(TlvTags.TAG_APPLICATION_LABEL, label, (short) 0, labelLength, out, p);
        out[p++] = (byte) TlvTags.TAG_PRIORITY_INDICATOR;
        out[p++] = (byte) 0x01;
        out[p++] = data.getPriority();
        out[p++] = (byte) 0x5F;
        out[p++] = (byte) 0x2D;
        out[p++] = (byte) 0x04;
        out[p++] = (byte) 0x6E; // "nlen"
        out[p++] = (byte) 0x6C;
        out[p++] = (byte) 0x65;
        out[p++] = (byte) 0x6E;
        if (data.getPdolLength() > 0) {
            // The PDOL is advertised in the FCI proprietary template (EMV v4.4 Book 3 §6.5.8).
            p = Tlv.append(TlvTags.TAG_PDOL, data.getPdol(), (short) 0,
                    data.getPdolLength(), out, p);
        }
        p = appendDiscretionary(out, p, data);

        short valueLength = p;
        short header = (short) (1 + Tlv.lengthSize(valueLength));
        if ((short) (header + valueLength) > out.length) {
            ISOException.throwIt(SW_WRONG_DATA);
        }
        for (short i = (short) (valueLength - 1); i >= 0; i--) {
            out[(short) (i + header)] = out[i];
        }
        out[0] = (byte) TlvTags.TAG_FCI_PROPRIETARY; // A5
        Tlv.appendLength(valueLength, out, (short) 1);
        return (short) (header + valueLength);
    }

    /**
     * Appends the FCI Issuer Discretionary Data (BF0C) to the value of the A5
     * template at out[0..a5Length) and returns the new A5 template length.  The
     * BF0C template is placed inside A5 (EMV v4.4 Book 1 Table 10).  If the
     * personalized A5 already carries a top-level BF0C, the Log Entry and the
     * optional data objects are merged into it instead of adding a second
     * BF0C (EMV CPS v2.0 Table A-14 allows the A5 to contain BF0C already).
     */
    private static short appendDiscretionaryInA5(byte[] out, short a5Length, PaymentData data) {
        short lenOff = Tlv.lengthOffset(out, (short) 0);
        short oldLenField = Tlv.lengthFieldLength(out, lenOff);
        short oldValueLen = Tlv.getLength(out, lenOff);
        short valueOff = (short) (lenOff + oldLenField);

        // Look for an existing top-level BF0C inside the A5 value.
        short bfLenOff = -1;
        short bfLenField = 0;
        short bfValOff = -1;
        short bfValLen = 0;
        short p = valueOff;
        short valueEnd = (short) (valueOff + oldValueLen);
        while (p < valueEnd) {
            short tag = Tlv.getTag(out, p);
            short lo = Tlv.lengthOffset(out, p);
            short lf = Tlv.lengthFieldLength(out, lo);
            if (lf == 0) {
                break;
            }
            short vl = Tlv.getLength(out, lo);
            short vo = Tlv.valueOffset(out, p);
            if ((short) (vo + vl) > valueEnd) {
                break;
            }
            if (tag == TlvTags.TAG_FCI_ISSUER_DISCRETIONARY) {
                bfLenOff = lo;
                bfLenField = lf;
                bfValOff = vo;
                bfValLen = vl;
                break;
            }
            p = (short) (vo + vl);
        }

        if (bfValOff >= 0) {
            // Merge the Log Entry into the existing BF0C.
            short inner = discretionaryInnerSize(data);
            short newBfValLen = (short) (bfValLen + inner);
            short newBfLenField = Tlv.lengthSize(newBfValLen);
            short bfDelta = (short) ((newBfLenField - bfLenField) + inner);
            short newA5ValueLen = (short) (oldValueLen + bfDelta);
            short newA5LenField = Tlv.lengthSize(newA5ValueLen);
            short a5Delta = (short) (newA5LenField - oldLenField);
            if ((short) (valueOff + oldValueLen + a5Delta + bfDelta) > out.length) {
                ISOException.throwIt(SW_WRONG_DATA);
            }
            // 1) Widen the A5 length field: shift the whole value right.
            if (a5Delta > 0) {
                for (short i = (short) (oldValueLen - 1); i >= 0; i--) {
                    out[(short) (valueOff + i + a5Delta)] = out[(short) (valueOff + i)];
                }
                valueOff += a5Delta;
                bfLenOff += a5Delta;
                bfValOff += a5Delta;
            }
            // 2) Insert the inner objects at the end of the BF0C value.
            short insertAt = (short) (bfValOff + bfValLen);
            short tail = (short) ((valueOff + oldValueLen) - insertAt);
            for (short i = (short) (tail - 1); i >= 0; i--) {
                out[(short) (insertAt + i + bfDelta)] = out[(short) (insertAt + i)];
            }
            short written = appendDiscretionaryInner(out,
                    (short) (bfValOff + (newBfLenField - bfLenField) + bfValLen), data);
            if (written != (short) (valueOff + newA5ValueLen)) {
                ISOException.throwIt(SW_WRONG_DATA);
            }
            Tlv.appendLength(newBfValLen, out, bfLenOff);
            Tlv.appendLength(newA5ValueLen, out, lenOff);
            return (short) (valueOff + newA5ValueLen);
        }

        // No existing BF0C: append a new one at the end of the A5 value.
        short newValueLen = (short) (oldValueLen + discretionarySize(data));
        short newLenField = Tlv.lengthSize(newValueLen);
        short delta = (short) (newLenField - oldLenField);
        if (delta > 0) {
            if ((short) (valueOff + oldValueLen + delta) > out.length) {
                ISOException.throwIt(SW_WRONG_DATA);
            }
            for (short i = (short) (oldValueLen - 1); i >= 0; i--) {
                out[(short) (valueOff + i + delta)] = out[(short) (valueOff + i)];
            }
            valueOff += delta;
        }
        short q = appendDiscretionary(out, (short) (valueOff + oldValueLen), data);
        if (q != (short) (valueOff + newValueLen)) {
            ISOException.throwIt(SW_WRONG_DATA);
        }
        Tlv.appendLength(newValueLen, out, lenOff);
        return (short) (valueOff + newValueLen);
    }

    /**
     * Appends the FCI Issuer Discretionary Data template (BF0C) at off: the Log
     * Entry (9F4D) with the SFI of the cyclic transaction log file and its record
     * capacity (EMV v4.4 Book 3 Annex D4), followed by the optional IINE (9F0C)
     * and ASRPD (9F0A) data objects (EMV v4.4 Book 3 Annex A Table 37).  The log file
     * itself is deliberately not listed in the AFL.
     */
    private static short appendDiscretionary(byte[] out, short off, PaymentData data) {
        short inner = discretionaryInnerSize(data);
        short p = off;
        p = Tlv.appendTag(TlvTags.TAG_FCI_ISSUER_DISCRETIONARY, out, p); // BF0C
        p = Tlv.appendLength(inner, out, p);
        return appendDiscretionaryInner(out, p, data);
    }

    /** Appends the BF0C inner content (9F4D plus optionals) at off. */
    private static short appendDiscretionaryInner(byte[] out, short off, PaymentData data) {
        short p = off;
        p = Tlv.appendTag(TlvTags.TAG_LOG_ENTRY, out, p); // 9F4D
        out[p++] = 0x02;
        out[p++] = (byte) TransactionLog.SFI;
        out[p++] = (byte) TransactionLog.CAPACITY;
        if (data.getIineLength() > 0) {
            p = Tlv.append(TlvTags.TAG_IINE, data.getIine(), (short) 0,
                    data.getIineLength(), out, p);
        }
        if (data.getAsrpdLength() > 0) {
            p = Tlv.append(TlvTags.TAG_ASRPD, data.getAsrpd(), (short) 0,
                    data.getAsrpdLength(), out, p);
        }
        return p;
    }
}
