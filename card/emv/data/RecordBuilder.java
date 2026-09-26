package card42.emv;

import card42.common.*;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;

/* Builds and reads the EMV records of a payment instance (EMV v4.4 Book 3 §6.5.11).
 *
 * A personalized record (DGI (SFI<<8)|record) is returned verbatim, with its
 * 70 template length normalised.  Otherwise records 1-5 of SFI 1 are built from
 * the structured PaymentData: record 1 from the transaction fields, record 2
 * from the SDA certificate chain, record 3 from the SSAD, record 4 from the ICC
 * PIN encipherment certificate and record 5 from the ICC DDA/CDA certificate.
 *
 * The state words follow EMV / ISO 7816: an SFI that is not advertised in the
 * AFL is a missing file (6A82), while a record number without data in an
 * existing file is a missing record (6A83).
 *
 * All methods are static and write into caller-supplied buffers.
 *
 * @author card42
 */

public final class RecordBuilder implements ISO7816 {

    /** A record is at most 254 bytes including tag and length (EMV v4.4 Book 3 §7). */
    private static final short MAX_RECORD_LENGTH = (short) 254;

    private RecordBuilder() {
    }

    /**
     * Provides the response to EMVCommands.INS_READ_RECORD in the response buffer.  The
     * role selects the default record 1 content (CVM list) and the readable SFI
     * set (AFL).
     */
    public static void readRecord(RecordStore records, byte[] apduBuffer,
            byte[] response, byte role, PaymentData data) {
        short sfi = (short) ((apduBuffer[OFFSET_P2] & 0xFF) >> 3);
        short rec = (short) (apduBuffer[OFFSET_P1] & 0xFF);
        short key = (short) ((sfi << 8) | rec);

        // An SFI the AFL of this role does not advertise is reported as a
        // missing file, so the card does not disclose which files it holds
        // (EMV v4.4 Book 3 §6.5.11).
        if (!isReadableSfi(data, sfi)) {
            ISOException.throwIt(SW_FILE_NOT_FOUND); // 6A82
        }

        short stored = records.lengthOf(key);
        if (stored >= 0) {
            if (stored > response.length || stored > MAX_RECORD_LENGTH) {
                // A record larger than a short APDU response (or than the
                // 254-byte EMV record limit) cannot be returned in one piece
                // (docs/specs/emv/personalization.md §1); fail explicitly.
                ISOException.throwIt(SW_WRONG_LENGTH);
            }
            short len = records.copyIfPresent(key, response, (short) 0);
            normaliseRecordLength(response, len);
            // Defensive: a stored record must be a well-formed '70' template
            // whose normalised length fits the 254-byte limit (EMV v4.4 Book 3 §7.1).
            // Personalization already enforces this, so a violation here is a
            // missing record rather than an oversized response.
            if (len < 2 || response[0] != (byte) TlvTags.TAG_RECORD_TEMPLATE
                    || Tlv.totalLength(response, (short) 0) > MAX_RECORD_LENGTH) {
                ISOException.throwIt(SW_RECORD_NOT_FOUND); // 6A83
            }
            return;
        }

        if (sfi == 1) {
            switch (rec) {
            case 1:
                buildDefaultRecord1(response, role, data);
                return;
            case 2:
                buildDefaultRecord2(response, data);
                return;
            case 3:
                buildDefaultRecord3(response, data);
                return;
            case 4:
                buildDefaultRecord4(response, data);
                return;
            case 5:
                buildDefaultRecord5(response, data);
                return;
            default:
                break;
            }
        }
        // The file exists (the AFL advertises it) but it has no such record
        // (EMV v4.4 Book 3 §6.5.11).
        ISOException.throwIt(SW_RECORD_NOT_FOUND); // 6A83
    }

    /** A stored record that can be served directly from the persistent pool. */
    public static final class View {
        public final byte[] pool;
        public final short offset;
        public final short length;

        View(byte[] pool, short offset, short length) {
            this.pool = pool;
            this.offset = offset;
            this.length = length;
        }
    }

    /**
     * Returns the stored record for the READ RECORD in {@code apduBuffer} as a
     * view over the persistent record pool, when it can be served without a
     * transient copy, or null when the caller must fall back to
     * {@link #readRecord}.  A record is served directly only when its '70'
     * template length field is already the exact width for its body (so no
     * normalisation is needed); a placeholder length still goes through the
     * response-buffer path.  The SFI readability rule and its 6A82 are applied
     * here exactly as in {@link #readRecord} (EMV v4.4 Book 3 §6.5.11).
     */
    public static View directView(RecordStore records, byte[] apduBuffer, PaymentData data) {
        short sfi = (short) ((apduBuffer[OFFSET_P2] & 0xFF) >> 3);
        short rec = (short) (apduBuffer[OFFSET_P1] & 0xFF);
        if (!isReadableSfi(data, sfi)) {
            ISOException.throwIt(SW_FILE_NOT_FOUND); // 6A82
        }
        short key = (short) ((sfi << 8) | rec);
        short stored = records.lengthOf(key);
        if (stored < 2 || stored > MAX_RECORD_LENGTH) {
            return null;
        }
        byte[] pool = records.pool();
        short offset = records.offsetOf(key);
        if (pool[offset] != (byte) TlvTags.TAG_RECORD_TEMPLATE) {
            return null;
        }
        short lenField = Tlv.lengthFieldLength(pool, (short) (offset + 1));
        if (lenField == 0) {
            return null;
        }
        short bodyLength = (short) (stored - 1 - lenField);
        if (bodyLength < 0 || Tlv.lengthSize(bodyLength) != lenField
                || Tlv.getLength(pool, (short) (offset + 1)) != bodyLength
                || Tlv.totalLength(pool, offset) != stored) {
            return null;
        }
        return new View(pool, offset, stored);
    }

    /**
     * True when the AFL advertised in the GPO response lists sfi, i.e. the
     * terminal is allowed to read it on this role.  A read of any other SFI is
     * answered with 6A82 so the card does not reveal the existence of files it
     * is not meant to serve (EMV v4.4 Book 3 §6.5.11).  The transaction log SFI
     * (11-30) is deliberately not in the AFL (EMV v4.4 Book 3 Annex D4) and
     * needs an explicit exemption, which the caller applies.
     */
    private static boolean isReadableSfi(PaymentData data, short sfi) {
        byte[] afl = data.getAFL();
        short length = data.getAFLLength();
        for (short i = 0; (short) (i + 3) < length; i += 4) {
            if ((short) ((afl[i] & 0xFF) >> 3) == sfi) {
                return true;
            }
        }
        return false;
    }

    /**
     * Rewrites the 70 template length of a stored record so the terminal sees a
     * consistent record even when the script wrote a placeholder
     * (docs/specs/emv/personalization.md §3).  The body is shifted when the required length field is
     * longer or shorter than the one in the stored record.
     */
    private static void normaliseRecordLength(byte[] response, short len) {
        if (len < 2 || response[0] != (byte) TlvTags.TAG_RECORD_TEMPLATE) {
            return;
        }
        short oldLengthField = Tlv.lengthFieldLength(response, (short) 1);
        if (oldLengthField == 0) {
            return;
        }
        short bodyOffset = (short) (1 + oldLengthField);
        short bodyLength = (short) (len - bodyOffset);
        short newLengthField = Tlv.lengthSize(bodyLength);
        if (newLengthField != oldLengthField) {
            Util.arrayCopyNonAtomic(response, bodyOffset, response,
                    (short) (1 + newLengthField), bodyLength);
        }
        Tlv.appendLength(bodyLength, response, (short) 1);
    }

    /** Encoded size of tag || length || value for a value of valueLength. */
    private static short tlvSize(short tag, short valueLength) {
        short tagLength = (tag & (short) 0xFF00) != 0 ? (short) 2 : (short) 1;
        return (short) (tagLength + Tlv.lengthSize(valueLength) + valueLength);
    }

    /** Throws 6700 when a record body does not fit the response buffer. */
    private static void ensureCapacity(byte[] response, short bodyLength) {
        short total = (short) (1 + Tlv.lengthSize(bodyLength) + bodyLength);
        if (total > MAX_RECORD_LENGTH || total > response.length) {
            ISOException.throwIt(SW_WRONG_LENGTH);
        }
    }

    /** Builds record 1 from the structured fields (fallback when no record DGI). */
    private static void buildDefaultRecord1(byte[] response, byte role, PaymentData data) {
        byte[] cvm;
        short cvmLen;
        if (data.getCvmLength() > 0) {
            cvm = data.getCvmList();
            cvmLen = data.getCvmLength();
        } else if (role == EMVRoles.ROLE_CONTACTLESS) {
            cvm = Defaults.CVM_LIST_CONTACTLESS;
            cvmLen = (short) Defaults.CVM_LIST_CONTACTLESS.length;
        } else {
            cvm = Defaults.CVM_LIST_CONTACT;
            cvmLen = (short) Defaults.CVM_LIST_CONTACT.length;
        }
        byte[] panBytes = valueOr(data.getPan(), data.getPanLength(), Defaults.PAN);
        short panLen = lengthOr(data.getPanLength(), Defaults.PAN);
        byte[] expBytes = valueOr(data.getExpiry(), data.getExpiryLength(), Defaults.EXPIRY);
        short expLen = lengthOr(data.getExpiryLength(), Defaults.EXPIRY);
        byte[] c1 = valueOr(data.getCdol1(), data.getCdol1Length(), Defaults.CDOL1);
        short c1Len = lengthOr(data.getCdol1Length(), Defaults.CDOL1);
        byte[] c2 = valueOr(data.getCdol2(), data.getCdol2Length(), Defaults.CDOL2);
        short c2Len = lengthOr(data.getCdol2Length(), Defaults.CDOL2);

        short p = 0;
        p = Tlv.appendTag(TlvTags.TAG_RECORD_TEMPLATE, response, p);
        // Reserve a 3-byte long-form length placeholder so a body longer than
        // 127 bytes does not overwrite the body; normaliseRecordLength() then
        // shrinks the length field to its exact width (docs/specs/common/architecture.md §2).
        response[p++] = (byte) 0x82;
        response[p++] = 0x00;
        response[p++] = 0x00;
        p = Tlv.append(TlvTags.TAG_CDOL1, c1, (short) 0, c1Len, response, p);
        p = Tlv.append(TlvTags.TAG_CDOL2, c2, (short) 0, c2Len, response, p);
        p = Tlv.append(TlvTags.TAG_PAN, panBytes, (short) 0, panLen, response, p);
        p = Tlv.append(TlvTags.TAG_EXPIRY_DATE, expBytes, (short) 0, expLen, response, p);
        p = Tlv.append(TlvTags.TAG_CVM_LIST, cvm, (short) 0, cvmLen, response, p);
        // Track 2 Equivalent Data (tag 57): the personalized value, or the
        // default derived from the default PAN/expiry, so a card without a
        // personalized record 1 still carries magnetic-stripe fallback data
        // (EMV v4.4 Book 3 Annex A Table 37).
        if (data.getTrack2Length() > 0) {
            p = Tlv.append(TlvTags.TAG_TRACK2_EQUIVALENT_DATA, data.getTrack2(),
                    (short) 0, data.getTrack2Length(), response, p);
        } else {
            p = Tlv.append(TlvTags.TAG_TRACK2_EQUIVALENT_DATA, Defaults.TRACK2,
                    (short) 0, (short) Defaults.TRACK2.length, response, p);
        }
        // Application Usage Control (9F07) and Application Version Number
        // (9F08) are optional and only emitted when personalized
        // (EMV v4.4 Book 3 §10.4.1/§10.4.2).
        if (data.getAucLength() > 0) {
            p = Tlv.append(TlvTags.TAG_APPLICATION_USAGE_CONTROL, data.getAuc(),
                    (short) 0, data.getAucLength(), response, p);
        }
        if (data.getApplicationVersionLength() > 0) {
            p = Tlv.append(TlvTags.TAG_APPLICATION_VERSION_NUMBER,
                    data.getApplicationVersion(), (short) 0,
                    data.getApplicationVersionLength(), response, p);
        }
        // Optional record data objects (EMV v4.4 Book 3 Annex A Table 37): the
        // Token Requestor ID, PAR and Last 4 Digits of PAN are only emitted when
        // personalized.
        if (data.getTokenRequestorIdLength() > 0) {
            p = Tlv.append(TlvTags.TAG_TOKEN_REQUESTOR_ID, data.getTokenRequestorId(),
                    (short) 0, data.getTokenRequestorIdLength(), response, p);
        }
        if (data.getParLength() > 0) {
            p = Tlv.append(TlvTags.TAG_PAR, data.getPar(), (short) 0,
                    data.getParLength(), response, p);
        }
        if (data.getLast4PanLength() > 0) {
            p = Tlv.append(TlvTags.TAG_LAST4_PAN, data.getLast4Pan(), (short) 0,
                    data.getLast4PanLength(), response, p);
        }
        normaliseRecordLength(response, p);
    }

    /** The personalized field when set, otherwise the fallback default. */
    private static byte[] valueOr(byte[] field, short fieldLength, byte[] fallback) {
        return fieldLength > 0 ? field : fallback;
    }

    /** The length of the personalized field, otherwise the default's length. */
    private static short lengthOr(short fieldLength, byte[] fallback) {
        return fieldLength > 0 ? fieldLength : (short) fallback.length;
    }

    /**
     * Builds record 2: the SDA certificate chain 8F/90/92/9F32 (and the
     * optional 9F4A tag list).  Without a personalized certificate the empty
     * placeholders are emitted (EMV v4.4 Book 2 §5).
     */
    private static void buildDefaultRecord2(byte[] response, PaymentData data) {
        SdaCertificateData certs = data.getCertificates();
        short bodyLength;
        if (certs.getIssuerCertLength() > 0) {
            bodyLength = tlvSize(TlvTags.TAG_CA_PUBLIC_KEY_INDEX, (short) 1);
            bodyLength += tlvSize(TlvTags.TAG_ISSUER_PUBLIC_KEY_CERT, certs.getIssuerCertLength());
            bodyLength += tlvSize(TlvTags.TAG_ISSUER_PUBLIC_KEY_REMAINDER, certs.getIssuerRemainderLength());
            bodyLength += tlvSize(TlvTags.TAG_ISSUER_PUBLIC_KEY_EXPONENT, certs.getIssuerExponentLength());
            if (certs.getSdaTagListLength() > 0) {
                bodyLength += tlvSize(TlvTags.TAG_SDA_TAG_LIST, certs.getSdaTagListLength());
            }
        } else {
            bodyLength = 9; // empty placeholders
        }
        ensureCapacity(response, bodyLength);

        short p = 0;
        p = Tlv.appendTag(TlvTags.TAG_RECORD_TEMPLATE, response, p);
        p = Tlv.appendLength(bodyLength, response, p);
        if (certs.getIssuerCertLength() > 0) {
            response[p++] = (byte) TlvTags.TAG_CA_PUBLIC_KEY_INDEX;
            response[p++] = 0x01;
            response[p++] = certs.getCaPublicKeyIndex();
            p = Tlv.append(TlvTags.TAG_ISSUER_PUBLIC_KEY_CERT, certs.getIssuerCert(),
                    (short) 0, certs.getIssuerCertLength(), response, p);
            p = Tlv.append(TlvTags.TAG_ISSUER_PUBLIC_KEY_REMAINDER, certs.getIssuerRemainder(),
                    (short) 0, certs.getIssuerRemainderLength(), response, p);
            p = Tlv.append(TlvTags.TAG_ISSUER_PUBLIC_KEY_EXPONENT, certs.getIssuerExponent(),
                    (short) 0, certs.getIssuerExponentLength(), response, p);
            if (certs.getSdaTagListLength() > 0) {
                p = Tlv.append(TlvTags.TAG_SDA_TAG_LIST, certs.getSdaTagList(),
                        (short) 0, certs.getSdaTagListLength(), response, p);
            }
        } else {
            response[p++] = (byte) 0x8F;
            response[p++] = 0x00;
            response[p++] = (byte) 0x90;
            response[p++] = 0x00;
            response[p++] = (byte) 0x92;
            response[p++] = 0x00;
            response[p++] = (byte) 0x9F;
            response[p++] = 0x32;
            response[p++] = 0x00;
        }
    }

    /**
     * Builds record 3: the Signed Static Application Data (tag 93) of the SDA
     * certificate chain (EMV v4.4 Book 2 §5).
     */
    private static void buildDefaultRecord3(byte[] response, PaymentData data) {
        SdaCertificateData certs = data.getCertificates();
        short bodyLength = tlvSize(TlvTags.TAG_SIGNED_STATIC_APPLICATION_DATA, certs.getSsadLength());
        ensureCapacity(response, bodyLength);

        short p = 0;
        p = Tlv.appendTag(TlvTags.TAG_RECORD_TEMPLATE, response, p);
        p = Tlv.appendLength(bodyLength, response, p);
        if (certs.getSsadLength() > 0) {
            p = Tlv.append(TlvTags.TAG_SIGNED_STATIC_APPLICATION_DATA, certs.getSsad(),
                    (short) 0, certs.getSsadLength(), response, p);
        } else {
            response[p++] = (byte) TlvTags.TAG_SIGNED_STATIC_APPLICATION_DATA;
            response[p++] = 0x00;
        }
    }

    /**
     * Builds record 4: the ICC PIN encipherment public key certificate
     * 9F2D/9F2F/9F2E (EMV v4.4 Book 2 §7.2).  The record only exists once a
     * PIN certificate has been personalized; otherwise the record is reported
     * as missing (6A83, EMV v4.4 Book 3 §6.5.11).
     */
    private static void buildDefaultRecord4(byte[] response, PaymentData data) {
        SdaCertificateData certs = data.getCertificates();
        if (certs.getPinCertLength() == 0) {
            ISOException.throwIt(SW_RECORD_NOT_FOUND);
        }
        short bodyLength = tlvSize(TlvTags.TAG_ICC_PIN_PUBLIC_KEY_CERT, certs.getPinCertLength());
        bodyLength += tlvSize(TlvTags.TAG_ICC_PIN_PUBLIC_KEY_REMAINDER, certs.getPinRemainderLength());
        bodyLength += tlvSize(TlvTags.TAG_ICC_PIN_PUBLIC_KEY_EXPONENT, certs.getPinExponentLength());
        ensureCapacity(response, bodyLength);

        short p = 0;
        p = Tlv.appendTag(TlvTags.TAG_RECORD_TEMPLATE, response, p);
        p = Tlv.appendLength(bodyLength, response, p);
        p = Tlv.append(TlvTags.TAG_ICC_PIN_PUBLIC_KEY_CERT, certs.getPinCert(),
                (short) 0, certs.getPinCertLength(), response, p);
        p = Tlv.append(TlvTags.TAG_ICC_PIN_PUBLIC_KEY_REMAINDER, certs.getPinRemainder(),
                (short) 0, certs.getPinRemainderLength(), response, p);
        p = Tlv.append(TlvTags.TAG_ICC_PIN_PUBLIC_KEY_EXPONENT, certs.getPinExponent(),
                (short) 0, certs.getPinExponentLength(), response, p);
    }

    /**
     * Builds record 5: the ICC DDA/CDA public key certificate 9F46/9F48/9F47
     * (EMV v4.4 Book 2 §6.5, §6.6).  The record only exists once an ICC
     * public key certificate has been personalized; otherwise the record is
     * reported as missing (6A83, EMV v4.4 Book 3 §6.5.11).
     */
    private static void buildDefaultRecord5(byte[] response, PaymentData data) {
        SdaCertificateData certs = data.getCertificates();
        if (certs.getIccCertLength() == 0) {
            ISOException.throwIt(SW_RECORD_NOT_FOUND);
        }
        short bodyLength = tlvSize(TlvTags.TAG_ICC_PUBLIC_KEY_CERT, certs.getIccCertLength());
        bodyLength += tlvSize(TlvTags.TAG_ICC_PUBLIC_KEY_REMAINDER, certs.getIccRemainderLength());
        bodyLength += tlvSize(TlvTags.TAG_ICC_PUBLIC_KEY_EXPONENT, certs.getIccExponentLength());
        ensureCapacity(response, bodyLength);

        short p = 0;
        p = Tlv.appendTag(TlvTags.TAG_RECORD_TEMPLATE, response, p);
        p = Tlv.appendLength(bodyLength, response, p);
        p = Tlv.append(TlvTags.TAG_ICC_PUBLIC_KEY_CERT, certs.getIccCert(),
                (short) 0, certs.getIccCertLength(), response, p);
        p = Tlv.append(TlvTags.TAG_ICC_PUBLIC_KEY_REMAINDER, certs.getIccRemainder(),
                (short) 0, certs.getIccRemainderLength(), response, p);
        p = Tlv.append(TlvTags.TAG_ICC_PUBLIC_KEY_EXPONENT, certs.getIccExponent(),
                (short) 0, certs.getIccExponentLength(), response, p);
    }
}
