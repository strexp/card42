package card42.emv;

import card42.common.*;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;

/* The structured, personalized data of a payment applet: the field set filled
 * by EMV CPS v2.0 Annex A (DGI '9102'/'9104'/'3001' and record 1) and the
 * accessors the transaction, FCI/GPO and record builders read.
 *
 * This is the data model only.  FciBuilder assembles the SELECT/GPO responses
 * from it, RecordBuilder the default records, and EMVStaticData is the facade
 * the applets use.  The instance role is not stored here (docs/specs/common/architecture.md §4):
 * the caller passes EMVProtocolState.getRole() to the accessors that need it.
 *
 * The DOL cursor is reused so the transaction path allocates nothing
 * (EMV v4.4 Book 3 §5.4).
 *
 * @author joeri (joeri@cs.ru.nl)
 * @author erikpoll (erikpoll@cs.ru.nl)
 * @author card42
 */

public class PaymentData implements ISO7816 {

    /** Structured payment fields (EMV CPS v2.0 Annex A DGI '3001' and record 1). */
    private final byte[] label = new byte[(short) 16];
    private short labelLength;
    private byte priority = (byte) 0x01;
    private final byte[] aip = new byte[(short) 2];
    private boolean hasAip;
    private final byte[] afl = new byte[(short) 16];
    private short aflLength;
    private final byte[] cvmList = new byte[(short) 32];
    private short cvmLength;
    private final byte[] cdol1 = new byte[(short) 64];
    private short cdol1Length;
    private final byte[] cdol2 = new byte[(short) 64];
    private short cdol2Length;

    /** PDOL definition (9F38); the GPO command data is validated against it. */
    private final byte[] pdol = new byte[(short) 64];
    private short pdolLength;

    /** Issuer Action Codes 9F0E/9F0F/9F0D and IAD 9F10 (EMV v4.4 Book 3 §10.8). */
    private final byte[] iacDenial = new byte[(short) 5];
    private short iacDenialLength;
    private final byte[] iacOnline = new byte[(short) 5];
    private short iacOnlineLength;
    private final byte[] iacDefault = new byte[(short) 5];
    private short iacDefaultLength;
    /**
     * CCD Issuer Application Data (EMV v4.4 Book 3 Annex C §C9): a fixed
     * 32-byte Format Code 'A' template.  The CVR (bytes 4-8) is rewritten by
     * setCvr() before every GENERATE AC.
     */
    private final byte[] iad = new byte[Iad.LENGTH];
    /** Cryptogram Version of the IAD Common Core Identifier (5 or 6). */
    private byte cryptogramVersion = (byte) 5;

    /** Log Format (9F4F) of the transaction log (EMV v4.4 Book 3 Annex D4). */
    private final byte[] logFormat = new byte[(short) 32];
    private short logFormatLength;

    /** Consecutive offline limits LCOL/UCOL (9F14/9F23, EMV v4.4 Book 3 Annex C §C9.3). */
    private byte lcol;
    private boolean hasLcol;
    private byte ucol;
    private boolean hasUcol;

    private final byte[] pan = new byte[(short) 10];
    private short panLength;
    private final byte[] expiry = new byte[(short) 3];
    private short expiryLength;

    /**
     * Optional card data objects (EMV v4.4 Book 3 Annex A Table 37): the IINE
     * ('9F0C') and ASRPD ('9F0A') are carried in the FCI, the Token Requestor ID
     * ('9F19'), PAR ('9F24') and Last 4 Digits of PAN ('9F25') in a record.
     * They are optional and only emitted when personalized.
     */
    private final byte[] iine = new byte[(short) 4];
    private short iineLength;
    private final byte[] asrpd = new byte[(short) 32];
    private short asrpdLength;
    private final byte[] tokenRequestorId = new byte[(short) 6];
    private short tokenRequestorIdLength;
    private final byte[] par = new byte[(short) 29];
    private short parLength;
    private final byte[] last4Pan = new byte[(short) 2];
    private short last4PanLength;

    /**
     * Track 2 Equivalent Data ('57', 1-19 bytes BCD) and the optional
     * Application Usage Control ('9F07') / Application Version Number ('9F08'),
     * all carried in a record template (EMV v4.4 Book 3 Annex A Table 37).
     */
    private final byte[] track2 = new byte[(short) 19];
    private short track2Length;
    private final byte[] auc = new byte[(short) 2];
    private short aucLength;
    private final byte[] applicationVersion = new byte[(short) 2];
    private short applicationVersionLength;

    /** Offline-data-authentication certificate material (EMV v4.4 Book 2 §5/§6.5/§7.2). */
    private final SdaCertificateData certificates = new SdaCertificateData();

    /** Whole-FCI override (EMV CPS v2.0 Annex A DGI '9102'); the value is an A5 template. */
    private final byte[] fciOverride = new byte[(short) 128];
    private short fciOverrideLength;

    /** Reused DOL cursor, so the transaction path allocates nothing (EMV v4.4 Book 3 §5.4). */
    private final DolReader dolReader = new DolReader();

    public PaymentData() {
        // A 32-byte Format Code 'A' IAD template with a zero CVR (EMV v4.4 Book 3 Annex C §C9).
        Util.arrayCopyNonAtomic(Defaults.IAD, (short) 0, iad, (short) 0, Iad.LENGTH);
    }

    // --- Personalization (EMV CPS v2.0 Annex A) -----------------------------

    /** Applies the structured tags of the EMV CPS v2.0 Annex A DGIs '3001'/'9104' or record 1. */
    public void applyPaymentConfig(byte[] buf, short off, short len) {
        TlvReader reader = new TlvReader(buf, off, len);
        while (reader.hasNext()) {
            reader.next();
            short tag = reader.tag();
            short valueOffset = reader.valueOffset();
            short valueLength = reader.valueLength();
            if (certificates.apply(tag, buf, valueOffset, valueLength)) {
                continue;
            }
            switch (tag) {
            case TlvTags.TAG_APPLICATION_LABEL:
                labelLength = copyInto(buf, valueOffset, valueLength, label, (short) 16);
                break;
            case TlvTags.TAG_PRIORITY_INDICATOR:
                // Application Priority Indicator is exactly one byte
                // (EMV CPS v2.0 Annex A Table A-18).
                if (valueLength != 1) {
                    ISOException.throwIt(SW_WRONG_DATA);
                }
                priority = buf[valueOffset];
                break;
            case TlvTags.TAG_AIP:
                // AIP is exactly two bytes (EMV CPS v2.0 Annex A Table A-15);
                // a short value must not silently fall back to the role default.
                if (valueLength != 2) {
                    ISOException.throwIt(SW_WRONG_DATA);
                }
                copyInto(buf, valueOffset, valueLength, aip, (short) 2);
                hasAip = true;
                break;
            case TlvTags.TAG_AFL:
                aflLength = copyInto(buf, valueOffset, valueLength, afl, (short) 16);
                break;
            case TlvTags.TAG_CVM_LIST:
                cvmLength = copyInto(buf, valueOffset, valueLength, cvmList, (short) 32);
                break;
            case TlvTags.TAG_CDOL1:
                // Only primitive data objects may be listed in a DOL
                // (EMV v4.4 Book 3 §5.4).
                dolReader.reset(buf, valueOffset, valueLength).validate();
                cdol1Length = copyInto(buf, valueOffset, valueLength, cdol1, (short) 64);
                break;
            case TlvTags.TAG_CDOL2:
                dolReader.reset(buf, valueOffset, valueLength).validate();
                cdol2Length = copyInto(buf, valueOffset, valueLength, cdol2, (short) 64);
                break;
            case TlvTags.TAG_PDOL:
                dolReader.reset(buf, valueOffset, valueLength).validate();
                pdolLength = copyInto(buf, valueOffset, valueLength, pdol, (short) 64);
                break;
            case TlvTags.TAG_IAC_DENIAL:
                iacDenialLength = copyInto(buf, valueOffset, valueLength, iacDenial, (short) 5);
                break;
            case TlvTags.TAG_IAC_ONLINE:
                iacOnlineLength = copyInto(buf, valueOffset, valueLength, iacOnline, (short) 5);
                break;
            case TlvTags.TAG_IAC_DEFAULT:
                iacDefaultLength = copyInto(buf, valueOffset, valueLength, iacDefault, (short) 5);
                break;
            case TlvTags.TAG_IAD:
                // A CCD Format Code 'A' IAD is exactly 32 bytes (EMV v4.4 Book 3 Annex C §C9).
                if (valueLength != Iad.LENGTH) {
                    ISOException.throwIt(SW_WRONG_DATA);
                }
                copyInto(buf, valueOffset, valueLength, iad, Iad.LENGTH);
                // The CCI carries the Cryptogram Version of the selected
                // profile (CryptoProfile); a personalized IAD must not override
                // it (EMV v4.4 Book 3 Annex C §C9).
                iad[1] = (byte) (0xA0 | (cryptogramVersion & 0x0F));
                break;
            case TlvTags.TAG_LOG_FORMAT:
                logFormatLength = copyInto(buf, valueOffset, valueLength,
                        logFormat, (short) 32);
                break;
            case TlvTags.TAG_LCOL:
                // LCOL is exactly one byte (EMV v4.4 Book 3 §10.8).
                if (valueLength != 1) {
                    ISOException.throwIt(SW_WRONG_DATA);
                }
                lcol = buf[valueOffset];
                hasLcol = true;
                break;
            case TlvTags.TAG_UCOL:
                // UCOL is exactly one byte (EMV v4.4 Book 3 §10.8).
                if (valueLength != 1) {
                    ISOException.throwIt(SW_WRONG_DATA);
                }
                ucol = buf[valueOffset];
                hasUcol = true;
                break;
            case TlvTags.TAG_PAN:
                panLength = copyInto(buf, valueOffset, valueLength, pan, (short) 10);
                break;
            case TlvTags.TAG_EXPIRY_DATE:
                expiryLength = copyInto(buf, valueOffset, valueLength, expiry, (short) 3);
                break;
            case TlvTags.TAG_IINE:
                iineLength = copyInto(buf, valueOffset, valueLength, iine, (short) 4);
                break;
            case TlvTags.TAG_ASRPD:
                asrpdLength = copyInto(buf, valueOffset, valueLength, asrpd, (short) 32);
                break;
            case TlvTags.TAG_TOKEN_REQUESTOR_ID:
                tokenRequestorIdLength = copyInto(buf, valueOffset, valueLength,
                        tokenRequestorId, (short) 6);
                break;
            case TlvTags.TAG_PAR:
                parLength = copyInto(buf, valueOffset, valueLength, par, (short) 29);
                break;
            case TlvTags.TAG_LAST4_PAN:
                last4PanLength = copyInto(buf, valueOffset, valueLength, last4Pan, (short) 2);
                break;
            case TlvTags.TAG_TRACK2_EQUIVALENT_DATA:
                // Track 2 Equivalent Data is 1-19 bytes and always carries the
                // PAN and the 'D' separator (EMV v4.4 Book 3 Annex A Table 37).
                PersoRules.validateTrack2(buf, valueOffset, valueLength);
                track2Length = copyInto(buf, valueOffset, valueLength, track2, (short) 19);
                break;
            case TlvTags.TAG_APPLICATION_USAGE_CONTROL:
                // Application Usage Control is exactly two bytes
                // (EMV v4.4 Book 3 §10.4.2).
                if (valueLength != 2) {
                    ISOException.throwIt(SW_WRONG_DATA);
                }
                aucLength = copyInto(buf, valueOffset, valueLength, auc, (short) 2);
                break;
            case TlvTags.TAG_APPLICATION_VERSION_NUMBER:
                // Application Version Number is exactly two bytes
                // (EMV v4.4 Book 3 §10.4.1).
                if (valueLength != 2) {
                    ISOException.throwIt(SW_WRONG_DATA);
                }
                applicationVersionLength = copyInto(buf, valueOffset, valueLength,
                        applicationVersion, (short) 2);
                break;
            default:
                break;
            }
        }
    }

    /** Stores the SELECT response A5 template (EMV CPS v2.0 Annex A DGI '9102'). */
    public void setFciOverride(byte[] buf, short off, short len) {
        fciOverrideLength = copyInto(buf, off, len, fciOverride, (short) 128);
        // The PDOL lives inside the A5 template (EMV CPS v2.0 Table A-14): extract it so
        // GET PROCESSING OPTIONS can validate the terminal data (EMV CPS v2.0 Annex A).
        pdolLength = 0;
        if (len >= 3 && (buf[off] & 0xFF) == 0xA5) {
            short valueOff = Tlv.valueOffset(buf, off);
            short valueLen = Tlv.getLength(buf, Tlv.lengthOffset(buf, off));
            if (valueOff >= 0 && valueLen > 0
                    && (short) (valueOff + valueLen) <= (short) (off + len)) {
                TlvReader reader = new TlvReader(buf, valueOff, valueLen);
                while (reader.hasNext()) {
                    reader.next();
                    if (reader.tag() == TlvTags.TAG_PDOL) {
                        // A DOL may only list primitive data objects (EMV v4.4 Book 3 §5.4).
                        dolReader.reset(buf, reader.valueOffset(),
                                reader.valueLength()).validate();
                        pdolLength = copyInto(buf, reader.valueOffset(),
                                reader.valueLength(), pdol, (short) 64);
                    }
                }
            }
        }
    }

    /** Parses a 70 record template and applies its structured fields. */
    public void applyRecord1Fields(byte[] buf, short off, short len) {
        if (len < 2 || (buf[off] & 0xFF) != TlvTags.TAG_RECORD_TEMPLATE) {
            return;
        }
        short bodyOff = Tlv.valueOffset(buf, off);
        short declared = Tlv.getLength(buf, Tlv.lengthOffset(buf, off));
        short available = (short) ((off + len) - bodyOff);
        // A '70 00' length placeholder (patched on read) leaves the body to the
        // end of the container.
        short bodyLen = (declared > 0 && declared <= available) ? declared : available;
        if (bodyLen > 0 && bodyOff >= 0) {
            try {
                applyPaymentConfig(buf, bodyOff, bodyLen);
            } catch (ISOException e) {
                // A malformed DOL (e.g. a constructed tag) must be reported as
                // 6A80, not swallowed (EMV v4.4 Book 3 §5.4).
                throw e;
            } catch (Exception e) {
                // A placeholder/foreign body is still stored and normalised on
                // read; non-ISO field extraction is best effort.
            }
        }
    }

    /**
     * Copies src into a fixed-size field and returns the length.  A value that
     * does not fit is rejected with 6A80 rather than silently truncated: a
     * truncated FCI/record would be corrupt yet still reported as applied
     * (EMV CPS v2.0 §4.3.4.5).
     */
    private static short copyInto(byte[] src, short off, short len,
            byte[] dst, short max) {
        if (len > max) {
            ISOException.throwIt(SW_WRONG_DATA);
        }
        Util.arrayCopyNonAtomic(src, off, dst, (short) 0, len);
        return len;
    }

    // --- Payment data accessors --------------------------------------------

    /** 2-byte AIP; role default unless personalization supplied one (docs/specs/common/architecture.md §4). */
    public short getAIP(byte role) {
        if (hasAip) {
            return (short) (((aip[0] & 0xFF) << 8) | (aip[1] & 0xFF));
        }
        byte[] d = role == EMVRoles.ROLE_CONTACTLESS ? Defaults.AIP_CONTACTLESS : Defaults.AIP_CONTACT;
        return (short) (((d[0] & 0xFF) << 8) | (d[1] & 0xFF));
    }

    public byte[] getAFL() {
        return aflLength > 0 ? afl : Defaults.AFL;
    }

    public short getAFLLength() {
        return aflLength > 0 ? aflLength : (short) Defaults.AFL.length;
    }

    /**
     * Length of the terminal data described by a DOL, i.e. the sum of the
     * value lengths of its (tag, length) entries.  This is what the terminal
     * sends in GENERATE AC and what computeAC() must MAC; it is *not* the
     * encoded length of the DOL definition itself (docs/specs/emv/personalization.md §3).
     */
    private short dolDataLength(byte[] dol, short len) {
        return dolReader.reset(dol, (short) 0, len).totalDataLength();
    }

    /** Sum of the data-element lengths of CDOL1 (43 for the default CDOL1). */
    public short getCDOL1DataLength() {
        return cdol1Length > 0
                ? dolDataLength(cdol1, cdol1Length)
                : dolDataLength(Defaults.CDOL1, (short) Defaults.CDOL1.length);
    }

    /** Sum of the data-element lengths of CDOL2 (27 for the default CDOL2). */
    public short getCDOL2DataLength() {
        return cdol2Length > 0
                ? dolDataLength(cdol2, cdol2Length)
                : dolDataLength(Defaults.CDOL2, (short) Defaults.CDOL2.length);
    }

    /**
     * Offset of the value of tag within the CDOL data sent by the terminal,
     * i.e. the sum of the lengths of the preceding entries; -1 when the tag is
     * not listed (DolReader, EMV v4.4 Book 3 §5.4).
     */
    private short dolValueOffset(byte[] cdol, short len, short tag) {
        return dolReader.reset(cdol, (short) 0, len).findValueOffset(tag);
    }

    /** Value length of tag within a DOL's data, or -1 when not listed. */
    private short dolValueLength(byte[] cdol, short len, short tag) {
        DolReader reader = dolReader.reset(cdol, (short) 0, len);
        while (reader.hasNext()) {
            reader.next();
            if (reader.tag() == tag) {
                return reader.valueLength();
            }
        }
        return -1;
    }

    /** Offset of tag's value in the CDOL1 data, or -1. */
    public short getCDOL1ValueOffset(short tag) {
        return cdol1Length > 0
                ? dolValueOffset(cdol1, cdol1Length, tag)
                : dolValueOffset(Defaults.CDOL1, (short) Defaults.CDOL1.length, tag);
    }

    /** Value length of tag in the CDOL1 data, or -1. */
    public short getCDOL1ValueLength(short tag) {
        return cdol1Length > 0
                ? dolValueLength(cdol1, cdol1Length, tag)
                : dolValueLength(Defaults.CDOL1, (short) Defaults.CDOL1.length, tag);
    }

    /** Offset of tag's value in the CDOL2 data, or -1. */
    public short getCDOL2ValueOffset(short tag) {
        return cdol2Length > 0
                ? dolValueOffset(cdol2, cdol2Length, tag)
                : dolValueOffset(Defaults.CDOL2, (short) Defaults.CDOL2.length, tag);
    }

    /** Value length of tag in the CDOL2 data, or -1. */
    public short getCDOL2ValueLength(short tag) {
        return cdol2Length > 0
                ? dolValueLength(cdol2, cdol2Length, tag)
                : dolValueLength(Defaults.CDOL2, (short) Defaults.CDOL2.length, tag);
    }

    /**
     * Whether the AIP advertises issuer authentication via EXTERNAL
     * AUTHENTICATE (byte 1 bit 3, EMV v4.4 Book 2 §8.2).  When clear (the CCD
     * default) the card uses the inline CDOL2 tag 91 instead and refuses
     * INS=82; when set the generic EXTERNAL AUTHENTICATE path is enabled.
     */
    public boolean externalAuthenticateSupported(byte role) {
        return (getAIP(role) & (short) 0x0400) != 0;
    }

    /**
     * Whether the application uses the CCD GENERATE AC response format
     * (Format 2, EMV v4.4 Book 3 CCD §6.5.5.4).  A CCD application carries the
     * inline Issuer Authentication Data (tag '91') in CDOL2
     * (EMV v4.4 Book 3 CCD §6.5.5.3); the response format is selected from that
     * data-format signal rather than from the AIP EXTERNAL AUTHENTICATE
     * capability bit, which is only a consequence of CCD compliance
     * (EMV v4.4 Book 3 CCD §6.5.4.1).
     */
    public boolean isCcdFormat() {
        return getCDOL2ValueLength(TlvTags.TAG_ISSUER_AUTH_DATA) > 0;
    }

    /** Offset of the 9F37 value in the CDOL1 data, or -1. */
    public short getCDOL1UnOffset() {
        return getCDOL1ValueOffset(TlvTags.TAG_UNPREDICTABLE_NUMBER);
    }

    /** Offset of the 9F37 value in the CDOL2 data, or -1. */
    public short getCDOL2UnOffset() {
        return getCDOL2ValueOffset(TlvTags.TAG_UNPREDICTABLE_NUMBER);
    }

    // --- PDOL (EMV v4.4 Book 3 §6.5.8) -------------------------------------

    public byte[] getPdol() {
        return pdol;
    }

    public short getPdolLength() {
        return pdolLength;
    }

    /** Total length of the PDOL-related data the terminal sends in GPO. */
    public short getPdolDataLength() {
        return pdolLength > 0
                ? dolReader.reset(pdol, (short) 0, pdolLength).totalDataLength()
                : 0;
    }

    /** Offset of tag's value in the PDOL data, or -1. */
    public short getPdolValueOffset(short tag) {
        return pdolLength > 0
                ? dolReader.reset(pdol, (short) 0, pdolLength).findValueOffset(tag)
                : -1;
    }

    // --- Card risk management (EMV v4.4 Book 3 §10.8) ----------------------

    /** Issuer Action Code - Denial; all-zero default (EMV v4.4 Book 3 section 10.7). */
    public byte[] getIacDenial() {
        return iacDenialLength > 0 ? iacDenial : Defaults.IAC_DENIAL;
    }

    public short getIacDenialLength() {
        return iacDenialLength > 0 ? iacDenialLength : (short) Defaults.IAC_DENIAL.length;
    }

    /** Issuer Action Code - Online; all-one default (EMV v4.4 Book 3 section 10.7). */
    public byte[] getIacOnline() {
        return iacOnlineLength > 0 ? iacOnline : Defaults.IAC_ONLINE;
    }

    public short getIacOnlineLength() {
        return iacOnlineLength > 0 ? iacOnlineLength : (short) Defaults.IAC_ONLINE.length;
    }

    /** Issuer Action Code - Default; all-one default (EMV v4.4 Book 3 section 10.7). */
    public byte[] getIacDefault() {
        return iacDefaultLength > 0 ? iacDefault : Defaults.IAC_DEFAULT;
    }

    public short getIacDefaultLength() {
        return iacDefaultLength > 0 ? iacDefaultLength : (short) Defaults.IAC_DEFAULT.length;
    }

    /**
     * Issuer Application Data (9F10): the fixed 32-byte Format Code 'A'
     * template, whose CVR bytes were last written by setCvr() (EMV v4.4 Book 3 Annex C §C9).
     */
    public byte[] getIad() {
        return iad;
    }

    public short getIadLength() {
        return Iad.LENGTH;
    }

    /**
     * Selects the Cryptogram Version of the IAD Common Core Identifier (5 or 6,
     * EMV v4.4 Book 3 Annex C §C9).  The CCI byte of the IAD is updated; a later
     * personalized 9F10 keeps the selected version (see applyPaymentConfig).
     */
    public void setCryptogramVersion(byte cryptogramVersion) {
        this.cryptogramVersion = cryptogramVersion;
        iad[1] = (byte) (0xA0 | (cryptogramVersion & 0x0F));
    }

    /**
     * Writes the transaction's Card Verification Results into the IAD
     * (bytes 4-8) so the AC input, the GENERATE AC response and the transaction
     * log all share the same 9F10 (EMV v4.4 Book 3 Annex C §C9).
     */
    public void setCvr(byte[] cvr, short off) {
        Iad.setCvr(iad, (short) 0, cvr, off);
    }

    // --- Transaction log (EMV v4.4 Book 3 Annex D4) -------------------------

    /** The personalized log format (9F4F), or the default when absent. */
    public byte[] getLogFormat() {
        return logFormatLength > 0 ? logFormat : Defaults.LOG_FORMAT;
    }

    public short getLogFormatLength() {
        return logFormatLength > 0 ? logFormatLength : (short) Defaults.LOG_FORMAT.length;
    }

    // --- Offline velocity checking (EMV v4.4 Book 3 Annex C §C9.3) ----------

    public boolean hasLcol() {
        return hasLcol;
    }

    public byte getLcol() {
        return lcol;
    }

    public boolean hasUcol() {
        return hasUcol;
    }

    public byte getUcol() {
        return ucol;
    }

    // --- Accessors for the response and record builders ---------------------

    /** The personalized application label, or null when absent. */
    byte[] getLabel() {
        return labelLength > 0 ? label : null;
    }

    short getLabelLength() {
        return labelLength;
    }

    byte getPriority() {
        return priority;
    }

    byte[] getCvmList() {
        return cvmList;
    }

    short getCvmLength() {
        return cvmLength;
    }

    byte[] getCdol1() {
        return cdol1;
    }

    short getCdol1Length() {
        return cdol1Length;
    }

    byte[] getCdol2() {
        return cdol2;
    }

    short getCdol2Length() {
        return cdol2Length;
    }

    byte[] getPan() {
        return pan;
    }

    short getPanLength() {
        return panLength;
    }

    byte[] getExpiry() {
        return expiry;
    }

    short getExpiryLength() {
        return expiryLength;
    }

    byte[] getIine() {
        return iine;
    }

    short getIineLength() {
        return iineLength;
    }

    byte[] getAsrpd() {
        return asrpd;
    }

    short getAsrpdLength() {
        return asrpdLength;
    }

    byte[] getTokenRequestorId() {
        return tokenRequestorId;
    }

    short getTokenRequestorIdLength() {
        return tokenRequestorIdLength;
    }

    byte[] getPar() {
        return par;
    }

    short getParLength() {
        return parLength;
    }

    byte[] getLast4Pan() {
        return last4Pan;
    }

    short getLast4PanLength() {
        return last4PanLength;
    }

    byte[] getTrack2() {
        return track2;
    }

    short getTrack2Length() {
        return track2Length;
    }

    byte[] getAuc() {
        return auc;
    }

    short getAucLength() {
        return aucLength;
    }

    byte[] getApplicationVersion() {
        return applicationVersion;
    }

    short getApplicationVersionLength() {
        return applicationVersionLength;
    }

    /** The offline-data-authentication certificate material (read by RecordBuilder). */
    SdaCertificateData getCertificates() {
        return certificates;
    }

    byte[] getFciOverride() {
        return fciOverride;
    }

    short getFciOverrideLength() {
        return fciOverrideLength;
    }
}
