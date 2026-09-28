package card42.emv;

import card42.common.*;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;

/* The card data of a payment applet, driven by personalization (EMV CPS v2.0
 * Annex A).
 *
 * It wires the structured data model (PaymentData), the record table
 * (RecordStore) and the response assemblers (FciBuilder, RecordBuilder) behind
 * the API the applets use.  The SELECT response is built from the EMV CPS v2.0 Annex A DGI '9102'
 * override or the structured fields, the GPO response from the AIP/AFL, and
 * records from the record table or the default builders.
 *
 * The instance role is not stored here (docs/specs/common/architecture.md §4): the caller passes
 * the single source of truth, EMVProtocolState.getRole(), to the accessors and
 * builders that need it.
 *
 * @author joeri (joeri@cs.ru.nl)
 * @author erikpoll (erikpoll@cs.ru.nl)
 * @author card42
 */

public class EMVStaticData implements ISO7816 {

    /** Instance AID, used as the DF name in the FCI. */
    private final byte[] aid = new byte[(short) 16];
    private short aidLength;

    /** Structured personalized fields (EMV CPS v2.0 Annex A DGI '3001'/'9104' and record 1). */
    private final PaymentData data;

    /** Records stored by personalization (docs/specs/common/architecture.md §2). */
    private final RecordStore records;

    /**
     * A record is at most 254 bytes including its tag and length
     * (EMV v4.4 Book 3 §7); a longer personalized record is rejected with 6A80
     * rather than stored and later failing to be served.
     */
    private static final short MAX_RECORD_LENGTH = (short) 254;

    /** Scratch / output buffers. */
    private final byte[] scratch = new byte[(short) 128];
    private final byte[] fci = new byte[(short) 192];
    private short fciLength;
    private final byte[] gpo = new byte[(short) 64];
    private short gpoLength;
    /** Role {@link #gpo} was built for; the GPO content depends on it. */
    private byte gpoRole;
    /**
     * The one view {@link #directRecord} hands out, repointed per READ RECORD
     * so the command allocates nothing on the persistent heap (which the
     * Java Card platform never reclaims).
     */
    private final RecordBuilder.View directView = new RecordBuilder.View();

    public EMVStaticData() {
        data = new PaymentData();
        records = new RecordStore();
    }

    /**
     * Sets the instance AID used as the DF name in the FCI.  The role is read
     * from EMVProtocolState by the callers (docs/specs/common/architecture.md §4).  The AID is
     * always set from the resolved role before any FCI is built.
     */
    public void setAid(byte[] newAid) {
        if (newAid.length > aid.length) {
            ISOException.throwIt(SW_WRONG_DATA);
        }
        aidLength = (short) newAid.length;
        Util.arrayCopyNonAtomic(newAid, (short) 0, aid, (short) 0, aidLength);
        invalidateCache(); // force a rebuild on the next getFCI()/getGpo()
    }

    /**
     * Drops the cached FCI and GPO: both are built from {@code data} (and the
     * role), so every personalization path that changes it must invalidate them
     * (docs/specs/emv/personalization.md §3).
     */
    private void invalidateCache() {
        fciLength = 0;
        gpoLength = 0;
    }

    // --- Personalization (EMV CPS v2.0 Annex A) -----------------------------

    /** Applies the structured tags of the EMV CPS v2.0 Annex A DGIs '3001'/'9104' or record 1. */
    public void applyPaymentConfig(byte[] buf, short off, short len) {
        data.applyPaymentConfig(buf, off, len);
        invalidateCache();
    }

    /** Stores the SELECT response A5 template (EMV CPS v2.0 Annex A DGI '9102'). */
    public void setFciOverride(byte[] buf, short off, short len) {
        data.setFciOverride(buf, off, len);
        invalidateCache();
    }

    /** Stores one record (DGI (SFI<<8)|record). */
    public void setRecord(short key, byte[] buf, short off, short len) {
        if (len > MAX_RECORD_LENGTH) {
            // EMV v4.4 Book 3 §7: a record is at most 254 bytes including tag
            // and length.
            ISOException.throwIt(SW_WRONG_DATA);
        }
        // The '70' record template is required for the EMV record DGIs
        // '01xx'-'0Axx' only (EMV CPS v2.0 §3.2); a proprietary record DGI
        // '0Bxx'-'1Exx' is stored verbatim.  The normalised length (after the
        // length field is rewritten to its exact width on read) must still fit
        // the 254-byte limit, otherwise the card would serve an oversized
        // record (EMV v4.4 Book 3 §7).
        short high = (short) ((key >> 8) & 0xFF);
        if (high >= 0x01 && high <= 0x0A) {
            if (len < 2 || buf[off] != (byte) TlvTags.TAG_RECORD_TEMPLATE) {
                ISOException.throwIt(SW_WRONG_DATA);
            }
            short lengthField = Tlv.lengthFieldLength(buf, (short) (off + 1));
            if (lengthField == 0) {
                ISOException.throwIt(SW_WRONG_DATA);
            }
            short bodyLength = (short) (len - 1 - lengthField);
            if (bodyLength < 0
                    || (short) (1 + Tlv.lengthSize(bodyLength) + bodyLength) > MAX_RECORD_LENGTH) {
                ISOException.throwIt(SW_WRONG_DATA);
            }
            // A non-zero inner '70' declared length must match the actual value
            // length (EMV CPS v2.0 §3.2).  A declared length of zero is the
            // project's placeholder convention, patched to the exact width on
            // read (docs/specs/emv/personalization.md §3).
            short declared = Tlv.getLength(buf, (short) (off + 1));
            if (declared != 0 && declared != bodyLength) {
                ISOException.throwIt(SW_WRONG_DATA);
            }
        }
        records.put(key, buf, off, len);
        if (key == (short) 0x0101) {
            // Record 1 carries the CDOLs, CVM list, PAN and expiry; extract
            // them so the transaction accessors work from the EMV CPS v2.0 record model
            // (EMV CPS v2.0 Annex A).
            data.applyRecord1Fields(buf, off, len);
            invalidateCache();
        }
    }

    // --- Payment data accessors --------------------------------------------

    /** 2-byte AIP; role default unless personalization supplied one (docs/specs/common/architecture.md §4). */
    public short getAIP(byte role) {
        return data.getAIP(role);
    }

    /**
     * True when record 1 carried the mandatory PAN (5A), expiry (5F24) and
     * CDOL1/CDOL2 (8C/8D) (EMV v4.4 Book 3 §7.2 Table 28).
     */
    public boolean hasMandatoryRecord1() {
        return data.getPanLength() > 0 && data.getExpiryLength() > 0
                && data.getCdol1Length() > 0 && data.getCdol2Length() > 0;
    }

    /** Sum of the data-element lengths of CDOL1 (43 for the default CDOL1). */
    public short getCDOL1DataLength() {
        return data.getCDOL1DataLength();
    }

    /** Sum of the data-element lengths of CDOL2 (27 for the default CDOL2). */
    public short getCDOL2DataLength() {
        return data.getCDOL2DataLength();
    }

    /** Offset of tag's value in the CDOL1 data, or -1. */
    public short getCDOL1ValueOffset(short tag) {
        return data.getCDOL1ValueOffset(tag);
    }

    /** Value length of tag in the CDOL1 data, or -1. */
    public short getCDOL1ValueLength(short tag) {
        return data.getCDOL1ValueLength(tag);
    }

    /** Offset of tag's value in the CDOL2 data, or -1. */
    public short getCDOL2ValueOffset(short tag) {
        return data.getCDOL2ValueOffset(tag);
    }

    /** Value length of tag in the CDOL2 data, or -1. */
    public short getCDOL2ValueLength(short tag) {
        return data.getCDOL2ValueLength(tag);
    }

    /**
     * Whether the AIP advertises issuer authentication via EXTERNAL
     * AUTHENTICATE (byte 1 bit 3, EMV v4.4 Book 2 §8.2).
     */
    public boolean externalAuthenticateSupported(byte role) {
        return data.externalAuthenticateSupported(role);
    }

    /**
     * Whether the application uses the CCD GENERATE AC response format
     * (Format 2, EMV v4.4 Book 3 CCD §6.5.5.4).
     */
    public boolean isCcdFormat() {
        return data.isCcdFormat();
    }

    /** Offset of the 9F37 value in the CDOL1 data, or -1. */
    public short getCDOL1UnOffset() {
        return data.getCDOL1UnOffset();
    }

    /** Offset of the 9F37 value in the CDOL2 data, or -1. */
    public short getCDOL2UnOffset() {
        return data.getCDOL2UnOffset();
    }

    // --- PDOL (EMV v4.4 Book 3 §6.5.8) -------------------------------------

    /** Total length of the PDOL-related data the terminal sends in GPO. */
    public short getPdolDataLength() {
        return data.getPdolDataLength();
    }

    /** Offset of tag's value in the PDOL data, or -1. */
    public short getPdolValueOffset(short tag) {
        return data.getPdolValueOffset(tag);
    }

    // --- Card risk management (EMV v4.4 Book 3 §10.8) ----------------------

    public byte[] getIacDenial() {
        return data.getIacDenial();
    }

    public short getIacDenialLength() {
        return data.getIacDenialLength();
    }

    public byte[] getIacOnline() {
        return data.getIacOnline();
    }

    public short getIacOnlineLength() {
        return data.getIacOnlineLength();
    }

    public byte[] getIacDefault() {
        return data.getIacDefault();
    }

    public short getIacDefaultLength() {
        return data.getIacDefaultLength();
    }

    public byte[] getIad() {
        return data.getIad();
    }

    public short getIadLength() {
        return data.getIadLength();
    }

    public void setCvr(byte[] cvr, short off) {
        data.setCvr(cvr, off);
    }

    /** Selects the Cryptogram Version of the IAD CCI (EMV v4.4 Book 3 Annex C §C9). */
    public void setCryptogramVersion(byte cryptogramVersion) {
        data.setCryptogramVersion(cryptogramVersion);
    }

    // --- Transaction log (EMV v4.4 Book 3 Annex D4) -------------------------

    public byte[] getLogFormat() {
        return data.getLogFormat();
    }

    public short getLogFormatLength() {
        return data.getLogFormatLength();
    }

    // --- Offline velocity checking (EMV v4.4 Book 3 Annex C §C9.3) ----------

    public boolean hasLcol() {
        return data.hasLcol();
    }

    public byte getLcol() {
        return data.getLcol();
    }

    public boolean hasUcol() {
        return data.hasUcol();
    }

    public byte getUcol() {
        return data.getUcol();
    }

    /**
     * The GPO response.  Format 2 (77 { 82 AIP, 94 AFL }) for a contactless
     * instance and Format 1 (80 AIP || AFL) for a contact instance
     * (EMV v4.4 Book 3 §6.5.8).
     */
    public byte[] getGpo(byte role) {
        if (gpoLength > 0 && gpoRole == role) {
            return gpo;
        }
        gpoRole = role;
        gpoLength = FciBuilder.buildGpo(role, data, gpo);
        return gpo;
    }

    public short getGpoLength(byte role) {
        if (gpoLength == 0 || gpoRole != role) {
            getGpo(role);
        }
        return gpoLength;
    }

    /** The FCI: the EMV CPS v2.0 Annex A DGI '9102' A5 override if present, else built from fields. */
    public byte[] getFCI(byte role) {
        if (fciLength > 0) {
            return fci;
        }
        fciLength = FciBuilder.buildFci(role, aid, aidLength, data, scratch, fci);
        return fci;
    }

    public short getFCILength(byte role) {
        if (fciLength == 0) {
            getFCI(role);
        }
        return fciLength;
    }

    // --- Records ------------------------------------------------------------

    /**
     * Provides the response to EMVCommands.INS_READ_RECORD in the response buffer
     * (EMV v4.4 Book 3 §6.5.11).
     */
    public void readRecord(byte[] apduBuffer, byte[] response, byte role) {
        RecordBuilder.readRecord(records, apduBuffer, response, role, data);
    }

    /**
     * A stored record that can be served directly from the persistent pool
     * without copying it into the transient response buffer, or null when the
     * caller must use {@link #readRecord} (EMV v4.4 Book 3 §7.1).
     */
    public RecordBuilder.View directRecord(byte[] apduBuffer) {
        return RecordBuilder.directView(records, apduBuffer, data, directView);
    }
}
