package card42.emv;

import card42.common.*;

import javacard.framework.Util;

/* Builds the default PSE / PPSE candidate list of a DirectoryApplet instance.
 *
 * A directory entry is a 61 template holding the ADF Name (4F), optionally the
 * Application Label (50), the Application Priority Indicator (87) and, for a
 * PPSE entry, the Kernel Identifier (9F2A) (EMV v4.4 Book 1 Table 12/13,
 * EMV Contactless Book B v2.12 Table 3-2).  The default PPSE wraps its entries
 * in A5 { BF0C { 61 { ... } ... } }.
 *
 * Both methods are static and write into caller-supplied buffers, so the
 * SELECT path allocates nothing.  The entry builder is called once per
 * candidate, which lets the caller emit one or several 61 templates
 * (EMV Contactless Book B v2.12 Table 3-2 allows several Directory Entries; priority is coded in
 * b4-b1 of 87 per Table 3-3, 1 being the highest).
 *
 * @author card42
 */

public final class DirectoryBuilder {

    private DirectoryBuilder() {
    }

    /**
     * Appends one Directory Entry 61 { 4F, [50], 87, [9F2A] } to out and
     * returns the offset just past it.
     *
     * <p>The Application Label (50) is omitted when labelLen is 0.  The Kernel
     * Identifier (9F2A) is omitted when kernelLen is 0 (the PSE entry has no
     * kernel; EMV Contactless Book B v2.12 Table 3-2 marks it conditional).  For a PPSE entry the
     * priority is masked to b4-b1 because b8-b5 are RFU (EMV Contactless Book B v2.12 Table 3-3); for
     * a PSE entry b8 is 'Application cannot be selected without confirmation by
     * the cardholder' and is preserved, only b7-b5 being RFU (EMV v4.4 Book 1 Table 13).
     */
    public static short appendDirectoryEntry(byte[] out, short off,
            byte[] aid, short aidLen,
            byte[] label, short labelLen,
            byte priority, boolean ppse,
            byte[] kernel, short kernelLen) {
        short valueLength = tlvSize(TlvTags.TAG_ADF_NAME, aidLen);
        if (labelLen > 0) {
            valueLength += tlvSize(TlvTags.TAG_APPLICATION_LABEL, labelLen);
        }
        valueLength += (short) 3; // 87 01 <priority>
        if (kernelLen > 0) {
            valueLength += tlvSize(TlvTags.TAG_KERNEL_IDENTIFIER, kernelLen);
        }

        off = Tlv.appendTag(TlvTags.TAG_DIRECTORY_ENTRY, out, off);
        off = Tlv.appendLength(valueLength, out, off);
        off = Tlv.append(TlvTags.TAG_ADF_NAME, aid, (short) 0, aidLen, out, off);
        if (labelLen > 0) {
            off = Tlv.append(TlvTags.TAG_APPLICATION_LABEL, label, (short) 0,
                    labelLen, out, off);
        }
        out[off++] = (byte) TlvTags.TAG_PRIORITY_INDICATOR;
        out[off++] = (byte) 0x01;
        out[off++] = (byte) (priority & (ppse ? 0x0F : 0x8F));
        if (kernelLen > 0) {
            off = Tlv.append(TlvTags.TAG_KERNEL_IDENTIFIER, kernel, (short) 0,
                    kernelLen, out, off);
        }
        return off;
    }

    /**
     * Wraps pre-built Directory Entries as the PPSE A5 FCI Proprietary
     * Template A5 { BF0C { entries } } and returns its encoded length
     * (EMV Contactless Book B v2.12 Table 3-2).  entries and out must be
     * different buffers; out must be large enough for the wrapper.
     */
    public static short buildPpseA5(byte[] entries, short entriesLength, byte[] out) {
        short bf0cLength = (short) (2 + Tlv.lengthSize(entriesLength) + entriesLength);
        short p = 0;
        p = Tlv.appendTag(TlvTags.TAG_FCI_PROPRIETARY, out, p); // A5
        p = Tlv.appendLength(bf0cLength, out, p);
        p = Tlv.appendTag(TlvTags.TAG_FCI_ISSUER_DISCRETIONARY, out, p); // BF0C
        p = Tlv.appendLength(entriesLength, out, p);
        Util.arrayCopyNonAtomic(entries, (short) 0, out, p, entriesLength);
        p += entriesLength;
        return p;
    }

    /** Encoded size of tag || length || value for a value of valueLength. */
    private static short tlvSize(short tag, short valueLength) {
        short tagLength = (tag & (short) 0xFF00) != 0 ? (short) 2 : (short) 1;
        return (short) (tagLength + Tlv.lengthSize(valueLength) + valueLength);
    }
}
