package card42.emv;

import card42.common.*;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;

/* Reusable validation rules for personalization DGI values (EMV CPS v2.0
 * Annex A).  The rules are pure static helpers with no card state and no
 * crypto dependency, so they can be unit-tested on the pure JVM
 * (docs/specs/common/toolchain.md §6).
 *
 * @author card42
 */

public final class PersoRules implements ISO7816 {

    private PersoRules() {
    }

    /**
     * The length of the STORE DATA Lc field: 1 byte, or 3 bytes when the first
     * byte is '00' and two more bytes are present ('00' || LcHi || LcLo,
     * EMV CPS v2.0 Table 4-8).  Returns 0 when the Lc byte itself is beyond
     * {@code end}.  A '00' with no room for two length bytes is a 1-byte Lc=0.
     *
     * @param lcOffset index of the first Lc byte
     * @param end      index one past the last available byte of the command
     */
    public static short storeDataLcFieldLength(byte[] buf, short lcOffset, short end) {
        if (lcOffset >= end) {
            return 0;
        }
        if ((buf[lcOffset] & 0xFF) != 0x00) {
            return 1;
        }
        return (short) ((short) (lcOffset + 3) <= end ? 3 : 1);
    }

    /** The STORE DATA Lc value for a field length returned by storeDataLcFieldLength. */
    public static short storeDataLc(byte[] buf, short lcOffset, short fieldLength) {
        if (fieldLength == 3) {
            return (short) (((buf[(short) (lcOffset + 1)] & 0xFF) << 8)
                    | (buf[(short) (lcOffset + 2)] & 0xFF));
        }
        return (short) (buf[lcOffset] & 0xFF);
    }

    /**
     * Validates that the DGI value at off/len is the FCI Proprietary Template
     * 'A5' and contains the mandatory tag (EMV CPS v2.0 Table A-14 / Table A-21):
     * the payment '9102' requires '50', the PSE '9102' requires '88' and the
     * PPSE '9102' (EMV Contactless Book B v2.12 §3.3) requires 'BF0C'.  Throws 6A80
     * when the value is not a well-formed A5 or the tag is missing.
     */
    public static void validateFciTemplate(byte[] buf, short off, short len,
            short requiredTag) {
        if (!isFciTemplate(buf, off, len, requiredTag)) {
            ISOException.throwIt(SW_WRONG_DATA);
        }
    }

    /**
     * True when off/len is a well-formed 'A5' FCI Proprietary Template whose
     * top level contains requiredTag.  A malformed inner TLV still aborts with
     * 6A80 (TlvReader), which is the same rejection validateFciTemplate wants.
     */
    public static boolean isFciTemplate(byte[] buf, short off, short len,
            short requiredTag) {
        if (len < 2 || (buf[off] & 0xFF) != TlvTags.TAG_FCI_PROPRIETARY) {
            return false;
        }
        short lenOffset = Tlv.lengthOffset(buf, off);
        short lengthField = Tlv.lengthFieldLength(buf, lenOffset);
        if (lengthField == 0) {
            return false; // indefinite length: not supported
        }
        short valueOffset = (short) (lenOffset + lengthField);
        short valueLength = Tlv.getLength(buf, lenOffset);
        if (valueLength < 0 || (short) (valueOffset + valueLength) > (short) (off + len)) {
            return false; // the A5 value runs past the container
        }
        TlvReader reader = new TlvReader(buf, valueOffset, valueLength);
        boolean found = false;
        while (reader.hasNext()) {
            reader.next();
            if (reader.tag() == requiredTag) {
                found = true;
            }
            // Application Label ('50') is 1-16 bytes
            // (EMV v4.4 Book 3 Annex A Table 37); an over-long label is a
            // personalization error.
            if (reader.tag() == TlvTags.TAG_APPLICATION_LABEL
                    && (reader.valueLength() < 1 || reader.valueLength() > 16)) {
                return false;
            }
        }
        return found;
    }

    /**
     * Validates the PSE '9102' A5 template (EMV v4.4 Book 1 §12.2.3): it must
     * contain the Directory SFI ('88'), which identifies the directory file and
     * must be in the range 1-10.  A personalized FCI advertising an SFI outside
     * that range is refused with 6A80.
     */
    public static void validatePseTemplate(byte[] buf, short off, short len) {
        if (!isFciTemplate(buf, off, len, TlvTags.TAG_SFI)) {
            ISOException.throwIt(SW_WRONG_DATA);
        }
        short lenOffset = Tlv.lengthOffset(buf, off);
        short lengthField = Tlv.lengthFieldLength(buf, lenOffset);
        short valueOffset = (short) (lenOffset + lengthField);
        short valueLength = Tlv.getLength(buf, lenOffset);
        TlvReader reader = new TlvReader(buf, valueOffset, valueLength);
        while (reader.hasNext()) {
            reader.next();
            if (reader.tag() == TlvTags.TAG_SFI) {
                short sfi = (short) (buf[reader.valueOffset()] & 0xFF);
                if (reader.valueLength() != 1 || sfi < (short) 0x01 || sfi > (short) 0x0A) {
                    ISOException.throwIt(SW_WRONG_DATA); // directory SFI must be 1-10
                }
                return;
            }
        }
        ISOException.throwIt(SW_WRONG_DATA); // 88 missing (unreachable)
    }

    /**
     * The Directory SFI ('88') of a PSE '9102' A5 template, 1-10
     * (EMV v4.4 Book 1 §12.2.3).  Call only after {@link #validatePseTemplate}
     * accepted the template; the default (SFI 1) is returned defensively.
     */
    public static short pseDirectorySfi(byte[] buf, short off, short len) {
        short lenOffset = Tlv.lengthOffset(buf, off);
        short lengthField = Tlv.lengthFieldLength(buf, lenOffset);
        short valueOffset = (short) (lenOffset + lengthField);
        short valueLength = Tlv.getLength(buf, lenOffset);
        TlvReader reader = new TlvReader(buf, valueOffset, valueLength);
        while (reader.hasNext()) {
            reader.next();
            if (reader.tag() == TlvTags.TAG_SFI) {
                return (short) (buf[reader.valueOffset()] & 0xFF);
            }
        }
        return (short) 1;
    }

    /**
     * Validates the PSE directory record DGI '0101' value (EMV CPS v2.0 Annex A
     * Table A-20): a Record Template '70' containing one or more Directory Entry
     * Templates '61', each carrying the mandatory Dedicated File Name ('4F',
     * 5-16 bytes) and, when present, a 1-16 byte Application Label ('50') /
     * Application Preferred Name ('9F12') and a one-byte Application Priority
     * Indicator ('87').  Throws 6A80 on any violation.
     */
    public static void validatePseRecord(byte[] buf, short off, short len) {
        if (!isRecordTemplate(buf, off, len)) {
            ISOException.throwIt(SW_WRONG_DATA);
        }
        short lenOffset = Tlv.lengthOffset(buf, off);
        short lengthField = Tlv.lengthFieldLength(buf, lenOffset);
        short valueOffset = (short) (lenOffset + lengthField);
        short valueLength = Tlv.getLength(buf, lenOffset);
        boolean anyEntry = false;
        TlvReader reader = new TlvReader(buf, valueOffset, valueLength);
        while (reader.hasNext()) {
            reader.next();
            if (reader.tag() != TlvTags.TAG_DIRECTORY_ENTRY) {
                continue; // a directory record only carries '61' entries
            }
            anyEntry = true;
            validatePseEntry(buf, reader.valueOffset(), reader.valueLength());
        }
        if (!anyEntry) {
            ISOException.throwIt(SW_WRONG_DATA); // 70 without a Directory Entry
        }
    }

    /** True when off/len is a well-formed '70' Record Template within its container. */
    private static boolean isRecordTemplate(byte[] buf, short off, short len) {
        if (len < 2 || (buf[off] & 0xFF) != TlvTags.TAG_RECORD_TEMPLATE) {
            return false;
        }
        short lenOffset = Tlv.lengthOffset(buf, off);
        short lengthField = Tlv.lengthFieldLength(buf, lenOffset);
        if (lengthField == 0) {
            return false; // indefinite length: not supported
        }
        short valueOffset = (short) (lenOffset + lengthField);
        short valueLength = Tlv.getLength(buf, lenOffset);
        return valueLength >= 0
                && (short) (valueOffset + valueLength) <= (short) (off + len);
    }

    /** Validates one '61' Directory Entry inside a PSE record. */
    private static void validatePseEntry(byte[] buf, short off, short len) {
        boolean hasAdf = false;
        boolean hasLabel = false;
        TlvReader entry = new TlvReader(buf, off, len);
        while (entry.hasNext()) {
            entry.next();
            short tag = entry.tag();
            short valueLength = entry.valueLength();
            if (tag == TlvTags.TAG_ADF_NAME) {
                // Dedicated File Name (AID) is 5-16 bytes
                // (EMV CPS v2.0 Annex A Table A-20).
                if (valueLength < 5 || valueLength > 16) {
                    ISOException.throwIt(SW_WRONG_DATA);
                }
                hasAdf = true;
            } else if (tag == TlvTags.TAG_APPLICATION_LABEL) {
                // The Application Label is mandatory in a PSE Directory Entry
                // (EMV v4.4 Book 1 §12.2.3 Table 12, 'M') and is 1-16 bytes.
                // CPS v2.0 Table A-20 marks it optional; the PSE is a Book 1
                // construct, so Book 1 is authoritative here.
                if (valueLength < 1 || valueLength > 16) {
                    ISOException.throwIt(SW_WRONG_DATA);
                }
                hasLabel = true;
            } else if (tag == TlvTags.TAG_APPLICATION_PREFERRED_NAME) {
                if (valueLength < 1 || valueLength > 16) {
                    ISOException.throwIt(SW_WRONG_DATA);
                }
            } else if (tag == TlvTags.TAG_PRIORITY_INDICATOR) {
                if (valueLength != 1) {
                    ISOException.throwIt(SW_WRONG_DATA);
                }
            }
        }
        if (!hasAdf || !hasLabel) {
            ISOException.throwIt(SW_WRONG_DATA); // 61 without 4F or without 50
        }
    }

    /**
     * Validates a Track 2 Equivalent Data value (tag 57, EMV v4.4 Book 3
     * Annex A Table 37): 1-19 bytes of BCD carrying the PAN and the 'D'
     * separator before the expiry.  An over-long value or a missing separator
     * is refused with 6A80.
     */
    public static void validateTrack2(byte[] buf, short off, short len) {
        if (len < 1 || len > 19) {
            ISOException.throwIt(SW_WRONG_DATA);
        }
        // The separator is the 'D' nibble; it may fall in either nibble of a
        // byte depending on the PAN length (odd or even number of digits).
        for (short i = 0; i < len; i++) {
            byte b = buf[(short) (off + i)];
            if ((b & 0x0F) == 0x0D || (b & 0xF0) == 0xD0) {
                return;
            }
        }
        ISOException.throwIt(SW_WRONG_DATA); // no 'D' separator
    }

    /**
     * Validates the PPSE '9102' A5 template (EMV Contactless Book B v2.12
     * Table 3-2 and Table A-1): it must contain 'BF0C', whose value must hold
     * at least one well-formed Directory Entry '61'; each entry must carry the
     * mandatory ADF Name ('4F'), an optional Kernel Identifier ('9F2A') of
     * length 1 or 3-8 (never 2), and the Extended Selection constraint
     * Length('9F29') + Length('4F') &lt;= 16.  Throws 6A80 on any violation.
     */
    public static void validatePpseTemplate(byte[] buf, short off, short len) {
        if (!isFciTemplate(buf, off, len, TlvTags.TAG_FCI_ISSUER_DISCRETIONARY)) {
            ISOException.throwIt(SW_WRONG_DATA);
        }
        short lenOffset = Tlv.lengthOffset(buf, off);
        short lengthField = Tlv.lengthFieldLength(buf, lenOffset);
        short valueOffset = (short) (lenOffset + lengthField);
        short valueLength = Tlv.getLength(buf, lenOffset);
        TlvReader reader = new TlvReader(buf, valueOffset, valueLength);
        while (reader.hasNext()) {
            reader.next();
            if (reader.tag() == TlvTags.TAG_FCI_ISSUER_DISCRETIONARY) {
                validatePpseEntries(buf, reader.valueOffset(), reader.valueLength());
                return;
            }
        }
        ISOException.throwIt(SW_WRONG_DATA); // BF0C missing (unreachable)
    }

    /** Validates the Directory Entries inside the PPSE 'BF0C' value. */
    private static void validatePpseEntries(byte[] buf, short off, short len) {
        boolean anyEntry = false;
        TlvReader reader = new TlvReader(buf, off, len);
        while (reader.hasNext()) {
            reader.next();
            if (reader.tag() != TlvTags.TAG_DIRECTORY_ENTRY) {
                continue; // additional data elements may be present
            }
            anyEntry = true;
            short adfLength = -1;
            short extendedLength = 0;
            TlvReader entry = new TlvReader(buf, reader.valueOffset(), reader.valueLength());
            while (entry.hasNext()) {
                entry.next();
                short tag = entry.tag();
                if (tag == TlvTags.TAG_ADF_NAME) {
                    // ADF Name is 5-16 bytes (EMV Contactless Book B v2.12
                    // Table 3-2 / §3.3.2.5 bullet A).
                    adfLength = entry.valueLength();
                    if (adfLength < 5 || adfLength > 16) {
                        ISOException.throwIt(SW_WRONG_DATA);
                    }
                } else if (tag == TlvTags.TAG_PRIORITY_INDICATOR) {
                    // Application Priority Indicator is one byte
                    // (EMV Contactless Book B v2.12 Table 3-3).
                    if (entry.valueLength() != 1) {
                        ISOException.throwIt(SW_WRONG_DATA);
                    }
                } else if (tag == TlvTags.TAG_KERNEL_IDENTIFIER) {
                    short kernelLength = entry.valueLength();
                    // EMV Contactless Book B v2.12 Table A-1 / Table 3-5 note 11:
                    // 9F2A is 1 or 3-8 bytes, never 2.
                    if (kernelLength < 1 || kernelLength == 2 || kernelLength > 8) {
                        ISOException.throwIt(SW_WRONG_DATA);
                    }
                } else if (tag == TlvTags.TAG_EXTENDED_SELECTION) {
                    extendedLength = entry.valueLength();
                } else if (tag == TlvTags.TAG_APPLICATION_LABEL) {
                    // Application Label is 1-16 bytes
                    // (EMV v4.4 Book 3 Annex A Table 37).
                    short labelLength = entry.valueLength();
                    if (labelLength < 1 || labelLength > 16) {
                        ISOException.throwIt(SW_WRONG_DATA);
                    }
                }
            }
            if (adfLength < 0) {
                ISOException.throwIt(SW_WRONG_DATA); // 61 without 4F
            }
            if ((short) (adfLength + extendedLength) > 16) {
                ISOException.throwIt(SW_WRONG_DATA); // 9F29 + 4F > 16
            }
        }
        if (!anyEntry) {
            ISOException.throwIt(SW_WRONG_DATA); // empty candidate list
        }
    }
}
