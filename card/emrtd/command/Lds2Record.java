package card42.emrtd;

import card42.common.Tlv;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;

/* LDS2 record and memory commands (Doc 9303-10 §3.7/§3.8):
 *
 *   READ RECORD     B2  one record or all records from a starting number
 *   APPEND RECORD   E2  append a variable-size record
 *   SEARCH RECORD   A2  search records for a byte string
 *   FMM             5F  file and memory management query
 *   UPDATE BINARY   D7  write an Additional Biometrics transparent EF
 *   ACTIVATE        44  freeze an Additional Biometrics EF
 *
 * The record EF is addressed by the short EF identifier in P2 (b8-b4) for
 * READ/APPEND; SEARCH and FMM carry a file reference DO.  All commands operate
 * on the LDS2 file system of the currently selected LDS2 application.
 *
 * @author card42
 */

public final class Lds2Record {

    /** Le/response cap for one READ RECORD (the SM response buffer is 256). */
    private static final short RESPONSE_MAX = (short) 256;

    /* Reused scratch: the J3R180 does not reclaim per-call allocations, and
     * LDS2 commands run repeatedly, so these must not be allocated in the
     * command handlers. */
    private static final short[] REF = new short[2];
    private static final short[] HANDLING = new short[2];
    private static final short[] SEARCH_STRING = new short[2];
    private static final short[] WINDOW = new short[2];
    private static final short[] FIRST = new short[2];
    private static final short[] SECOND = new short[2];
    private static final short[] TERMINATION = new short[2];
    private static final short[] OFFSET_DO = new short[2];
    private static final short[] VALUE_DO = new short[2];
    private static final short[] SIZE_DO = new short[2];
    private static final byte[] FMM_BODY = new byte[16];
    private static final byte[] SEARCH_BODY = new byte[64];

    private Lds2Record() {
    }

    /** READ RECORD (B2): P2 b8-b4 SFI, b3=1, b2b1 = single (00) / all (01). */
    public static short readRecord(EmrtdApplet applet, byte p1, byte p2, short le) {
        applet.requirePace();
        // The short EF identifier is P2 b8..b4 (Doc 9303-10 §3.7.2 Table 13),
        // i.e. (p2 >> 3) & 0x1F; SFI 0 addresses the current EF.
        short sfi = (short) ((p2 >> 3) & 0x1F);
        Lds2RecordFile file = sfi == 0
                ? applet.lds2.getSelectedRecord()
                : applet.lds2.recordBySfi(sfi);
        if (file == null) {
            ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
        }
        applet.lds2.selectRecord(file);
        short number = (short) (p1 & 0xFF);
        if (number == 0) {
            // P1='00' references the current record (Doc 9303-10 §3.7.2 Table 11).
            number = file.currentRecord();
        }
        short max = le <= 0 ? RESPONSE_MAX : le;
        if (max > RESPONSE_MAX) {
            max = RESPONSE_MAX;
        }
        if ((p2 & 0x03) == 0x01) {
            return file.readRecords(number, applet.response, (short) 0, max);
        }
        return file.readRecord(number, applet.response, (short) 0, max);
    }

    /** APPEND RECORD (E2): P2 b8-b4 SFI, data is the record. */
    public static short appendRecord(EmrtdApplet applet, byte p1, byte p2,
                                     byte[] data, short off, short len) {
        applet.requirePace();
        if ((p1 & 0xFF) != 0) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        short sfi = (short) ((p2 >> 3) & 0x1F);
        Lds2RecordFile file = sfi == 0
                ? applet.lds2.getSelectedRecord()
                : applet.lds2.recordBySfi(sfi);
        if (file == null) {
            ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
        }
        applet.lds2.selectRecord(file);
        file.append(data, off, len);
        return 0;
    }

    /** FMM (5F): P1 selects the EF, P2 the requested information. */
    public static short fileMemoryManagement(EmrtdApplet applet, byte p1, byte p2,
                                             byte[] data, short off, short len) {
        applet.requirePace();
        if ((p1 & 0xFF) == 0x01) {
            short[] ref = REF;
            if (!find(data, off, len, EmrtdTags.DO_FILE_REFERENCE, ref)) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }
            short fid;
            if (ref[1] == 1) {
                short sfi = (short) ((data[ref[0]] & 0xFF) >> 3);
                Lds2TransparentFile t = applet.lds2.transparentBySfi(sfi);
                if (t != null) {
                    applet.lds2.selectTransparent(t);
                } else {
                    Lds2RecordFile r = applet.lds2.recordBySfi(sfi);
                    if (r == null) {
                        ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
                    }
                    applet.lds2.selectRecord(r);
                }
                return fmmResponse(applet, p2);
            }
            fid = Util.getShort(data, ref[0]);
            applet.lds2.select(fid);
        } else if ((p1 & 0xFF) != 0x00) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        return fmmResponse(applet, p2);
    }

    private static short fmmResponse(EmrtdApplet applet, byte p2) {
        byte[] body = FMM_BODY;
        short p = 0;
        Lds2TransparentFile t = applet.lds2.getSelectedTransparent();
        Lds2RecordFile r = applet.lds2.getSelectedRecord();
        if ((p2 & 0x01) != 0) {
            short total = t != null ? t.getLength() : (r != null ? r.totalBytes() : 0);
            body[p++] = (byte) 0x81;
            p = writeNumber(body, p, total);
        }
        if ((p2 & 0x02) != 0) {
            if (r == null) {
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
            }
            body[p++] = (byte) 0x82;
            p = writeNumber(body, p, r.remainingRecords());
        }
        if ((p2 & 0x04) != 0) {
            if (r == null) {
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
            }
            body[p++] = (byte) 0x83;
            p = writeNumber(body, p, r.recordCount());
        }
        byte[] out = applet.response;
        short n = Tlv.appendTag(EmrtdTags.DO_FMM, out, (short) 0);
        n = Tlv.appendLength(p, out, n);
        Util.arrayCopyNonAtomic(body, (short) 0, out, n, p);
        return (short) (n + p);
    }

    /** SEARCH RECORD (A2): data is a Record handling DO '7F76'. */
    public static short searchRecord(EmrtdApplet applet, byte p2, byte[] data, short off, short len) {
        applet.requirePace();
        // P2 = 11111000b: search through multiple EFs (Doc 9303-10 §3.7.3 Table 16).
        if ((p2 & 0xFF) != 0xF8) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        short[] handling = HANDLING;
        if (!find(data, off, len, EmrtdTags.DO_RECORD_HANDLING, handling)) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        short[] ref = REF;
        if (!find(data, handling[0], handling[1], EmrtdTags.DO_FILE_REFERENCE, ref)) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        Lds2RecordFile file = ref[1] == 1
                ? applet.lds2.recordBySfi((short) ((data[ref[0]] & 0xFF) >> 3))
                : applet.lds2.record(Util.getShort(data, ref[0]));
        if (file == null) {
            ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
        }
        applet.lds2.selectRecord(file);

        short[] searchString = SEARCH_STRING;
        if (!find(data, handling[0], handling[1], (short) 0x81, searchString)) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        short windowOffset = 0;
        short windowLength = 0;
        short[] window = WINDOW;
        if (find(data, handling[0], handling[1], (short) 0xB0, window)) {
            short[] first = FIRST;
            if (find(data, window[0], window[1], (short) 0x02, first)) {
                windowOffset = Util.getShort(data, first[0]);
                // The next '02' after the offset value is the byte count.
                short nextOff = (short) (first[0] + first[1]);
                short[] second = SECOND;
                if (find(data, nextOff, (short) (window[0] + window[1] - nextOff),
                        (short) 0x02, second)) {
                    windowLength = Util.getShort(data, second[0]);
                }
            }
        }

        // Search termination DO'80': '30' stops after the first match
        // (Doc 9303-10 §3.7.3 Table 17).
        boolean stopFirst = false;
        short[] termination = TERMINATION;
        if (find(data, handling[0], handling[1], (short) 0x80, termination)
                && termination[1] > 0 && data[termination[0]] == 0x30) {
            stopFirst = true;
        }

        byte[] out = applet.response;
        short bodyStart = 0;
        byte[] body = SEARCH_BODY;
        short p = Tlv.appendTag(EmrtdTags.DO_FILE_REFERENCE, body, (short) 0);
        p = Tlv.appendLength(ref[1], body, p);
        Util.arrayCopyNonAtomic(data, ref[0], body, p, ref[1]);
        p += ref[1];
        short matches = 0;
        for (short number = 1; number <= file.recordCount(); number++) {
            if ((short) (p + 4) > (short) body.length) {
                break;
            }
            if (file.search(number, data, searchString[0], searchString[1],
                    windowOffset, windowLength)) {
                body[p++] = (byte) 0x02;
                p = writeNumber(body, p, number);
                matches++;
                if (stopFirst) {
                    break;
                }
            }
        }
        if (matches == 0) {
            ISOException.throwIt((short) 0x6282);
        }
        short n = Tlv.appendTag(EmrtdTags.DO_RECORD_HANDLING, out, (short) 0);
        n = Tlv.appendLength(p, out, n);
        Util.arrayCopyNonAtomic(body, bodyStart, out, n, p);
        return (short) (n + p);
    }

    /** UPDATE BINARY with odd INS (D7): offset DO '54' + data DO '53'. */
    public static short updateBinary(EmrtdApplet applet, byte[] data, short off, short len) {
        applet.requirePace();
        Lds2TransparentFile file = applet.lds2.getSelectedTransparent();
        if (file == null || file.isActivated()) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
        short[] offsetDo = OFFSET_DO;
        if (!find(data, off, len, EmrtdTags.DO_OFFSET, offsetDo)) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        short offset = 0;
        if (offsetDo[1] == 1) {
            offset = (short) (data[offsetDo[0]] & 0xFF);
        } else if (offsetDo[1] >= 2) {
            offset = Util.getShort(data, offsetDo[0]);
        }
        // The first UPDATE BINARY MUST start at offset 0 (Doc 9303-10 §3.8/§3.8.1).
        if (!file.isWritten() && offset != 0) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        short[] valueDo = VALUE_DO;
        if (!find(data, off, len, EmrtdTags.DO_DISCRETIONARY, valueDo)) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        // The optional File Size DO'C0' (Doc 9303-10 §3.8.1 Note 1) reserves the
        // EF's final size up front so its page table is allocated once; without
        // it the store simply grows as the writes arrive.
        short[] sizeDo = SIZE_DO;
        if (find(data, off, len, EmrtdTags.DO_FILE_SIZE, sizeDo)) {
            if (sizeDo[1] == 1) {
                file.ensureCapacity((short) (data[sizeDo[0]] & 0xFF));
            } else if (sizeDo[1] >= 2) {
                file.ensureCapacity(Util.getShort(data, sizeDo[0]));
            }
        }
        file.update(offset, data, valueDo[0], valueDo[1]);
        return 0;
    }

    /** ACTIVATE (44): freeze the selected Additional Biometrics transparent EF. */
    public static short activate(EmrtdApplet applet, byte p1, byte p2) {
        applet.requirePace();
        if (p1 != 0 || p2 != 0) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        Lds2TransparentFile file = applet.lds2.getSelectedTransparent();
        if (file == null) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        file.activate();
        return 0;
    }

    // --- helpers -------------------------------------------------------------

    /** Writes a minimal-length big-endian integer; returns the new offset. */
    private static short writeNumber(byte[] out, short off, short value) {
        short u = value;
        if (u == 0) {
            out[off] = 0;
            return (short) (off + 1);
        }
        short size = 0;
        short v = u;
        while (v != 0) {
            size++;
            v = (short) ((v >> 8) & 0xFF);
        }
        out[off] = (byte) size;
        for (short i = 0; i < size; i++) {
            out[(short) (off + 1 + i)] = (byte) (u >> (8 * (size - 1 - i)));
        }
        return (short) (off + 1 + size);
    }

    /**
     * Recursively finds the first TLV with the given tag in [off, off+len) and
     * writes {value offset, value length} to result.  Returns false when absent.
     */
    static boolean find(byte[] buf, short off, short len, short tag, short[] result) {
        short p = off;
        short end = (short) (off + len);
        while (p < end) {
            short lenOff = Tlv.lengthOffset(buf, p);
            if (Tlv.lengthFieldLength(buf, lenOff) == 0) {
                return false;
            }
            short total = Tlv.totalLength(buf, p);
            if (total <= 0 || (short) (p + total) > end) {
                return false;
            }
            short t = Tlv.getTag(buf, p);
            short valueOff = Tlv.valueOffset(buf, p);
            short valueLen = Tlv.getLength(buf, lenOff);
            if (t == tag) {
                result[0] = valueOff;
                result[1] = valueLen;
                return true;
            }
            if (Tlv.isConstructed(t) && find(buf, valueOff, valueLen, tag, result)) {
                return true;
            }
            p = (short) (p + total);
        }
        return false;
    }
}
