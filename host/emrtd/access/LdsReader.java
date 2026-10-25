package card42.host.emrtd.access;

import java.io.ByteArrayOutputStream;

import javax.smartcardio.ResponseAPDU;

import card42.host.common.util.Sw;
import card42.host.emrtd.transport.EmrtdTerminal;

/**
 * Reads one LDS1 elementary file: SELECT FILE then chunked READ BINARY
 * (H0.3).  Offset reads request Le=256 (the short-APDU maximum) so the card
 * can cap the window to its active secure-messaging profile; a smaller
 * specific Le makes some chips answer 6CXX for every file shorter than the
 * request and then reject the continuation of the SM session.
 */
public final class LdsReader {

    /**
     * READ BINARY Le for a short-EF-identifier read (SFI) and for callers that
     * need a fixed window; the chunked EF reads below use {@link #READ_LE}.
     * The 3DES SM wrapper adds ~25 bytes of overhead to a response.
     */
    public static final int CHUNK = 0xE7;

    /**
     * READ BINARY Le for chunked EF reads: 256 asks the card for the largest
     * short-APDU window.  The card caps the returned plaintext to the active SM
     * profile (231 B for 3DES, 223 B for AES-128), so one request cannot exceed
     * the response buffer, while a file shorter than the request returns its
     * actual length with 9000 instead of a 6CXX wrong-length status.
     */
    public static final int READ_LE = 256;

    /**
     * Le for READ RECORD.  Doc 9303-10 §3.7.2 Table 11/Appendix H.2 requires the
     * extended form '00 00 00' (65536): one response must carry the whole
     * record, including a 900-byte EF.Certificates record.  A short Le (0xE7)
     * silently truncates such a record to the SM window.
     */
    public static final int RECORD_LE = 65536;

    private LdsReader() {
    }

    /**
     * READ RECORD one record of the selected LDS2 record EF (Doc 9303-10 §3.7).
     * The record EF is addressed by its short EF identifier; the extended Le
     * lets the card return the complete record.
     */
    public static byte[] readRecord(EmrtdTerminal terminal, int sfi, int number)
            throws Exception {
        ResponseAPDU r = terminal.readRecord(sfi, number, false, RECORD_LE);
        if (r.getSW() != 0x9000) {
            throw new IllegalStateException("READ RECORD " + String.format("%02X", sfi)
                    + "/" + number + " failed: " + Sw.format(r.getSW()));
        }
        return r.getData();
    }

    /**
     * READ RECORD(S) in the "all records from P1 up to the last" form
     * (P2 b2b1 = 01, Doc 9303-10 §3.7.2 Table 13) and returns the concatenated
     * response.  The extended Le asks the card for the whole sequence; a
     * response that ends on a record boundary contains complete records, while
     * the last record may be truncated at the card's response-buffer limit.
     */
    public static byte[] readRecordSequence(EmrtdTerminal terminal, int sfi, int first)
            throws Exception {
        ResponseAPDU r = terminal.readRecord(sfi, first, true, RECORD_LE);
        if (r.getSW() != 0x9000) {
            throw new IllegalStateException("READ RECORD(S) from " + first + " failed: "
                    + Sw.format(r.getSW()));
        }
        return r.getData();
    }

    /**
     * Reads every record of the selected LDS2 record EF from {@code first},
     * one record at a time, until the card reports 6A83 (record not found).
     */
    public static java.util.List<byte[]> readAllRecords(EmrtdTerminal terminal, int sfi, int first)
            throws Exception {
        java.util.List<byte[]> out = new java.util.ArrayList<byte[]>();
        for (int number = first; ; number++) {
            ResponseAPDU r = terminal.readRecord(sfi, number, false, RECORD_LE);
            if (r.getSW() == 0x6A83) {
                break;
            }
            if (r.getSW() != 0x9000) {
                throw new IllegalStateException("READ RECORD " + number + " failed: "
                        + Sw.format(r.getSW()));
            }
            out.add(r.getData());
        }
        return out;
    }

    /** Selects the EF and reads it whole, concatenating the chunks. */
    public static byte[] read(EmrtdTerminal terminal, int fid) throws Exception {
        ResponseAPDU selected = terminal.selectFile(fid);
        if (selected.getSW() != 0x9000) {
            throw new IllegalStateException("SELECT FILE " + String.format("%04X", fid)
                    + " failed: " + Sw.formatWithDescription(selected.getSW()));
        }
        return readSelected(terminal, fid);
    }

    /**
     * Reads the EF that is already selected, concatenating the chunks.  Used by
     * {@link #read} and {@link #readMf} after their own SELECT.
     */
    private static byte[] readSelected(EmrtdTerminal terminal, int fid) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int offset = 0;
        while (true) {
            ResponseAPDU r = terminal.readBinary(offset, READ_LE);
            int sw = r.getSW();
            // 6CXX: wrong Le, the card reports the exact remaining length.  A
            // zero length means the offset is already at the EF end.  Real
            // passports use this form instead of returning the shorter window;
            // retrying works there, but some chips also invalidate the SM
            // session after a wrong-length command, hence READ_LE above.
            if ((sw & 0xFF00) == 0x6C00) {
                int exact = sw & 0xFF;
                if (exact == 0) {
                    break;
                }
                r = terminal.readBinary(offset, exact);
                sw = r.getSW();
            }
            // 6B00/6A82: offset beyond the EF; some chips (observed on a PRC
            // passport) answer 6A86 for an offset past the end instead.
            if (sw == 0x6B00 || sw == Sw.FILE_NOT_FOUND
                    || (sw == Sw.INCORRECT_P1P2 && offset > 0)) {
                break;
            }
            if (sw != 0x9000) {
                throw new IllegalStateException("READ BINARY " + String.format("%04X", fid)
                        + " at offset " + offset + " failed: "
                        + Sw.formatWithDescription(sw));
            }
            byte[] data = r.getData();
            if (data.length == 0) {
                break;
            }
            out.write(data, 0, data.length);
            offset += data.length;
            // Do NOT stop on a short chunk: the card caps the window to the
            // active SM profile (231 B for 3DES, 223 B for AES-128, under the
            // requested 256), so only the offset reaching the EF end (0 bytes /
            // 6B00 / 6A82 / 6A86) means the file is complete.
        }
        return out.toByteArray();
    }

    /**
     * Reads a master-file EF (EF.CardAccess 011C, EF.CardSecurity 011D): SELECT
     * MF then SELECT FILE by FID (Doc 9303-10 §3.11.3/§3.11.4).  The eMRTD DF
     * serves a different file for the same FID (EF.CVCA / EF.SOD), so this is
     * only used when the caller actually needs the MF file (PACE/CA), not for a
     * BAC-only document.
     */
    public static byte[] readMf(EmrtdTerminal terminal, int fid) throws Exception {
        ResponseAPDU mf = terminal.selectMf();
        if (mf.getSW() != 0x9000) {
            throw new IllegalStateException("SELECT MF failed: "
                    + Sw.formatWithDescription(mf.getSW()));
        }
        return read(terminal, fid);
    }
}
