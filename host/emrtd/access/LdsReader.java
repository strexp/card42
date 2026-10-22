package card42.host.emrtd.access;

import java.io.ByteArrayOutputStream;

import javax.smartcardio.ResponseAPDU;

import card42.host.common.util.Sw;
import card42.host.emrtd.transport.EmrtdTerminal;

/**
 * Reads one LDS1 elementary file: SELECT FILE then chunked READ BINARY
 * (H0.3).  The chunk size keeps the SM-wrapped response inside the card's
 * 256-byte APDU buffer.
 */
public final class LdsReader {

    /** Maximum READ BINARY length; the SM wrapper adds ~25 bytes of overhead. */
    public static final int CHUNK = 0xE7;

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
                    + " failed: " + Sw.format(selected.getSW()));
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int offset = 0;
        while (true) {
            ResponseAPDU r = terminal.readBinary(offset, CHUNK);
            int sw = r.getSW();
            // 6CXX: wrong Le, the card reports the exact remaining length.  Real
            // passports use this instead of returning the shorter window.
            if ((sw & 0xFF00) == 0x6C00) {
                int exact = sw & 0xFF;
                r = terminal.readBinary(offset, exact == 0 ? 256 : exact);
                sw = r.getSW();
            }
            if (sw == 0x6B00 || sw == 0x6A82) {
                break; // offset beyond the end of the EF
            }
            if (sw != 0x9000) {
                throw new IllegalStateException("READ BINARY failed: "
                        + Sw.format(sw));
            }
            byte[] data = r.getData();
            if (data.length == 0) {
                break;
            }
            out.write(data, 0, data.length);
            offset += data.length;
            // Do NOT stop on a short chunk: the card caps a window to the active
            // SM profile (AES returns at most 223 B, under the requested 0xE7),
            // so only the offset reaching the EF end (0 bytes / 6B00 / 6A82)
            // means the file is complete.
        }
        return out.toByteArray();
    }

    /**
     * Reads a master-file EF (EF.CardAccess 011C, EF.CardSecurity 011D): SELECT
     * MF then SELECT FILE by FID (Doc 9303-10 §3.11.3/§3.11.4).  The eMRTD DF
     * serves a different file for the same FID (EF.CVCA / EF.SOD).
     */
    public static byte[] readMf(EmrtdTerminal terminal, int fid) throws Exception {
        ResponseAPDU mf = terminal.selectMf();
        if (mf.getSW() != 0x9000) {
            throw new IllegalStateException("SELECT MF failed: " + Sw.format(mf.getSW()));
        }
        return read(terminal, fid);
    }
}
