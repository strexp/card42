package card42.host.emrtd.lds;

import java.io.ByteArrayOutputStream;

import javax.smartcardio.ResponseAPDU;

import card42.host.emrtd.transport.EmrtdTerminal;

/**
 * Reads one LDS1 elementary file: SELECT FILE then chunked READ BINARY
 * (H0.3).  The chunk size keeps the SM-wrapped response inside the card's
 * 256-byte APDU buffer.
 */
public final class LdsReader {

    /** Maximum READ BINARY length; the SM wrapper adds ~25 bytes of overhead. */
    public static final int CHUNK = 0xE7;

    private LdsReader() {
    }

    /**
     * READ RECORD one record of the selected LDS2 record EF (Doc 9303-10 §3.7).
     * The record EF is addressed by its short EF identifier.
     */
    public static byte[] readRecord(EmrtdTerminal terminal, int sfi, int number)
            throws Exception {
        ResponseAPDU r = terminal.readRecord(sfi, number, false, CHUNK);
        if (r.getSW() != 0x9000) {
            throw new IllegalStateException("READ RECORD " + Integer.toHexString(sfi)
                    + "/" + number + " failed: " + Integer.toHexString(r.getSW()));
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
            ResponseAPDU r = terminal.readRecord(sfi, number, false, CHUNK);
            if (r.getSW() == 0x6A83) {
                break;
            }
            if (r.getSW() != 0x9000) {
                throw new IllegalStateException("READ RECORD " + number + " failed: "
                        + Integer.toHexString(r.getSW()));
            }
            out.add(r.getData());
        }
        return out;
    }

    /** Selects the EF and reads it whole, concatenating the chunks. */
    public static byte[] read(EmrtdTerminal terminal, int fid) throws Exception {
        ResponseAPDU selected = terminal.selectFile(fid);
        if (selected.getSW() != 0x9000) {
            throw new IllegalStateException("SELECT FILE " + Integer.toHexString(fid)
                    + " failed: " + Integer.toHexString(selected.getSW()));
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
                        + Integer.toHexString(sw));
            }
            byte[] data = r.getData();
            if (data.length == 0) {
                break;
            }
            out.write(data, 0, data.length);
            offset += data.length;
            if (data.length < CHUNK) {
                break;
            }
        }
        return out.toByteArray();
    }
}
