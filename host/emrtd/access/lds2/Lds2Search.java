package card42.host.emrtd.access.lds2;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.smartcardio.ResponseAPDU;

import card42.host.common.codec.DerWriter;
import card42.host.common.codec.TlvCursor;
import card42.host.common.util.Sw;
import card42.host.emrtd.transport.EmrtdTerminal;

/**
 * SEARCH RECORD (Doc 9303-10 §3.7.3, Table 14/15/16/17).
 *
 * <p>The command data field is a Record handling DO'7F76' carrying a file
 * reference DO'51', a search configuration template DO'A1' (search parameter
 * DO'80' and optional window DO'B0') and a search string template DO'A3'
 * (DO'B1' containing the string DO'81').  The response is DO'7F76' with the
 * referenced file DO'51' and one DO'02' per matching record number; no match
 * is the warning status '6282'.
 */
public final class Lds2Search {

    private Lds2Search() {
    }

    /**
     * Builds the SEARCH RECORD command data for a two-byte file identifier
     * (DO'51' length 2, Table 25).
     *
     * @param offset       window start within each record (DO'02' in DO'B0')
     * @param windowLength window size; 0 means "all bytes from offset" (Note 2)
     * @param stopFirst    true for search termination '30' (first match only)
     */
    public static byte[] command(int fid, int offset, int windowLength, byte[] needle,
                                 boolean stopFirst) {
        return command(DerWriter.tlv(0x51,
                        new byte[] { (byte) (fid >> 8), (byte) fid }),
                offset, windowLength, needle, stopFirst);
    }

    /**
     * Builds the SEARCH RECORD command data for a one-byte short EF identifier
     * (DO'51' length 1).  Appendix I.1/J.1 use the raw identifier ('01'/'1A');
     * the card also accepts the shifted form.
     */
    public static byte[] commandSfi(int sfi, int offset, int windowLength, byte[] needle,
                                    boolean stopFirst) {
        return command(DerWriter.tlv(0x51, new byte[] { (byte) sfi }),
                offset, windowLength, needle, stopFirst);
    }

    private static byte[] command(byte[] fileReference, int offset, int windowLength,
                                  byte[] needle, boolean stopFirst) {
        if (needle == null || needle.length == 0) {
            throw new IllegalArgumentException("SEARCH RECORD needs a non-empty search string");
        }
        byte[] window = DerWriter.concat(DerWriter.integer(offset),
                DerWriter.integer(windowLength));
        byte[] configuration = DerWriter.concat(
                DerWriter.tlv(0x80, new byte[] { (byte) (stopFirst ? 0x30 : 0x00) }),
                DerWriter.tlv(0xB0, window));
        byte[] searchString = DerWriter.tlv(0xA3,
                DerWriter.tlv(0xB1, DerWriter.tlv(0x81, needle)));
        return DerWriter.tlv(0x7F76, DerWriter.concat(
                fileReference,
                DerWriter.tlv(0xA1, configuration),
                searchString));
    }

    /** Searches one EF addressed by a two-byte file identifier. */
    public static List<Integer> search(EmrtdTerminal terminal, int fid, int offset,
                                       int windowLength, byte[] needle, boolean stopFirst)
            throws Exception {
        return send(terminal, command(fid, offset, windowLength, needle, stopFirst));
    }

    /** Searches one EF addressed by a one-byte short EF identifier (raw form). */
    public static List<Integer> searchSfi(EmrtdTerminal terminal, int sfi, int offset,
                                          int windowLength, byte[] needle, boolean stopFirst)
            throws Exception {
        return send(terminal, commandSfi(sfi, offset, windowLength, needle, stopFirst));
    }

    private static List<Integer> send(EmrtdTerminal terminal, byte[] command) throws Exception {
        ResponseAPDU response = terminal.searchRecord(command);
        if (response.getSW() == 0x6282) {
            return Collections.emptyList();
        }
        if (response.getSW() != 0x9000) {
            throw new IllegalStateException("SEARCH RECORD -> " + Sw.format(response.getSW()));
        }
        return parse(response.getData());
    }

    /** Extracts the DO'02' record numbers from the DO'7F76' response. */
    public static List<Integer> parse(byte[] response) {
        List<Integer> records = new ArrayList<Integer>();
        TlvCursor cursor = new TlvCursor(response);
        while (cursor.next() == TlvCursor.Status.OK) {
            if (cursor.tag() != 0x7F76) {
                continue;
            }
            TlvCursor fields = cursor.child();
            while (fields.next() == TlvCursor.Status.OK) {
                if (fields.tag() == 0x02) {
                    byte[] value = fields.value();
                    int number = 0;
                    for (byte b : value) {
                        number = (number << 8) | (b & 0xFF);
                    }
                    records.add(number);
                }
            }
        }
        return records;
    }
}
