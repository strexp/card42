package card42.host.emrtd.access.lds2;

import javax.smartcardio.ResponseAPDU;

import card42.host.common.codec.DerWriter;
import card42.host.common.codec.TlvCursor;
import card42.host.common.util.Sw;
import card42.host.emrtd.transport.EmrtdTerminal;

/**
 * FILE AND MEMORY MANAGEMENT (Doc 9303-10 §3.8.3, Table 22/23/24/25/26/27).
 *
 * <p>FMM is the proprietary LDS2 query used before writing: P2 bit 1 asks for
 * the total number of bytes, bit 2 for the remaining record count (record EFs
 * only) and bit 3 for the existing record count.  P1 selects the current EF
 * ('00') or carries a file reference DO'51' ('01').
 */
public final class Lds2Fmm {

    /** P2 bit map (Doc 9303-10 Table 24). */
    public static final int TOTAL_BYTES = 0x01;
    public static final int REMAINING_RECORDS = 0x02;
    public static final int EXISTING_RECORDS = 0x04;
    public static final int ALL = TOTAL_BYTES | REMAINING_RECORDS | EXISTING_RECORDS;

    /** The DO'81'/DO'82'/DO'83' values; -1 when the response omits that DO. */
    public static final class Info {
        public final int totalBytes;
        public final int remainingRecords;
        public final int existingRecords;

        Info(int totalBytes, int remainingRecords, int existingRecords) {
            this.totalBytes = totalBytes;
            this.remainingRecords = remainingRecords;
            this.existingRecords = existingRecords;
        }

        @Override
        public String toString() {
            return "FMM[total=" + totalBytes + ", remaining=" + remainingRecords
                    + ", existing=" + existingRecords + "]";
        }
    }

    private Lds2Fmm() {
    }

    /** Queries the current EF (P1='00', no data field). */
    public static Info queryCurrent(EmrtdTerminal terminal, int p2) throws Exception {
        return send(terminal, 0x00, p2, new byte[0]);
    }

    /** Queries an EF by two-byte file identifier (P1='01', DO'51' length 2). */
    public static Info query(EmrtdTerminal terminal, int fid, int p2) throws Exception {
        return send(terminal, 0x01, p2, DerWriter.tlv(0x51,
                new byte[] { (byte) (fid >> 8), (byte) fid }));
    }

    /**
     * Queries an EF by one-byte short EF identifier (P1='01', DO'51' length 1).
     * Table 25 encodes the identifier in bits b8..b4, so the raw SFI is shifted
     * left by three (SFI 1 = '08').
     */
    public static Info querySfi(EmrtdTerminal terminal, int sfi, int p2) throws Exception {
        return send(terminal, 0x01, p2, DerWriter.tlv(0x51,
                new byte[] { (byte) (sfi << 3) }));
    }

    private static Info send(EmrtdTerminal terminal, int p1, int p2, byte[] data)
            throws Exception {
        ResponseAPDU response = terminal.fileMemoryManagement(p1, p2, data);
        if (response.getSW() != 0x9000) {
            throw new IllegalStateException("FMM P1=" + p1 + " P2=" + p2 + " -> "
                    + Sw.format(response.getSW()));
        }
        return parse(response.getData());
    }

    /** Parses the DO'7F78' response into its DO'81'/DO'82'/DO'83' values. */
    public static Info parse(byte[] response) {
        int total = -1;
        int remaining = -1;
        int existing = -1;
        TlvCursor cursor = new TlvCursor(response);
        while (cursor.next() == TlvCursor.Status.OK) {
            if (cursor.tag() != 0x7F78) {
                continue;
            }
            TlvCursor fields = cursor.child();
            while (fields.next() == TlvCursor.Status.OK) {
                int value = number(fields.value());
                if (fields.tag() == 0x81) {
                    total = value;
                } else if (fields.tag() == 0x82) {
                    remaining = value;
                } else if (fields.tag() == 0x83) {
                    existing = value;
                }
            }
        }
        return new Info(total, remaining, existing);
    }

    private static int number(byte[] value) {
        int result = 0;
        for (byte b : value) {
            result = (result << 8) | (b & 0xFF);
        }
        return result;
    }
}
