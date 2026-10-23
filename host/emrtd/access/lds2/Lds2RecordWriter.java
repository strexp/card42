package card42.host.emrtd.access.lds2;

import java.io.ByteArrayOutputStream;

import javax.smartcardio.ResponseAPDU;

import card42.host.common.codec.DerWriter;
import card42.host.common.util.Sw;
import card42.host.emrtd.lds.common.LdsFileUtil;
import card42.host.emrtd.transport.EmrtdTerminal;

/**
 * Writes a pre-built LDS2 record.  Travel/Visa/Certificates use APPEND RECORD
 * (Doc 9303-10 §3.7.1); Additional Biometrics uses UPDATE BINARY and ACTIVATE
 * (Doc 9303-10 §3.8).  The caller must already have selected the LDS2
 * application and established PACE (+ Terminal Authentication with the append
 * authorization bit).
 */
public final class Lds2RecordWriter {

    /** LDS2 command data is kept below the SM short-APDU window (256 B). */
    private static final int BIOMETRICS_CHUNK = 200;

    private Lds2RecordWriter() {
    }

    public static void append(EmrtdTerminal terminal, int fid, byte[] record)
            throws Exception {
        ResponseAPDU response = terminal.appendRecord(LdsFileUtil.sfi(fid), record);
        if (response.getSW() != 0x9000) {
            throw new IllegalStateException("APPEND RECORD " + String.format("%04X", fid)
                    + " failed: " + Sw.format(response.getSW()));
        }
    }

    /**
     * Writes (and then ACTIVATEs) an Additional Biometrics EF.  The record is
     * usually a {@code 7F2E { 5F2E, 5F37, 5F38 }} envelope from
     * {@link card42.host.emrtd.lds.lds2.BiometricsRecordBuilder}.
     */
    public static void writeBiometrics(EmrtdTerminal terminal, int fid, byte[] record)
            throws Exception {
        ResponseAPDU selected = terminal.selectFile(fid);
        if (selected.getSW() != 0x9000) {
            throw new IllegalStateException("SELECT FILE " + String.format("%04X", fid)
                    + " failed: " + Sw.format(selected.getSW()));
        }
        for (int offset = 0; offset < record.length; offset += BIOMETRICS_CHUNK) {
            int length = Math.min(BIOMETRICS_CHUNK, record.length - offset);
            ByteArrayOutputStream data = new ByteArrayOutputStream();
            data.write(DerWriter.tlv(0x54, unsigned(offset)));
            data.write(DerWriter.tlv(0x53, java.util.Arrays.copyOfRange(
                    record, offset, offset + length)));
            if (offset == 0) {
                data.write(DerWriter.tlv(0xC0, unsigned(record.length)));
            }
            ResponseAPDU response = offset == 0
                    ? terminal.updateBinaryWithSize(data.toByteArray())
                    : terminal.updateBinary(data.toByteArray());
            if (response.getSW() != 0x9000) {
                throw new IllegalStateException("UPDATE BINARY " + String.format("%04X", fid)
                        + " @" + offset + " failed: " + Sw.format(response.getSW()));
            }
        }
        ResponseAPDU activated = terminal.activate();
        if (activated.getSW() != 0x9000) {
            throw new IllegalStateException("ACTIVATE " + String.format("%04X", fid)
                    + " failed: " + Sw.format(activated.getSW()));
        }
    }

    private static byte[] unsigned(int value) {
        if (value <= 0xFF) {
            return new byte[] { (byte) value };
        }
        return new byte[] { (byte) (value >> 8), (byte) value };
    }
}
