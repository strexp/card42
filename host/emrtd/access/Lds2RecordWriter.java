package card42.host.emrtd.access;

import javax.smartcardio.ResponseAPDU;

import card42.host.common.util.Sw;
import card42.host.emrtd.lds.LdsFileUtil;
import card42.host.emrtd.transport.EmrtdTerminal;

/**
 * Appends a pre-built LDS2 record with APPEND RECORD (Doc 9303-10 §3.7.1).
 * The caller must already have selected the LDS2 application and established
 * PACE (+ Terminal Authentication with the append authorization bit); this
 * helper only translates the FID to its short EF identifier and checks the
 * status word.
 */
public final class Lds2RecordWriter {

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
}
