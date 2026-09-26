package card42.test;

import card42.emv.Dgi;
import card42.emv.DgiReader;
import javacard.framework.ISO7816;

/** Pure-JVM tests for the card-side DGI reader (docs/specs/common/toolchain.md §6). */
final class DgiTest {

    private DgiTest() {
    }

    static void run() {
        System.out.println("DGI");

        // --- single-byte EMV CPS v2.0 length (0x00-0xFE) -----------------------------
        byte[] buf = new byte[8];
        buf[0] = (byte) 0xE0;
        buf[1] = 0x01;
        buf[2] = 0x03;
        buf[3] = 0x11;
        buf[4] = 0x22;
        buf[5] = 0x33;
        Asserts.eq(0xE001, Dgi.getDgi(buf, (short) 0) & 0xFFFF, "getDgi");
        Asserts.eq(1, Dgi.lengthFieldLength(buf, (short) 0), "lengthFieldLength short");
        Asserts.eq(3, Dgi.getValueLength(buf, (short) 0), "getValueLength short");
        Asserts.eq(3, Dgi.valueOffset(buf, (short) 0), "valueOffset short");
        Asserts.eq(6, Dgi.totalLength(buf, (short) 0), "totalLength short");

        // A length of 0xFE is still a single byte under the EMV CPS v2.0 encoding.
        byte[] fe = new byte[3];
        fe[0] = 0x01;
        fe[1] = 0x02;
        fe[2] = (byte) 0xFE;
        Asserts.eq(1, Dgi.lengthFieldLength(fe, (short) 0), "lengthFieldLength 0xFE");
        Asserts.eq(0xFE, Dgi.getValueLength(fe, (short) 0), "getValueLength 0xFE");

        // --- 'FF' + 2-byte EMV CPS v2.0 long form ------------------------------------
        byte[] big = new byte[160];
        big[0] = (byte) 0x91;
        big[1] = 0x02;
        big[2] = (byte) 0xFF;
        big[3] = 0x00;
        big[4] = (byte) 0x85; // 133
        Asserts.eq(3, Dgi.lengthFieldLength(big, (short) 0), "lengthFieldLength 0xFF");
        Asserts.eq(133, Dgi.getValueLength(big, (short) 0), "getValueLength 0xFF");
        Asserts.eq(5, Dgi.valueOffset(big, (short) 0), "valueOffset 0xFF");
        Asserts.eq(138, Dgi.totalLength(big, (short) 0), "totalLength 0xFF");

        // --- DgiReader over two containers, second in 0xFF long form --------
        byte[] seq = new byte[10 + 300];
        seq[0] = 0x01;
        seq[1] = 0x02;
        seq[2] = 0x02;
        seq[3] = (byte) 0xAA;
        seq[4] = (byte) 0xBB;
        seq[5] = (byte) 0x91;
        seq[6] = 0x04;
        seq[7] = (byte) 0xFF;
        seq[8] = 0x01;
        seq[9] = 0x2C; // 300
        DgiReader reader = new DgiReader(seq, (short) 0, (short) seq.length);
        Asserts.check(reader.hasNext(), "DgiReader hasNext");
        reader.next();
        Asserts.eq(0x0102, reader.dgi(), "DgiReader dgi 1");
        Asserts.eq(3, reader.valueOffset(), "DgiReader valueOffset 1");
        Asserts.eq(2, reader.valueLength(), "DgiReader valueLength 1");
        reader.next();
        Asserts.eq(0x9104, reader.dgi() & 0xFFFF, "DgiReader dgi 2");
        Asserts.eq(10, reader.valueOffset(), "DgiReader valueOffset 2");
        Asserts.eq(300, reader.valueLength(), "DgiReader valueLength 2 (0xFF)");
        Asserts.check(!reader.hasNext(), "DgiReader exhausted");

        // --- DgiReader rejects a truncated container ------------------------
        byte[] truncated = { (byte) 0xE0, 0x01, 0x05, 0x00 };
        final DgiReader bad = new DgiReader(truncated, (short) 0, (short) truncated.length);
        Asserts.sw(ISO7816.SW_WRONG_DATA, () -> bad.next(),
                "DgiReader truncated -> 6A80");

        // A truncated 'FF' length field is rejected rather than over-read.
        byte[] shortFf = { 0x01, 0x02, (byte) 0xFF, 0x01 };
        final DgiReader badFf = new DgiReader(shortFf, (short) 0, (short) shortFf.length);
        Asserts.sw(ISO7816.SW_WRONG_DATA, () -> badFf.next(),
                "DgiReader truncated 0xFF -> 6A80");

        // --- CPS length encoding, not BER (EMV CPS v2.0 §3.2) ---------------
        // A value of length 0xFF must use the 3-byte EMV CPS v2.0 form 'FF 00 FF'; the
        // reader must not treat a lone 0xFF byte as a BER long form marker.
        byte[] maxShort = new byte[2 + 3 + 255];
        maxShort[0] = (byte) 0x91;
        maxShort[1] = 0x02;
        maxShort[2] = (byte) 0xFF;
        maxShort[3] = 0x00;
        maxShort[4] = (byte) 0xFF;
        Asserts.eq(3, Dgi.lengthFieldLength(maxShort, (short) 0), "lengthFieldLength 0xFF value");
        Asserts.eq(255, Dgi.getValueLength(maxShort, (short) 0), "getValueLength 0xFF value");
        Asserts.eq(260, Dgi.totalLength(maxShort, (short) 0), "totalLength 0xFF value");
        DgiReader maxReader = new DgiReader(maxShort, (short) 0, (short) maxShort.length);
        maxReader.next();
        Asserts.eq(0x9102, maxReader.dgi() & 0xFFFF, "DgiReader 0xFF value dgi");
        Asserts.eq(255, maxReader.valueLength(), "DgiReader 0xFF value length");
        Asserts.check(!maxReader.hasNext(), "DgiReader 0xFF value exhausted");

        // A zero-length value is a valid container (DGI || 0x00).
        byte[] empty = { (byte) 0xE0, 0x01, 0x00 };
        DgiReader emptyReader = new DgiReader(empty, (short) 0, (short) empty.length);
        Asserts.check(emptyReader.hasNext(), "DgiReader empty hasNext");
        emptyReader.next();
        Asserts.eq(0xE001, emptyReader.dgi() & 0xFFFF, "DgiReader empty dgi");
        Asserts.eq(0, emptyReader.valueLength(), "DgiReader empty length");
        Asserts.check(!emptyReader.hasNext(), "DgiReader empty exhausted");
    }
}
