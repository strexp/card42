package card42.test;

import card42.common.Tlv;
import card42.common.TlvReader;
import card42.emv.TlvTags;
import javacard.framework.ISO7816;

/**
 * Pure-JVM tests for the card-side BER-TLV reader/writer.
 *
 * <p>Internal codec coverage: this suite has no EMV/ICAO/BSI/CPS clause and is
 * not counted as spec-derived coverage.
 */
final class TlvTest {

    private TlvTest() {
    }

    static void run() {
        System.out.println("TLV");

        // --- lengthSize -----------------------------------------------------
        Asserts.eq(1, Tlv.lengthSize((short) 0x00), "lengthSize 0");
        Asserts.eq(1, Tlv.lengthSize((short) 0x7F), "lengthSize 127");
        Asserts.eq(2, Tlv.lengthSize((short) 0x80), "lengthSize 128");
        Asserts.eq(2, Tlv.lengthSize((short) 0xFF), "lengthSize 255");
        Asserts.eq(3, Tlv.lengthSize((short) 0x100), "lengthSize 256");

        // --- tags -----------------------------------------------------------
        byte[] b = new byte[8];
        short p = Tlv.appendTag((short) 0x5A, b, (short) 0);
        Asserts.eq(1, p, "appendTag 1-byte returns +1");
        Asserts.eq(0x5A, b[0] & 0xFF, "appendTag 1-byte");
        p = Tlv.appendTag(TlvTags.TAG_EXPIRY_DATE, b, (short) 0);
        Asserts.eq(2, p, "appendTag 2-byte returns +2");
        Asserts.eq(0x5F, b[0] & 0xFF, "appendTag 2-byte hi");
        Asserts.eq(0x24, b[1] & 0xFF, "appendTag 2-byte lo");

        // --- length fields --------------------------------------------------
        byte[] out = new byte[8];
        p = Tlv.appendLength((short) 5, out, (short) 0);
        Asserts.eq(1, p, "appendLength short size");
        Asserts.eq(5, out[0] & 0xFF, "appendLength short");
        p = Tlv.appendLength((short) 200, out, (short) 0);
        Asserts.eq(2, p, "appendLength 0x81 size");
        Asserts.eq(0x81, out[0] & 0xFF, "appendLength 0x81 marker");
        Asserts.eq(200, out[1] & 0xFF, "appendLength 0x81 value");
        p = Tlv.appendLength((short) 300, out, (short) 0);
        Asserts.eq(3, p, "appendLength 0x82 size");
        Asserts.eq(0x82, out[0] & 0xFF, "appendLength 0x82 marker");
        Asserts.eq(300, ((out[1] & 0xFF) << 8) | (out[2] & 0xFF), "appendLength 0x82 value");

        byte[] indefinite = { (byte) 0xFF };
        Asserts.eq(0, Tlv.lengthFieldLength(indefinite, (short) 0),
                "lengthFieldLength indefinite -> 0");

        // --- append + read back (one-byte tag) ------------------------------
        byte[] buf = new byte[32];
        byte[] val = { 0x12, 0x34, 0x56 };
        p = Tlv.append(TlvTags.TAG_PAN, val, (short) 0, (short) 3, buf, (short) 0);
        Asserts.eq(5, p, "append total length");
        Asserts.eq(0x5A, Tlv.getTag(buf, (short) 0), "getTag 1-byte");
        Asserts.eq(1, Tlv.lengthFieldLength(buf, (short) 1), "lengthFieldLength 1");
        Asserts.eq(3, Tlv.getLength(buf, (short) 1), "getLength short");
        Asserts.eq(2, Tlv.valueOffset(buf, (short) 0), "valueOffset 1-byte tag");
        Asserts.eq(5, Tlv.totalLength(buf, (short) 0), "totalLength 1-byte tag");

        // --- append + read back (two-byte tag) ------------------------------
        p = Tlv.append(TlvTags.TAG_EXPIRY_DATE, val, (short) 0, (short) 3, buf, (short) 0);
        Asserts.eq(6, p, "append 2-byte tag total");
        Asserts.eq(0x5F24, Tlv.getTag(buf, (short) 0), "getTag 2-byte");
        Asserts.eq(2, Tlv.tagLength(buf, (short) 0), "tagLength 2-byte");
        Asserts.eq(3, Tlv.valueOffset(buf, (short) 0), "valueOffset 2-byte tag");
        Asserts.eq(6, Tlv.totalLength(buf, (short) 0), "totalLength 2-byte tag");

        // --- FCI wrapper ----------------------------------------------------
        byte[] aid = { 0x45, 0x4D, 0x56, 0x34, 0x32, 0x01 };
        byte[] content = { (byte) 0xBF, 0x0C };
        byte[] fci = new byte[32];
        p = Tlv.appendFci(aid, (short) 0, (short) aid.length,
                content, (short) 0, (short) content.length, fci, (short) 0);
        Asserts.eq(0x6F, Tlv.getTag(fci, (short) 0), "FCI tag");
        Asserts.eq(2 + aid.length + content.length, Tlv.getLength(fci, (short) 1),
                "FCI length");
        Asserts.eq(0x84, Tlv.getTag(fci, (short) 2), "FCI DF name tag");
        Asserts.eq(aid.length, Tlv.getLength(fci, (short) 3), "FCI DF name length");
        Asserts.eq(p, Tlv.totalLength(fci, (short) 0), "FCI totalLength");
        Asserts.bytes(aid, java.util.Arrays.copyOfRange(fci, 4, 4 + aid.length),
                "FCI DF name value");

        // --- TlvReader cursor + long form -----------------------------------
        byte[] seq = new byte[4 + 2 + 2 + 130];
        seq[0] = 0x5A;
        seq[1] = 0x02;
        seq[2] = (byte) 0xAA;
        seq[3] = (byte) 0xBB;
        seq[4] = (byte) 0x9F;
        seq[5] = 0x38;
        seq[6] = (byte) 0x81;
        seq[7] = (byte) 0x82; // 130
        TlvReader reader = new TlvReader(seq, (short) 0, (short) seq.length);
        Asserts.check(reader.hasNext(), "TlvReader hasNext");
        reader.next();
        Asserts.eq(0x5A, reader.tag(), "TlvReader tag 1");
        Asserts.eq(2, reader.valueOffset(), "TlvReader valueOffset 1");
        Asserts.eq(2, reader.valueLength(), "TlvReader valueLength 1");
        reader.next();
        Asserts.eq(0x9F38, reader.tag() & 0xFFFF, "TlvReader tag 2");
        Asserts.eq(8, reader.valueOffset(), "TlvReader valueOffset 2 (long form)");
        Asserts.eq(130, reader.valueLength(), "TlvReader valueLength 2 (long form)");
        Asserts.check(!reader.hasNext(), "TlvReader exhausted");

        // --- TlvReader rejects a truncated TLV ------------------------------
        byte[] truncated = { 0x5A, 0x05, 0x00 };
        final TlvReader bad = new TlvReader(truncated, (short) 0, (short) truncated.length);
        Asserts.sw(ISO7816.SW_WRONG_DATA, () -> bad.next(),
                "TlvReader truncated -> 6A80");
    }
}
