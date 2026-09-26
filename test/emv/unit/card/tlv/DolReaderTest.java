package card42.test;

import card42.emv.DolReader;
import card42.host.common.util.Hex;
import card42.host.common.codec.Tags;

/**
 * Pure-JVM tests for the DOL cursor (EMV v4.4 Book 3 §5.4): tag lengths, long
 * BER lengths, the parallel data-offset tracking and malformed definitions.
 */
final class DolReaderTest {

    private DolReaderTest() {
    }

    static void run() {
        System.out.println("DolReader");

        byte[] cdol1 = Hex.parse(
                "9F02 06 9F03 06 9F1A 02 95 05 5F2A 02 9A 03 9C 01 9F37 04");
        DolReader r = new DolReader();

        Asserts.eq(29, r.reset(cdol1, (short) 0, (short) cdol1.length)
                .totalDataLength(), "totalDataLength of CDOL1");
        Asserts.eq(0, r.reset(cdol1, (short) 0, (short) cdol1.length)
                .findValueOffset((short) 0x9F02), "offset of first entry");
        Asserts.eq(14, r.reset(cdol1, (short) 0, (short) cdol1.length)
                .findValueOffset((short) 0x95), "offset of 1-byte-tag entry");
        Asserts.eq(25, r.reset(cdol1, (short) 0, (short) cdol1.length)
                .findValueOffset((short) 0x9F37), "offset of 2-byte-tag entry");
        Asserts.eq(-1, r.reset(cdol1, (short) 0, (short) cdol1.length)
                .findValueOffset((short) 0x1234), "missing tag");

        // Cursor iteration: one entry at a time, tracking the data offset.
        r.reset(cdol1, (short) 0, (short) cdol1.length);
        int entries = 0;
        short lastOffset = -1;
        while (r.hasNext()) {
            r.next();
            lastOffset = r.dataOffset();
            entries++;
        }
        Asserts.eq(8, entries, "CDOL1 entry count");
        Asserts.eq(25, lastOffset, "data offset of the last entry");

        // Long-form BER length (82 01 2C = 300).
        byte[] longDol = Hex.parse("9F02 82 01 2C 95 05");
        Asserts.eq(305, r.reset(longDol, (short) 0, (short) longDol.length)
                .totalDataLength(), "long-form length");

        // A 2-byte tag with a 0x81 length field, and the parallel offset of the
        // entry that follows it.
        byte[] mixed = Hex.parse("9F02 81 06 95 05");
        r.reset(mixed, (short) 0, (short) mixed.length);
        r.next();
        Asserts.eq(0x9F02, r.tag() & 0xFFFF, "2-byte tag");
        Asserts.eq(6, r.valueLength(), "0x81 length field");
        r.next();
        Asserts.eq(6, r.dataOffset(), "parallel data offset after a long entry");

        // Tags longer than 2 bytes are not supported (see TLV): the parser
        // treats the third byte as the length, but never reads out of bounds.
        byte[] threeByteTag = Hex.parse("1F 81 06");
        r.reset(threeByteTag, (short) 0, (short) threeByteTag.length);
        r.next();
        Asserts.eq(0x1F81, r.tag() & 0xFFFF, "3-byte tag read as a 2-byte tag");
        Asserts.eq(6, r.valueLength(), "3-byte tag length field");

        // Malformed definitions abort with 6A80 instead of reading out of range.
        Asserts.sw((short) 0x6A80, () -> r
                .reset(Hex.parse("9F02"), (short) 0, (short) 2)
                .totalDataLength(), "tag without length -> 6A80");
        Asserts.sw((short) 0x6A80, () -> r
                .reset(Hex.parse("9F02 82"), (short) 0, (short) 3)
                .totalDataLength(), "truncated length field -> 6A80");
        Asserts.sw((short) 0x6A80, () -> r
                .reset(Hex.parse("9F"), (short) 0, (short) 1)
                .totalDataLength(), "truncated two-byte tag -> 6A80");

        // A DOL may only list primitive data objects (EMV v4.4 Book 3 §5.4): validate()
        // accepts a primitive list and rejects a constructed tag with 6A80.
        Asserts.eq(29, r.reset(cdol1, (short) 0, (short) cdol1.length)
                .validate(), "primitive DOL validates");
        Asserts.sw((short) 0x6A80, () -> r
                .reset(Hex.parse("70 01 00"), (short) 0, (short) 3)
                .validate(), "constructed 70 in a DOL -> 6A80");
        Asserts.sw((short) 0x6A80, () -> r
                .reset(Hex.parse("9F02 06 A5 01 00"), (short) 0, (short) 6)
                .validate(), "constructed A5 in a DOL -> 6A80");
        Asserts.sw((short) 0x6A80, () -> r
                .reset(Hex.parse("BF0C 01 00"), (short) 0, (short) 4)
                .validate(), "constructed BF0C in a DOL -> 6A80");
        Asserts.check(card42.common.Tlv.isConstructed((short) 0x70), "70 is constructed");
        Asserts.check(!card42.common.Tlv.isConstructed((short) 0x9F02), "9F02 is primitive");
    }
}
