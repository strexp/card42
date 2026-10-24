package card42.test;

import java.io.ByteArrayOutputStream;
import card42.host.common.util.Hex;
import card42.host.common.codec.Tags;
import card42.host.common.codec.TlvWriter;

/**
 * Pure-JVM tests for the host-side BER-TLV finder: nested constructed
 * templates (6F/A5/BF0C/61), long-form lengths and a missing tag.  It must
 * agree with the card-side TLV reader.
 *
 * <p>Internal codec coverage: this suite has no EMV/ICAO/BSI/CPS clause and is
 * not counted as spec-derived coverage.
 */
final class TagsTest {

    private TagsTest() {
    }

    static void run() throws Exception {
        System.out.println("Tags.find");

        // 6F { 84, A5 { BF0C { 61 { 4F, 50, 87 } } } }, the PPSE shape.
        ByteArrayOutputStream entry = new ByteArrayOutputStream();
        TlvWriter.writeTlv(entry, 0x4F, Hex.parse("43415244420101"));
        TlvWriter.writeTlv(entry, 0x50, "card42".getBytes("US-ASCII"));
        TlvWriter.writeTlv(entry, 0x87, new byte[] { 0x01 });

        ByteArrayOutputStream bf0c = new ByteArrayOutputStream();
        TlvWriter.writeTlv(bf0c, 0x61, entry.toByteArray());

        ByteArrayOutputStream a5 = new ByteArrayOutputStream();
        TlvWriter.writeTlv(a5, 0xBF0C, bf0c.toByteArray());

        ByteArrayOutputStream body = new ByteArrayOutputStream();
        TlvWriter.writeTlv(body, 0x84, Hex.parse("325041592E5359532E4444463031"));
        body.write(a5.toByteArray());

        ByteArrayOutputStream sixf = new ByteArrayOutputStream();
        TlvWriter.writeTlv(sixf, 0x6F, body.toByteArray());
        byte[] fci = sixf.toByteArray();

        Asserts.bytes(Hex.parse("43415244420101"), Tags.find(fci, 0x4F),
                "nested 4F");
        Asserts.eq("card42", new String(Tags.find(fci, 0x50), "US-ASCII"),
                "nested 50");
        Asserts.bytes(new byte[] { 0x01 }, Tags.find(fci, 0x87), "nested 87");
        Asserts.check(Tags.find(fci, 0x61) != null, "nested 61");
        Asserts.bytes(Hex.parse("325041592E5359532E4444463031"),
                Tags.find(fci, 0x84), "top-level 84");
        Asserts.check(Tags.find(fci, 0x99) == null, "missing tag -> null");

        // Long-form (0x81) value length.
        byte[] longValue = new byte[200];
        for (int i = 0; i < longValue.length; i++) {
            longValue[i] = (byte) i;
        }
        ByteArrayOutputStream longOut = new ByteArrayOutputStream();
        TlvWriter.writeTlv(longOut, 0x9F38, longValue);
        byte[] found = Tags.find(longOut.toByteArray(), 0x9F38);
        Asserts.eq(200, found.length, "long-form value length");
        Asserts.bytes(longValue, found, "long-form value content");

        // DOL well-formedness is a structural check of the reader.
        Asserts.check(Tags.isWellFormedDol(Hex.parse("9F02 06 9F4E 04")),
                "a well-formed Log Format is accepted");
        Asserts.check(!Tags.isWellFormedDol(Hex.parse("9F02")),
                "a truncated Log Format is malformed");
    }
}
