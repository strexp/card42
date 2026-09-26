package card42.test;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileWriter;
import java.io.Writer;
import java.util.List;
import card42.host.emv.crypto.EmvKeys;
import card42.host.common.util.Hex;
import card42.host.emv.app.perso.PersoExporter;
import card42.host.emv.app.perso.PersoScript;
import card42.host.emv.app.perso.SdaKeyProfile;
import card42.host.emv.oda.SdaKeys;
import card42.host.common.codec.Tags;
import card42.host.common.codec.TlvWriter;

/** Pure-JVM tests for the host-side personalization script codec.
 *
 * <p>Tool coverage of the project script format (docs/specs/common/toolchain.md §6),
 * not an EMV/ICAO/BSI/CPS clause.
 */
final class PersoScriptTest {

    private PersoScriptTest() {
    }

    static void run() throws Exception {
        System.out.println("PersoScript");

        // --- hex / bcd ------------------------------------------------------
        Asserts.bytes(new byte[] { 0x12, (byte) 0xAB }, Hex.parse("12 ab"),
                "hex parses separators");
        Asserts.eq("12AB", Hex.format(new byte[] { 0x12, (byte) 0xAB }),
                "hex formats upper-case");
        Asserts.bytes(new byte[] { 0x12, 0x34 }, Hex.bcd("1234"), "bcd even");
        Asserts.bytes(new byte[] { 0x12, 0x34, 0x5F }, Hex.bcd("12345"),
                "bcd odd pads with F");

        // --- parseValue -----------------------------------------------------
        Asserts.bytes(new byte[] { 0x5A, 0x02, 0x41, 0x42 },
                PersoScript.parseValue("5A 02 \"AB\""), "parseValue hex + quoted ascii");

        // --- writeTlv -------------------------------------------------------
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        TlvWriter.writeTlv(out, 0x8F, new byte[] { 0x01 });
        Asserts.bytes(new byte[] { (byte) 0x8F, 0x01, 0x01 }, out.toByteArray(),
                "writeTlv short form");
        out.reset();
        byte[] big = new byte[200];
        TlvWriter.writeTlv(out, 0x9F32, big);
        byte[] enc = out.toByteArray();
        Asserts.eq(0x9F, enc[0] & 0xFF, "writeTlv 2-byte tag hi");
        Asserts.eq(0x32, enc[1] & 0xFF, "writeTlv 2-byte tag lo");
        Asserts.eq(0x81, enc[2] & 0xFF, "writeTlv 0x81 length marker");
        Asserts.eq(200, enc[3] & 0xFF, "writeTlv 0x81 length value");
        Asserts.eq(204, enc.length, "writeTlv total length");

        // --- writeDgi / dgi -------------------------------------------------
        out.reset();
        TlvWriter.writeDgi(out, 0xE001, new byte[] { 0x01, 0x02 });
        Asserts.bytes(new byte[] { (byte) 0xE0, 0x01, 0x02, 0x01, 0x02 },
                out.toByteArray(), "writeDgi");
        Asserts.bytes(new byte[] { (byte) 0xE0, 0x01, 0x02, 0x01, 0x02 },
                TlvWriter.dgi(0xE001, new byte[] { 0x01, 0x02 }), "dgi helper");
        // --- chunk ----------------------------------------------------------
        List<byte[]> chunks = PersoScript.chunk(new byte[10], 4);
        Asserts.eq(3, chunks.size(), "chunk count");
        Asserts.eq(4, chunks.get(0).length, "chunk 0 length");
        Asserts.eq(2, chunks.get(2).length, "chunk 2 length");

        // --- parse a script file --------------------------------------------
        File file = File.createTempFile("card42-unit", ".perso");
        file.deleteOnExit();
        try (Writer w = new FileWriter(file)) {
            w.write("# comment\n");
            w.write("@instance 43415244420101\n");
            w.write("@record sfi=1 rec=1\n");
            w.write("70 05 5A 03 12 34 56\n");
            w.write("@no-complete\n");
        }
        PersoScript script = PersoScript.parse(file.getPath());
        Asserts.eq(1, script.entries.size(), "parsed entry count");
        PersoScript.Entry entry = script.entries.get(0);
        Asserts.eq("43415244420101", entry.aid, "parsed aid");
        Asserts.bytes(new byte[] { 0x01, 0x01, 0x07,
                        0x70, 0x05, 0x5A, 0x03, 0x12, 0x34, 0x56 },
                PersoScript.sequence(entry), "sequence of @no-complete entry");

        // --- PersoExporter (make card-emv-perso) ----------------------------------
        // One "<AID> <DGI-sequence-hex>" line per instance, consumed by the
        // `make card-emv-perso` target (docs/specs/common/toolchain.md §5).
        List<String> exported = PersoExporter.lines(script);
        Asserts.eq(1, exported.size(), "export line count");
        Asserts.eq("43415244420101 01010770055A03123456", exported.get(0),
                "export line AID + hex sequence");

        // --- DGI CPS length encoding (EMV CPS v2.0 §3.2) --------------------
        byte[] dgi200 = TlvWriter.dgi(0xE001, new byte[200]);
        Asserts.eq(0xC8, dgi200[2] & 0xFF, "DGI 200 byte single-byte length");
        Asserts.eq(203, dgi200.length, "DGI 200 byte total length");
        byte[] dgi300 = TlvWriter.dgi(0xE001, new byte[300]);
        Asserts.eq(0xFF, dgi300[2] & 0xFF, "DGI 300 byte length marker");
        Asserts.eq(300, ((dgi300[3] & 0xFF) << 8) | (dgi300[4] & 0xFF),
                "DGI 300 byte length");
        Asserts.eq(305, dgi300.length, "DGI 300 byte total length");

        // --- DFxx pseudo-tag mapping ----------------------------------------
        File pseudo = writeTemp("@instance 43415244420101\nDF21 0102030405060708\n");
        PersoScript pseudoScript = PersoScript.parse(pseudo.getPath());
        Asserts.bytes(Hex.parse("0102030405060708"),
                pseudoScript.entries.get(0).dgis.get(0x8000), "DF21 maps to 8000");
        Asserts.check(pseudoScript.entries.get(0).dgis.get(0x3001) == null,
                "DFxx line is not also added to 3001");

        // --- @sda emits records 2-5 and the EMV CPS v2.0 key parts --------------------
        File sda = writeTemp("@instance 43415244420101\n"
                + "@record sfi=1 rec=1\n"
                + "70 0D 5A 05 12 34 56 78 90 5F24 03 29 12 31\n"
                + "@sda\n");
        PersoScript sdaScript = PersoScript.parse(sda.getPath(), TestKeys.sdaKeys());
        PersoScript.Entry sdaEntry = sdaScript.entries.get(0);
        byte[] record2 = sdaEntry.dgis.get(0x0102);
        byte[] record3 = sdaEntry.dgis.get(0x0103);
        byte[] record4 = sdaEntry.dgis.get(0x0104);
        byte[] record5 = sdaEntry.dgis.get(0x0105);
        Asserts.check(record2 != null
                && Tags.find(record2, 0x8F) != null
                && Tags.find(record2, 0x90) != null
                && Tags.find(record2, 0x92) != null
                && Tags.find(record2, 0x9F32) != null
                && record3 != null && Tags.find(record3, 0x93) != null
                && record4 != null
                && Tags.find(record4, 0x9F2D) != null
                && Tags.find(record4, 0x9F2F) != null
                && Tags.find(record4, 0x9F2E) != null
                && record5 != null
                && Tags.find(record5, 0x9F46) != null
                && Tags.find(record5, 0x9F48) != null
                && Tags.find(record5, 0x9F47) != null,
                "@sda emits records 2-5");
        Asserts.check(sdaEntry.dgis.get(0x8103) != null
                && sdaEntry.dgis.get(0x8101) != null
                && sdaEntry.dgis.get(0x8104) != null
                && sdaEntry.dgis.get(0x8102) != null,
                "@sda emits the CPS DDA/PIN key parts");

        // --- @sda token selection (records / dda / pin) ---------------------
        File sdaPin = writeTemp("@instance 43415244420101\n"
                + "@record sfi=1 rec=1\n"
                + "70 0D 5A 05 12 34 56 78 90 5F24 03 29 12 31\n"
                + "@sda records pin\n");
        PersoScript.Entry sdaPinEntry = PersoScript.parse(sdaPin.getPath(), TestKeys.sdaKeys())
                .entries.get(0);
        Asserts.check(sdaPinEntry.dgis.get(0x0102) != null
                && sdaPinEntry.dgis.get(0x8104) != null
                && sdaPinEntry.dgis.get(0x8102) != null,
                "@sda records pin emits records and the PIN key");
        Asserts.check(sdaPinEntry.dgis.get(0x8103) == null
                && sdaPinEntry.dgis.get(0x8101) == null,
                "@sda records pin omits the DDA key");

        File sdaRecords = writeTemp("@instance 43415244420101\n"
                + "@record sfi=1 rec=1\n"
                + "70 0D 5A 05 12 34 56 78 90 5F24 03 29 12 31\n"
                + "@sda records\n");
        PersoScript.Entry sdaRecordsEntry = PersoScript.parse(sdaRecords.getPath(),
                TestKeys.sdaKeys()).entries.get(0);
        Asserts.check(sdaRecordsEntry.dgis.get(0x0102) != null
                && sdaRecordsEntry.dgis.get(0x8101) == null
                && sdaRecordsEntry.dgis.get(0x8102) == null,
                "@sda records emits only the records");

        final File sdaBogus = writeTemp("@instance 43415244420101\n"
                + "@record sfi=1 rec=1\n"
                + "70 0D 5A 05 12 34 56 78 90 5F24 03 29 12 31\n"
                + "@sda bogus\n");
        Asserts.throwsIo(() -> PersoScript.parse(sdaBogus.getPath(), TestKeys.sdaKeys()),
                "unknown @sda option is rejected");

        // --- @key derive (EMV v4.4 Book 2 Annex A1.4) -----------------------
        // EMV CPS v2.0 §3.2: DES and AES keys must not share one data grouping,
        // so this DGI 8000 carries only 3DES keys.
        File derive = writeTemp("@instance 43415244420101\n"
                + "@key icc derive 0123456789ABCDEFFEDCBA9876543210 99012345678901234 45\n"
                + "@key sm-mac derive 0F0E0D0C0B0A09080706050403020100 1234567890 00\n"
                + "@key sm-enc derive 0F0E0D0C0B0A09080706050403020100 1234567890 00\n");
        PersoScript deriveScript = PersoScript.parse(derive.getPath());
        byte[] dgi8000 = deriveScript.entries.get(0).dgis.get(0x8000);
        Asserts.check(dgi8000 != null && dgi8000.length == 48,
                "@key derive emits a 48-byte DGI 8000");
        // Option B external vector (pyEMV) for the AC key.
        Asserts.bytes(Hex.parse("985EC4FD3EDF6162E31AF1C7D0543416"),
                java.util.Arrays.copyOfRange(dgi8000, 0, 16), "@key icc derive uses Option B");
        Asserts.bytes(EmvKeys.desMasterKey(
                        Hex.parse("0F0E0D0C0B0A09080706050403020100"), "1234567890", 0x00),
                java.util.Arrays.copyOfRange(dgi8000, 16, 32), "@key sm-mac derive (3DES)");
        Asserts.bytes(EmvKeys.desMasterKey(
                        Hex.parse("0F0E0D0C0B0A09080706050403020100"), "1234567890", 0x00),
                java.util.Arrays.copyOfRange(dgi8000, 32, 48), "@key sm-enc derive (3DES)");

        // An AES key grouping is a separate all-AES DGI 8000
        // (EMV CPS v2.0 §3.2).
        File deriveAes = writeTemp("@instance 43415244420101\n"
                + "@key icc derive 0123456789ABCDEFFEDCBA9876543210 99012345678901234 45 aes\n"
                + "@key sm-mac derive 0F0E0D0C0B0A09080706050403020100 1234567890 00 aes\n"
                + "@key sm-enc derive 0F0E0D0C0B0A09080706050403020100 1234567890 00 aes\n");
        PersoScript aesScript = PersoScript.parse(deriveAes.getPath());
        byte[] aes8000 = aesScript.entries.get(0).dgis.get(0x8000);
        Asserts.check(aes8000 != null && aes8000.length == 48,
                "@key derive aes emits a 48-byte DGI 8000");
        Asserts.bytes(EmvKeys.aesMasterKey(
                        Hex.parse("0F0E0D0C0B0A09080706050403020100"), "1234567890", 0x00, 16),
                java.util.Arrays.copyOfRange(aes8000, 32, 48), "@key sm-enc derive (AES)");
        final File badDerive = writeTemp("@instance 43415244420101\n@key icc derive 0F0E\n");
        Asserts.throwsIo(() -> PersoScript.parse(badDerive.getPath()),
                "short @key derive is rejected");

        // --- malformed scripts are rejected ---------------------------------
        final File unknown = writeTemp("@instance 43415244420101\n@bogus 01\n");
        Asserts.throwsIo(() -> PersoScript.parse(unknown.getPath()),
                "unknown directive is rejected");
        final File noRecord = writeTemp("@instance 43415244420101\n@sda\n");
        Asserts.throwsIo(() -> PersoScript.parse(noRecord.getPath(), TestKeys.sdaKeys()),
                "@sda without a record is rejected");
        Asserts.check(throwsIllegal(() -> Hex.parse("ABC")),
                "odd-length hex is rejected");

        // --- the demo key profile file matches the in-source fixture --------
        SdaKeys fromFile = SdaKeyProfile.load("perso/emv/sample.perso.sda.keys");
        SdaKeys fixture = TestKeys.sdaKeys();
        Asserts.check(fromFile.caModulus.equals(fixture.caModulus)
                && fromFile.issuerModulus.equals(fixture.issuerModulus)
                && fromFile.caPrivateExponent.equals(fixture.caPrivateExponent)
                && fromFile.issuerPrivateExponent.equals(fixture.issuerPrivateExponent)
                && java.util.Arrays.equals(fromFile.caPublicKeyIndex, fixture.caPublicKeyIndex)
                && java.util.Arrays.equals(fromFile.exponent, fixture.exponent),
                "perso/emv/sample.perso.sda.keys matches TestKeys");
    }

    private static File writeTemp(String content) throws Exception {
        File file = File.createTempFile("card42-unit", ".perso");
        file.deleteOnExit();
        try (Writer w = new FileWriter(file)) {
            w.write(content);
        }
        return file;
    }

    private static boolean throwsIllegal(Runnable action) {
        try {
            action.run();
            return false;
        } catch (IllegalArgumentException e) {
            return true;
        }
    }
}
