package card42.test;

import java.io.ByteArrayOutputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;

import card42.emrtd.EmrtdApplet;
import card42.emrtd.EmrtdInstallParameters;
import card42.emrtd.EmrtdTags;
import card42.emrtd.Lds2FileSystem;
import card42.emrtd.Lds2Record;
import card42.emrtd.Lds2TransparentFile;
import card42.host.common.util.Hex;

/**
 * Command-level tests for the LDS2 / Additional Biometrics command handlers in
 * {@code card/emrtd/command/Lds2Record.java}.  The existing
 * {@code EmrtdLds2Test} exercises only the {@code Lds2*File} abstraction; these
 * tests drive the real static handlers on a real {@link EmrtdApplet} instance,
 * so the DO parsing, status words and response encodings are covered.
 *
 * <p>Spec references:
 * <ul>
 *   <li>SEARCH RECORD: ICAO Doc 9303-10 §3.7.3 (Table 14/15/16/17), Appendix
 *       I.1 and Appendix J.1;</li>
 *   <li>FMM (FILE AND MEMORY MANAGEMENT): Doc 9303-10 §3.8.3 (Table 22/23/24/
 *       25/26/27), Appendix H.1;</li>
 *   <li>UPDATE BINARY (odd INS): Doc 9303-10 §3.8.1 (Table 18/19);</li>
 *   <li>ACTIVATE: Doc 9303-10 §3.8.2 (Table 20/21).</li>
 * </ul>
 *
 * <p>The applet is built through its private constructor via reflection and the
 * {@code paceDone} session flag is set directly: LDS2 access control requires
 * PACE (Doc 9303-11 §1.2 Note 2 / §4.2 step 3; Doc 9303-10 §3.11.4 Table 34),
 * so without that flag every command would be refused with 6982 before its own
 * logic runs.  The PACE protocol itself is covered by the simulator suite
 * {@code EmrtdPaceIntegrationTest}.
 */
final class EmrtdCommandTest {

    /** The applet DF name used for the LDS2 Travel Records role. */
    private static final byte[] TRAVEL = EmrtdTags.DF_NAME_TRAVEL;

    private EmrtdCommandTest() {
    }

    static void run() throws Exception {
        System.out.println("EmrtdCommand");
        searchRecordP2();
        searchRecordRoundTrip();
        searchRecordFileReference();
        searchRecordErrors();
        fileMemoryManagement();
        updateBinary();
        activate();
        paceRequired();
    }

    // --- SEARCH RECORD (Doc 9303-10 §3.7.3) ---------------------------------

    /** P2 MUST be 'F8' (11111000b); any other value is RFU (§3.7.3 Table 16). */
    private static void searchRecordP2() throws Exception {
        EmrtdApplet applet = travelApplet();
        byte[] data = searchData(fidRef(EmrtdTags.FID_RECORDS),
                (byte) 0x00, null, null, Hex.parse("5F44"));
        Asserts.sw((short) 0x6A86,
                () -> Lds2Record.searchRecord(applet, (byte) 0xF9, data, (short) 0,
                        (short) data.length),
                "SEARCH RECORD P2 != F8 -> 6A86");
        Asserts.sw((short) 0x6A86,
                () -> Lds2Record.searchRecord(applet, (byte) 0x00, data, (short) 0,
                        (short) data.length),
                "SEARCH RECORD P2 = 00 -> 6A86 (RFU)");
    }

    /**
     * A search with the whole record as the window returns every matching record
     * number in a DO'7F76' carrying DO'51' and DO'02' (§3.7.3 Table 15/17,
     * Appendix I.1).
     */
    private static void searchRecordRoundTrip() throws Exception {
        EmrtdApplet applet = travelApplet();
        append(applet, "5F4403555341"); // 5F44 03 'USA'
        append(applet, "5F440343414E"); // 5F44 03 'CAN'

        byte[] data = searchData(fidRef(EmrtdTags.FID_RECORDS),
                (byte) 0x00, null, null, Hex.parse("5F44"));
        short n = Lds2Record.searchRecord(applet, (byte) 0xF8, data, (short) 0, (short) data.length);
        Asserts.bytes(Hex.parse("7F760A51020101020101020102"),
                java.util.Arrays.copyOf(response(applet), n),
                "SEARCH RECORD returns every matching record number");

        // Termination DO'80' = '30' stops after the first match (§3.7.3 Table 17).
        byte[] firstOnly = searchData(fidRef(EmrtdTags.FID_RECORDS),
                (byte) 0x30, null, null, Hex.parse("5F44"));
        n = Lds2Record.searchRecord(applet, (byte) 0xF8, firstOnly, (short) 0,
                (short) firstOnly.length);
        Asserts.bytes(Hex.parse("7F760751020101020101"),
                java.util.Arrays.copyOf(response(applet), n),
                "SEARCH RECORD '30' terminates after the first match");

        // A search window selects bytes within each record: offset 3, length 3
        // covers the state code in the ICAO Doc 9303-10 §3.7.3 Appendix I.1
        // example.  The offset/length are encoded here as two-byte BER integers
        // because the handler decodes DO'02' with Util.getShort (fixed-width);
        // the minimal one-byte form shown by the appendix is not handled — see
        // the SEARCH RECORD entry in TODO.emrtd.md.
        byte[] windowed = searchData(fidRef(EmrtdTags.FID_RECORDS),
                (byte) 0x00, 3, 3, Hex.parse("555341")); // 'USA'
        n = Lds2Record.searchRecord(applet, (byte) 0xF8, windowed, (short) 0,
                (short) windowed.length);
        Asserts.bytes(Hex.parse("7F760751020101020101"),
                java.util.Arrays.copyOf(response(applet), n),
                "SEARCH RECORD window offset/length selects the state code");

        byte[] noMatch = searchData(fidRef(EmrtdTags.FID_RECORDS),
                (byte) 0x00, null, null, Hex.parse("5A5A5A")); // 'ZZZ'
        Asserts.sw((short) 0x6282,
                () -> Lds2Record.searchRecord(applet, (byte) 0xF8, noMatch, (short) 0,
                        (short) noMatch.length),
                "SEARCH RECORD without a match -> 6282 (§3.7.3 Table 15)");
    }

    /**
     * DO'51' accepts a two-byte file identifier or a one-byte short EF
     * identifier whose bits b8-b4 carry the SFI (§3.7.3 Table 17; the b8-b4
     * coding is the same as READ/APPEND RECORD P2, Table 10/13).  Appendix
     * I.1/J.1 show the short EF identifier for EF.EntryRecords/EF.Certificates.
     */
    private static void searchRecordFileReference() throws Exception {
        EmrtdApplet applet = travelApplet();
        append(applet, "5F4403555341");

        // Short EF identifier form: SFI 1 is b8-b4 = 001, i.e. 0x08.
        byte[] sfi = searchData(tlv(0x51, new byte[] { 0x08 }),
                (byte) 0x00, null, null, Hex.parse("5F44"));
        short n = Lds2Record.searchRecord(applet, (byte) 0xF8, sfi, (short) 0, (short) sfi.length);
        Asserts.bytes(Hex.parse("7F7606510108020101"),
                java.util.Arrays.copyOf(response(applet), n),
                "SEARCH RECORD resolves a short EF identifier");

        // A file identifier with no matching EF is 6A82 (§3.7.3 Table 15).
        byte[] missing = searchData(fidRef((short) 0x0199),
                (byte) 0x00, null, null, Hex.parse("5F44"));
        Asserts.sw((short) 0x6A82,
                () -> Lds2Record.searchRecord(applet, (byte) 0xF8, missing, (short) 0,
                        (short) missing.length),
                "SEARCH RECORD unknown file reference -> 6A82");
    }

    /** Missing mandatory DOs are 6A80 (§3.7.3 Table 17, Note 3). */
    private static void searchRecordErrors() throws Exception {
        EmrtdApplet applet = travelApplet();

        // No Record handling DO'7F76' at all.
        byte[] none = Hex.parse("51020101");
        Asserts.sw((short) 0x6A80,
                () -> Lds2Record.searchRecord(applet, (byte) 0xF8, none, (short) 0,
                        (short) none.length),
                "SEARCH RECORD without DO'7F76' -> 6A80");

        // Handling DO without the file reference.
        byte[] noRef = tlv(0x7F76, tlv(0xA3, tlv(0xB1, tlv(0x81, Hex.parse("5F44")))));
        Asserts.sw((short) 0x6A80,
                () -> Lds2Record.searchRecord(applet, (byte) 0xF8, noRef, (short) 0,
                        (short) noRef.length),
                "SEARCH RECORD without DO'51' -> 6A80");

        // Handling DO without the search string.
        byte[] noString = tlv(0x7F76, fidRef(EmrtdTags.FID_RECORDS));
        Asserts.sw((short) 0x6A80,
                () -> Lds2Record.searchRecord(applet, (byte) 0xF8, noString, (short) 0,
                        (short) noString.length),
                "SEARCH RECORD without the search string -> 6A80");
    }

    // --- FMM (Doc 9303-10 §3.8.3) -------------------------------------------

    /**
     * P1=P0 (current EF) and P2 as a bitmap; the response is a DO'7F78' with
     * DO'81'/'82'/'83' only for the bits requested (Table 22/24/26/27, and the
     * §3.8.3 remaining-records maximum-size assumption).
     */
    private static void fileMemoryManagement() throws Exception {
        EmrtdApplet applet = travelApplet();
        append(applet, "5F4403555341"); // 6 bytes
        append(applet, "5F440343414E"); // 6 bytes
        fs(applet).select(EmrtdTags.FID_RECORDS);

        // P2 = 04: existing record count only (Appendix H.1 uses the same bit).
        short n = Lds2Record.fileMemoryManagement(applet, (byte) 0x00, (byte) 0x04,
                new byte[0], (short) 0, (short) 0);
        Asserts.bytes(Hex.parse("7F7803830102"),
                java.util.Arrays.copyOf(response(applet), n),
                "FMM P2=04 returns the existing record count");

        // P2 = 01: total bytes in the EF.
        n = Lds2Record.fileMemoryManagement(applet, (byte) 0x00, (byte) 0x01,
                new byte[0], (short) 0, (short) 0);
        Asserts.bytes(Hex.parse("7F780381010C"),
                java.util.Arrays.copyOf(response(applet), n),
                "FMM P2=01 returns the total byte count");

        // P2 = 02: remaining records, each assumed to be of maximum size (§3.8.3):
        // (1024 - 12) / 256 = 3.
        n = Lds2Record.fileMemoryManagement(applet, (byte) 0x00, (byte) 0x02,
                new byte[0], (short) 0, (short) 0);
        Asserts.bytes(Hex.parse("7F7803820103"),
                java.util.Arrays.copyOf(response(applet), n),
                "FMM P2=02 returns the remaining record count");

        // P2 = 07: all three DOs, in DO order 81, 82, 83 (Table 27).
        n = Lds2Record.fileMemoryManagement(applet, (byte) 0x00, (byte) 0x07,
                new byte[0], (short) 0, (short) 0);
        Asserts.bytes(Hex.parse("7F780981010C820103830102"),
                java.util.Arrays.copyOf(response(applet), n),
                "FMM P2=07 returns all requested DOs");

        // P1 = 01: file reference DO'51' in the command data (Table 22/25),
        // two-byte file identifier and one-byte short EF identifier.
        byte[] fid = tlv(0x51, new byte[] { 0x01, 0x01 });
        n = Lds2Record.fileMemoryManagement(applet, (byte) 0x01, (byte) 0x04,
                fid, (short) 0, (short) fid.length);
        Asserts.bytes(Hex.parse("7F7803830102"),
                java.util.Arrays.copyOf(response(applet), n),
                "FMM P1=01 resolves a file identifier");

        byte[] sfi = tlv(0x51, new byte[] { 0x08 });
        n = Lds2Record.fileMemoryManagement(applet, (byte) 0x01, (byte) 0x04,
                sfi, (short) 0, (short) sfi.length);
        Asserts.bytes(Hex.parse("7F7803830102"),
                java.util.Arrays.copyOf(response(applet), n),
                "FMM P1=01 resolves a short EF identifier");

        // A record-only DO on a transparent EF is not applicable (Table 24).
        EmrtdApplet biometrics = biometricsApplet();
        fs(biometrics).select(EmrtdTags.FID_BIOMETRICS);
        Asserts.sw((short) 0x6A86,
                () -> Lds2Record.fileMemoryManagement(biometrics, (byte) 0x00, (byte) 0x02,
                        new byte[0], (short) 0, (short) 0),
                "FMM record count on a transparent EF -> 6A86");

        // P1 = 01 without DO'51' -> 6A80; P1 RFU -> 6A86 (Table 22/23).
        Asserts.sw((short) 0x6A80,
                () -> Lds2Record.fileMemoryManagement(applet, (byte) 0x01, (byte) 0x04,
                        new byte[0], (short) 0, (short) 0),
                "FMM P1=01 without DO'51' -> 6A80");
        Asserts.sw((short) 0x6A86,
                () -> Lds2Record.fileMemoryManagement(applet, (byte) 0x07, (byte) 0x04,
                        new byte[0], (short) 0, (short) 0),
                "FMM P1 RFU -> 6A86");
        byte[] unknown = tlv(0x51, new byte[] { 0x01, (byte) 0x99 });
        Asserts.sw((short) 0x6A82,
                () -> Lds2Record.fileMemoryManagement(applet, (byte) 0x01, (byte) 0x04,
                        unknown, (short) 0, (short) unknown.length),
                "FMM unknown file reference -> 6A82");
    }

    // --- UPDATE BINARY (Doc 9303-10 §3.8.1) ---------------------------------

    /**
     * The first UPDATE BINARY MUST start at offset 0; later writes may continue
     * at any offset.  DO'54' is the offset and DO'53' the data; the optional
     * proprietary DO'C0' is ignored (Table 18/19, §3.8 writing sequence).
     */
    private static void updateBinary() throws Exception {
        EmrtdApplet applet = biometricsApplet();
        fs(applet).select(EmrtdTags.FID_BIOMETRICS);

        // First write at offset 0.
        byte[] first = updateData(0, "0102030405");
        short n = Lds2Record.updateBinary(applet, first, (short) 0, (short) first.length);
        Asserts.eq(0, n, "UPDATE BINARY returns no data (Table 19)");
        Asserts.eq(5, selected(applet).getLength(), "UPDATE BINARY set the length");

        // Historical write at offset n+1 (§3.8).
        byte[] next = updateData(5, "06");
        n = Lds2Record.updateBinary(applet, next, (short) 0, (short) next.length);
        Asserts.eq(0, n, "subsequent UPDATE BINARY returns 9000");
        byte[] out = new byte[8];
        short read = selected(applet).read((short) 0, (short) 6, out, (short) 0);
        Asserts.bytes(Hex.parse("010203040506"), java.util.Arrays.copyOf(out, read),
                "UPDATE BINARY content read back");

        // A first, non-zero offset is a parameter error (Table 19 '6A80').
        EmrtdApplet fresh = biometricsApplet();
        fs(fresh).select(EmrtdTags.FID_BIOMETRICS);
        byte[] gap = updateData(1, "06");
        Asserts.sw((short) 0x6A80,
                () -> Lds2Record.updateBinary(fresh, gap, (short) 0, (short) gap.length),
                "first UPDATE BINARY at offset != 0 -> 6A80");

        // The optional DO'C0' File Size is now a hint that reserves the EF's
        // final size up front (§3.8.1 Note 1) without changing the current
        // length; the store also grows on its own without it.
        EmrtdApplet withSize = biometricsApplet();
        fs(withSize).select(EmrtdTags.FID_BIOMETRICS);
        byte[] sized = cat(tlv(0x54, new byte[] { 0x00 }), tlv(0xC0, new byte[] { 0x04, 0x00 }),
                tlv(0x53, Hex.parse("AA")));
        n = Lds2Record.updateBinary(withSize, sized, (short) 0, (short) sized.length);
        Asserts.eq(0, n, "UPDATE BINARY accepts DO'C0'");
        Asserts.eq(1, selected(withSize).getLength(), "DO'C0' does not change the length");
        Asserts.eq(1024, selected(withSize).getCapacity(),
                "DO'C0' reserves the declared file size");

        // DO'54' / DO'53' are mandatory.
        byte[] noOffset = tlv(0x53, new byte[] { 0x01 });
        Asserts.sw((short) 0x6A80,
                () -> Lds2Record.updateBinary(applet, noOffset, (short) 0, (short) noOffset.length),
                "UPDATE BINARY without DO'54' -> 6A80");
        byte[] noData = tlv(0x54, new byte[] { 0x00 });
        Asserts.sw((short) 0x6A80,
                () -> Lds2Record.updateBinary(applet, noData, (short) 0, (short) noData.length),
                "UPDATE BINARY without DO'53' -> 6A80");
    }

    // --- ACTIVATE (Doc 9303-10 §3.8.2) --------------------------------------

    /**
     * ACTIVATE freezes the selected Additional Biometrics EF: P1/P2 are '00'
     * (Table 20), after which no write is allowed (6982, Table 19) while reads
     * continue (§3.8.2).
     */
    private static void activate() throws Exception {
        EmrtdApplet applet = biometricsApplet();
        fs(applet).select(EmrtdTags.FID_BIOMETRICS);
        byte[] first = updateData(0, "0102030405");
        Lds2Record.updateBinary(applet, first, (short) 0, (short) first.length);

        short n = Lds2Record.activate(applet, (byte) 0x00, (byte) 0x00);
        Asserts.eq(0, n, "ACTIVATE returns no data (Table 21)");
        Asserts.check(selected(applet).isActivated(), "ACTIVATE sets the Activated state");

        // Activated: writing is permanently refused (Table 19 '6982', §3.8.2).
        byte[] more = updateData(0, "AA");
        Asserts.sw((short) 0x6982,
                () -> Lds2Record.updateBinary(applet, more, (short) 0, (short) more.length),
                "UPDATE BINARY after ACTIVATE -> 6982");

        // Read access is unaffected by ACTIVATE (§3.8.2).
        byte[] out = new byte[8];
        short read = selected(applet).read((short) 0, (short) 5, out, (short) 0);
        Asserts.bytes(Hex.parse("0102030405"), java.util.Arrays.copyOf(out, read),
                "ACTIVATE keeps the EF readable");

        // P1/P2 other than '00' -> 6A86 (Table 20).
        Asserts.sw((short) 0x6A86,
                () -> Lds2Record.activate(applet, (byte) 0x01, (byte) 0x00),
                "ACTIVATE P1 != 0 -> 6A86");
        Asserts.sw((short) 0x6A86,
                () -> Lds2Record.activate(applet, (byte) 0x00, (byte) 0x01),
                "ACTIVATE P2 != 0 -> 6A86");

        // No transparent EF selected: conditions of use not satisfied
        // (ISO/IEC 7816-4 6985; Table 21 leaves it to the implementation).
        EmrtdApplet travel = travelApplet();
        Asserts.sw((short) 0x6985,
                () -> Lds2Record.activate(travel, (byte) 0x00, (byte) 0x00),
                "ACTIVATE without a transparent EF -> 6985");
    }

    /**
     * Every LDS2 command is gated on PACE (Doc 9303-11 §1.2 Note 2 / §4.2
     * step 3; Doc 9303-10 §3.11.4 Table 34): without it the handler refuses the
     * command with 6982 before any DO parsing.
     */
    private static void paceRequired() throws Exception {
        EmrtdApplet applet = travelApplet(false);
        byte[] data = searchData(fidRef(EmrtdTags.FID_RECORDS),
                (byte) 0x00, null, null, Hex.parse("5F44"));
        Asserts.sw((short) 0x6982,
                () -> Lds2Record.searchRecord(applet, (byte) 0xF8, data, (short) 0,
                        (short) data.length),
                "SEARCH RECORD without PACE -> 6982");
        Asserts.sw((short) 0x6982,
                () -> Lds2Record.fileMemoryManagement(applet, (byte) 0x00, (byte) 0x04,
                        new byte[0], (short) 0, (short) 0),
                "FMM without PACE -> 6982");
        Asserts.sw((short) 0x6982,
                () -> Lds2Record.activate(applet, (byte) 0x00, (byte) 0x00),
                "ACTIVATE without PACE -> 6982");
    }

    // --- helpers ------------------------------------------------------------

    private static EmrtdApplet travelApplet() throws Exception {
        return travelApplet(true);
    }

    private static EmrtdApplet travelApplet(boolean pace) throws Exception {
        return newApplet(EmrtdInstallParameters.ROLE_LDS2_TRAVEL, TRAVEL, pace);
    }

    private static EmrtdApplet biometricsApplet() throws Exception {
        return newApplet(EmrtdInstallParameters.ROLE_LDS2_BIOMETRICS,
                EmrtdTags.DF_NAME_BIOMETRICS, true);
    }

    /**
     * Builds a real applet through its private constructor.  The unit build has
     * no JCRE, so the constructor is invoked reflectively and the PACE session
     * flag (normally set by a completed PACE) is set directly; see the class
     * note.
     */
    private static EmrtdApplet newApplet(byte role, byte[] dfName, boolean paceDone)
            throws Exception {
        Constructor<EmrtdApplet> ctor = EmrtdApplet.class.getDeclaredConstructor(
                byte.class, byte[].class, short.class);
        ctor.setAccessible(true);
        EmrtdApplet applet = ctor.newInstance(role, dfName, (short) dfName.length);
        Field flag = EmrtdApplet.class.getDeclaredField("paceDone");
        flag.setAccessible(true);
        flag.setBoolean(applet, paceDone);
        return applet;
    }

    private static Lds2FileSystem fs(EmrtdApplet applet) throws Exception {
        Field field = EmrtdApplet.class.getDeclaredField("lds2");
        field.setAccessible(true);
        return (Lds2FileSystem) field.get(applet);
    }

    private static byte[] response(EmrtdApplet applet) throws Exception {
        Field field = EmrtdApplet.class.getDeclaredField("response");
        field.setAccessible(true);
        return (byte[]) field.get(applet);
    }

    private static Lds2TransparentFile selected(EmrtdApplet applet) throws Exception {
        return fs(applet).getSelectedTransparent();
    }

    /** APPEND RECORD (E2) as the command to seed a record EF (§3.7.1). */
    private static void append(EmrtdApplet applet, String hex) {
        byte[] record = Hex.parse(hex);
        short p2 = (short) (((EmrtdTags.FID_RECORDS & 0x1F) << 3) | 0x00);
        short r = Lds2Record.appendRecord(applet, (byte) 0x00, (byte) p2,
                record, (short) 0, (short) record.length);
        Asserts.eq(0, r, "APPEND RECORD accepted");
    }

    private static byte[] fidRef(short fid) {
        return tlv(0x51, new byte[] { (byte) (fid >> 8), (byte) fid });
    }

    /**
     * Builds a SEARCH RECORD command data field (Record handling DO'7F76' with
     * DO'51', the DO'A1' configuration template and the DO'A3' search string
     * template) per §3.7.3 Table 17.
     */
    private static byte[] searchData(byte[] fileRef, byte termination,
                                     Integer windowOffset, Integer windowLength,
                                     byte[] needle) {
        byte[] configuration = tlv(0x80, new byte[] { termination });
        if (windowOffset != null) {
            byte[] window = cat(tlv(0x02, twoBytes(windowOffset)),
                    tlv(0x02, twoBytes(windowLength)));
            configuration = cat(configuration, tlv(0xB0, window));
        }
        byte[] searchString = tlv(0xA3, tlv(0xB1, tlv(0x81, needle)));
        return tlv(0x7F76, cat(fileRef, tlv(0xA1, configuration), searchString));
    }

    private static byte[] updateData(int offset, String valueHex) {
        byte[] value = Hex.parse(valueHex);
        return cat(tlv(0x54, new byte[] { (byte) offset }), tlv(0x53, value));
    }

    private static byte[] twoBytes(int value) {
        return new byte[] { (byte) (value >> 8), (byte) value };
    }

    /** Minimal BER-TLV writer for the test vectors (tags 1-2 bytes). */
    private static byte[] tlv(int tag, byte[] value) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        if ((tag & 0xFF00) != 0) {
            out.write((tag >> 8) & 0xFF);
        }
        out.write(tag & 0xFF);
        if (value.length <= 0x7F) {
            out.write(value.length);
        } else if (value.length <= 0xFF) {
            out.write(0x81);
            out.write(value.length);
        } else {
            out.write(0x82);
            out.write((value.length >> 8) & 0xFF);
            out.write(value.length & 0xFF);
        }
        out.write(value, 0, value.length);
        return out.toByteArray();
    }

    private static byte[] cat(byte[]... parts) {
        int length = 0;
        for (byte[] part : parts) {
            length += part.length;
        }
        byte[] out = new byte[length];
        int off = 0;
        for (byte[] part : parts) {
            System.arraycopy(part, 0, out, off, part.length);
            off += part.length;
        }
        return out;
    }
}
