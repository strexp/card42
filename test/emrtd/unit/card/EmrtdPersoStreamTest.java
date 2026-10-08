package card42.test;

import java.io.ByteArrayOutputStream;

import card42.emrtd.AaCrypto;
import card42.emrtd.ChipAuth;
import card42.emrtd.DgiStream;
import card42.emrtd.EmrtdTags;
import card42.emrtd.Lds2FileSystem;
import card42.emrtd.Lds2Perso;
import card42.emrtd.Lds2RecordFile;
import card42.emrtd.Lds2TransparentFile;
import card42.emrtd.LdsCatalog;
import card42.emrtd.LdsFile;
import card42.emrtd.LdsFileSystem;
import card42.emrtd.LdsMfStore;
import card42.emrtd.LdsPerso;
import card42.emrtd.PaceSeedSink;
import card42.host.common.util.Hex;

/**
 * Pure-JVM tests for the streaming eMRTD personalization path and the paged EF
 * store.
 *
 * <p>The card used to reassemble the whole DGI sequence in one 4096-byte buffer,
 * which capped the DG2 face image and burned persistent memory; personalization
 * now applies each STORE DATA block as it arrives ({@link DgiStream} +
 * {@link LdsPerso} / {@link Lds2Perso}) and the transparent EFs are paged.  The
 * tests feed a sequence in tiny chunks so every DGI header/value split is
 * exercised, include a DGI larger than the old 4096-byte buffer, and check the
 * malformed / oversize / incomplete cases the SD relies on.
 */
final class EmrtdPersoStreamTest {

    private EmrtdPersoStreamTest() {
    }

    static void run() throws Exception {
        System.out.println("EmrtdPersoStream");
        pagedFile();
        pagedTransparentFile();
        maxEfBound();
        recordStreaming();
        dgiStreamFraming();
        lds1PersonalizationStreaming();
        largeSignedObjects();
        lds2PersonalizationStreaming();
    }

    // --- Paged transparent EF (LdsFile) --------------------------------------

    private static void pagedFile() {
        byte[] src = pattern(5000);
        LdsFile file = new LdsFile(EmrtdTags.FID_DG2);
        Asserts.eq(0, file.getCapacity(), "a fresh paged EF declares no fixed budget");

        // Append in 7-byte chunks so every page boundary is crossed mid-chunk.
        int off = 0;
        while (off < src.length) {
            int n = Math.min(7, src.length - off);
            file.append(src, (short) off, (short) n);
            off += n;
        }
        Asserts.eq(5000, file.getLength(), "paged append length");
        Asserts.eq(5000, file.getCapacity(), "paged append grows the capacity to the content");

        sameBytes(slice(src, 200, 300), read(file, 200, 300),
                "paged read spans a page boundary");
        sameBytes(slice(src, 250, 12), read(file, 250, 12),
                "paged read starts just before a page boundary");
        sameBytes(slice(src, 4999, 1), read(file, 4999, 1),
                "paged read of the last byte");

        Asserts.sw((short) 0x6700,
                () -> file.read((short) 4999, (short) 2, new byte[2], (short) 0),
                "paged read past the end -> 6700");

        // set() restarts and reuses the already allocated pages.
        byte[] small = pattern(1000);
        file.set(small, (short) 0, (short) 1000);
        Asserts.eq(1000, file.getLength(), "paged set restarts the length");
        sameBytes(small, read(file, 0, 1000), "paged set overwrites the content");
    }

    // --- Paged transparent EF (Lds2TransparentFile) --------------------------

    private static void pagedTransparentFile() {
        byte[] src = pattern(1000);
        Lds2TransparentFile file = new Lds2TransparentFile((short) 0x0201, false);

        file.append(src, (short) 0, (short) 10);
        Asserts.eq(10, file.getLength(), "LDS2 append length");
        // UPDATE BINARY beyond the end leaves the gap zero (no stale page bytes).
        file.update((short) 20, src, (short) 20, (short) 5);
        Asserts.eq(25, file.getLength(), "LDS2 update extends the length");
        byte[] out = read(file, 0, 25);
        sameBytes(slice(src, 0, 10), slice(out, 0, 10), "LDS2 appended bytes");
        for (int i = 10; i < 20; i++) {
            Asserts.eq(0, out[i] & 0xFF, "LDS2 update gap byte " + i + " is zero");
        }
        sameBytes(slice(src, 20, 5), slice(out, 20, 5), "LDS2 updated bytes");

        file.activate();
        Asserts.sw((short) 0x6982,
                () -> file.update((short) 0, src, (short) 0, (short) 1),
                "LDS2 write after ACTIVATE -> 6982");
    }

    /**
     * The only per-file bound left is the protocol maximum: a 15-bit READ
     * BINARY offset / DGI length (32767).  A write past it is refused with
     * 6700 (LDS1) / 6A84 (LDS2); the old fixed budgets are gone.
     */
    private static void maxEfBound() {
        byte[] max = pattern(EmrtdTags.MAX_EF_BYTES);

        LdsFile lds1 = new LdsFile(EmrtdTags.FID_DG16);
        lds1.append(max, (short) 0, EmrtdTags.MAX_EF_BYTES);
        Asserts.eq(EmrtdTags.MAX_EF_BYTES, lds1.getLength(), "LDS1 EF fills to MAX_EF");
        Asserts.sw((short) 0x6700, () -> lds1.append(new byte[1], (short) 0, (short) 1),
                "LDS1 append past MAX_EF -> 6700");
        Asserts.sw((short) 0x6700, () -> lds1.ensureCapacity((short) 32768),
                "LDS1 ensureCapacity past MAX_EF -> 6700");

        Lds2TransparentFile lds2 = new Lds2TransparentFile((short) 0x0201, false);
        lds2.append(max, (short) 0, EmrtdTags.MAX_EF_BYTES);
        Asserts.eq(EmrtdTags.MAX_EF_BYTES, lds2.getLength(), "LDS2 EF fills to MAX_EF");
        Asserts.sw((short) 0x6A84, () -> lds2.append(new byte[1], (short) 0, (short) 1),
                "LDS2 append past MAX_EF -> 6A84");
        Asserts.sw((short) 0x6A84, () -> lds2.ensureCapacity((short) 32768),
                "LDS2 ensureCapacity past MAX_EF -> 6A84");
    }

    // --- Streaming record EF (Lds2RecordFile) --------------------------------

    private static void recordStreaming() {
        Lds2RecordFile file = Lds2FileSystem.travel().record(EmrtdTags.FID_RECORDS);
        byte[] record = pattern(200);
        file.beginRecord();
        int off = 0;
        while (off < record.length) {
            int n = Math.min(11, record.length - off);
            file.appendChunk(record, (short) off, (short) n);
            off += n;
        }
        file.endRecord();
        Asserts.eq(1, file.recordCount(), "streamed record appended");
        Asserts.eq(200, file.recordLength((short) 1), "streamed record length");
        byte[] out = new byte[200];
        short n = file.readRecord((short) 1, out, (short) 0, (short) 200);
        sameBytes(record, java.util.Arrays.copyOf(out, n), "streamed record round-trips");

        // The record is only committed by endRecord: a record over the maximum
        // leaves the file untouched.
        final Lds2RecordFile fresh = Lds2FileSystem.travel().record(EmrtdTags.FID_RECORDS);
        fresh.beginRecord();
        Asserts.sw((short) 0x6700,
                () -> fresh.appendChunk(new byte[257], (short) 0, (short) 257),
                "record over the maximum -> 6700");
        fresh.endRecord();
        Asserts.eq(0, fresh.recordLength((short) 1), "rejected record is not committed");

        // Four 256-byte records fill the 1024-byte pool; the fifth -> 6A84.
        Lds2RecordFile pool = Lds2FileSystem.travel().record(EmrtdTags.FID_RECORDS);
        for (int i = 0; i < 4; i++) {
            pool.append(pattern(256), (short) 0, (short) 256);
        }
        Asserts.sw((short) 0x6A84, () -> pool.append(pattern(256), (short) 0, (short) 256),
                "record pool full -> 6A84");

        Asserts.sw((short) 0x6700,
                () -> fresh.appendChunk(new byte[1], (short) 0, (short) 1),
                "appendChunk without beginRecord -> 6700");
    }

    // --- Incremental DGI framing ---------------------------------------------

    private static void dgiStreamFraming() {
        byte[] dg2 = pattern(5000);
        ByteArrayOutputStream seq = new ByteArrayOutputStream();
        writeDgi(seq, EmrtdTags.DGI_BAC_SEED, pattern(16));
        writeDgi(seq, EmrtdTags.FID_DG2, dg2);
        writeDgi(seq, EmrtdTags.FID_COM, new byte[] { 0x60, 0x00 });

        RecordingSink sink = new RecordingSink();
        DgiStream stream = new DgiStream(sink);
        feedAll(stream, seq.toByteArray(), 1);
        stream.finish();

        Asserts.eq(3, sink.dgis.size(), "stream parses three DGIs");
        Asserts.eq(EmrtdTags.DGI_BAC_SEED, sink.dgis.get(0).shortValue(), "first DGI is FF01");
        Asserts.eq(EmrtdTags.FID_DG2, sink.dgis.get(1).shortValue(), "second DGI is DG2");
        Asserts.eq(EmrtdTags.FID_COM, sink.dgis.get(2).shortValue(), "third DGI is COM");
        sameBytes(pattern(16), sink.values.get(0), "short DGI value streamed");
        sameBytes(dg2, sink.values.get(1), "5000-byte DGI value streamed");
        sameBytes(new byte[] { 0x60, 0x00 }, sink.values.get(2), "small DGI value streamed");

        // An empty value is delivered as begin + end with no data.
        RecordingSink empty = new RecordingSink();
        DgiStream emptyStream = new DgiStream(empty);
        emptyStream.feed(new byte[] { 0x01, 0x01, 0x00 }, (short) 0, (short) 3);
        emptyStream.finish();
        Asserts.eq(1, empty.dgis.size(), "empty DGI parsed");
        Asserts.eq(0, empty.values.get(0).length, "empty DGI has no value");

        // A sequence that stops inside a DGI is refused (truncated).
        RecordingSink partial = new RecordingSink();
        DgiStream partialStream = new DgiStream(partial);
        partialStream.feed(new byte[] { 0x01, 0x02, 0x10, 0x01, 0x02 }, (short) 0, (short) 5);
        Asserts.sw((short) 0x6700, partialStream::finish, "truncated DGI sequence -> 6700");

        // A value larger than the 15-bit / signed-short limit is refused.
        RecordingSink tooLong = new RecordingSink();
        DgiStream tooLongStream = new DgiStream(tooLong);
        Asserts.sw((short) 0x6700,
                () -> tooLongStream.feed(
                        new byte[] { 0x01, 0x02, (byte) 0xFF, (byte) 0x80, 0x00 },
                        (short) 0, (short) 5),
                "DGI value over 32767 -> 6700");
    }

    // --- LDS1 streaming personalization --------------------------------------

    private static void lds1PersonalizationStreaming() throws Exception {
        byte[] seed = pattern(16);
        byte[] paceSeed = pattern(20);
        byte[] dg1 = Hex.parse("615B5F1F58504C383938393032433C");
        byte[] dg2 = pattern(5000);
        byte[] dg15 = Hex.parse("6F00");
        byte[] cardAccess = Hex.parse("3003020100");
        byte[] cardSecurity = Hex.parse("308103020100A0");
        byte[] sod = Hex.parse("7703616263");
        byte[] aaKey = aaKey();

        ByteArrayOutputStream seq = new ByteArrayOutputStream();
        writeDgi(seq, EmrtdTags.DGI_BAC_SEED, seed);
        writeDgi(seq, EmrtdTags.DGI_PACE_SEED, paceSeed);
        byte[] scalar = new byte[32];
        scalar[31] = 1;
        writeDgi(seq, EmrtdTags.DGI_CA_KEY, scalar);
        writeDgi(seq, EmrtdTags.FID_DG1, dg1);
        writeDgi(seq, EmrtdTags.FID_DG2, dg2);
        writeDgi(seq, EmrtdTags.FID_DG15, dg15);
        writeDgi(seq, EmrtdTags.FID_CARD_ACCESS, cardAccess);
        writeDgi(seq, EmrtdTags.DGI_CARD_SECURITY, cardSecurity);
        writeDgi(seq, EmrtdTags.FID_SOD, sod);
        writeDgi(seq, EmrtdTags.DGI_AA_KEY, aaKey);
        byte[] sequence = seq.toByteArray();

        LdsCatalog catalog = new LdsCatalog();
        AaCrypto aa = new AaCrypto((short) 2048, AaCrypto.AA_SHA1);
        ChipAuth chipAuth = new ChipAuth();
        final int[] paceLength = new int[1];
        PaceSeedSink pace = (src, off, len) -> paceLength[0] = len;
        LdsPerso perso = new LdsPerso(catalog, aa, chipAuth, pace);

        // Feed in 13-byte chunks: the DGI headers and 5000-byte DG2 straddle
        // many STORE DATA blocks.
        perso.reset();
        feedAll(perso, sequence, 13);
        perso.finish();

        Asserts.check(perso.seedSet(), "LDS1 streaming set the BAC seed");
        sameBytes(seed, perso.seed(), "LDS1 streaming BAC seed value");
        sameBytes(dg1, read(catalog.file(EmrtdTags.FID_DG1), 0, dg1.length),
                "LDS1 streaming DG1 content");
        Asserts.eq(5000, catalog.file(EmrtdTags.FID_DG2).getLength(),
                "LDS1 streaming DG2 larger than the old 4096-byte buffer");
        sameBytes(dg2, read(catalog.file(EmrtdTags.FID_DG2), 0, 5000),
                "LDS1 streaming DG2 content");
        sameBytes(dg15, read(catalog.file(EmrtdTags.FID_DG15), 0, dg15.length),
                "LDS1 streaming DG15 content");
        sameBytes(sod, read(catalog.file(EmrtdTags.FID_SOD), 0, sod.length),
                "LDS1 streaming SOD content");
        Asserts.check(aa.isInitialized(), "LDS1 streaming set the AA private key");
        Asserts.check(chipAuth.isInitialized(), "LDS1 streaming set the CA scalar");
        Asserts.eq(20, paceLength[0], "LDS1 streaming set the PACE key seed");

        // DGI FF05 carries the master-file EF.CardSecurity (Doc 9303-10
        // §3.11.4), which the LDS1 catalog cannot hold (FID 011D is EF.SOD).
        Lds2TransparentFile mfSecurity = LdsMfStore.file(EmrtdTags.FID_CARD_SECURITY);
        Asserts.eq(cardSecurity.length, mfSecurity.getLength(),
                "LDS1 streaming wrote the MF EF.CardSecurity length");
        sameBytes(cardSecurity, read(mfSecurity, 0, cardSecurity.length),
                "LDS1 streaming MF EF.CardSecurity content");

        // The on-card COM index lists the streamed data groups.
        catalog.select(EmrtdTags.FID_COM);
        LdsFile com = catalog.getSelected();
        byte[] comBytes = new byte[64];
        short n = com.read((short) 0, com.getLength(), comBytes, (short) 0);
        card42.host.emrtd.lds.Com parsed = card42.host.emrtd.lds.Com.parse(
                java.util.Arrays.copyOf(comBytes, n));
        Asserts.eq(3, parsed.dataGroupTags.length, "LDS1 streaming COM data group count");
        Asserts.eq(0x61, parsed.dataGroupTags[0], "LDS1 streaming COM DG1 tag");
        Asserts.eq(0x75, parsed.dataGroupTags[1], "LDS1 streaming COM DG2 tag");
        Asserts.eq(0x6F, parsed.dataGroupTags[2], "LDS1 streaming COM DG15 tag");

        // A sequence without DG1 is incomplete (the seed alone is not enough).
        ByteArrayOutputStream missing = new ByteArrayOutputStream();
        writeDgi(missing, EmrtdTags.DGI_BAC_SEED, seed);
        writeDgi(missing, EmrtdTags.FID_DG2, dg2);
        byte[] missingDg1 = missing.toByteArray();
        LdsCatalog otherCatalog = new LdsCatalog();
        final LdsPerso other = new LdsPerso(otherCatalog,
                new AaCrypto((short) 2048, AaCrypto.AA_SHA1), new ChipAuth(),
                (src, off, len) -> { });
        Asserts.sw((short) 0x6A80,
                () -> other.apply(missingDg1, (short) 0, (short) missingDg1.length),
                "LDS1 sequence without DG1 -> 6A80");
    }

    // --- large signed objects (EF.SOD / EF.CardSecurity) ---------------------

    /**
     * Regression: EF.SOD and EF.CardSecurity embed the Document Signer
     * certificate chain, so a real DSC made the CMS objects ~2 KB (a script
     * with a 1243-byte DSC produced a 1938-byte EF.CardSecurity and a 2005-byte
     * EF.SOD).  The old fixed budgets (SOD 2048, EF.CardSecurity 1792) were
     * too small and STORE DATA failed with 6A84; the paged budgets are now
     * generous enough that a multi-KB signed object personalizes intact.
     */
    private static void largeSignedObjects() {
        byte[] dg1 = Hex.parse("615B5F1F58504C383938393032433C");
        byte[] cardSecurity = pattern(2000);
        byte[] sod = pattern(2500);

        ByteArrayOutputStream seq = new ByteArrayOutputStream();
        writeDgi(seq, EmrtdTags.DGI_BAC_SEED, pattern(16));
        writeDgi(seq, EmrtdTags.FID_DG1, dg1);
        writeDgi(seq, EmrtdTags.DGI_CARD_SECURITY, cardSecurity);
        writeDgi(seq, EmrtdTags.FID_SOD, sod);
        byte[] sequence = seq.toByteArray();

        LdsCatalog catalog = new LdsCatalog();
        LdsPerso perso = new LdsPerso(catalog,
                new AaCrypto((short) 2048, AaCrypto.AA_SHA1), new ChipAuth(),
                (src, off, len) -> { });
        perso.apply(sequence, (short) 0, (short) sequence.length);

        Lds2TransparentFile mfSecurity = LdsMfStore.file(EmrtdTags.FID_CARD_SECURITY);
        Asserts.eq(cardSecurity.length, mfSecurity.getLength(),
                "multi-KB MF EF.CardSecurity length");
        sameBytes(cardSecurity, read(mfSecurity, 0, cardSecurity.length),
                "multi-KB MF EF.CardSecurity content");
        Asserts.eq(sod.length, catalog.file(EmrtdTags.FID_SOD).getLength(),
                "multi-KB EF.SOD length");
        sameBytes(sod, read(catalog.file(EmrtdTags.FID_SOD), 0, sod.length),
                "multi-KB EF.SOD content");
    }

    // --- LDS2 streaming personalization --------------------------------------

    private static void lds2PersonalizationStreaming() {
        Lds2FileSystem travel = Lds2FileSystem.travel();
        ChipAuth chipAuth = new ChipAuth();
        final int[] paceLength = new int[1];
        PaceSeedSink pace = (src, off, len) -> paceLength[0] = len;
        Lds2Perso perso = new Lds2Perso(travel, chipAuth, pace);

        byte[] cardAccess = Hex.parse("3003020100");
        byte[] record = pattern(200);
        byte[] scalar = new byte[32];
        scalar[31] = 1;
        byte[] paceSeed = pattern(20);

        ByteArrayOutputStream seq = new ByteArrayOutputStream();
        writeDgi(seq, EmrtdTags.FID_CARD_ACCESS, cardAccess);
        writeDgi(seq, (short) (0x7000 | EmrtdTags.FID_RECORDS), record);
        writeDgi(seq, EmrtdTags.DGI_CA_KEY, scalar);
        writeDgi(seq, EmrtdTags.DGI_PACE_SEED, paceSeed);

        // One byte at a time: every header and every chunk boundary.
        perso.reset();
        feedAll(perso, seq.toByteArray(), 1);
        perso.finish();

        Lds2TransparentFile access = LdsMfStore.file(EmrtdTags.FID_CARD_ACCESS);
        sameBytes(cardAccess, read(access, 0, cardAccess.length),
                "LDS2 streaming wrote the MF EF.CardAccess");
        Lds2RecordFile entry = travel.record(EmrtdTags.FID_RECORDS);
        Asserts.eq(1, entry.recordCount(), "LDS2 streaming appended one record");
        Asserts.eq(200, entry.recordLength((short) 1), "LDS2 streaming record length");
        byte[] out = new byte[200];
        short n = entry.readRecord((short) 1, out, (short) 0, (short) 200);
        sameBytes(record, java.util.Arrays.copyOf(out, n), "LDS2 streaming record content");
        Asserts.check(chipAuth.isInitialized(), "LDS2 streaming set the CA static key");
        Asserts.eq(20, paceLength[0], "LDS2 streaming set the PACE key seed");

        // A transparent biometric EF larger than one block.
        Lds2FileSystem biometrics = Lds2FileSystem.biometrics();
        Lds2Perso bioPerso = new Lds2Perso(biometrics, new ChipAuth(), (src, off, len) -> { });
        byte[] biometric = pattern(1000);
        ByteArrayOutputStream bioSeq = new ByteArrayOutputStream();
        writeDgi(bioSeq, Lds2FileSystem.FID_BIOMETRIC, biometric);
        bioPerso.apply(bioSeq.toByteArray(), (short) 0, (short) bioSeq.size());
        Lds2TransparentFile bioFile = biometrics.transparent(Lds2FileSystem.FID_BIOMETRIC);
        sameBytes(biometric, read(bioFile, 0, 1000), "LDS2 streaming biometric EF content");
    }

    // --- helpers -------------------------------------------------------------

    /** A DGI recording sink: one entry per completed DGI. */
    private static final class RecordingSink extends DgiStream.Sink {
        final java.util.List<Short> dgis = new java.util.ArrayList<Short>();
        final java.util.List<byte[]> values = new java.util.ArrayList<byte[]>();
        private ByteArrayOutputStream current;
        private short currentDgi;

        public void onReset() {
        }

        public void onBeginDgi(short dgi, short valueLength) {
            currentDgi = dgi;
            current = new ByteArrayOutputStream();
        }

        public void onData(byte[] buf, short off, short len) {
            current.write(buf, off, len);
        }

        public void onEndDgi() {
            dgis.add(Short.valueOf(currentDgi));
            values.add(current.toByteArray());
        }

        public void onFinish() {
        }
    }

    private static void feedAll(DgiStream stream, byte[] data, int step) {
        int off = 0;
        while (off < data.length) {
            int n = Math.min(step, data.length - off);
            stream.feed(data, (short) off, (short) n);
            off += n;
        }
    }

    private static void feedAll(LdsPerso perso, byte[] data, int step) {
        int off = 0;
        while (off < data.length) {
            int n = Math.min(step, data.length - off);
            perso.feed(data, (short) off, (short) n);
            off += n;
        }
    }

    private static void feedAll(Lds2Perso perso, byte[] data, int step) {
        int off = 0;
        while (off < data.length) {
            int n = Math.min(step, data.length - off);
            perso.feed(data, (short) off, (short) n);
            off += n;
        }
    }

    private static byte[] read(LdsFile file, int off, int len) {
        byte[] out = new byte[len];
        file.read((short) off, (short) len, out, (short) 0);
        return out;
    }

    private static byte[] read(Lds2TransparentFile file, int off, int len) {
        byte[] out = new byte[len];
        file.read((short) off, (short) len, out, (short) 0);
        return out;
    }

    private static byte[] slice(byte[] src, int off, int len) {
        return java.util.Arrays.copyOfRange(src, off, off + len);
    }

    /** Byte equality without dumping large hex blobs into the test log. */
    private static void sameBytes(byte[] expected, byte[] actual, String what) {
        if (java.util.Arrays.equals(expected, actual)) {
            Asserts.check(true, what);
        } else {
            Asserts.check(false, what + " (expected " + expected.length
                    + " B, got " + actual.length + " B)");
        }
    }

    /** Deterministic byte pattern (i * 31 + 7). */
    private static byte[] pattern(int length) {
        byte[] out = new byte[length];
        for (int i = 0; i < length; i++) {
            out[i] = (byte) (i * 31 + 7);
        }
        return out;
    }

    /** An LDS1 AA private key DGI: modLen(2) || modulus(256) || expLen(2) || exponent(3). */
    private static byte[] aaKey() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(0x01);
        out.write(0x00);
        out.write(pattern(256), 0, 256);
        out.write(0x00);
        out.write(0x03);
        out.write(0x01);
        out.write(0x00);
        out.write(0x01);
        return out.toByteArray();
    }

    private static void writeDgi(ByteArrayOutputStream out, short dgi, byte[] value) {
        out.write((dgi >> 8) & 0xFF);
        out.write(dgi & 0xFF);
        if (value.length < 0xFF) {
            out.write(value.length);
        } else {
            out.write(0xFF);
            out.write((value.length >> 8) & 0xFF);
            out.write(value.length & 0xFF);
        }
        out.write(value, 0, value.length);
    }
}
