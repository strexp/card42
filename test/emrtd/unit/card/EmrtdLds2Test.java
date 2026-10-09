package card42.test;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

import card42.emrtd.ChipAuth;
import card42.emrtd.EmrtdTags;
import card42.emrtd.Lds2FileSystem;
import card42.emrtd.LdsMfStore;
import card42.emrtd.Lds2Perso;
import card42.emrtd.Lds2RecordFile;
import card42.emrtd.Lds2TransparentFile;
import card42.host.common.util.Hex;

/**
 * Pure-JVM tests for the LDS2 file system, the LDS2 personalization path and
 * card-side Chip Authentication.
 *
 * <p>The Chip Authentication test runs the card-side {@link ChipAuth} ECDH
 * against an independent JCE ephemeral key pair: the shared secret is never
 * exposed, so the derived 3DES session keys must agree with the host KDF.
 *
 * <p>The LDS2 file-system / personalization portions are project-internal
 * (the record semantics are exercised end to end); the CA portion maps to ICAO
 * Doc 9303-11 §6.2.
 */
final class EmrtdLds2Test {

    private EmrtdLds2Test() {
    }

    static void run() throws Exception {
        System.out.println("EmrtdLds2");
        recordFiles();
        recordCapsAndBiometrics();
        masterFileAtrDir();
        transparentFiles();
        lds2Personalization();
        chipAuthentication();
    }

    private static void recordFiles() {
        Lds2FileSystem travel = Lds2FileSystem.travel();
        travel.select(EmrtdTags.FID_RECORDS);
        Lds2RecordFile entry = travel.getSelectedRecord();
        Asserts.check(entry != null && entry.getFid() == EmrtdTags.FID_RECORDS,
                "LDS2 entry records selectable");

        byte[] first = Hex.parse("5F440101");
        byte[] second = Hex.parse("5F44020203");
        Asserts.eq(1, entry.append(first, (short) 0, (short) first.length), "append record 1");
        Asserts.eq(2, entry.append(second, (short) 0, (short) second.length), "append record 2");
        Asserts.eq(2, entry.recordCount(), "record count");
        Asserts.eq(9, entry.totalBytes(), "total record bytes");
        Asserts.eq(5, entry.recordLength((short) 2), "record 2 length");
        // FMM reports remaining records assuming every remaining record is at
        // its maximum size (Doc 9303-10 §3.8.3): (1024 - 9) / 256 = 3.
        Asserts.eq(3, entry.remainingRecords(), "remaining records (max-size assumption)");

        byte[] out = new byte[8];
        short n = entry.readRecord((short) 1, out, (short) 0, (short) 8);
        Asserts.bytes(first, java.util.Arrays.copyOf(out, n), "read record 1");
        n = entry.readRecords((short) 1, out, (short) 0, (short) 8);
        Asserts.bytes(Hex.parse("5F4401015F440202"), java.util.Arrays.copyOf(out, n),
                "read all records from 1");

        // Search: record 2 contains 5F440202.
        Asserts.check(entry.search((short) 2, Hex.parse("5F4402"), (short) 0, (short) 3,
                (short) 0, (short) 0), "search finds the byte string");
        Asserts.check(!entry.search((short) 1, Hex.parse("5F4402"), (short) 0, (short) 3,
                (short) 0, (short) 0), "search rejects a non-matching record");

        final Lds2RecordFile missing = entry;
        Asserts.sw((short) 0x6A83, () -> missing.readRecord((short) 9, out, (short) 0, (short) 8),
                "missing record -> 6A83");

        // Certificate file is separate.
        travel.select(EmrtdTags.FID_CERTIFICATES);
        Asserts.check(travel.getSelectedRecord() != null
                && travel.getSelectedRecord().getFid() == EmrtdTags.FID_CERTIFICATES,
                "certificates file selectable");
    }

    private static void recordCapsAndBiometrics() {
        // EF.Certificates holds up to 254 records (Travel/Visa) or 64
        // (Additional Biometrics) (Doc 9303-10 §5.1.2/§5.2.2/§5.3.2).
        Lds2FileSystem travel = Lds2FileSystem.travel();
        travel.select(EmrtdTags.FID_CERTIFICATES);
        Lds2RecordFile certs = travel.getSelectedRecord();
        byte[] one = new byte[] { 1 };
        for (short i = 0; i < (short) 254; i++) {
            certs.append(one, (short) 0, (short) 1);
        }
        Asserts.eq(254, certs.recordCount(), "Travel EF.Certificates holds 254 records");
        Asserts.sw((short) 0x6A84, () -> certs.append(one, (short) 0, (short) 1),
                "Travel EF.Certificates 255th record -> 6A84");

        Lds2FileSystem bio = Lds2FileSystem.biometrics();
        bio.select(EmrtdTags.FID_CERTIFICATES);
        Lds2RecordFile bioCerts = bio.getSelectedRecord();
        for (short i = 0; i < (short) 64; i++) {
            bioCerts.append(one, (short) 0, (short) 1);
        }
        Asserts.eq(64, bioCerts.recordCount(), "Biometrics EF.Certificates holds 64 records");
        Asserts.sw((short) 0x6A84, () -> bioCerts.append(one, (short) 0, (short) 1),
                "Biometrics EF.Certificates 65th record -> 6A84");

        // EF.Biometrics1-64 are FIDs 0201-0240 with Short EF Identifier N/A
        // (Doc 9303-10 §5.3.3 Table 92).
        bio.select((short) 0x0201);
        Asserts.check(bio.getSelectedTransparent() != null
                && bio.getSelectedTransparent().getFid() == 0x0201, "EF.Biometrics1 selectable");
        bio.select((short) 0x0240);
        Asserts.check(bio.getSelectedTransparent() != null
                && bio.getSelectedTransparent().getFid() == 0x0240, "EF.Biometrics64 selectable");
        Asserts.sw((short) 0x6A82, () -> bio.select((short) 0x0241),
                "EF.Biometrics beyond 0240 -> 6A82");
        Asserts.check(bio.transparentBySfi((short) 0x01) == null,
                "EF.Biometrics has no Short EF Identifier");
    }

    /** EF.ATR/INFO and EF.DIR are master-file files (Doc 9303-10 §3.11.1/§3.11.2). */
    private static void masterFileAtrDir() {
        byte[] lds1Aid = { (byte) 0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01 };
        LdsMfStore.addDirectoryEntry(lds1Aid, (short) lds1Aid.length);

        Lds2TransparentFile dir = LdsMfStore.file(EmrtdTags.FID_DIR);
        Asserts.check(dir != null && dir.getLength() >= 11, "EF.DIR has an application template");
        Asserts.check(LdsMfStore.file(EmrtdTags.FID_ATR_INFO) != null, "EF.ATR/INFO present");
        Asserts.check(LdsMfStore.fileBySfi((short) 0x1E) == dir, "EF.DIR resolvable by SFI 1E");
        Asserts.check(LdsMfStore.fileBySfi((short) 0x01)
                == LdsMfStore.file(EmrtdTags.FID_ATR_INFO),
                "EF.ATR/INFO resolvable by SFI 01");

        byte[] out = new byte[16];
        short n = dir.read((short) 0, (short) 11, out, (short) 0);
        Asserts.eq(11, n, "EF.DIR template length");
        Asserts.eq(0x61, out[0] & 0xFF, "EF.DIR application template tag");
        Asserts.eq(0x09, out[1] & 0xFF, "EF.DIR application template length");
        Asserts.eq(0x4F, out[2] & 0xFF, "EF.DIR AID tag");
        Asserts.eq(7, out[3] & 0xFF, "EF.DIR AID length");

        Lds2TransparentFile atr = LdsMfStore.file(EmrtdTags.FID_ATR_INFO);
        byte[] atrOut = new byte[16];
        short an = atr.read((short) 0, atr.getLength(), atrOut, (short) 0);
        Asserts.eq(0x47, atrOut[0] & 0xFF, "EF.ATR/INFO card capabilities tag");
        Asserts.eq(0x7F, atrOut[5] & 0xFF, "EF.ATR/INFO extended length tag");
        Asserts.check(an == atr.getLength() && an > 0, "EF.ATR/INFO readable");
    }

    private static void transparentFiles() {
        Lds2FileSystem biometrics = Lds2FileSystem.biometrics();
        biometrics.select(Lds2FileSystem.FID_BIOMETRIC);
        Lds2TransparentFile file = biometrics.getSelectedTransparent();
        Asserts.check(file != null, "biometric EF selectable");

        byte[] data = Hex.parse("0102030405");
        file.update((short) 0, data, (short) 0, (short) data.length);
        Asserts.eq(5, file.getLength(), "transparent length after update");
        byte[] out = new byte[8];
        short n = file.read((short) 0, (short) 5, out, (short) 0);
        Asserts.bytes(data, java.util.Arrays.copyOf(out, n), "transparent read");

        file.activate();
        Asserts.check(file.isActivated(), "biometric EF activated");
        Asserts.sw((short) 0x6982, () -> file.update((short) 0, data, (short) 0, (short) 1),
                "write after ACTIVATE -> 6982");
    }

    private static void lds2Personalization() throws Exception {
        Lds2FileSystem travel = Lds2FileSystem.travel();
        card42.emrtd.ChipAuth chipAuth = new card42.emrtd.ChipAuth();
        final int[] paceSeedLength = new int[1];
        final int[] paceCanSeedLength = new int[1];
        card42.emrtd.PaceSeedSink pace = new card42.emrtd.PaceSeedSink() {
            public void setSeed(byte[] src, short off, short len) {
                paceSeedLength[0] = len;
            }

            public void setCanSeed(byte[] src, short off, short len) {
                paceCanSeedLength[0] = len;
            }
        };
        Lds2Perso perso = new Lds2Perso(travel, chipAuth, pace);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        writeDgi(out, EmrtdTags.FID_CARD_ACCESS, Hex.parse("30 03 0201 00"));
        writeDgi(out, (short) (0x7000 | EmrtdTags.FID_RECORDS), Hex.parse("5F4401AA"));

        // The project DGIs carry the key material the LDS2 EF.CardAccess
        // advertises: FF03 = CA static P-256 scalar, FF04 = PACE key seed.
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(256);
        KeyPair ca = generator.generateKeyPair();
        byte[] caScalar = unsigned(((ECPrivateKey) ca.getPrivate()).getS());
        writeDgi(out, EmrtdTags.DGI_CA_KEY, caScalar);
        writeDgi(out, EmrtdTags.DGI_PACE_SEED, new byte[20]);
        writeDgi(out, EmrtdTags.DGI_PACE_CAN_SEED, new byte[20]);
        perso.apply(out.toByteArray(), (short) 0, (short) out.size());

        // EF.CardAccess is a master-file file shared by every application, not
        // a file of the LDS2 DF (Doc 9303-10 §3.11.3).
        Lds2TransparentFile access = LdsMfStore.file(EmrtdTags.FID_CARD_ACCESS);
        Asserts.check(travel.transparent(EmrtdTags.FID_CARD_ACCESS) == null,
                "EF.CardAccess is not a DF file");
        Asserts.eq(5, access.getLength(), "LDS2 perso wrote the MF EF.CardAccess");
        Lds2RecordFile entry = travel.record(EmrtdTags.FID_RECORDS);
        Asserts.eq(1, entry.recordCount(), "LDS2 perso appended one record");
        Asserts.eq(4, entry.recordLength((short) 1), "LDS2 perso record length");
        Asserts.check(chipAuth.isInitialized(), "LDS2 perso set the CA static key");
        Asserts.eq(20, paceSeedLength[0], "LDS2 perso set the PACE key seed");
        Asserts.eq(20, paceCanSeedLength[0], "LDS2 perso set the CAN PACE key seed");
    }

    private static void chipAuthentication() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(256);
        KeyPair chip = generator.generateKeyPair();
        KeyPair ephemeral = generator.generateKeyPair();

        ChipAuth card = new ChipAuth();
        byte[] scalar = unsigned(((ECPrivateKey) chip.getPrivate()).getS());
        card.setPrivateKey(scalar, (short) 0, (short) scalar.length);
        Asserts.check(card.isInitialized(), "card CA key initialized");

        byte[] enc = new byte[16];
        byte[] mac = new byte[16];
        card.deriveSessionKeys(card42.host.emrtd.access.ChipAuth.encodeW(
                (ECPublicKey) ephemeral.getPublic()), (short) 0, (short) 65, enc, (short) 0,
                mac, (short) 0);

        // Independent JCE ECDH on the terminal side.
        javax.crypto.KeyAgreement agreement = javax.crypto.KeyAgreement.getInstance("ECDH");
        agreement.init(ephemeral.getPrivate());
        agreement.doPhase(chip.getPublic(), true);
        byte[] z = agreement.generateSecret();
        Asserts.bytes(card42.host.emrtd.access.ChipAuth.deriveKey(z, 1), enc,
                "card CA Ks_enc matches the host KDF");
        Asserts.bytes(card42.host.emrtd.access.ChipAuth.deriveKey(z, 2), mac,
                "card CA Ks_mac matches the host KDF");

        // The re-keyed secure messaging must interoperate.
        card42.emrtd.Iso7816Sm cardSm = new card42.emrtd.Iso7816Sm();
        byte[] ssc = new byte[8];
        byte[] payload = Hex.parse("0102030405");
        byte[] wrapped = new byte[64];
        short n = cardSm.wrap(enc, mac, ssc, payload, (short) payload.length,
                (short) 0x9000, wrapped, (short) 0);
        card42.host.emrtd.access.Iso7816Sm hostSm =
                new card42.host.emrtd.access.Iso7816Sm(enc, mac, 0L);
        short[] sw = new short[1];
        byte[] plain = hostSm.unwrapResponse(java.util.Arrays.copyOf(wrapped, n), sw);
        Asserts.bytes(payload, plain, "CA re-keyed SM card wrap -> host unwrap");
        Asserts.eq(0x9000, sw[0] & 0xFFFF, "CA re-keyed SM status word");
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

    private static byte[] unsigned(BigInteger value) {
        byte[] raw = value.toByteArray();
        if (raw.length > 1 && raw[0] == 0) {
            return java.util.Arrays.copyOfRange(raw, 1, raw.length);
        }
        return raw;
    }
}
