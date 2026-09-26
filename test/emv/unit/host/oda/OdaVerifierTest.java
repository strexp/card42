package card42.test;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import card42.host.emv.oda.CaKey;
import card42.host.emv.oda.CamVerifier;
import card42.host.emv.oda.SdaVerifier;
import card42.host.emv.lib.IssuerKey;
import card42.host.emv.oda.Sda;
import card42.host.common.codec.Tags;
import card42.host.common.codec.TlvWriter;
import card42.host.emv.lib.Terminal;
import card42.host.common.util.Hex;

/**
 * Pure-JVM negative tests for the terminal ODA verifiers
 * (EMV v4.4 Book 2 §5, §6.4, §6.6): {@link SdaVerifier} and
 * {@link CamVerifier} had no direct unit tests, so a regression was only caught
 * by the end-to-end suites.
 *
 * <p>A valid SDA certificate chain is generated with the demo keys
 * ({@link TestKeys}) and served through a scripted {@code CardChannel}; every
 * negative below then corrupts exactly one input (tag list, missing data,
 * unknown CA index, PAN, expiry, certificate bytes, READ RECORD) and checks
 * that the verifier reports the failure instead of accepting it.  The DDA/CDA
 * negatives use the recovered ICC public key.
 */
final class OdaVerifierTest {

    private OdaVerifierTest() {
    }

    /** AFL: SFI 1, records 1-3, one record in the static-data input. */
    private static final byte[] AFL = { 0x08, 0x01, 0x03, 0x01 };
    private static final int AIP = 0x5800;

    static void run() throws Exception {
        System.out.println("OdaVerifier");

        byte[] record1 = record1(Hex.parse("1234567890"));
        Sda.Result perso = Sda.personalize(record1, TestKeys.sdaKeys());

        // --- SDA positive (sanity for the negatives below) ------------------
        RecordChannel channel = channel(record1, perso);
        SdaVerifier.Result ok = SdaVerifier.verify(new Terminal(channel), AFL, AIP,
                TestKeys.caKeyStore());
        Asserts.check(ok.ok, "SDA certificate chain verifies"
                + (ok.ok ? "" : " (" + ok.reason + ")"));
        Asserts.check(ok.key != null, "SDA returns the recovered issuer key");
        Asserts.bytes(Hex.parse("1234567890"), ok.key.pan, "SDA carries the card PAN");

        // --- SDA Tag List with a tag other than 82 is refused ---------------
        // EMV v4.4 Book 2 §5.3 step 5: only '82' (AIP) is allowed for SDA.
        byte[] tagged = append(record1, tlv(0x9F4A, Hex.parse("5F24")));
        SdaVerifier.Result badTag = SdaVerifier.verify(new Terminal(channel(tagged, perso)),
                AFL, AIP, TestKeys.caKeyStore());
        Asserts.check(!badTag.ok && badTag.reason != null
                && badTag.reason.contains("tag list"),
                "SDA Tag List with a non-82 tag is refused");

        // --- missing required data (90) -------------------------------------
        RecordChannel noCert = channel(record1, perso);
        noCert.put(2, 1, new byte[0]);
        SdaVerifier.Result missing = SdaVerifier.verify(new Terminal(noCert), AFL, AIP,
                TestKeys.caKeyStore());
        Asserts.check(!missing.ok && missing.dataMissing,
                "missing issuer certificate -> dataMissing");

        // --- unknown CA Public Key Index ------------------------------------
        RecordChannel unknownCa = channel(record1, perso);
        unknownCa.put(2, 1, replaceTopLevel(perso.record2, 0x8F, Hex.parse("02")));
        SdaVerifier.Result noCa = SdaVerifier.verify(new Terminal(unknownCa), AFL, AIP,
                TestKeys.caKeyStore());
        Asserts.check(!noCa.ok && noCa.reason != null && noCa.reason.contains("CA Public Key"),
                "unknown CA Public Key Index is refused");

        // --- PAN mismatch between record 1 and the issuer certificate -------
        // The certificate was generated for PAN 1234567890; record 1 now carries
        // a different PAN, so the issuer identifier check must fail.
        byte[] otherPan = record1(Hex.parse("9999999999"));
        SdaVerifier.Result pan = SdaVerifier.verify(new Terminal(channel(otherPan, perso)),
                AFL, AIP, TestKeys.caKeyStore());
        Asserts.check(!pan.ok, "issuer identifier / PAN mismatch is refused");

        // --- issuer certificate expiry across the century boundary ----------
        // The demo certificate expires MMYY 12/29.  EMV v4.4 Book 4 §6.7.1 /
        // §6.7.3 expands the two-digit transaction year 99 to 1999, so the
        // certificate is NOT expired; a raw byte comparison would wrongly
        // refuse it.
        SdaVerifier.Result pre2000 = SdaVerifier.verify(new Terminal(channel(record1, perso)),
                AFL, AIP, TestKeys.caKeyStore(), true, Hex.parse("991231"));
        Asserts.check(pre2000.ok,
                "pre-2000 transaction date does not expire a 2029 certificate");
        // A transaction date after the certificate expiry (2030) is refused.
        SdaVerifier.Result expired = SdaVerifier.verify(new Terminal(channel(record1, perso)),
                AFL, AIP, TestKeys.caKeyStore(), true, Hex.parse("300101"));
        Asserts.check(!expired.ok, "transaction date after the expiry is refused");

        // --- corrupted certificate bytes ------------------------------------
        RecordChannel corrupt = channel(record1, perso);
        byte[] cert = Tags.find(perso.record2, 0x90);
        cert[40] ^= 0x01;
        corrupt.put(2, 1, replaceTopLevel(perso.record2, 0x90, cert));
        SdaVerifier.Result corruptResult = SdaVerifier.verify(new Terminal(corrupt), AFL, AIP,
                TestKeys.caKeyStore());
        Asserts.check(!corruptResult.ok, "corrupted issuer certificate is refused");

        // --- wrong CA key (recovery yields a malformed block) ---------------
        SdaVerifier.Result wrongKey = SdaVerifier.verify(new Terminal(channel(record1, perso)),
                AFL, AIP, index -> new CaKey(TestKeys.CA_MODULUS,
                        TestKeys.CA_EXPONENT.add(BigInteger.ONE)));
        Asserts.check(!wrongKey.ok, "wrong CA key is refused");

        // --- READ RECORD failure terminates SDA -----------------------------
        RecordChannel readFail = channel(record1, perso);
        readFail.fail(2, 1, 0x6A82);
        SdaVerifier.Result readResult = SdaVerifier.verify(new Terminal(readFail), AFL, AIP,
                TestKeys.caKeyStore());
        Asserts.check(!readResult.ok && readResult.reason != null
                && readResult.reason.contains("READ RECORD"),
                "READ RECORD failure is reported");

        // --- DDA/CDA negatives ----------------------------------------------
        SdaVerifier.Result iccResult = SdaVerifier.recoverIccKey(new Terminal(channel),
                ok.key);
        Asserts.check(iccResult.ok, "ICC public key certificate recovers"
                + (iccResult.ok ? "" : " (" + iccResult.reason + ")"));
        IssuerKey iccKey = iccResult.key;

        // The same century rule applies to the ICC certificate (expiry
        // 12/29, offset 12 MMYY): a 1999 transaction date (99 -> 1999) is
        // before it, while a 2030 date is past it (EMV v4.4 Book 2 §6.4 step 9;
        // Book 4 §6.7.1/§6.7.3).
        SdaVerifier.Result iccPre2000 = SdaVerifier.recoverIccKey(new Terminal(channel),
                ok.key, Hex.parse("991231"));
        Asserts.check(iccPre2000.ok,
                "pre-2000 transaction date does not expire the ICC certificate");
        SdaVerifier.Result iccExpired = SdaVerifier.recoverIccKey(new Terminal(channel),
                ok.key, Hex.parse("300101"));
        Asserts.check(!iccExpired.ok, "expired ICC public key certificate is refused");

        // The ICC certificate length must equal the issuer modulus length
        // (EMV v4.4 Book 2 §6.4 step 1).
        RecordChannel shortIcc = channel(record1, perso);
        byte[] iccCert = Tags.find(perso.record5, 0x9F46);
        shortIcc.put(5, 1, replaceTopLevel(perso.record5, 0x9F46,
                Arrays.copyOf(iccCert, iccCert.length - 1)));
        SdaVerifier.Result iccShort = SdaVerifier.recoverIccKey(new Terminal(shortIcc), ok.key);
        Asserts.check(!iccShort.ok && iccShort.reason != null
                && iccShort.reason.contains("length"),
                "ICC certificate length mismatch is refused");

        CamVerifier.Result noKey = CamVerifier.verifyDda(new byte[128], new byte[4], null);
        Asserts.check(!noKey.ok, "DDA without an ICC key is refused");

        CamVerifier.Result garbage = CamVerifier.verifyDda(new byte[128], new byte[4], iccKey);
        Asserts.check(!garbage.ok, "DDA over a malformed SDAD is refused");

        CamVerifier.Result wrongLength = CamVerifier.verifyDda(new byte[64], new byte[4], iccKey);
        Asserts.check(!wrongLength.ok, "DDA with a wrong SDAD length is refused");

        CamVerifier.Result noCdaTags = CamVerifier.verifyCda(Hex.parse("7700"), new byte[0],
                null, new byte[0], new byte[4], iccKey, null, 0x40);
        Asserts.check(!noCdaTags.ok, "CDA without 9F27/9F36/9F4B/9F10 is refused");

        CamVerifier.Result wrongCid = CamVerifier.verifyCda(cdaResponse(0x40, 0x0001,
                new byte[8], new byte[128]), new byte[0], null, new byte[0], new byte[4],
                iccKey, null, 0x80);
        Asserts.check(!wrongCid.ok, "CDA with a mismatched response CID is refused");

        CamVerifier.Result badSdad = CamVerifier.verifyCda(cdaResponse(0x40, 0x0001,
                new byte[8], new byte[128]), new byte[0], null, new byte[0], new byte[4],
                iccKey, null, 0x40);
        Asserts.check(!badSdad.ok, "CDA over a malformed SDAD is refused");
    }

    // --- fixtures ------------------------------------------------------------

    /** A minimal record 1: 70 { 5A PAN, 5F24 expiry }. */
    private static byte[] record1(byte[] pan) {
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        TlvWriter.writeTlv(body, 0x5A, pan);
        TlvWriter.writeTlv(body, 0x5F24, Hex.parse("291231"));
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        TlvWriter.writeTlv(out, 0x70, body.toByteArray());
        return out.toByteArray();
    }

    private static RecordChannel channel(byte[] record1, Sda.Result perso) {
        RecordChannel channel = new RecordChannel();
        channel.put(1, 1, record1);
        channel.put(2, 1, perso.record2);
        channel.put(3, 1, perso.record3);
        channel.put(4, 1, perso.record4);
        channel.put(5, 1, perso.record5);
        return channel;
    }

    /** A Format 2 GENERATE AC response 77 { 9F27, 9F36, 9F10, 9F4B }. */
    private static byte[] cdaResponse(int cid, int atc, byte[] iad, byte[] sdad) {
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        TlvWriter.writeTlv(body, 0x9F27, new byte[] { (byte) cid });
        TlvWriter.writeTlv(body, 0x9F36, new byte[] { (byte) (atc >> 8), (byte) atc });
        TlvWriter.writeTlv(body, 0x9F10, iad);
        TlvWriter.writeTlv(body, 0x9F4B, sdad);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        TlvWriter.writeTlv(out, 0x77, body.toByteArray());
        return out.toByteArray();
    }

    /** One TLV as a new array. */
    private static byte[] tlv(int tag, byte[] value) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        TlvWriter.writeTlv(out, tag, value);
        return out.toByteArray();
    }

    /** Appends a complete TLV to a record (outside the 70 template). */
    private static byte[] append(byte[] record, byte[] tlv) {
        byte[] out = new byte[record.length + tlv.length];
        System.arraycopy(record, 0, out, 0, record.length);
        System.arraycopy(tlv, 0, out, record.length, tlv.length);
        return out;
    }

    /**
     * Rebuilds a single-70-template record, replacing the value of one
     * primitive top-level tag (the generated record 2 is 70 { 8F, 90, 92, 9F32 }).
     */
    private static byte[] replaceTopLevel(byte[] record, int tag, byte[] value) {
        int first = record[1] & 0xFF;
        int lenField = (first & 0x80) == 0 ? 1 : 1 + (first & 0x7F);
        int p = 1 + lenField;
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        while (p < record.length) {
            int start = p;
            int b = record[p] & 0xFF;
            int t;
            int tagLen;
            if ((b & 0x1F) == 0x1F) {
                t = (b << 8) | (record[p + 1] & 0xFF);
                tagLen = 2;
            } else {
                t = b;
                tagLen = 1;
            }
            int lOff = p + tagLen;
            int lb = record[lOff] & 0xFF;
            int lLen = (lb & 0x80) == 0 ? 1 : 1 + (lb & 0x7F);
            int vLen;
            if (lLen == 1) {
                vLen = lb;
            } else {
                vLen = 0;
                for (int i = 0; i < lLen - 1; i++) {
                    vLen = (vLen << 8) | (record[lOff + 1 + i] & 0xFF);
                }
            }
            int end = lOff + lLen + vLen;
            if (t == tag) {
                byte[] tlv = tlv(tag, value);
                body.write(tlv, 0, tlv.length);
            } else {
                body.write(record, start, end - start);
            }
            p = end;
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        TlvWriter.writeTlv(out, 0x70, body.toByteArray());
        return out.toByteArray();
    }

    /** A CardChannel serving READ RECORD responses by (record, SFI). */
    private static final class RecordChannel extends CardChannel {
        private final Map<String, ResponseAPDU> records = new HashMap<String, ResponseAPDU>();

        void put(int record, int sfi, byte[] data) {
            records.put(key(record, sfi), ok(data));
        }

        void fail(int record, int sfi, int sw) {
            records.put(key(record, sfi),
                    new ResponseAPDU(new byte[] { (byte) (sw >> 8), (byte) sw }));
        }

        private static String key(int record, int sfi) {
            return sfi + ":" + record;
        }

        private static ResponseAPDU ok(byte[] data) {
            byte[] full = new byte[data.length + 2];
            System.arraycopy(data, 0, full, 0, data.length);
            full[data.length] = (byte) 0x90;
            full[data.length + 1] = 0x00;
            return new ResponseAPDU(full);
        }

        @Override
        public Card getCard() {
            throw new UnsupportedOperationException();
        }

        @Override
        public int getChannelNumber() {
            return 0;
        }

        @Override
        public ResponseAPDU transmit(CommandAPDU command) throws CardException {
            if (command.getINS() == 0xB2) {
                int record = command.getP1();
                int sfi = (command.getP2() & 0xFF) >> 3;
                ResponseAPDU r = records.get(key(record, sfi));
                if (r != null) {
                    return r;
                }
            }
            throw new CardException("unexpected command");
        }

        @Override
        public int transmit(ByteBuffer command, ByteBuffer response) throws CardException {
            throw new UnsupportedOperationException();
        }

        @Override
        public void close() throws CardException {
        }
    }
}
