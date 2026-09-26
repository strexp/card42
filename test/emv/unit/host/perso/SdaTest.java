package card42.test;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.util.Arrays;
import card42.host.common.util.Bytes;
import card42.host.common.util.Digests;
import card42.host.common.util.Hex;
import card42.host.emv.oda.Sda;
import card42.host.common.codec.Tags;
import card42.host.common.codec.TlvWriter;

/**
 * Pure-JVM tests for the host-side SDA certificate generator (docs/specs/common/toolchain.md §6).
 * It uses the hard-coded test CA/issuer keys, so the certificate chain and the
 * SSAD can be recovered and hash-checked without the simulator.  Under the EMV CPS v2.0
 * v2.0 model the generator returns records 2-5 as 70
 * templates and the ICC private keys as modulus/exponent pairs.
 *
 * <p>Host generator round-trip (tool coverage); the SDA verification itself is
 * exercised by {@link OdaVerifierTest}.
 */
final class SdaTest {

    private SdaTest() {
    }

    static void run() throws Exception {
        System.out.println("Sda");

        // --- templateValue --------------------------------------------------
        byte[] shortRec = { 0x70, 0x03, 0x5A, 0x01, 0x00 };
        Asserts.bytes(new byte[] { 0x5A, 0x01, 0x00 }, Sda.templateValue(shortRec),
                "templateValue short form");
        byte[] longRec = new byte[3 + 200];
        longRec[0] = 0x70;
        longRec[1] = (byte) 0x81;
        longRec[2] = (byte) 200;
        for (int i = 0; i < 200; i++) {
            longRec[3 + i] = (byte) i;
        }
        byte[] longValue = Sda.templateValue(longRec);
        Asserts.eq(200, longValue.length, "templateValue long form length");
        Asserts.eq(0, longValue[0] & 0xFF, "templateValue long form first byte");

        // --- personalize ----------------------------------------------------
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        TlvWriter.writeTlv(body, 0x5A, Hex.parse("1234567890"));
        TlvWriter.writeTlv(body, 0x5F24, Hex.parse("291231"));
        byte[] value = body.toByteArray();
        byte[] record1 = new byte[2 + value.length];
        record1[0] = 0x70;
        record1[1] = (byte) value.length;
        System.arraycopy(value, 0, record1, 2, value.length);

        Sda.Result result = Sda.personalize(record1, TestKeys.sdaKeys());
        Asserts.eq(0x70, result.record2[0] & 0xFF, "record 2 is a 70 template");
        Asserts.eq(0x70, result.record3[0] & 0xFF, "record 3 is a 70 template");
        Asserts.eq(0x70, result.record4[0] & 0xFF, "record 4 is a 70 template");
        Asserts.eq(0x70, result.record5[0] & 0xFF, "record 5 is a 70 template");
        byte[] caIndex = Tags.find(result.record2, 0x8F);
        byte[] cert = Tags.find(result.record2, 0x90);
        byte[] remainder = Tags.find(result.record2, 0x92);
        byte[] exponent = Tags.find(result.record2, 0x9F32);
        byte[] ssad = Tags.find(result.record3, 0x93);
        byte[] pinCert = Tags.find(result.record4, 0x9F2D);
        byte[] pinRemainder = Tags.find(result.record4, 0x9F2F);
        byte[] pinExponent = Tags.find(result.record4, 0x9F2E);
        byte[] iccCert = Tags.find(result.record5, 0x9F46);
        byte[] iccRemainder = Tags.find(result.record5, 0x9F48);
        byte[] iccExponent = Tags.find(result.record5, 0x9F47);
        Asserts.check(caIndex != null && cert != null && remainder != null
                && exponent != null && ssad != null && pinCert != null
                && pinRemainder != null && pinExponent != null
                && iccCert != null && iccRemainder != null && iccExponent != null,
                "records 2-5 carry 8F/90/92/9F32/93/9F2D/9F2F/9F2E/9F46/9F48/9F47");
        Asserts.eq(TestKeys.NCA, cert.length, "issuer certificate length");
        Asserts.eq(36, remainder.length, "issuer remainder length");
        Asserts.eq(TestKeys.NI, ssad.length, "SSAD length");
        Asserts.eq(TestKeys.NI, pinCert.length, "PIN certificate length");
        Asserts.eq(TestKeys.NIC, iccCert.length, "ICC certificate length");
        Asserts.eq(TestKeys.NIC - (TestKeys.NI - 42), iccRemainder.length, "ICC remainder length");

        // --- issuer certificate (recovered with the CA key) -----------------
        byte[] recCert = Sda.recover(cert, TestKeys.CA_MODULUS, TestKeys.CA_EXPONENT);
        Asserts.check(recCert[0] == 0x6A && recCert[1] == 0x02
                && recCert[recCert.length - 1] == (byte) 0xBC,
                "issuer certificate structure");
        byte[] certHashInput = Bytes.concat(
                Arrays.copyOfRange(recCert, 1, recCert.length - 21), remainder, exponent);
        Asserts.check(Arrays.equals(Digests.sha1(certHashInput),
                        Arrays.copyOfRange(recCert, recCert.length - 21, recCert.length - 1)),
                "issuer certificate hash");

        // --- SSAD (recovered with the issuer key) ---------------------------
        int keyDigits = recCert.length - 36;
        byte[] issuerModulus = Bytes.concat(
                Arrays.copyOfRange(recCert, 15, 15 + keyDigits), remainder);
        BigInteger issuerExponent = new BigInteger(1, exponent);
        byte[] recSsad = Sda.recover(ssad, new BigInteger(1, issuerModulus), issuerExponent);
        Asserts.check(recSsad[0] == 0x6A && recSsad[1] == 0x03
                && recSsad[recSsad.length - 1] == (byte) 0xBC, "SSAD structure");
        byte[] ssadHashInput = Bytes.concat(
                Arrays.copyOfRange(recSsad, 1, recSsad.length - 21),
                Sda.templateValue(record1));
        Asserts.check(Arrays.equals(Digests.sha1(ssadHashInput),
                        Arrays.copyOfRange(recSsad, recSsad.length - 21, recSsad.length - 1)),
                "SSAD hash over the static data");

        // --- PIN certificate (recovered with the issuer key) ----------------
        byte[] recPin = Sda.recover(pinCert, new BigInteger(1, issuerModulus), issuerExponent);
        Asserts.check(recPin[0] == 0x6A && recPin[1] == 0x04
                && recPin[recPin.length - 1] == (byte) 0xBC, "PIN certificate structure");
        byte[] pinHashInput = Bytes.concat(
                Arrays.copyOfRange(recPin, 1, 21 + TestKeys.PIN_LEFTOPMOST),
                pinRemainder, pinExponent);
        Asserts.check(Arrays.equals(Digests.sha1(pinHashInput),
                        Arrays.copyOfRange(recPin, 21 + TestKeys.PIN_LEFTOPMOST,
                                21 + TestKeys.PIN_LEFTOPMOST + 20)),
                "PIN certificate hash");

        // --- PIN private key parts (EMV CPS v2.0 Annex A DGI '8104'/'8102') ----------------------
        Asserts.eq(TestKeys.NPE, result.pinModulus.length, "PIN modulus length");
        Asserts.eq(TestKeys.NPE, result.pinExponent.length, "PIN exponent length");
        Asserts.check(!isZero(result.pinExponent), "PIN exponent is non-zero");

        // --- ICC DDA/CDA certificate (recovered with the issuer key) --------
        int leftmost = TestKeys.NI - 42;
        byte[] recIcc = Sda.recover(iccCert, new BigInteger(1, issuerModulus), issuerExponent);
        Asserts.check(recIcc[0] == 0x6A && recIcc[1] == 0x04
                && recIcc[recIcc.length - 1] == (byte) 0xBC, "ICC certificate structure");
        byte[] iccHashInput = Bytes.concat(
                Arrays.copyOfRange(recIcc, 1, 21 + leftmost),
                iccRemainder, iccExponent,
                Sda.templateValue(record1));
        Asserts.check(Arrays.equals(Digests.sha1(iccHashInput),
                        Arrays.copyOfRange(recIcc, 21 + leftmost, 21 + leftmost + 20)),
                "ICC certificate hash");
        byte[] iccModulus = Bytes.concat(
                Arrays.copyOfRange(recIcc, 21, 21 + leftmost), iccRemainder);

        // --- DDA private key parts (EMV CPS v2.0 Annex A DGI '8103'/'8101') ----------------------
        Asserts.eq(TestKeys.NIC, result.ddaModulus.length, "DDA modulus length");
        Asserts.eq(TestKeys.NIC, result.ddaExponent.length, "DDA exponent length");
        Asserts.check(!isZero(result.ddaExponent), "DDA exponent is non-zero");
        Asserts.eq(TestKeys.NIC, iccModulus.length, "ICC modulus length");

        // --- EMV v4.4 Book 2 Table 43 modulus / EMV v4.4 Book 3 §7 record limits --------------
        Asserts.check(Sda.MAX_CA_MODULUS == 248 && Sda.MAX_ISSUER_MODULUS == 247
                && Sda.MAX_ISSUER_MODULUS_SDA == 248 && Sda.MAX_ICC_MODULUS == 247
                && Sda.MAX_PIN_MODULUS == 247 && Sda.MAX_RECORD_LENGTH == 254,
                "RSA modulus / record upper bounds");
        Asserts.check(result.record2.length <= Sda.MAX_RECORD_LENGTH
                && result.record3.length <= Sda.MAX_RECORD_LENGTH
                && result.record4.length <= Sda.MAX_RECORD_LENGTH
                && result.record5.length <= Sda.MAX_RECORD_LENGTH,
                "generated records are within the 254-byte limit");
        Asserts.check(TestKeys.NI <= Sda.MAX_ISSUER_MODULUS
                && TestKeys.NIC <= Sda.MAX_ICC_MODULUS
                && TestKeys.NPE <= Sda.MAX_PIN_MODULUS,
                "test key sizes respect the Table 43 limits");
        boolean threw = false;
        try {
            Sda.checkModulus("test", 248, Sda.MAX_ISSUER_MODULUS);
        } catch (IllegalArgumentException e) {
            threw = true;
        }
        Asserts.check(threw, "checkModulus rejects an overlong modulus");
        threw = false;
        try {
            Sda.checkRecord(new byte[Sda.MAX_RECORD_LENGTH + 1]);
        } catch (IllegalArgumentException e) {
            threw = true;
        }
        Asserts.check(threw, "checkRecord rejects an overlong record");
        Sda.checkModulus("test", 247, Sda.MAX_ISSUER_MODULUS);
        Sda.checkRecord(new byte[Sda.MAX_RECORD_LENGTH]);
        Asserts.check(true, "checkModulus / checkRecord accept the limit");

        // --- 9F4A (SDA Tag List) containing 82: the SSAD covers the AIP ------
        // EMV v4.4 Book 3 section 10.3: when the SDA Tag List contains 82, the AIP is
        // appended to the static data input before the SSAD hash is checked.
        byte[] aip = { 0x58, 0x00 };
        byte[] daInput = Sda.templateValue(record1);
        byte[] daWithAip = Bytes.concat(daInput, aip);
        byte[] ssadWithAip = Sda.ssad(daWithAip, TestKeys.sdaKeys());
        byte[] recWithAip = Sda.recover(ssadWithAip,
                new BigInteger(1, issuerModulus), issuerExponent);
        byte[] storedHash = Arrays.copyOfRange(recWithAip, recWithAip.length - 21,
                recWithAip.length - 1);
        Asserts.check(Arrays.equals(Digests.sha1(Bytes.concat(
                        Arrays.copyOfRange(recWithAip, 1, recWithAip.length - 21), daWithAip)),
                        storedHash),
                "SSAD with 9F4A 82 covers the AIP");
        Asserts.check(!Arrays.equals(Digests.sha1(Bytes.concat(
                        Arrays.copyOfRange(recWithAip, 1, recWithAip.length - 21), daInput)),
                        storedHash),
                "SSAD without the AIP does not verify");
    }

    private static boolean isZero(byte[] a) {
        for (byte b : a) {
            if (b != 0) {
                return false;
            }
        }
        return true;
    }
}
