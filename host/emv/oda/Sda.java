package card42.host.emv.oda;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;

import card42.host.common.codec.TlvWriter;
import card42.host.common.codec.Tags;
import card42.host.common.util.Digests;
import card42.host.common.util.Bytes;

/**
 * Offline SDA certificate-chain generator for the simulator personalization
 * (EMV v4.4 Book 2 §5).
 *
 * It signs with the CA and Issuer key pairs of the supplied {@link SdaKeys}
 * profile and produces the EMV data objects of Static Data Authentication from
 * the record 1 value that the card will return:
 *
 * <pre>
 *   8F   CA Public Key Index (1 byte, fixed 01)
 *   90   Issuer Public Key Certificate (NCA = 128 bytes, signed by the CA)
 *   92   Issuer Public Key Remainder  (NI - (NCA - 36) = 36 bytes)
 *   9F32 Issuer Public Key Exponent   (01 00 01)
 *   93   Signed Static Application Data (NI = 128 bytes, signed by the issuer)
 * </pre>
 *
 * The recovered data layouts follow EMV v4.4 Book 2, tables 6 and 7, and the hash
 * inputs follow the recovery rules: the certificate hash covers Certificate
 * Format through the leftmost key digits, the remainder and the exponent; the
 * SSAD hash covers Signed Data Format through the pad pattern followed by the
 * static data to authenticate (the value of the record 1 template, EMV v4.4 Book 3
 * section 10.3).
 */
public final class Sda {

    /**
     * RSA modulus upper bounds of EMV v4.4 Book 2 Table 43 (bytes).  The CA key
     * is at most 248 bytes; an issuer key is at most 247 bytes when the card
     * also carries an ICC (DDA/CDA or PIN encipherment) certificate, and 248
     * for an SDA-only card; the ICC and ICC PIN encipherment keys are at most
     * 247 bytes (EMV v4.4 Book 2 Annex D1.1/D1.2).
     */
    public static final int MAX_CA_MODULUS = 248;
    public static final int MAX_ISSUER_MODULUS = 247;
    public static final int MAX_ISSUER_MODULUS_SDA = 248;
    public static final int MAX_ICC_MODULUS = 247;
    public static final int MAX_PIN_MODULUS = 247;

    /** A record is at most 254 bytes including tag and length (EMV v4.4 Book 3 §7). */
    public static final int MAX_RECORD_LENGTH = 254;

    private Sda() {
    }

    /**
     * The data-authentication objects produced for one payment instance
     * (EMV v4.4 Book 2 §5–§7.2, EMV CPS v2.0 Annex A): the four record templates
     * (records 2-5 of SFI 1) and the ICC DDA/CDA and PIN private keys as
     * modulus/exponent pairs (the EMV CPS v2.0 Annex A DGIs '8103'/'8101' and '8104'/'8102').
     */
    public static final class Result {
        /** DGI '0102' value: 70 { 8F, 90, 92, 9F32[, 9F4A] }. */
        public final byte[] record2;
        /** DGI '0103' value: 70 { 93 }. */
        public final byte[] record3;
        /** DGI '0104' value: 70 { 9F2D, 9F2F, 9F2E }. */
        public final byte[] record4;
        /** DGI '0105' value: 70 { 9F46, 9F48, 9F47 }. */
        public final byte[] record5;
        /** DGI '8103' value: the ICC DDA/CDA key modulus. */
        public final byte[] ddaModulus;
        /** DGI '8101' value: the ICC DDA/CDA private exponent. */
        public final byte[] ddaExponent;
        /** DGI '8104' value: the ICC PIN encipherment key modulus. */
        public final byte[] pinModulus;
        /** DGI '8102' value: the ICC PIN encipherment private exponent. */
        public final byte[] pinExponent;

        Result(byte[] record2, byte[] record3, byte[] record4, byte[] record5,
               byte[] ddaModulus, byte[] ddaExponent,
               byte[] pinModulus, byte[] pinExponent) {
            this.record2 = record2;
            this.record3 = record3;
            this.record4 = record4;
            this.record5 = record5;
            this.ddaModulus = ddaModulus;
            this.ddaExponent = ddaExponent;
            this.pinModulus = pinModulus;
            this.pinExponent = pinExponent;
        }
    }

    /**
     * Builds the data-authentication objects for the given record 1 value (a
     * complete 70 template), together with fresh ICC DDA/CDA and ICC PIN
     * encipherment key pairs.  Records 2-5 are returned as complete 70
     * templates and the private keys as modulus/exponent pairs (EMV CPS v2.0 Annex A).
     */
    public static Result personalize(byte[] record1Value, SdaKeys keys) {
        byte[] daInput = templateValue(record1Value);
        byte[] pan = Tags.find(record1Value, 0x5A);
        byte[] expiry = Tags.find(record1Value, 0x5F24);
        if (pan == null || pan.length < 4) {
            throw new IllegalArgumentException("@sda: record 1 has no usable PAN (5A)");
        }
        if (expiry == null || expiry.length < 3) {
            throw new IllegalArgumentException("@sda: record 1 has no expiry (5F24)");
        }

        byte[] issuerModulus = toFixed(keys.issuerModulus, keys.issuerModulusBytes);
        byte[] cert = issuerCertificate(issuerModulus, pan, expiry, keys);
        byte[] remainder = Arrays.copyOfRange(issuerModulus,
                keys.caModulusBytes - 36, keys.issuerModulusBytes);
        byte[] ssad = signedStaticApplicationData(daInput, keys);

        // ICC DDA/CDA key pair (EMV v4.4 Book 2 §6.5/§6.6).
        KeyPair ddaPair = generateRsaKeyPair(keys.iccModulusBytes);
        RSAPublicKey ddaPublic = (RSAPublicKey) ddaPair.getPublic();
        RSAPrivateCrtKey ddaPrivate = (RSAPrivateCrtKey) ddaPair.getPrivate();
        byte[] ddaModulus = toFixed(ddaPublic.getModulus(), keys.iccModulusBytes);
        byte[] ddaCert = iccCertificate(ddaModulus, keys.iccModulusBytes,
                keys.iccModulusBytes - 42, pan, expiry, 0x04, daInput, keys);
        byte[] ddaRemainder = Arrays.copyOfRange(ddaModulus,
                keys.iccModulusBytes - 42, keys.iccModulusBytes);

        // ICC PIN encipherment key pair (EMV v4.4 Book 2 §7.2).
        KeyPair pinPair = generateRsaKeyPair(keys.pinModulusBytes);
        RSAPublicKey pinPublic = (RSAPublicKey) pinPair.getPublic();
        RSAPrivateCrtKey pinPrivate = (RSAPrivateCrtKey) pinPair.getPrivate();
        byte[] pinModulus = toFixed(pinPublic.getModulus(), keys.pinModulusBytes);
        byte[] pinCert = iccCertificate(pinModulus, keys.pinModulusBytes, keys.pinLeftmost(),
                pan, expiry, 0x04, null, keys);

        // Record 2: SDA certificate chain (8F/90/92/9F32).
        ByteArrayOutputStream r2 = new ByteArrayOutputStream();
        TlvWriter.writeTlv(r2, 0x8F, keys.caPublicKeyIndex);
        TlvWriter.writeTlv(r2, 0x90, cert);
        TlvWriter.writeTlv(r2, 0x92, remainder);
        TlvWriter.writeTlv(r2, 0x9F32, keys.exponent);
        // Record 3: SSAD.
        ByteArrayOutputStream r3 = new ByteArrayOutputStream();
        TlvWriter.writeTlv(r3, 0x93, ssad);
        // Record 4: ICC PIN encipherment public key certificate.
        ByteArrayOutputStream r4 = new ByteArrayOutputStream();
        TlvWriter.writeTlv(r4, 0x9F2D, pinCert);
        TlvWriter.writeTlv(r4, 0x9F2F,
                Arrays.copyOfRange(pinModulus, keys.pinLeftmost(), keys.pinModulusBytes));
        TlvWriter.writeTlv(r4, 0x9F2E, keys.exponent);
        // Record 5: ICC DDA/CDA public key certificate.
        ByteArrayOutputStream r5 = new ByteArrayOutputStream();
        TlvWriter.writeTlv(r5, 0x9F46, ddaCert);
        TlvWriter.writeTlv(r5, 0x9F48, ddaRemainder);
        TlvWriter.writeTlv(r5, 0x9F47, keys.exponent);

        // The generated key material must respect the EMV v4.4 Book 2 Table 43 modulus
        // bounds and each record the EMV v4.4 Book 3 §7 254-byte limit (EMV v4.4 Book 2 Annex
        // D1.1/D1.2); otherwise the chain could not be stored or served.
        checkModulus("CA", keys.caModulusBytes, MAX_CA_MODULUS);
        checkModulus("issuer", keys.issuerModulusBytes, MAX_ISSUER_MODULUS);
        checkModulus("ICC", keys.iccModulusBytes, MAX_ICC_MODULUS);
        checkModulus("PIN", keys.pinModulusBytes, MAX_PIN_MODULUS);
        byte[] record2 = record(r2.toByteArray());
        byte[] record3 = record(r3.toByteArray());
        byte[] record4 = record(r4.toByteArray());
        byte[] record5 = record(r5.toByteArray());
        checkRecord(record2);
        checkRecord(record3);
        checkRecord(record4);
        checkRecord(record5);

        return new Result(record2, record3, record4, record5,
                ddaModulus, toFixed(ddaPrivate.getPrivateExponent(), keys.iccModulusBytes),
                pinModulus, toFixed(pinPrivate.getPrivateExponent(), keys.pinModulusBytes));
    }

    /**
     * Rejects a modulus longer than the EMV v4.4 Book 2 Table 43 bound.  The generator
     * uses fixed key sizes, so this guards a future change of the key profile.
     */
    public static void checkModulus(String name, int length, int max) {
        if (length > max) {
            throw new IllegalArgumentException("@sda: " + name + " modulus "
                    + length + " B exceeds the Book 2 Table 43 limit of " + max + " B");
        }
    }

    /** Rejects a record longer than the EMV v4.4 Book 3 §7 254-byte limit. */
    public static void checkRecord(byte[] record) {
        if (record.length > MAX_RECORD_LENGTH) {
            throw new IllegalArgumentException("@sda: record of " + record.length
                    + " B exceeds the Book 3 section 7 limit of "
                    + MAX_RECORD_LENGTH + " B");
        }
    }

    /** Wraps a record body in a 70 record template. */
    private static byte[] record(byte[] body) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        TlvWriter.writeTlv(out, 0x70, body);
        return out.toByteArray();
    }

    /** Generates an ICC key pair (RSA, e=65537) at the given modulus length. */
    private static KeyPair generateRsaKeyPair(int modulusBytes) {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(modulusBytes * 8);
            return generator.generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException("@sda: cannot generate RSA key pair", e);
        }
    }

    /**
     * Builds and issuer-signs an ICC public key certificate (tag 9F46 for the
     * DDA/CDA key, 9F2D for the PIN key), recovered data format per EMV v4.4 Book 2
     * tables 13/23: certificate format, a 10-byte PAN, the leftmost modulus
     * field and the issuer signature.  Both certificate formats are 0x04
     * (EMV v4.4 Book 2 Tables 14 and 23).  For the DDA/CDA certificate the hash input
     * also covers the static data to be authenticated (EMV v4.4 Book 2 §6.4 step 5 /
     * Table 14); the PIN certificate hash omits it (EMV v4.4 Book 2 Table 23 note 31).
     */
    private static byte[] iccCertificate(byte[] modulus, int modulusLen, int leftmost,
                                         byte[] pan, byte[] expiry, int certFormat,
                                         byte[] staticData, SdaKeys keys) {
        byte[] exponent = toFixed(BigInteger.valueOf(65537), 3);
        byte[] cert = new byte[keys.issuerModulusBytes];
        cert[0] = 0x6A;                                  // recovered data header
        cert[1] = (byte) certFormat;                     // 04 (ICC and PIN)
        System.arraycopy(pan, 0, cert, 2, Math.min(pan.length, 10));
        for (int i = 2 + Math.min(pan.length, 10); i < 12; i++) {
            cert[i] = (byte) 0xFF;                       // PAN padded with F
        }
        cert[12] = expiry[1];                            // expiration MM
        cert[13] = expiry[0];                            // expiration YY
        cert[14] = 0x00;                                 // certificate serial
        cert[15] = 0x00;
        cert[16] = 0x01;
        cert[17] = 0x01;                                 // hash algorithm (SHA-1)
        cert[18] = 0x01;                                 // public key algorithm (RSA)
        cert[19] = (byte) modulusLen;                    // public key length
        cert[20] = (byte) exponent.length;               // exponent length
        System.arraycopy(modulus, 0, cert, 21, leftmost);

        // Hash input: Certificate Format .. leftmost key digits, then the
        // remainder, the exponent and (DDA/CDA only) the static data to be
        // authenticated (EMV v4.4 Book 2, tables 14/23).
        byte[] hashInput = Bytes.concat(
                Arrays.copyOfRange(cert, 1, 21 + leftmost),
                Arrays.copyOfRange(modulus, leftmost, modulusLen),
                exponent,
                staticData == null ? new byte[0] : staticData);
        System.arraycopy(Digests.sha1(hashInput), 0, cert, 21 + leftmost, 20);
        cert[keys.issuerModulusBytes - 1] = (byte) 0xBC;             // recovered data trailer

        return rsaPrivate(cert, keys.issuerModulus, keys.issuerPrivateExponent);
    }

    /** Builds and CA-signs the Issuer Public Key Certificate (tag 90). */
    private static byte[] issuerCertificate(byte[] issuerModulus, byte[] pan,
                                            byte[] expiry, SdaKeys keys) {
        int keyFieldLength = keys.caModulusBytes - 36;
        byte[] cert = new byte[keys.caModulusBytes];
        cert[0] = 0x6A;                                  // recovered data header
        cert[1] = 0x02;                                  // certificate format
        System.arraycopy(pan, 0, cert, 2, 4);            // issuer identifier
        cert[6] = expiry[1];                             // expiration MM
        cert[7] = expiry[0];                             // expiration YY
        cert[8] = 0x00;                                  // certificate serial
        cert[9] = 0x00;
        cert[10] = 0x01;
        cert[11] = 0x01;                                 // hash algorithm (SHA-1)
        cert[12] = 0x01;                                 // issuer PK algorithm (RSA)
        cert[13] = (byte) keys.issuerModulusBytes;      // issuer public key length
        cert[14] = (byte) keys.exponent.length;         // exponent length
        System.arraycopy(issuerModulus, 0, cert, 15, keyFieldLength);

        // Hash input: Certificate Format .. leftmost key digits, remainder,
        // exponent (EMV v4.4 Book 2, table 6 step 5).
        byte[] hashInput = Bytes.concat(
                Arrays.copyOfRange(cert, 1, 1 + 14 + keyFieldLength),
                Arrays.copyOfRange(issuerModulus, keyFieldLength, keys.issuerModulusBytes),
                keys.exponent);
        System.arraycopy(Digests.sha1(hashInput), 0, cert, 15 + keyFieldLength, 20);
        cert[keys.caModulusBytes - 1] = (byte) 0xBC;             // recovered data trailer

        return rsaPrivate(cert, keys.caModulus, keys.caPrivateExponent);
    }

    /** Builds and issuer-signs the Signed Static Application Data (tag 93). */
    private static byte[] signedStaticApplicationData(byte[] daInput, SdaKeys keys) {
        byte[] rec = new byte[keys.issuerModulusBytes];
        rec[0] = 0x6A;                                   // recovered data header
        rec[1] = 0x03;                                   // signed data format
        rec[2] = 0x01;                                   // hash algorithm (SHA-1)
        rec[3] = 0x00;                                   // data authentication code
        rec[4] = 0x00;
        for (int i = 5; i < keys.issuerModulusBytes - 21; i++) {
            rec[i] = (byte) 0xBB;                        // pad pattern
        }

        // Hash input: Signed Data Format .. pad pattern, then the static data
        // to authenticate (EMV v4.4 Book 2, table 7 step 5).
        byte[] hashInput = Bytes.concat(
                Arrays.copyOfRange(rec, 1, keys.issuerModulusBytes - 21), daInput);
        System.arraycopy(Digests.sha1(hashInput), 0, rec, keys.issuerModulusBytes - 21, 20);
        rec[keys.issuerModulusBytes - 1] = (byte) 0xBC;  // recovered data trailer

        return rsaPrivate(rec, keys.issuerModulus, keys.issuerPrivateExponent);
    }

    // --- shared recovery helpers (also used by the simulator verifiers) --------

    /**
     * Builds and issuer-signs an SSAD over daInput.  Exposed for the 9F4A
     * (SDA Tag List) tests, which need an SSAD whose hash input includes the
     * AIP (docs/specs/common/toolchain.md §6).
     */
    public static byte[] ssad(byte[] daInput, SdaKeys keys) {
        return signedStaticApplicationData(daInput, keys);
    }

    /**
     * Raw RSA public-key recovery: returns signature^exponent mod modulus as a
     * fixed modulus-length byte string (EMV v4.4 Book 2 Annex A2.1).
     */
    public static byte[] recover(byte[] signature, BigInteger modulus, BigInteger exponent) {
        return toFixed(new BigInteger(1, signature).modPow(exponent, modulus), modulusLength(modulus));
    }

    /** The value of a complete 70 template, without the wrapper. */
    public static byte[] templateValue(byte[] record) {
        if (record.length < 2 || (record[0] & 0xFF) != 0x70) {
            throw new IllegalArgumentException("Not a 70 record template");
        }
        int first = record[1] & 0xFF;
        int lengthField = (first & 0x80) == 0 ? 1 : 1 + (first & 0x7F);
        return Arrays.copyOfRange(record, 1 + lengthField, record.length);
    }

    // --- small helpers -------------------------------------------------------

    private static byte[] rsaPrivate(byte[] block, BigInteger modulus, BigInteger privateExponent) {
        return toFixed(new BigInteger(1, block).modPow(privateExponent, modulus), modulusLength(modulus));
    }

    private static int modulusLength(BigInteger modulus) {
        return (modulus.bitLength() + 7) / 8;
    }

    /** Big-endian byte string of exactly length bytes, left-padded with zero. */
    private static byte[] toFixed(BigInteger value, int length) {
        byte[] raw = value.toByteArray();
        int start = (raw.length > 1 && raw[0] == 0) ? 1 : 0;
        int size = raw.length - start;
        if (size > length) {
            throw new IllegalArgumentException("Value does not fit in " + length + " bytes");
        }
        byte[] out = new byte[length];
        System.arraycopy(raw, start, out, length - size, size);
        return out;
    }
}
