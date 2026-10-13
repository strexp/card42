package card42.host.emv.oda;

import java.math.BigInteger;
import java.util.Arrays;

import javax.smartcardio.ResponseAPDU;

import card42.host.emv.lib.IssuerKey;
import card42.host.emv.lib.RsaRecovery;
import card42.host.emv.lib.Terminal;
import card42.host.common.codec.Tags;
import card42.host.common.util.Bytes;
import card42.host.common.util.Digests;
import card42.host.common.util.Sw;

/**
 * Terminal-side recovery of the ICC public key certificates (EMV v4.4 Book 2
 * §6.4/§7.2): reads the certificate record, recovers it with the issuer public
 * key and verifies its structure, hash, PAN and expiry.  Split out of
 * {@link SdaVerifier}, which keeps the SDA path and the shared
 * {@link SdaVerifier.Result}; the two differ only in the record, tags, whether
 * the static data to be authenticated enters the hash input, and the wording.
 */
final class IccKeyRecovery {

    private IccKeyRecovery() {
    }

    /**
     * Reads the ICC PIN encipherment public key certificate from record 4,
     * recovers it with the issuer public key and verifies its structure and
     * hash (EMV v4.4 Book 2, table 23).  The recovered key is in
     * {@link SdaVerifier.Result#key}.
     */
    static SdaVerifier.Result recoverPinKey(Terminal terminal, IssuerKey issuer)
            throws Exception {
        return recoverPinKey(terminal, issuer, null);
    }

    /** As {@link #recoverPinKey(Terminal, IssuerKey)} with the certificate
     * expiry checked against {@code transactionDate} (tag '9A', YYMMDD). */
    static SdaVerifier.Result recoverPinKey(Terminal terminal, IssuerKey issuer,
            byte[] transactionDate) throws Exception {
        // The PIN certificate hash omits the static data to be authenticated
        // (EMV v4.4 Book 2 Table 23 note 31).
        return recoverIssuerSignedKey(terminal, issuer, 4,
                0x9F2D, 0x9F2F, 0x9F2E, "PIN", "ICC PIN", "9F2D/9F2F/9F2E", false,
                transactionDate);
    }

    /**
     * Reads the ICC DDA/CDA public key certificate from record 5, recovers it
     * with the issuer public key and verifies its structure and hash (EMV Book
     * 2, table 13).  The recovered key is in {@link SdaVerifier.Result#key}.
     */
    static SdaVerifier.Result recoverIccKey(Terminal terminal, IssuerKey issuer)
            throws Exception {
        return recoverIccKey(terminal, issuer, null);
    }

    /** As {@link #recoverIccKey(Terminal, IssuerKey)} with the certificate
     * expiry checked against {@code transactionDate} (tag '9A', YYMMDD). */
    static SdaVerifier.Result recoverIccKey(Terminal terminal, IssuerKey issuer,
            byte[] transactionDate) throws Exception {
        // The ICC DDA/CDA certificate hash includes the static data to be
        // authenticated (EMV v4.4 Book 2 §6.4 step 5 / Table 14).
        return recoverIssuerSignedKey(terminal, issuer, 5,
                0x9F46, 0x9F48, 0x9F47, "ICC", "ICC", "9F46/9F48/9F47", true,
                transactionDate);
    }

    /**
     * Reads one ICC public key certificate record, recovers it with the issuer
     * public key and verifies its structure (format '04') and hash (EMV v4.4
     * Book 2 Tables 13/23).
     *
     * @param includeStaticData true for the DDA/CDA certificate, false for the
     *                          PIN encipherment certificate
     */
    private static SdaVerifier.Result recoverIssuerSignedKey(Terminal terminal, IssuerKey issuer,
            int record, int certTag, int remainderTag, int exponentTag,
            String recordLabel, String name, String tagList, boolean includeStaticData,
            byte[] transactionDate) throws Exception {
        ResponseAPDU rec = terminal.readRecord(record, 1);
        if (rec.getSW() != 0x9000) {
            return new SdaVerifier.Result(false,
                    "READ RECORD " + recordLabel + " certificate -> " + Sw.format(rec.getSW()),
                    null);
        }
        byte[] cert = Tags.find(rec.getData(), certTag);
        byte[] remainder = Tags.find(rec.getData(), remainderTag);
        byte[] exponent = Tags.find(rec.getData(), exponentTag);
        // The ICC Public Key Remainder is present only when the ICC modulus is
        // longer than NI-42 (EMV v4.4 Book 2 Table 14).
        if (cert == null || exponent == null) {
            return new SdaVerifier.Result(false,
                    name + " certificate data present (" + tagList + ")",
                    null, null, true);
        }
        // The ICC Public Key Certificate length must equal the Issuer Public Key
        // Modulus length (EMV v4.4 Book 2 §6.4 step 1).
        if (cert.length != issuer.modulusBytes) {
            return new SdaVerifier.Result(false, name + " public key certificate length", null);
        }

        // Recover the certificate with the issuer public key (EMV v4.4 Book 2
        // Tables 13/23).  The leftmost 21 bytes hold the header and the
        // certificate expiration/ serial data; the hash follows the key
        // modulus.
        int leftmost = issuer.modulusBytes - 42;
        byte[] recCert = RsaRecovery.recover(cert, issuer.modulus, issuer.exponent);
        boolean structure = recCert[0] == 0x6A && recCert[1] == 0x04
                && recCert[recCert.length - 1] == (byte) 0xBC;
        // ICC Public Key Algorithm Indicator (offset 18): RSA ('01') only.
        boolean algorithm = recCert[18] == 0x01;
        // Application PAN (offset 2) matches the card PAN, with 'F' padding
        // (EMV v4.4 Book 2 §6.4 step 8).
        boolean panMatch = issuer.pan == null
                || CertificateChecks.applicationPanMatches(recCert, issuer.pan);
        // Certificate Expiration Date (offset 12, MMYY).
        boolean expiry = CertificateChecks.certificateNotExpired(recCert, 12, transactionDate);
        byte[] base = Arrays.copyOfRange(recCert, 1, 21 + leftmost);
        byte[] certHashInput = remainder == null
                ? (includeStaticData
                        ? Bytes.concat(base, exponent,
                                issuer.staticData == null ? new byte[0] : issuer.staticData)
                        : Bytes.concat(base, exponent))
                : (includeStaticData
                        ? Bytes.concat(base, remainder, exponent,
                                issuer.staticData == null ? new byte[0] : issuer.staticData)
                        : Bytes.concat(base, remainder, exponent));
        boolean hash = Arrays.equals(Digests.sha1(certHashInput),
                Arrays.copyOfRange(recCert, 21 + leftmost, 21 + leftmost + 20));
        if (!(structure && algorithm && panMatch && expiry && hash)) {
            return new SdaVerifier.Result(false, name + " public key certificate", null);
        }
        // ICC modulus = leftmost digits (offset 21) followed by the remainder
        // only when NIC > NI-42; a shorter key is stored padded with 'BB' and
        // its length is the ICC Public Key Length byte at offset 19.
        int iccModulusLength = recCert[19] & 0xFF;
        byte[] modulus;
        if (iccModulusLength > leftmost) {
            if (remainder == null) {
                return new SdaVerifier.Result(false, name + " public key remainder", null, null, true);
            }
            modulus = Bytes.concat(
                    Arrays.copyOfRange(recCert, 21, 21 + leftmost), remainder);
        } else {
            modulus = Arrays.copyOfRange(recCert, 21, 21 + iccModulusLength);
        }
        return new SdaVerifier.Result(true, null, new IssuerKey(new BigInteger(1, modulus),
                new BigInteger(1, exponent), issuer.staticData, modulus.length, issuer.pan));
    }
}
