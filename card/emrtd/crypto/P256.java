package card42.emrtd;

import javacard.security.ECKey;

/* P-256 (secp256r1) domain parameters, FIPS 186-4 / BSI TR-03110 Table 6.
 *
 * Shared by PACE (ECDH generic mapping) and Chip Authentication, which both
 * build P-256 keys and previously carried an identical copy of these five
 * constants and of setCurve().  The constants are read-only.
 *
 * @author card42
 */

final class P256 {

    private static final byte[] FP = {
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, 0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF };
    private static final byte[] FA = {
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, 0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFC };
    private static final byte[] FB = {
        0x5A, (byte) 0xC6, 0x35, (byte) 0xD8, (byte) 0xAA, 0x3A, (byte) 0x93, (byte) 0xE7,
        (byte) 0xB3, (byte) 0xEB, (byte) 0xBD, 0x55, 0x76, (byte) 0x98, (byte) 0x86, (byte) 0xBC,
        0x65, 0x1D, 0x06, (byte) 0xB0, (byte) 0xCC, 0x53, (byte) 0xB0, (byte) 0xF6,
        0x3B, (byte) 0xCE, 0x3C, 0x3E, 0x27, (byte) 0xD2, 0x60, 0x4B };
    private static final byte[] FG = {
        0x04,
        0x6B, 0x17, (byte) 0xD1, (byte) 0xF2, (byte) 0xE1, 0x2C, 0x42, 0x47,
        (byte) 0xF8, (byte) 0xBC, (byte) 0xE6, (byte) 0xE5, 0x63, (byte) 0xA4, 0x40, (byte) 0xF2,
        0x77, 0x03, 0x7D, (byte) 0x81, 0x2D, (byte) 0xEB, 0x33, (byte) 0xA0,
        (byte) 0xF4, (byte) 0xA1, 0x39, 0x45, (byte) 0xD8, (byte) 0x98, (byte) 0xC2, (byte) 0x96,
        0x4F, (byte) 0xE3, 0x42, (byte) 0xE2, (byte) 0xFE, 0x1A, 0x7F, (byte) 0x9B,
        (byte) 0x8E, (byte) 0xE7, (byte) 0xEB, 0x4A, 0x7C, 0x0F, (byte) 0x9E, 0x16,
        0x2B, (byte) 0xCE, 0x33, 0x57, 0x6B, 0x31, 0x5E, (byte) 0xCE,
        (byte) 0xCB, (byte) 0xB6, 0x40, 0x68, 0x37, (byte) 0xBF, 0x51, (byte) 0xF5 };
    private static final byte[] FR = {
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, 0x00, 0x00, 0x00, 0x00,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xBC, (byte) 0xE6, (byte) 0xFA, (byte) 0xAD, (byte) 0xA7, 0x17, (byte) 0x9E, (byte) 0x84,
        (byte) 0xF3, (byte) 0xB9, (byte) 0xCA, (byte) 0xC2, (byte) 0xFC, 0x63, 0x25, 0x51 };

    private P256() {
    }

    /** Loads the P-256 domain parameters into an EC key. */
    static void setCurve(ECKey key) {
        key.setFieldFP(FP, (short) 0, (short) FP.length);
        key.setA(FA, (short) 0, (short) FA.length);
        key.setB(FB, (short) 0, (short) FB.length);
        key.setG(FG, (short) 0, (short) FG.length);
        key.setR(FR, (short) 0, (short) FR.length);
        key.setK((short) 1);
    }

    /**
     * True when the 32-byte big-endian value at off is strictly less than the
     * field prime p (a coordinate outside [0, p) is not reduced).
     *
     * <p>The comparison is done explicitly as unsigned bytes: some Java Card
     * platforms implement {@code Util.arrayCompare} with signed bytes (the
     * J3R180 / nextgen simulator does), which made the Chip Authentication
     * peer-point check reject a valid coordinate whenever its first differing
     * byte differed in the high bit, so CA failed intermittently (regression
     * test: {@code EmrtdChipAuthIntegrationTest}).
     */
    static boolean isLessThanP(byte[] value, short off) {
        for (short i = 0; i < (short) 32; i++) {
            short v = (short) (value[(short) (off + i)] & 0xFF);
            short p = (short) (FP[i] & 0xFF);
            if (v != p) {
                return v < p;
            }
        }
        return false; // equal to p is not less than p
    }
}
