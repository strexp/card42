package card42.test;

import card42.emv.CardRiskManagement;

/**
 * Pure-JVM tests for Card Action Analysis (EMV v4.4 Book 3 §10.8): the three
 * Issuer Action Codes, their defaults and the request/response hierarchy.
 */
final class CardRiskManagementTest {

    private static final byte[] NO_TVR = { 0x00, 0x00, 0x00, 0x00, 0x00 };
    private static final byte[] IAC_DENIAL = { (byte) 0x80, 0, 0, 0, 0 };
    private static final byte[] IAC_ONLINE = {
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF };
    private static final byte[] IAC_DEFAULT = {
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF };
    private static final byte[] IAC_ZERO = { 0, 0, 0, 0, 0 };

    private CardRiskManagementTest() {
    }

    static void run() {
        System.out.println("CardRiskManagement");

        // No TVR bit -> approve offline.
        Asserts.eq(0x40, decide(NO_TVR, IAC_DENIAL, IAC_ONLINE, IAC_DEFAULT),
                "no TVR -> TC");

        // IAC-Denial wins over IAC-Online.
        Asserts.eq(0x00, decide(new byte[] { (byte) 0x80, 0, 0, 0, 0 },
                IAC_DENIAL, IAC_ONLINE, IAC_DEFAULT), "denial -> AAC");

        // A bit only in IAC-Online -> go online.
        Asserts.eq(0x80, decide(new byte[] { 0x40, 0, 0, 0, 0 },
                IAC_DENIAL, IAC_ONLINE, IAC_DEFAULT), "online -> ARQC");

        // Same bit with no IAC-Online but with IAC-Default -> decline.
        Asserts.eq(0x00, decide(new byte[] { 0x40, 0, 0, 0, 0 },
                IAC_DENIAL, IAC_ZERO, IAC_DEFAULT), "default -> AAC");

        // No action code matches -> approve offline.
        Asserts.eq(0x40, decide(new byte[] { 0x40, 0, 0, 0, 0 },
                IAC_DENIAL, IAC_ZERO, IAC_ZERO), "no matching action -> TC");

        // A short IAC only matches its leading bytes.
        Asserts.eq(0x00, CardRiskManagement.decide(
                new byte[] { (byte) 0x80, 0, 0, 0, 0 }, (short) 0, (short) 5,
                new byte[] { (byte) 0x80 }, (short) 1,
                IAC_ONLINE, (short) 5, IAC_DEFAULT, (short) 5) & 0xFF,
                "short IAC matches leading byte");

        // Request/response hierarchy: the card may only downgrade.
        Asserts.eq(0x80, CardRiskManagement.capToRequest((byte) 0x80, (byte) 0x40) & 0xFF,
                "TC decision capped to ARQC request");
        Asserts.eq(0x80, CardRiskManagement.capToRequest((byte) 0x40, (byte) 0x80) & 0xFF,
                "ARQC decision against TC request");
        Asserts.eq(0x00, CardRiskManagement.capToRequest((byte) 0x40, (byte) 0x00) & 0xFF,
                "AAC decision against TC request");
        Asserts.eq(0x00, CardRiskManagement.capToRequest((byte) 0x00, (byte) 0x40) & 0xFF,
                "TC decision capped to AAC request");

        // An ARQC request is never upgraded to a TC (EMV v4.4 Book 3 section 9.3).
        Asserts.eq(0x80, CardRiskManagement.capToRequest((byte) 0x80, (byte) 0x40) & 0xFF,
                "ARQC request is not upgraded to TC");
        // An AAC request always yields an AAC.
        Asserts.eq(0x00, CardRiskManagement.capToRequest((byte) 0x00, (byte) 0x40) & 0xFF,
                "AAC request with TC decision is AAC");
        Asserts.eq(0x00, CardRiskManagement.capToRequest((byte) 0x00, (byte) 0x80) & 0xFF,
                "AAC request with ARQC decision is AAC");

        // IAC longer than the TVR: only the leading bytes matter.
        Asserts.eq(0x00, decide(new byte[] { (byte) 0x80, 0, 0, 0, 0 },
                IAC_DENIAL, IAC_ZERO, IAC_ZERO), "denial with a 5-byte TVR");
        Asserts.eq(0x40, decide(new byte[] { 0x00, 0x00, 0x00 }, IAC_ZERO, IAC_ZERO,
                new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00 }),
                "IAC longer than the TVR only matches leading bytes");
        // IAC shorter than the TVR: trailing TVR bits have no effect, so a bit
        // beyond the 1-byte default IAC does not match and the card approves.
        Asserts.eq(0x40, CardRiskManagement.decide(
                new byte[] { 0x00, (byte) 0x80, 0, 0, 0 }, (short) 0, (short) 5,
                IAC_ZERO, (short) 5, IAC_ZERO, (short) 5,
                new byte[] { (byte) 0x80 }, (short) 1) & 0xFF,
                "IAC shorter than the TVR ignores trailing bits");

        // All three action codes match: Denial wins (EMV v4.4 Book 3 section 10.7 order).
        Asserts.eq(0x00, decide(new byte[] { (byte) 0x80, 0, 0, 0, 0 },
                IAC_DENIAL, IAC_ONLINE, IAC_DEFAULT), "denial wins over online/default");
    }

    private static long decide(byte[] tvr, byte[] denial, byte[] online, byte[] def) {
        return CardRiskManagement.decide(tvr, (short) 0, (short) tvr.length,
                denial, (short) denial.length,
                online, (short) online.length,
                def, (short) def.length) & 0xFF;
    }
}
