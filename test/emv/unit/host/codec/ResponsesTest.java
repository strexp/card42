package card42.test;

import card42.host.common.codec.Responses;

/**
 * Pure-JVM tests for the Cryptogram Information Data helpers
 * (EMV v4.4 Book 3 Table 15): the advice bit b4 and the reason/advice code
 * b3-b1 that drive Card Action Analysis (EMV v4.4 Book 4 §6.3.7).
 */
final class ResponsesTest {

    private ResponsesTest() {
    }

    static void run() {
        System.out.println("Responses");

        byte tc = (byte) 0x40;
        Asserts.check(!Responses.adviceRequired(tc), "TC has no advice bit");
        Asserts.eq(0, Responses.adviceReason(tc), "TC reason/advice code is 0");

        byte aacService = (byte) (0x08 | 0x01); // advice + reason 001b
        Asserts.check(Responses.adviceRequired(aacService), "AAC advice bit is set");
        Asserts.eq(Responses.CID_SERVICE_NOT_ALLOWED, Responses.adviceReason(aacService),
                "reason is Service not allowed");

        byte arqcAuthFailed = (byte) (0x80 | 0x08 | 0x03);
        Asserts.check(Responses.adviceRequired(arqcAuthFailed), "ARQC advice bit is set");
        Asserts.eq(Responses.CID_ISSUER_AUTH_FAILED, Responses.adviceReason(arqcAuthFailed),
                "reason is Issuer authentication failed");
    }
}
