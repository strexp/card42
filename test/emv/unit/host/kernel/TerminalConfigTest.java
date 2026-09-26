package card42.test;

import card42.host.common.util.Hex;
import card42.host.emv.kernel.data.TerminalConfig;
import card42.host.emv.kernel.data.TransactionRequest;

/**
 * Unit tests for the {@link TerminalConfig} and {@link TransactionRequest} models
 * (EMV v4.4 Book 4 §A1 / Book 3 §5).  The DOL/BCD processing lives in
 * {@code TerminalDolTest}/{@code BcdTest}.
 */
final class TerminalConfigTest {

    private TerminalConfigTest() {
    }

    static void run() {
        System.out.println("TerminalConfigTest");

        // The terminal config carries the contactless TTQ (Kernel 3 RSA profile).
        TerminalConfig ttqDefault = TerminalConfig.builder().build();
        Asserts.bytes(Hex.parse("31008000"), ttqDefault.ttq, "TTQ value");
        // TTQ byte 1: EMV mode (b6), EMV contact chip (b5) and ODA for online
        // authorizations (b1) set; online PIN (b3) and signature (b2) clear,
        // matching the kernel (Book A Table 5-4).  Byte 3 b8 advertises Issuer
        // Update Processing, which the kernel performs.
        byte[] ttq = ttqDefault.ttq;
        Asserts.eq(0x31, ttq[0] & 0xFF, "TTQ byte 1 ODA-for-online bit");
        Asserts.eq(0x00, ttq[1] & 0xFF, "TTQ byte 2 has no CVM/online-cryptogram bit");
        Asserts.eq(0x80, ttq[2] & 0xFF, "TTQ byte 3 Issuer Update Processing bit");

        TerminalConfig data = TerminalConfig.builder().build();
        // Terminal Type environment: '22' is attended, '14'/'24' unattended
        // (EMV v4.4 Book 4 §5.1: attended is 'x1'/'x2'/'x3').
        Asserts.check(!data.isUnattended(), "merchant terminal '22' is attended");
        TerminalConfig unattended = TerminalConfig.builder().terminalType(0x14).build();
        Asserts.check(unattended.isUnattended(), "terminal '14' is unattended");
        unattended = TerminalConfig.builder().terminalType(0x26).build();
        Asserts.check(unattended.isUnattended(), "terminal '26' is unattended");

        // The TSI is two bytes (EMV v4.4 Book 3 Annex A / Annex C6 Table 47).
        Asserts.eq(2, card42.host.emv.kernel.data.Tsi.LENGTH, "Tsi.LENGTH is two bytes");

        // The default (contactless) capabilities advertise No CVM (byte 2 b4)
        // only and SDA/DDA/CDA (byte 3 b8/b7/b4), not Card capture (b6) or XDA (b3)
        // (EMV v4.4 Book 4 Annex A2 Tables 26/27).
        byte[] contactlessCaps = data.terminalCapabilities;
        Asserts.bytes(Hex.parse("E008C8"), contactlessCaps,
                "contactless terminal capabilities");
        Asserts.eq(0x08, contactlessCaps[1] & 0xFF, "contactless byte 2 is No CVM only");
        Asserts.eq(0xC8, contactlessCaps[2] & 0xFF, "contactless byte 3 is SDA+DDA+CDA");

        // The contact factory advertises the offline PIN methods it performs and
        // No CVM (9F33 byte 2 b8/b5/b4), and SDA/DDA/CDA (byte 3)
        // (EMV v4.4 Book 4 Annex A2 Tables 26/27).
        TerminalConfig contact = TerminalConfig.forContact().build();
        byte[] contactCaps = contact.terminalCapabilities;
        Asserts.bytes(Hex.parse("E098C8"), contactCaps,
                "contact terminal capabilities advertise offline PIN");
        Asserts.eq(0x98, contactCaps[1] & 0xFF,
                "contact byte 2 is plaintext+enciphered offline PIN+No CVM");
        Asserts.eq(0xC8, contactCaps[2] & 0xFF, "contact byte 3 is SDA+DDA+CDA");
        // The terminal AID ('9F06') is per-transaction and defaults to the
        // contactless instance.
        Asserts.bytes(Hex.parse("43415244420102"),
                new TransactionRequest(contact).applicationIdentifier,
                "default terminal AID");

        // Attended / unattended terminal types (EMV v4.4 Book 4 §5.1).
        Asserts.check(TerminalConfig.builder().build().isAttended(), "'22' is attended");
        TerminalConfig unattendedType = TerminalConfig.builder().terminalType(0x14).build();
        Asserts.check(!unattendedType.isAttended(), "'14' is not attended");

        // The exception file matches on PAN, and on PAN Sequence Number when the
        // entry carries one (EMV v4.4 Book 4 §6.3.5).
        TerminalConfig exception = TerminalConfig.builder()
                .addException(Hex.parse("4761739001010010"), null)
                .addException(Hex.parse("4761739001010028"), Hex.parse("01"))
                .build();
        Asserts.check(exception.inExceptionFile(Hex.parse("4761739001010010"), null),
                "PAN match in the exception file");
        Asserts.check(exception.inExceptionFile(
                        Hex.parse("4761739001010028"), Hex.parse("01")),
                "PAN + sequence match in the exception file");
        Asserts.check(!exception.inExceptionFile(
                        Hex.parse("4761739001010028"), Hex.parse("02")),
                "PAN with a different sequence does not match");
        Asserts.check(!exception.inExceptionFile(Hex.parse("4761739001010099"), null),
                "unknown PAN does not match");
        Asserts.check(!exception.inExceptionFile(null, null), "null PAN does not match");
    }
}
