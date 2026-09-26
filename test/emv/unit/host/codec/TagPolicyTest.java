package card42.test;

import java.io.ByteArrayOutputStream;
import card42.host.common.util.Hex;
import card42.host.emv.lib.TagPolicy;
import card42.host.common.codec.Tags;
import card42.host.common.codec.TlvWriter;

/**
 * Pure-JVM tests for the EMV v4.4 Book 3 §7.5 data-object policy
 * (docs/specs/common/toolchain.md §6): terminal-/issuer-sourced objects from the ICC
 * are ignored, and format errors in the Table 34 objects are tolerated.
 */
final class TagPolicyTest {

    private TagPolicyTest() {
    }

    static void run() throws Exception {
        System.out.println("TagPolicy");

        // --- EMV v4.4 Book 3 §7.5: terminal/issuer-sourced data from the ICC -----------
        // The terminal shall ignore data objects the dictionary designates as
        // terminal- or issuer-sourced, even if the card sends them.
        ByteArrayOutputStream card = new ByteArrayOutputStream();
        TlvWriter.writeTlv(card, 0x9F02, Hex.parse("000000001000")); // terminal
        TlvWriter.writeTlv(card, 0x91, Hex.parse("AABBCCDD"));       // issuer
        TlvWriter.writeTlv(card, 0x9F0E, Hex.parse("8000000000"));   // ICC
        byte[] cardBytes = card.toByteArray();
        Asserts.check(Tags.find(cardBytes, 0x9F02) != null,
                "find returns a terminal-sourced 9F02");
        Asserts.check(TagPolicy.findIcc(cardBytes, 0x9F02) == null,
                "findIcc ignores a terminal-sourced 9F02");
        Asserts.check(TagPolicy.findIcc(cardBytes, 0x91) == null,
                "findIcc ignores an issuer-sourced 91");
        Asserts.bytes(Hex.parse("8000000000"), TagPolicy.findIcc(cardBytes, 0x9F0E),
                "findIcc keeps an ICC-sourced 9F0E");
        Asserts.check(TagPolicy.isTerminalOrIssuerSourced(0x9F02),
                "9F02 is terminal-sourced");
        Asserts.check(TagPolicy.isTerminalOrIssuerSourced(0x91),
                "91 is issuer-sourced");
        Asserts.check(!TagPolicy.isTerminalOrIssuerSourced(0x9F0E),
                "9F0E is ICC-sourced");

        // --- EMV v4.4 Book 3 §7.5 / Table 34: format errors in the listed objects -----
        // are ignored (the object is treated as absent) instead of aborting.
        Asserts.check(TagPolicy.isFormatErrorTolerated(0x9F0C),
                "9F0C format errors are tolerated");
        Asserts.check(TagPolicy.isFormatErrorTolerated(0x9F4D),
                "9F4D format errors are tolerated");
        Asserts.check(!TagPolicy.isFormatErrorTolerated(0x9F0E),
                "9F0E is not in the Table 34 list");
        ByteArrayOutputStream badIine = new ByteArrayOutputStream();
        TlvWriter.writeTlv(badIine, 0x9F0C, Hex.parse("1234")); // 2 bytes: not 3 or 4
        byte[] badIineBytes = badIine.toByteArray();
        Asserts.check(Tags.find(badIineBytes, 0x9F0C) != null,
                "find returns the malformed IINE");
        Asserts.check(TagPolicy.findIcc(badIineBytes, 0x9F0C) == null,
                "findIcc ignores a malformed IINE");
        Asserts.check(TagPolicy.isMalformed(0x9F0C, Hex.parse("1234")),
                "a 2-byte IINE is malformed");
        Asserts.check(!TagPolicy.isMalformed(0x9F0C, Hex.parse("123456")),
                "a 3-byte IINE is well-formed");
        Asserts.check(!TagPolicy.isMalformed(0x9F0C, Hex.parse("12345678")),
                "a 4-byte IINE is well-formed");
        Asserts.check(TagPolicy.isMalformed(0x42, Hex.parse("1234")),
                "a 2-byte IIN is malformed");
        Asserts.check(TagPolicy.isMalformed(0x9F4D, Hex.parse("0F")),
                "a 1-byte Log Entry is malformed");
    }
}
