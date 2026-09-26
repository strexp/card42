package card42.test;

import java.util.Arrays;
import card42.host.common.util.Hex;
import card42.host.emv.kernel.core.TransactionResult;
import card42.host.emv.kernel.data.TerminalConfig;
import card42.host.emv.kernel.data.TerminalDol;
import card42.host.emv.kernel.data.TransactionRequest;

/**
 * Unit tests for {@link TerminalDol} (DOL building, EMV v4.4 Book 3 §5.4).
 */
final class TerminalDolTest {

    private TerminalDolTest() {
    }

    static void run() {
        System.out.println("TerminalDolTest");

        // A DOL is filled tag by tag, padded/truncated to the declared length.
        TerminalConfig config = TerminalConfig.builder()
                .ttq(Hex.parse("30000000"))
                .terminalType(0x22)
                .build();
        TransactionRequest data = new TransactionRequest(config);
        TransactionResult.Mutable result = new TransactionResult.Mutable();
        byte[] dol = Hex.parse("9F66 04 9F35 01 9F02 06 9F37 04");
        Asserts.eq(15, TerminalDol.dolDataLength(dol), "DOL data length");
        byte[] built = TerminalDol.buildDolData(data, result, dol);
        Asserts.eq(15, built.length, "built DOL length");
        Asserts.bytes(Hex.parse("300000002200000000050011223344"), built, "built DOL content");

        // An unknown tag yields an all-zero field of the declared length, so the
        // card's length validation still matches.
        byte[] unknown = TerminalDol.buildDolData(data, result, Hex.parse("9F99 03"));
        Asserts.bytes(new byte[] { 0, 0, 0 }, unknown, "unknown DOL tag is zero-filled");

        // The terminal model carries the contactless TTQ (Kernel 3 RSA profile).
        // (The test above overrode it to 30000000 for the DOL check.)
        TransactionRequest ttqDefault = new TransactionRequest(TerminalConfig.builder().build());
        Asserts.bytes(Hex.parse("31008000"), TerminalDol.valueFor(ttqDefault, result, 0x9F66),
                "TTQ value");
        Asserts.check(Arrays.equals(new byte[] { 0x22 },
                        TerminalDol.valueFor(data, result, 0x9F35)),
                "terminal type value");
        Asserts.check(TerminalDol.valueFor(data, result, 0x1234) == null,
                "unknown tag has no value");

        // DOL padding when the declared length differs from the value length
        // (EMV v4.4 Book 3 §5.4): numeric keeps the rightmost bytes and left-pads with
        // zeroes, any other format keeps the leftmost bytes and right-pads.
        data.transactionType = 0x20;
        Asserts.bytes(Hex.parse("0020"), TerminalDol.buildDolData(data, result, Hex.parse("9C 02")),
                "numeric DOL field is left-padded");
        Asserts.bytes(Hex.parse("50"), TerminalDol.buildDolData(data, result, Hex.parse("9F1A 01")),
                "numeric DOL field keeps the rightmost byte");
        Asserts.bytes(Hex.parse("000250"), TerminalDol.buildDolData(data, result, Hex.parse("9F1A 03")),
                "numeric DOL field is left-padded to a longer length");
        Asserts.bytes(Hex.parse("3000"), TerminalDol.buildDolData(data, result, Hex.parse("9F66 02")),
                "non-numeric DOL field keeps the leftmost bytes");
        Asserts.bytes(Hex.parse("300000000000"),
                TerminalDol.buildDolData(data, result, Hex.parse("9F66 06")),
                "non-numeric DOL field is right-padded");
        // Compressed numeric (cn) format is classified for the 'FF' padding
        // rule (EMV v4.4 Book 3 §5.4); the terminal model currently carries no
        // cn data object (PAN/track data are ICC-sourced).
        Asserts.check(TerminalDol.isCompressedNumeric(0x5A), "PAN is compressed numeric");
        Asserts.check(TerminalDol.isCompressedNumeric(0x57), "track 2 is compressed numeric");
        Asserts.check(!TerminalDol.isCompressedNumeric(0x9F02),
                "amount is not compressed numeric");

        // Transaction Sequence Counter ('9F41', EMV v4.4 Book 4 §6.5.5): initial
        // value 1, incremented per transaction, never zero.
        TransactionRequest tsc = new TransactionRequest(TerminalConfig.builder().build());
        tsc.transactionSequenceCounter = tsc.config.state.nextTransactionSequenceCounter();
        Asserts.bytes(Hex.parse("00000001"),
                TerminalDol.buildDolData(tsc, result, Hex.parse("9F41 04")),
                "first transaction sequence counter is 1");
        tsc.transactionSequenceCounter = tsc.config.state.nextTransactionSequenceCounter();
        Asserts.bytes(Hex.parse("00000002"),
                TerminalDol.buildDolData(tsc, result, Hex.parse("9F41 04")),
                "transaction sequence counter increments");

        // POI Information (SDOL tag '8B', EMV Contactless Book B v2.12 Annex A
        // Table A-1 / §C.1.3): the value is the Terminal Category POI
        // Information object '0001' + length + value (Table A-2).
        TransactionRequest poi = new TransactionRequest(TerminalConfig.builder().build());
        Asserts.bytes(Hex.parse("0001020001"),
                TerminalDol.valueFor(poi, result, 0x8B),
                "SDOL 8B carries the default Terminal Category '0001'");
        TransactionRequest poiOther = new TransactionRequest(TerminalConfig.builder()
                .terminalCategory(Hex.parse("0002")).build());
        Asserts.bytes(Hex.parse("0001020002"),
                TerminalDol.valueFor(poiOther, result, 0x8B),
                "SDOL 8B follows the configured Terminal Category");
        Asserts.bytes(Hex.parse("0001020001"),
                TerminalDol.buildDolData(poi, result, Hex.parse("8B 05")),
                "SDOL 8B is filled with the POI Information value");
    }
}
