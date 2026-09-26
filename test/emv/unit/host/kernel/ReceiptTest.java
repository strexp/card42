package card42.test;

import java.nio.charset.StandardCharsets;

import card42.host.emv.kernel.core.TransactionResult;
import card42.host.emv.kernel.data.TerminalConfig;
import card42.host.emv.kernel.data.TransactionRequest;
import card42.host.emv.report.Receipt;
import card42.host.emv.report.ReceiptRenderer;
import card42.host.common.util.Hex;

/**
 * Pure-JVM tests for the receipt model and the reference renderers:
 * the PAN mask, the amount and the text / JSON output.
 *
 * <p>Internal receipt model/renderer coverage, not an EMV/ICAO/BSI/CPS clause.
 */
final class ReceiptTest {

    private ReceiptTest() {
    }

    static void run() {
        System.out.println("Receipt");

        TerminalConfig config = TerminalConfig.builder()
                .terminalId(Hex.parse("454D5634323030303030303030"))
                .merchantName("card42 TEST".getBytes(StandardCharsets.US_ASCII))
                .build();
        TransactionRequest data = new TransactionRequest(config);
        data.amountAuthorised = Hex.parse("000000001234");
        data.transactionCurrencyCode = Hex.parse("0978");
        data.transactionDate = Hex.parse("260925");
        data.transactionTime = Hex.parse("120000");

        TransactionResult.Mutable result = new TransactionResult.Mutable();
        result.aidHex("43415244420101");
        result.putRecord((1 << 8) | 1, Hex.parse("70 07 5A 05 12 34 56 78 90"));
        result.cvmResults(Hex.parse("010002"));
        result.arc(Hex.parse("3030"));

        Receipt r = Receipt.from(result, data);
        Asserts.check(r.approved, "approved receipt");
        Asserts.eq("43415244420101", r.aidHex, "AID carried");
        Asserts.eq("******7890", r.panMasked, "PAN masked to the last four digits");
        Asserts.eq(1234, r.amountMinor(), "amount in minor units");
        Asserts.eq("010002", r.cvmResults, "CVM results");
        Asserts.eq("3030", r.arc, "ARC");

        String text = ReceiptRenderer.text().render(r);
        Asserts.check(text.contains("card42 RECEIPT"), "text receipt header");
        Asserts.check(text.contains("APPROVED"), "text receipt result");
        Asserts.check(text.contains("******7890"), "text receipt PAN");
        Asserts.check(text.contains("1234"), "text receipt amount");
        Asserts.check(text.contains("card42 TEST"), "text receipt merchant");

        String json = ReceiptRenderer.json().render(r);
        Asserts.check(json.startsWith("{") && json.endsWith("}"), "json receipt braces");
        Asserts.check(json.contains("\"approved\":true"), "json approved");
        Asserts.check(json.contains("\"pan\":\"******7890\""), "json PAN");
        Asserts.check(json.contains("\"amount\":1234"), "json amount");
        Asserts.check(json.contains("\"merchantName\":\"card42 TEST\""), "json merchant");

        result.declined(true);
        Asserts.check(!Receipt.from(result, data).approved, "declined receipt");
        Asserts.check(ReceiptRenderer.text().render(Receipt.from(result, data))
                        .contains("DECLINED"),
                "text receipt declined");
    }
}
