package card42.host.emv.report;

import card42.host.common.codec.Json;
import card42.host.common.util.Hex;

/**
 * Renders a {@link Receipt} for a cardholder.  The actual presentation (screen,
 * printer) is out of scope of this project and lives in a separate UI project;
 * {@link #text()} and {@link #json()} are the reference implementations.
 */
public interface ReceiptRenderer {

    /** Renders the receipt as text. */
    String render(Receipt receipt);

    /** The reference plain-text renderer. */
    static ReceiptRenderer text() {
        return new TextRenderer();
    }

    /** The reference JSON renderer. */
    static ReceiptRenderer json() {
        return new JsonRenderer();
    }

    /** Plain-text reference renderer. */
    final class TextRenderer implements ReceiptRenderer {
        @Override
        public String render(Receipt r) {
            StringBuilder out = new StringBuilder();
            line(out, "card42 RECEIPT");
            field(out, "Merchant", r.merchantName);
            field(out, "Terminal", r.terminalId);
            field(out, "AID", r.aidHex);
            field(out, "PAN", r.panMasked);
            field(out, "Amount", r.amountMinor() + (r.currency == null ? ""
                    : " " + Hex.format(r.currency)));
            field(out, "Date/Time", dateTime(r));
            field(out, "CVM", r.cvmResults);
            field(out, "ARC", r.arc);
            line(out, r.approved ? "APPROVED" : "DECLINED");
            return out.toString();
        }

        private static String dateTime(Receipt r) {
            if (r.date == null && r.time == null) {
                return null;
            }
            return (r.date == null ? "" : Hex.format(r.date))
                    + (r.time == null ? "" : " " + Hex.format(r.time));
        }
    }

    /** JSON reference renderer. */
    final class JsonRenderer implements ReceiptRenderer {
        @Override
        public String render(Receipt r) {
            Json.Obj out = new Json.Obj().put("approved", r.approved);
            if (r.aidHex != null) {
                out.put("aid", r.aidHex);
            }
            if (r.panMasked != null) {
                out.put("pan", r.panMasked);
            }
            out.put("amount", r.amountMinor());
            if (r.currency != null) {
                out.put("currency", Hex.format(r.currency));
            }
            if (r.date != null) {
                out.put("date", Hex.format(r.date));
            }
            if (r.time != null) {
                out.put("time", Hex.format(r.time));
            }
            if (r.cvmResults != null) {
                out.put("cvmResults", r.cvmResults);
            }
            if (r.arc != null) {
                out.put("arc", r.arc);
            }
            if (r.terminalId != null) {
                out.put("terminalId", r.terminalId);
            }
            if (r.merchantName != null) {
                out.put("merchantName", r.merchantName);
            }
            return out.build();
        }
    }

    /** Appends {@code label: value} when value is present. */
    static void field(StringBuilder out, String label, String value) {
        if (value != null) {
            out.append(label).append(": ").append(value).append(System.lineSeparator());
        }
    }

    /** Appends a plain line. */
    static void line(StringBuilder out, String text) {
        out.append(text).append(System.lineSeparator());
    }
}
