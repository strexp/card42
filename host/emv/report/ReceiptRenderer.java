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
            StringBuilder out = new StringBuilder();
            out.append('{');
            field(out, "approved", String.valueOf(r.approved));
            field(out, "aid", r.aidHex == null ? null : Json.quote(r.aidHex));
            field(out, "pan", r.panMasked == null ? null : Json.quote(r.panMasked));
            field(out, "amount", String.valueOf(r.amountMinor()));
            field(out, "currency", r.currency == null ? null : Json.quote(Hex.format(r.currency)));
            field(out, "date", r.date == null ? null : Json.quote(Hex.format(r.date)));
            field(out, "time", r.time == null ? null : Json.quote(Hex.format(r.time)));
            field(out, "cvmResults", r.cvmResults == null ? null : Json.quote(r.cvmResults));
            field(out, "arc", r.arc == null ? null : Json.quote(r.arc));
            field(out, "terminalId", r.terminalId == null ? null : Json.quote(r.terminalId));
            field(out, "merchantName",
                    r.merchantName == null ? null : Json.quote(r.merchantName));
            // Drop the trailing comma and close.
            if (out.charAt(out.length() - 1) == ',') {
                out.setLength(out.length() - 1);
            }
            out.append('}');
            return out.toString();
        }

        private static void field(StringBuilder out, String name, String value) {
            if (value == null) {
                return;
            }
            out.append(Json.quote(name)).append(':').append(value).append(',');
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
