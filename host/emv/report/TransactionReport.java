package card42.host.emv.report;

import java.util.ArrayList;
import java.util.List;

import card42.host.emv.kernel.data.Cvm;
import card42.host.common.codec.Json;
import card42.host.common.codec.Tags;
import card42.host.emv.kernel.core.Outcome;
import card42.host.emv.kernel.core.TransactionResult;
import card42.host.emv.kernel.data.TransactionRequest;
import card42.host.emv.kernel.data.Tsi;
import card42.host.emv.kernel.data.Tvr;
import card42.host.common.util.Hex;

/**
 * Renders a {@link TransactionResult} as a human-readable block or as a JSON
 * object (docs/specs/common/toolchain.md §7.1).
 *
 * <p>All values come from the result the kernel already produced (plus the
 * Application Label '50' in the FCI); the report performs no card I/O and needs
 * no kernel change.
 */
public final class TransactionReport {

    private TransactionReport() {
    }

    /** The human-readable report. */
    public static String text(TransactionResult r, TransactionRequest data,
                              String iface, String reader, long elapsedMillis) {
        StringBuilder out = new StringBuilder();
        line(out, "interface", iface);
        line(out, "reader", reader);
        line(out, "AID", r.aidHex());
        byte[] label = displayName(r.fci());
        line(out, "label", label == null ? null : ascii(label));
        line(out, "AIP", String.format("%04X", r.aip()) + " (" + String.join(", ", aipNames(r.aip())) + ")");
        line(out, "AFL", hex(r.afl()));
        line(out, "PDOL data", hex(r.pdolData()));
        line(out, "ODA", odaText(r));
        line(out, "TVR", hex(r.tvr()) + " (" + names(tvrNames(r.tvr())) + ")");
        line(out, "TSI", hex(r.tsi()) + " (" + names(tsiNames(r.tsi())) + ")");
        line(out, "CVM results", cvmText(r.cvmResults()));
        line(out, "requested AC", cidName(r.requestedFirstAc()));
        line(out, "first AC", acText(r.firstCid(), r.firstAc()));
        line(out, "second AC", r.secondAc() == null ? null : acText(r.secondCid(), r.secondAc()));
        line(out, "online", yesNo(r.wentOnline()));
        line(out, "issuer auth", yesNo(r.issuerAuthPerformed()));
        line(out, "issuer scripts", r.issuerScriptResults() == null
                ? null : hex(r.issuerScriptResults()));
        line(out, "ARC", hex(r.arc()));
        if (r.referralRequested()) {
            line(out, "referral", r.attendantForcedAcceptance()
                    ? "accepted by attendant" : "declined");
        }
        if (r.cardCaptureRequested()) {
            line(out, "card capture", "requested");
        }
        if (r.adviceRequired()) {
            line(out, "advice", r.serviceNotAllowed() ? "service not allowed" : "required");
        }
        if (r.reversalRequired()) {
            line(out, "reversal", "required (card declined after online approval)");
        }
        line(out, "result", decisionName(r.decision()));
        if (r.outcome() != null) {
            line(out, "outcome", outcomeName(r.outcome().finalOutcome)
                    + (r.outcome().restart ? " (restart)" : ""));
        }
        line(out, "elapsed", elapsedMillis + " ms");
        return out.toString();
    }

    /** The structured JSON report (one object). */
    public static String json(TransactionResult r, TransactionRequest data,
                              String iface, String reader, long elapsedMillis) {
        byte[] label = displayName(r.fci());
        StringBuilder out = new StringBuilder();
        out.append('{');
        field(out, "interface", Json.quote(iface)).append(',');
        field(out, "reader", Json.quote(reader)).append(',');
        field(out, "aid", Json.quote(nullToEmpty(r.aidHex()))).append(',');
        field(out, "label", label == null ? "null" : Json.quote(ascii(label))).append(',');
        field(out, "aip", "{\"hex\":" + Json.quote(String.format("%04X", r.aip()))
                + ",\"sda\":" + ((r.aip() & 0x4000) != 0)
                + ",\"dda\":" + ((r.aip() & 0x2000) != 0)
                + ",\"cvm\":" + ((r.aip() & 0x1000) != 0)
                + ",\"cda\":" + ((r.aip() & 0x0100) != 0)
                + ",\"issuerAuth\":" + ((r.aip() & 0x0400) != 0)
                + ",\"trm\":" + ((r.aip() & 0x0800) != 0) + "}").append(',');
        field(out, "afl", Json.quote(nullToEmpty(hex(r.afl())))).append(',');
        field(out, "pdol", Json.quote(nullToEmpty(hex(r.pdolData())))).append(',');
        field(out, "oda", "{\"sdaPerformed\":" + r.sdaPerformed()
                + ",\"sdaFailed\":" + r.sdaFailed()
                + ",\"ddaPerformed\":" + r.ddaPerformed()
                + ",\"ddaFailed\":" + r.ddaFailed()
                + ",\"cdaPerformed\":" + r.cdaPerformed()
                + ",\"cdaFailed\":" + r.cdaFailed() + "}").append(',');
        field(out, "tvr", "{\"hex\":" + Json.quote(nullToEmpty(hex(r.tvr())))
                + ",\"bits\":" + jsonStrings(tvrNames(r.tvr())) + "}").append(',');
        field(out, "tsi", "{\"hex\":" + Json.quote(nullToEmpty(hex(r.tsi())))
                + ",\"bits\":" + jsonStrings(tsiNames(r.tsi())) + "}").append(',');
        field(out, "cvmResults", cvmJson(r.cvmResults())).append(',');
        field(out, "requestedFirstAc", Json.quote(cidName(r.requestedFirstAc()))).append(',');
        field(out, "firstAc", acJson(r.firstCid(), r.firstAc())).append(',');
        field(out, "secondAc", r.secondAc() == null ? "null" : acJson(r.secondCid(), r.secondAc())).append(',');
        field(out, "arc", Json.quote(nullToEmpty(hex(r.arc())))).append(',');
        field(out, "wentOnline", String.valueOf(r.wentOnline())).append(',');
        field(out, "issuerAuthPerformed", String.valueOf(r.issuerAuthPerformed())).append(',');
        field(out, "issuerScriptResults", r.issuerScriptResults() == null
                ? "null" : Json.quote(hex(r.issuerScriptResults()))).append(',');
        field(out, "referralRequested", String.valueOf(r.referralRequested())).append(',');
        field(out, "attendantForcedAcceptance", String.valueOf(r.attendantForcedAcceptance())).append(',');
        field(out, "cardCaptureRequested", String.valueOf(r.cardCaptureRequested())).append(',');
        field(out, "adviceRequired", String.valueOf(r.adviceRequired())).append(',');
        field(out, "serviceNotAllowed", String.valueOf(r.serviceNotAllowed())).append(',');
        field(out, "reversalRequired", String.valueOf(r.reversalRequired())).append(',');
        field(out, "decision", Json.quote(decisionName(r.decision()))).append(',');
        field(out, "approved", String.valueOf(
                r.decision() == TransactionResult.Decision.APPROVE)).append(',');
        field(out, "declined", String.valueOf(
                r.decision() == TransactionResult.Decision.DECLINE)).append(',');
        if (r.outcome() != null) {
            field(out, "outcome", "{\"final\":\"" + outcomeName(r.outcome().finalOutcome)
                    + "\",\"start\":" + r.outcome().start
                    + ",\"restart\":" + r.outcome().restart + "}").append(',');
        }
        field(out, "elapsedMillis", String.valueOf(elapsedMillis));
        out.append('}');
        return out.toString();
    }

    // --- Decoders ------------------------------------------------------------

    /**
     * The unified transaction decision name (EMV v4.4 Book 4 §6.3.2 terminal
     * decision / EMV Contactless Book A v2.12 Table 6-1 Outcome).
     */
    private static String decisionName(TransactionResult.Decision decision) {
        switch (decision) {
        case APPROVE: return "APPROVED";
        case DECLINE: return "DECLINED";
        case ONLINE: return "ONLINE";
        case END_APPLICATION: return "END APPLICATION";
        default: return decision.name();
        }
    }

    /** The Final Outcome name (EMV Contactless Book A v2.12 Table 6-3/6-4/6-5). */
    public static String outcomeName(int finalOutcome) {
        switch (finalOutcome) {
        case Outcome.APPROVE: return "Approve";
        case Outcome.DECLINE: return "Decline";
        case Outcome.ONLINE_REQUEST: return "Online Request";
        case Outcome.REQUEST_ONLINE_PIN: return "Request Online PIN";
        case Outcome.SELECT_NEXT: return "Select Next";
        case Outcome.TRY_AGAIN: return "Try Again";
        case Outcome.END_APPLICATION: return "End Application";
        case Outcome.TRY_ANOTHER_INTERFACE: return "Try Another Interface";
        default: return String.format("Outcome %02X", finalOutcome);
        }
    }

    /** The AIP bit names (EMV v4.4 Book 3 Annex C1). */
    public static List<String> aipNames(int aip) {
        List<String> names = new ArrayList<>();
        if ((aip & 0x4000) != 0) names.add("SDA");
        if ((aip & 0x2000) != 0) names.add("DDA");
        if ((aip & 0x1000) != 0) names.add("CVM");
        if ((aip & 0x0800) != 0) names.add("TRM");
        if ((aip & 0x0400) != 0) names.add("issuer-auth");
        if ((aip & 0x0100) != 0) names.add("CDA");
        return names;
    }

    /** The names of the set TVR bits (EMV v4.4 Book 3 Annex C5). */
    public static List<String> tvrNames(byte[] tvr) {
        List<String> names = new ArrayList<>();
        if (tvr == null) {
            return names;
        }
        add(names, Tvr.isSet(tvr, 0, Tvr.ODA_NOT_PERFORMED), "ODA not performed");
        add(names, Tvr.isSet(tvr, 0, Tvr.SDA_FAILED), "SDA failed");
        add(names, Tvr.isSet(tvr, 0, Tvr.ICC_DATA_MISSING), "ICC data missing");
        add(names, Tvr.isSet(tvr, 0, Tvr.CARD_ON_EXCEPTION_FILE), "card on exception file");
        add(names, Tvr.isSet(tvr, 0, Tvr.DDA_FAILED), "DDA failed");
        add(names, Tvr.isSet(tvr, 0, Tvr.CDA_FAILED), "CDA failed");
        add(names, Tvr.isSet(tvr, 0, Tvr.SDA_SELECTED), "SDA selected");
        add(names, Tvr.isSet(tvr, 0, Tvr.XDA_SELECTED), "XDA selected");
        add(names, Tvr.isSet(tvr, 1, Tvr.APPLICATION_VERSION_MISMATCH), "version mismatch");
        add(names, Tvr.isSet(tvr, 1, Tvr.EXPIRED_APPLICATION), "expired application");
        add(names, Tvr.isSet(tvr, 1, Tvr.APPLICATION_NOT_YET_EFFECTIVE), "not yet effective");
        add(names, Tvr.isSet(tvr, 1, Tvr.SERVICE_NOT_ALLOWED), "service not allowed");
        add(names, Tvr.isSet(tvr, 1, Tvr.NEW_CARD), "new card");
        add(names, Tvr.isSet(tvr, 2, Tvr.CVM_NOT_SUCCESSFUL), "CVM not successful");
        add(names, Tvr.isSet(tvr, 2, Tvr.UNRECOGNISED_CVM), "unrecognised CVM");
        add(names, Tvr.isSet(tvr, 2, Tvr.PIN_TRY_LIMIT_EXCEEDED), "PIN try limit exceeded");
        add(names, Tvr.isSet(tvr, 2, Tvr.PIN_PAD_NOT_PRESENT), "PIN pad not present");
        add(names, Tvr.isSet(tvr, 2, Tvr.PIN_NOT_ENTERED), "PIN not entered");
        add(names, Tvr.isSet(tvr, 2, Tvr.ONLINE_PIN_ENTERED), "online PIN entered");
        add(names, Tvr.isSet(tvr, 3, Tvr.FLOOR_LIMIT_EXCEEDED), "floor limit exceeded");
        add(names, Tvr.isSet(tvr, 3, Tvr.LOWER_OFFLINE_LIMIT_EXCEEDED), "lower offline limit exceeded");
        add(names, Tvr.isSet(tvr, 3, Tvr.UPPER_OFFLINE_LIMIT_EXCEEDED), "upper offline limit exceeded");
        add(names, Tvr.isSet(tvr, 3, Tvr.RANDOM_SELECTION), "random selection");
        add(names, Tvr.isSet(tvr, 3, Tvr.MERCHANT_FORCED_ONLINE), "merchant forced online");
        add(names, Tvr.isSet(tvr, 3, Tvr.BIOMETRIC_TYPE_NOT_SUPPORTED), "biometric not supported");
        add(names, Tvr.isSet(tvr, 4, Tvr.DEFAULT_TDOL_USED), "default TDOL used");
        add(names, Tvr.isSet(tvr, 4, Tvr.ISSUER_AUTH_FAILED), "issuer auth failed");
        add(names, Tvr.isSet(tvr, 4, Tvr.SCRIPT_FAILED_BEFORE_FINAL_AC), "script failed before final AC");
        add(names, Tvr.isSet(tvr, 4, Tvr.SCRIPT_FAILED_AFTER_FINAL_AC), "script failed after final AC");
        return names;
    }

    /** The names of the set TSI bits (EMV v4.4 Book 3 Annex C6). */
    public static List<String> tsiNames(byte[] tsi) {
        List<String> names = new ArrayList<>();
        if (tsi == null) {
            return names;
        }
        add(names, Tsi.isSet(tsi, Tsi.ODA_PERFORMED), "ODA performed");
        add(names, Tsi.isSet(tsi, Tsi.CVM_PERFORMED), "CVM performed");
        add(names, Tsi.isSet(tsi, Tsi.CARD_RISK_MANAGEMENT_PERFORMED), "card risk management performed");
        add(names, Tsi.isSet(tsi, Tsi.ISSUER_AUTH_PERFORMED), "issuer auth performed");
        add(names, Tsi.isSet(tsi, Tsi.TERMINAL_RISK_MANAGEMENT_PERFORMED), "TRM performed");
        add(names, Tsi.isSet(tsi, Tsi.SCRIPT_PROCESSING_PERFORMED), "script processing performed");
        return names;
    }

    /** The decoded CVM Results, e.g. {@code 010002 (offline PIN plaintext, successful)}. */
    public static String cvmText(byte[] cvmResults) {
        if (cvmResults == null || cvmResults.length < 3) {
            return null;
        }
        return hex(cvmResults) + " (" + cvmCodeName(cvmResults[0] & 0xFF)
                + ", " + cvmResultName(cvmResults[2] & 0xFF) + ")";
    }

    private static String cvmJson(byte[] cvmResults) {
        if (cvmResults == null || cvmResults.length < 3) {
            return "null";
        }
        return "{\"hex\":" + Json.quote(hex(cvmResults))
                + ",\"cvm\":" + Json.quote(cvmCodeName(cvmResults[0] & 0xFF))
                + ",\"condition\":" + Json.quote(String.format("%02X", cvmResults[1] & 0xFF))
                + ",\"result\":" + Json.quote(cvmResultName(cvmResults[2] & 0xFF)) + "}";
    }

    private static String cvmCodeName(int code) {
        switch (code & 0x3F) {
        case Cvm.CVM_FAIL: return "fail CVM processing";
        case Cvm.CVM_PLAINTEXT_PIN_ICC: return "offline PIN plaintext";
        case Cvm.CVM_ONLINE_PIN: return "online PIN";
        case Cvm.CVM_PLAINTEXT_PIN_SIGNATURE: return "offline PIN plaintext + signature";
        case Cvm.CVM_ENCIPHERED_PIN_ICC: return "offline PIN enciphered";
        case Cvm.CVM_ENCIPHERED_PIN_SIGNATURE: return "offline PIN enciphered + signature";
        case Cvm.CVM_SIGNATURE: return "signature";
        case Cvm.CVM_NO_CVM: return "no CVM required";
        case Cvm.NO_CVM_PERFORMED: return "no CVM performed";
        default: return String.format("CVM %02X", code);
        }
    }

    private static String cvmResultName(int result) {
        switch (result) {
        case Cvm.RESULT_UNKNOWN: return "unknown";
        case Cvm.RESULT_FAILED: return "failed";
        case Cvm.RESULT_SUCCESSFUL: return "successful";
        default: return String.format("%02X", result);
        }
    }

    /** The CID name of a GENERATE AC (EMV v4.4 Book 3 Table 14). */
    public static String cidName(byte cid) {
        switch (cid & 0xC0) {
        case 0x00: return "AAC";
        case 0x40: return "TC";
        case 0x80: return "ARQC";
        default: return String.format("%02X", cid & 0xFF);
        }
    }

    // --- Small helpers -------------------------------------------------------

    private static String odaText(TransactionResult r) {
        List<String> parts = new ArrayList<>();
        parts.add("SDA " + outcome(r.sdaPerformed(), r.sdaFailed()));
        parts.add("DDA " + outcome(r.ddaPerformed(), r.ddaFailed()));
        parts.add("CDA " + outcome(r.cdaPerformed(), r.cdaFailed()));
        return String.join(", ", parts);
    }

    private static String outcome(boolean performed, boolean failed) {
        if (failed) {
            return "failed";
        }
        return performed ? "ok" : "not performed";
    }

    private static String acText(byte cid, card42.host.common.codec.Responses.AcResponse ac) {
        if (ac == null) {
            return null;
        }
        return cidName(cid) + " ATC=" + String.format("%04X", ac.atc)
                + " AC=" + hex(ac.ac) + " IAD=" + hex(ac.iad);
    }

    private static String acJson(byte cid, card42.host.common.codec.Responses.AcResponse ac) {
        return "{\"cid\":" + Json.quote(String.format("%02X", cid & 0xFF))
                + ",\"name\":" + Json.quote(cidName(cid))
                + ",\"atc\":" + ac.atc
                + ",\"ac\":" + Json.quote(nullToEmpty(hex(ac.ac)))
                + ",\"iad\":" + Json.quote(nullToEmpty(hex(ac.iad))) + "}";
    }

    private static String names(List<String> values) {
        return values.isEmpty() ? "none" : String.join(", ", values);
    }

    private static String jsonStrings(List<String> values) {
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < values.size(); i++) {
            if (i > 0) {
                sb.append(',');
            }
            sb.append(Json.quote(values.get(i)));
        }
        return sb.append(']').toString();
    }

    private static void add(List<String> names, boolean set, String name) {
        if (set) {
            names.add(name);
        }
    }

    private static StringBuilder field(StringBuilder out, String key, String value) {
        return out.append(Json.quote(key)).append(':').append(value);
    }

    private static void line(StringBuilder out, String key, String value) {
        out.append(String.format("  %-14s: %s%n", key, value == null ? "-" : value));
    }

    private static String hex(byte[] value) {
        return value == null ? null : Hex.format(value);
    }

    private static String nullToEmpty(String value) {
        return value == null ? "" : value;
    }

    private static String yesNo(boolean value) {
        return value ? "yes" : "no";
    }

    /**
     * The name displayed for the selected application (EMV v4.4 Book 1 §12.4):
     * the Application Preferred Name ('9F12') when the Issuer Code Table Index
     * ('9F11') is present, otherwise the Application Label ('50').
     */
    private static byte[] displayName(byte[] fci) {
        if (fci == null) {
            return null;
        }
        byte[] preferred = Tags.find(fci, 0x9F12);
        if (preferred != null && Tags.find(fci, 0x9F11) != null) {
            return preferred;
        }
        return Tags.find(fci, 0x50);
    }

    private static String ascii(byte[] value) {
        StringBuilder sb = new StringBuilder(value.length);
        for (byte b : value) {
            sb.append((char) (b & 0xFF));
        }
        return sb.toString().trim();
    }
}
