package card42.host.common.codec;

import java.util.HashMap;
import java.util.Map;

/**
 * Generic BER-TLV pretty-printer for the host CLI (EMV v4.4 Book 3 Annex B).
 *
 * <p>It walks a BER-TLV buffer and renders each data object on its own line,
 * indenting the children of constructed templates (tag bit b6 set).  A tag
 * whose name is in the small EMV dictionary is annotated, so {@code inspect}
 * and {@code tlv decode} can reuse the same printer.
 *
 * <p>Malformed input is not rejected: a truncated tag/length/value is rendered
 * with a {@code <truncated>} marker and the walk stops, so the tool can show a
 * card's broken response instead of throwing.
 */
public final class TlvDump {

    private static final Map<Integer, String> NAMES = new HashMap<>();

    static {
        NAMES.put(0x4F, "ADF Name");
        NAMES.put(0x50, "Application Label");
        NAMES.put(0x57, "Track 2 Equivalent Data");
        NAMES.put(0x5A, "Application PAN");
        NAMES.put(0x5F20, "Cardholder Name");
        NAMES.put(0x5F24, "Application Expiration Date");
        NAMES.put(0x5F25, "Application Effective Date");
        NAMES.put(0x5F28, "Issuer Country Code");
        NAMES.put(0x5F2A, "Transaction Currency Code");
        NAMES.put(0x5F34, "PAN Sequence Number");
        NAMES.put(0x61, "Application Template");
        NAMES.put(0x6F, "FCI Template");
        NAMES.put(0x70, "Record Template");
        NAMES.put(0x71, "Issuer Script Template 1");
        NAMES.put(0x72, "Issuer Script Template 2");
        NAMES.put(0x77, "Response Template (Format 2)");
        NAMES.put(0x80, "Response Template (Format 1)");
        NAMES.put(0x82, "Application Interchange Profile");
        NAMES.put(0x83, "Command Template");
        NAMES.put(0x84, "Dedicated File Name");
        NAMES.put(0x86, "Issuer Script Command");
        NAMES.put(0x87, "Application Priority Indicator");
        NAMES.put(0x88, "SFI of Directory File");
        NAMES.put(0x8A, "Authorisation Response Code");
        NAMES.put(0x8C, "CDOL1");
        NAMES.put(0x8D, "CDOL2");
        NAMES.put(0x8E, "CVM List");
        NAMES.put(0x8F, "CA Public Key Index");
        NAMES.put(0x90, "Issuer Public Key Certificate");
        NAMES.put(0x91, "Issuer Authentication Data");
        NAMES.put(0x92, "Issuer Public Key Remainder");
        NAMES.put(0x93, "Signed Static Application Data");
        NAMES.put(0x94, "Application File Locator");
        NAMES.put(0x95, "Terminal Verification Results");
        NAMES.put(0x9A, "Transaction Date");
        NAMES.put(0x9B, "Transaction Status Information");
        NAMES.put(0x9C, "Transaction Type");
        NAMES.put(0x9F06, "Application Identifier (AID)");
        NAMES.put(0x9F07, "Application Usage Control");
        NAMES.put(0x9F08, "Application Version Number (ICC)");
        NAMES.put(0x9F09, "Application Version Number (terminal)");
        NAMES.put(0x9F0D, "IAC-Default");
        NAMES.put(0x9F0E, "IAC-Denial");
        NAMES.put(0x9F0F, "IAC-Online");
        NAMES.put(0x9F10, "Issuer Application Data");
        NAMES.put(0x9F13, "Last Online ATC Register");
        NAMES.put(0x9F17, "PIN Try Counter");
        NAMES.put(0x9F1A, "Terminal Country Code");
        NAMES.put(0x9F1B, "Terminal Floor Limit");
        NAMES.put(0x9F1C, "Terminal Identification");
        NAMES.put(0x9F1E, "Interface Device Serial Number");
        NAMES.put(0x9F21, "Transaction Time");
        NAMES.put(0x9F26, "Application Cryptogram");
        NAMES.put(0x9F27, "Cryptogram Information Data");
        NAMES.put(0x9F2A, "Kernel Identifier");
        NAMES.put(0x9F32, "Issuer Public Key Exponent");
        NAMES.put(0x9F33, "Terminal Capabilities");
        NAMES.put(0x9F34, "CVM Results");
        NAMES.put(0x9F35, "Terminal Type");
        NAMES.put(0x9F36, "Application Transaction Counter");
        NAMES.put(0x9F37, "Unpredictable Number");
        NAMES.put(0x9F38, "PDOL");
        NAMES.put(0x9F40, "Additional Terminal Capabilities");
        NAMES.put(0x9F42, "Application Currency Code");
        NAMES.put(0x9F46, "ICC Public Key Certificate");
        NAMES.put(0x9F47, "ICC Public Key Exponent");
        NAMES.put(0x9F48, "ICC Public Key Remainder");
        NAMES.put(0x9F49, "Dynamic Data Authentication Data Object List");
        NAMES.put(0x9F4A, "Static Data Authentication Tag List");
        NAMES.put(0x9F4B, "Signed Dynamic Application Data");
        NAMES.put(0x9F4E, "Merchant Name and Location");
        NAMES.put(0x9F5B, "Issuer Script Results");
        NAMES.put(0x9F66, "Terminal Transaction Qualifiers");
        NAMES.put(0xBF0C, "FCI Issuer Discretionary Data");
    }

    private TlvDump() {
    }

    /** The EMV name of a tag, or null when it is not in the dictionary. */
    public static String tagName(int tag) {
        return NAMES.get(tag);
    }

    /** Renders a BER-TLV buffer, one data object per line, children indented. */
    public static String format(byte[] tlv) {
        StringBuilder out = new StringBuilder();
        append(out, tlv, 0, tlv == null ? 0 : tlv.length, 0);
        return out.toString();
    }

    private static void append(StringBuilder out, byte[] buf, int off, int len, int depth) {
        int p = off;
        int end = off + len;
        while (p < end) {
            for (int i = 0; i < depth; i++) {
                out.append("  ");
            }
            int start = p;
            int b = buf[p] & 0xFF;
            int tag;
            if ((b & 0x1F) == 0x1F) {
                if (p + 1 >= end) {
                    out.append("<truncated tag>\n");
                    return;
                }
                tag = (b << 8) | (buf[p + 1] & 0xFF);
                p += 2;
            } else {
                tag = b;
                p += 1;
            }
            out.append(String.format("%0" + ((tag > 0xFF) ? 4 : 2) + "X", tag));
            int lb = p < end ? buf[p] & 0xFF : -1;
            if (lb < 0) {
                out.append(" <truncated length>\n");
                return;
            }
            p++;
            int vLen;
            if ((lb & 0x80) == 0) {
                vLen = lb;
            } else {
                int n = lb & 0x7F;
                if (n == 0 || p + n > end) {
                    out.append(" <truncated length>\n");
                    return;
                }
                vLen = 0;
                for (int i = 0; i < n; i++) {
                    vLen = (vLen << 8) | (buf[p++] & 0xFF);
                }
            }
            if (p + vLen > end) {
                out.append(" <truncated value>\n");
                return;
            }
            String name = tagName(tag);
            out.append(' ').append(String.format("%02X", vLen));
            if (name != null) {
                out.append(" (").append(name).append(')');
            }
            boolean constructed = (b & 0x20) != 0;
            if (constructed && vLen > 0) {
                out.append('\n');
                append(out, buf, p, vLen, depth + 1);
            } else {
                out.append("  ").append(hex(buf, p, vLen)).append('\n');
            }
            p += vLen;
            if (p <= start) {
                return; // defensive: never loop on malformed input
            }
        }
    }

    private static String hex(byte[] buf, int off, int len) {
        StringBuilder sb = new StringBuilder(len * 2);
        for (int i = 0; i < len; i++) {
            sb.append(String.format("%02X", buf[off + i]));
        }
        return sb.toString();
    }
}
