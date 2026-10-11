package card42.host.emv.kernel.script;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * A parsed EMV Issuer Script template (tag '71' / '72'), EMV v4.4 Book 3
 * Figure 11: the Script Identifier ('9F18', optional) and the individual Issuer
 * Script Commands (each tag '86').
 *
 * <p>This is the parse of one script; {@link IssuerScriptProcessor} sends its
 * commands and aggregates the Issuer Script Results (tag '9F5B').
 */
public final class IssuerScript {

    /** The script template tag: '71' (before final AC) or '72' (after). */
    public final int tag;
    public final byte[] scriptId;
    /** Each entry is the raw command APDU carried by one tag 86. */
    public final List<byte[]> commands;

    IssuerScript(int tag, byte[] scriptId, List<byte[]> commands) {
        this.tag = tag;
        this.scriptId = scriptId;
        this.commands = commands;
    }

    /** The tag ('71' or '72') of an Issuer Script template, or -1 if malformed. */
    public static int tagOf(byte[] template) {
        if (template == null || template.length < 1) {
            return -1;
        }
        int tag = template[0] & 0xFF;
        return (tag == 0x71 || tag == 0x72) ? tag : -1;
    }

    /**
     * Parses a 71/72 Issuer Script template (the tag and length are included):
     * optional 9F18 Script Identifier and any number of 86 command APDUs
     * (EMV v4.4 Book 3 Figure 11).
     */
    public static IssuerScript parse(byte[] template) {
        int p = 0;
        int tag = template[p++] & 0xFF;
        if (tag != 0x71 && tag != 0x72) {
            throw new IllegalArgumentException("Not an issuer script template: "
                    + String.format("%02X", tag));
        }
        int lb = template[p++] & 0xFF;
        int len;
        if ((lb & 0x80) == 0) {
            len = lb;
        } else {
            int n = lb & 0x7F;
            len = 0;
            for (int i = 0; i < n; i++) {
                len = (len << 8) | (template[p++] & 0xFF);
            }
        }
        int end = p + len;
        byte[] scriptId = null;
        List<byte[]> commands = new ArrayList<>();
        while (p < end) {
            int t = template[p++] & 0xFF;
            if ((t & 0x1F) == 0x1F) {
                t = (t << 8) | (template[p++] & 0xFF);
            }
            int vLen = template[p++] & 0xFF;
            if ((vLen & 0x80) != 0) {
                int n = vLen & 0x7F;
                vLen = 0;
                for (int i = 0; i < n; i++) {
                    vLen = (vLen << 8) | (template[p++] & 0xFF);
                }
            }
            byte[] value = Arrays.copyOfRange(template, p, p + vLen);
            p += vLen;
            if (t == 0x9F18) {
                scriptId = value;
            } else if (t == 0x86) {
                commands.add(value);
            }
        }
        return new IssuerScript(tag, scriptId, commands);
    }
}
