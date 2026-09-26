package card42.host.emv.kernel.entry;

import java.io.ByteArrayOutputStream;
import java.util.Arrays;

import javax.smartcardio.ResponseAPDU;

import card42.host.common.codec.Tags;
import card42.host.common.codec.TlvWriter;
import card42.host.emv.kernel.core.TransactionResult;
import card42.host.emv.kernel.data.TransactionRequest;
import card42.host.emv.kernel.data.TerminalDol;
import card42.host.emv.lib.Terminal;

/**
 * SEND POI INFORMATION (EMV Contactless Book B v2.12 Annex C).
 *
 * <p>The card advertises SPI support by returning the Terminal Categories
 * Supported List ('9F3E') and/or the Supported Data Object List ('9F3F') in the
 * PPSE FCI.  The reader then sends {@code CLA=80 INS=1A} with a '83' Command
 * Template carrying the SDOL-requested values, followed by the POI Information
 * object of the Terminal Category ('0001') <em>only</em> when the terminal
 * category is on the card's '9F3E' list (Book B §C.1.3 / Figure C-1), and uses
 * the returned FCI for Entry Point Combination Selection.
 */
public final class Spi {

    private Spi() {
    }

    /**
     * True when Entry Point must send SEND POI INFORMATION (Book B §3.3.2.3):
     * the terminal's category is on the returned Terminal Categories Supported
     * List ('9F3E'), or the Supported Data Object List ('9F3F') is returned.
     */
    public static boolean advertised(byte[] ppseFci, byte[] terminalCategory) {
        byte[] discretionary = Tags.find(ppseFci, 0xBF0C);
        if (discretionary == null) {
            return false;
        }
        byte[] categories = Tags.find(discretionary, 0x9F3E);
        if (categories != null && containsCategory(categories, terminalCategory)) {
            return true;
        }
        return Tags.find(discretionary, 0x9F3F) != null;
    }

    /** True when the 2-byte terminal category appears in the '9F3E' list. */
    private static boolean containsCategory(byte[] list, byte[] category) {
        if (list == null || category == null || category.length != 2) {
            return false;
        }
        for (int i = 0; i + 1 < list.length; i += 2) {
            if (list[i] == category[0] && list[i + 1] == category[1]) {
                return true;
            }
        }
        return false;
    }

    /**
     * Sends SEND POI INFORMATION: the SDOL values from the card's '9F3F' (empty
     * when absent), then the POI Information object '0001' (Terminal Category)
     * <em>only</em> when the terminal's category is on the card's Terminal
     * Categories Supported List ('9F3E') (EMV Contactless Book B v2.12 §C.1.3 /
     * Figure C-1: the Terminal Category object is conditionally included).  When
     * only the SDOL triggered the SPI, the data field carries the SDOL values
     * alone.  The POI Information ID is two bytes (Figure C-1), so it is encoded
     * explicitly.
     */
    public static ResponseAPDU send(Terminal terminal, byte[] ppseFci,
            TransactionRequest data, TransactionResult result,
            EntryPointConfiguration config) throws Exception {
        byte[] discretionary = Tags.find(ppseFci, 0xBF0C);
        byte[] sdol = discretionary == null ? null : Tags.find(discretionary, 0x9F3F);
        byte[] sdolData = sdol == null ? new byte[0]
                : TerminalDol.buildDolData(data, result, sdol);
        ByteArrayOutputStream value = new ByteArrayOutputStream();
        value.write(sdolData, 0, sdolData.length);
        // Book B §C.1.3: the POI Information object of the Terminal Category
        // ('0001') is sent only when the terminal category is on the returned
        // Terminal Categories Supported List ('9F3E').
        byte[] categories = discretionary == null ? null : Tags.find(discretionary, 0x9F3E);
        if (containsCategory(categories, config.terminalCategory)) {
            // POI Information: ID '0001' (2 bytes), L, V.
            value.write(0x00);
            value.write(0x01);
            value.write(config.terminalCategory.length);
            value.write(config.terminalCategory, 0, config.terminalCategory.length);
        }
        return terminal.sendPoiInformation(value.toByteArray());
    }

    /**
     * Strips the Terminal Categories Supported List ('9F3E') and the Supported
     * Data Object List ('9F3F') from an SPI response FCI (EMV Contactless Book B
     * v2.12 Annex C.1.4): those objects advertise SPI support on the pre-SPI
     * FCI and must not be carried into the FCI used for Combination Selection.
     * Constructed ancestors are rebuilt with their lengths updated; a response
     * without the advertisement is returned unchanged.
     */
    public static byte[] stripAdvertisement(byte[] fci) {
        if (fci == null
                || (Tags.find(fci, 0x9F3E) == null && Tags.find(fci, 0x9F3F) == null)) {
            return fci;
        }
        return strip(fci, 0, fci.length);
    }

    /** Rebuilds a TLV sequence, dropping 9F3E/9F3F and recursing into constructed values. */
    private static byte[] strip(byte[] buf, int off, int end) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int p = off;
        while (p < end) {
            int b = buf[p] & 0xFF;
            int tag;
            int tagLen;
            if ((b & 0x1F) == 0x1F) {
                if (p + 2 > end) {
                    out.write(buf, p, end - p); // malformed tail: copy verbatim
                    break;
                }
                tag = (b << 8) | (buf[p + 1] & 0xFF);
                tagLen = 2;
            } else {
                tag = b;
                tagLen = 1;
            }
            int lOff = p + tagLen;
            if (lOff >= end) {
                out.write(buf, p, end - p);
                break;
            }
            int lb = buf[lOff] & 0xFF;
            int lLen;
            int vLen;
            if ((lb & 0x80) == 0) {
                lLen = 1;
                vLen = lb;
            } else {
                int n = lb & 0x7F;
                if (n == 0 || lOff + 1 + n > end) {
                    out.write(buf, p, end - p);
                    break;
                }
                lLen = 1 + n;
                vLen = 0;
                for (int i = 0; i < n; i++) {
                    vLen = (vLen << 8) | (buf[lOff + 1 + i] & 0xFF);
                }
            }
            int vOff = lOff + lLen;
            if (vOff + vLen > end) {
                out.write(buf, p, end - p);
                break;
            }
            if (tag != 0x9F3E && tag != 0x9F3F) {
                byte[] value = (b & 0x20) != 0
                        ? strip(buf, vOff, vOff + vLen)
                        : Arrays.copyOfRange(buf, vOff, vOff + vLen);
                TlvWriter.writeTlv(out, tag, value);
            }
            p = vOff + vLen;
        }
        return out.toByteArray();
    }
}
