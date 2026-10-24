package card42.host.emrtd.lds.common;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;

/**
 * Text decoding for LDS data groups (ICAO Doc 9303-10 §4.7.11/§4.7.12).
 *
 * <p>LDS strings are ASCII in the MRZ and either UTF-8 (when the document
 * supports the Unicode version advertised in EF.COM) or a national character
 * set in DG11/DG12.  There is no reliable in-band marker, so the helper
 * prefers US-ASCII, then strict UTF-8, and finally falls back to ISO-8859-1
 * while telling the caller that the fallback happened (the parser turns that
 * into a {@link LdsIssue.Code#BAD_ENCODING} warning).
 */
public final class LdsText {

    /** A decoded string and how it was decoded. */
    public static final class Decoded {
        public final String text;
        /** "US-ASCII", "UTF-8" or "ISO-8859-1". */
        public final String charset;
        /** True when the ISO-8859-1 fallback was used. */
        public final boolean fallback;

        Decoded(String text, String charset, boolean fallback) {
            this.text = text;
            this.charset = charset;
            this.fallback = fallback;
        }
    }

    private LdsText() {
    }

    /** Decodes as US-ASCII, replacing non-ASCII bytes with '?'. */
    public static String ascii(byte[] bytes) {
        return bytes == null ? null : new String(bytes, StandardCharsets.US_ASCII);
    }

    /** Decodes as ISO-8859-1 (the lossless one-byte fallback). */
    public static String latin1(byte[] bytes) {
        return bytes == null ? null : new String(bytes, StandardCharsets.ISO_8859_1);
    }

    /** True when every byte is in the 7-bit range. */
    public static boolean isAscii(byte[] bytes) {
        if (bytes == null) {
            return false;
        }
        for (byte b : bytes) {
            if (b < 0) {
                return false;
            }
        }
        return true;
    }

    /** Strict UTF-8 validation (no replacement characters). */
    public static boolean isUtf8(byte[] bytes) {
        if (bytes == null) {
            return false;
        }
        try {
            StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(bytes));
            return true;
        } catch (CharacterCodingException e) {
            return false;
        }
    }

    /**
     * Decodes a DG11/DG12-style string: ASCII when possible, strict UTF-8 when
     * the bytes are valid multi-byte text, ISO-8859-1 otherwise.  The caller
     * decides whether {@link Decoded#fallback} becomes an issue.
     */
    public static Decoded utf8OrLatin1(byte[] bytes) {
        if (bytes == null || bytes.length == 0) {
            return new Decoded("", "US-ASCII", false);
        }
        if (isAscii(bytes)) {
            return new Decoded(new String(bytes, StandardCharsets.US_ASCII), "US-ASCII", false);
        }
        if (isUtf8(bytes)) {
            return new Decoded(new String(bytes, StandardCharsets.UTF_8), "UTF-8", false);
        }
        return new Decoded(new String(bytes, StandardCharsets.ISO_8859_1), "ISO-8859-1", true);
    }

    /** A copy of {@code bytes} with trailing zero bytes removed (BCD padding). */
    public static byte[] trimTrailingZeros(byte[] bytes) {
        if (bytes == null) {
            return null;
        }
        int end = bytes.length;
        while (end > 0 && bytes[end - 1] == 0) {
            end--;
        }
        return java.util.Arrays.copyOfRange(bytes, 0, end);
    }
}
