package card42.host.emrtd.lds;

import card42.host.common.codec.Tags;

/**
 * EF.COM: the LDS common data object (ICAO Doc 9303-10 §4.6.1 Table 35).
 * 60 { 5F01 LDS version (4 bytes "aabb"), 5F36 Unicode version (6 bytes
 * "aabbcc"), 5C data group list } (H1.4).  There is no 5F37 in EF.COM.
 */
public final class Com {

    public final String ldsVersion;
    public final String unicodeVersion;
    public final int[] dataGroupTags;

    private Com(String ldsVersion, String unicodeVersion, int[] dataGroupTags) {
        this.ldsVersion = ldsVersion;
        this.unicodeVersion = unicodeVersion;
        this.dataGroupTags = dataGroupTags;
    }

    public static Com parse(byte[] com) {
        byte[] body = Tags.find(com, 0x60);
        if (body == null) {
            body = com;
        }
        byte[] lds = Tags.find(body, 0x5F01);
        byte[] unicode = Tags.find(body, 0x5F36);
        byte[] tags = Tags.find(body, 0x5C);
        return new Com(ascii(lds), ascii(unicode), parseTags(tags));
    }

    private static int[] parseTags(byte[] tags) {
        if (tags == null) {
            return new int[0];
        }
        java.util.List<Integer> out = new java.util.ArrayList<Integer>();
        int p = 0;
        while (p < tags.length) {
            int b = tags[p] & 0xFF;
            if ((b & 0x1F) == 0x1F) {
                if (p + 1 >= tags.length) {
                    break; // truncated two-byte tag: stop rather than overrun
                }
                out.add((b << 8) | (tags[p + 1] & 0xFF));
                p += 2;
            } else {
                out.add(b);
                p++;
            }
        }
        int[] result = new int[out.size()];
        for (int i = 0; i < result.length; i++) {
            result[i] = out.get(i);
        }
        return result;
    }

    private static String ascii(byte[] value) {
        return value == null ? null
                : new String(value, java.nio.charset.StandardCharsets.US_ASCII);
    }
}
