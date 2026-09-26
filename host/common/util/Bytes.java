package card42.host.common.util;

import java.io.ByteArrayOutputStream;

/** Small byte-array helpers shared by the host tooling and the tests. */
public final class Bytes {

    private Bytes() {
    }

    /** Concatenates byte arrays into one new array. */
    public static byte[] concat(byte[]... arrays) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] a : arrays) {
            out.write(a, 0, a.length);
        }
        return out.toByteArray();
    }
}
