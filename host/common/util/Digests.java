package card42.host.common.util;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/** Message digests shared by the host tooling (the SDA generator and tests). */
public final class Digests {

    private Digests() {
    }

    /** SHA-1 digest; the EMV data-authentication hash algorithm. */
    public static byte[] sha1(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-1").digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-1 not available", e);
        }
    }
}
