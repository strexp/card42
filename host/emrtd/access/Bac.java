package card42.host.emrtd.access;

import java.security.SecureRandom;
import java.util.Arrays;

import javax.smartcardio.ResponseAPDU;

import card42.host.common.crypto.Iso9797;
import card42.host.emrtd.transport.EmrtdTerminal;

/**
 * Terminal-side Basic Access Control (ICAO Doc 9303-11 §4.3), the mirror of the
 * card's {@code card42.emrtd.BacCrypto} (H2.2).
 *
 * <p>It derives K_enc/K_mac from the MRZ key seed, runs the three-pass mutual
 * authentication and returns the session keys and initial send sequence
 * counter as an {@link Session}.
 */
public final class Bac {

    /** The BAC session: Ks_enc, Ks_mac and the initial SSC. */
    public static final class Session {
        public final byte[] ksEnc;
        public final byte[] ksMac;
        public final long ssc;

        Session(byte[] ksEnc, byte[] ksMac, long ssc) {
            this.ksEnc = ksEnc;
            this.ksMac = ksMac;
            this.ssc = ssc;
        }

        public Iso7816Sm secureMessaging() {
            return new Iso7816Sm(ksEnc, ksMac, ssc);
        }
    }

    private Bac() {
    }

    /** Derives K_enc (marker 1) or K_mac (marker 2) from the 16-byte seed. */
    public static byte[] deriveKey(byte[] seed, int marker) {
        byte[] in = new byte[20];
        System.arraycopy(seed, 0, in, 0, 16);
        in[19] = (byte) marker;
        byte[] key = Arrays.copyOf(sha1(in), 16);
        adjustParity(key);
        return key;
    }

    /** Runs BAC against the terminal and returns the session keys/SSC. */
    public static Session authenticate(EmrtdTerminal terminal, byte[] seed) throws Exception {
        byte[] kenc = deriveKey(seed, 1);
        byte[] kmac = deriveKey(seed, 2);

        byte[] rndIcc = terminal.getChallenge();
        byte[] rndIfd = random(8);
        byte[] kifd = random(16);

        byte[] s = concat(rndIfd, rndIcc, kifd);
        byte[] eifd = Iso9797.des3CbcEncrypt(kenc, s);
        byte[] mifd = Iso9797.mac(kmac, eifd);
        ResponseAPDU r = terminal.externalAuthenticate(concat(eifd, mifd));
        if (r.getSW() != 0x9000 || r.getData().length != 40) {
            throw new IllegalStateException("BAC EXTERNAL AUTHENTICATE failed: "
                    + Integer.toHexString(r.getSW()));
        }
        byte[] eic = Arrays.copyOfRange(r.getData(), 0, 32);
        byte[] mic = Arrays.copyOfRange(r.getData(), 32, 40);
        if (!Arrays.equals(mic, Iso9797.mac(kmac, eic))) {
            throw new IllegalStateException("BAC M_IC mismatch");
        }
        byte[] s2 = Iso9797.des3CbcDecrypt(kenc, new byte[8], eic);
        if (!Arrays.equals(rndIcc, Arrays.copyOfRange(s2, 0, 8))
                || !Arrays.equals(rndIfd, Arrays.copyOfRange(s2, 8, 16))) {
            throw new IllegalStateException("BAC random mismatch");
        }
        byte[] kic = Arrays.copyOfRange(s2, 16, 32);
        byte[] sessionSeed = sessionSeed(kifd, kic);
        byte[] ksEnc = deriveKey(sessionSeed, 1);
        byte[] ksMac = deriveKey(sessionSeed, 2);
        long ssc = ((long) uint32(rndIcc, 4) << 32) | uint32(rndIfd, 4);
        return new Session(ksEnc, ksMac, ssc);
    }

    /**
     * The BAC session key seed {@code K_IFD XOR K_IC} (Doc 9303-11 §4.3.1
     * step 5 / §9.7.4, Appendix D.3).  The session keys are then derived from it with
     * the same KDF as the static keys: {@code Ks_enc = KDF(seed, 1)} and
     * {@code Ks_mac = KDF(seed, 2)}.
     */
    public static byte[] sessionSeed(byte[] kifd, byte[] kic) {
        byte[] seed = new byte[16];
        for (int i = 0; i < 16; i++) {
            seed[i] = (byte) (kifd[i] ^ kic[i]);
        }
        return seed;
    }

    private static byte[] sha1(byte[] in) {
        try {
            return java.security.MessageDigest.getInstance("SHA-1").digest(in);
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static void adjustParity(byte[] key) {
        for (int i = 0; i < key.length; i++) {
            if ((Integer.bitCount(key[i] & 0xFF) & 1) == 0) {
                key[i] ^= 0x01;
            }
        }
    }

    private static long uint32(byte[] buf, int off) {
        return ((long) (buf[off] & 0xFF) << 24)
                | ((buf[off + 1] & 0xFF) << 16)
                | ((buf[off + 2] & 0xFF) << 8)
                | (buf[off + 3] & 0xFF);
    }

    private static byte[] random(int n) {
        byte[] out = new byte[n];
        new SecureRandom().nextBytes(out);
        return out;
    }

    private static byte[] concat(byte[]... parts) {
        int len = 0;
        for (byte[] p : parts) {
            len += p.length;
        }
        byte[] out = new byte[len];
        int off = 0;
        for (byte[] p : parts) {
            System.arraycopy(p, 0, out, off, p.length);
            off += p.length;
        }
        return out;
    }
}
