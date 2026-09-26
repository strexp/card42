package card42.emrtd;

/**
 * Unit-test-only link seam for {@code card42.emrtd.Pace} (Docs: BSI TR-03110-3
 * A.3/B.1, ICAO Doc 9303-11 §4).
 *
 * <p>The command-level LDS2 tests must build a real {@link EmrtdApplet} so the
 * real {@link Lds2Record} handlers can be driven.  {@code EmrtdApplet} names the
 * concrete PACE class, but the production {@code card/emrtd/access/Pace.java}
 * links against {@code KeyAgreement.ALG_EC_PACE_GM}, which the pure-JVM
 * {@code javacard.security} stub deliberately does not implement (see
 * {@code test/common/stubs/javacard/security/KeyAgreement.java}).  The unit
 * build therefore links the applet against this no-op stand-in instead; the
 * PACE protocol path itself is covered end to end by the simulator suite
 * {@code EmrtdPaceIntegrationTest}, which drives the real class on the card.
 *
 * <p>Every method here is a stub: the LDS2 command tests set the applet's
 * {@code paceDone} flag directly and never reach PACE.
 */
final class Pace implements PaceSeedSink {

    Pace() {
    }

    void reset() {
    }

    boolean isAes() {
        return false;
    }

    void mseSetAt(byte[] data, short off, short len) {
    }

    short generalAuthenticate(EmrtdApplet applet, byte[] data, short off, short len,
                              byte[] out) {
        return 0;
    }

    @Override
    public void setSeed(byte[] src, short off, short len) {
    }
}
