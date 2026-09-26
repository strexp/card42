package card42.host.common.crypto;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Self-contained P-256 (secp256r1) arithmetic for PACE generic mapping and
 * Chip Authentication (BSI TR-03110-3 A.3/B.1 and A.4/B.2, H7.1).  The host
 * stack has no EC library, so the
 * affine point addition and scalar multiplication are implemented here with
 * {@link BigInteger}; no external provider is required at runtime.
 *
 * <p>It is cross-checked against BouncyCastle in a throwaway harness and by the
 * host-PACE/card-PACE integration suite.
 */
public final class P256 {

    public static final BigInteger P = new BigInteger(
            "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16);
    public static final BigInteger A = P.subtract(BigInteger.valueOf(3));
    public static final BigInteger B = new BigInteger(
            "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", 16);
    public static final BigInteger GX = new BigInteger(
            "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296", 16);
    public static final BigInteger GY = new BigInteger(
            "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5", 16);
    public static final BigInteger N = new BigInteger(
            "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16);

    /** An affine point; {@code infinity} marks the identity. */
    public static final class Point {
        public final BigInteger x;
        public final BigInteger y;
        public final boolean infinity;

        public Point(BigInteger x, BigInteger y) {
            this.x = x;
            this.y = y;
            this.infinity = false;
        }

        private Point() {
            this.x = BigInteger.ZERO;
            this.y = BigInteger.ZERO;
            this.infinity = true;
        }

        public static final Point INFINITY = new Point();
    }

    private P256() {
    }

    public static Point generator() {
        return new Point(GX, GY);
    }

    /** Affine point addition (with doubling and the inverse case). */
    public static Point add(Point p, Point q) {
        if (p.infinity) {
            return q;
        }
        if (q.infinity) {
            return p;
        }
        if (p.x.equals(q.x)) {
            if (p.y.add(q.y).mod(P).signum() == 0) {
                return Point.INFINITY;
            }
            return doublePoint(p);
        }
        BigInteger lambda = q.y.subtract(p.y)
                .multiply(q.x.subtract(p.x).modInverse(P)).mod(P);
        BigInteger x3 = lambda.multiply(lambda).subtract(p.x).subtract(q.x).mod(P);
        BigInteger y3 = lambda.multiply(p.x.subtract(x3)).subtract(p.y).mod(P);
        return new Point(x3, y3);
    }

    public static Point doublePoint(Point p) {
        if (p.infinity || p.y.signum() == 0) {
            return Point.INFINITY;
        }
        BigInteger lambda = p.x.multiply(p.x).multiply(BigInteger.valueOf(3)).add(A)
                .multiply(p.y.shiftLeft(1).modInverse(P)).mod(P);
        BigInteger x3 = lambda.multiply(lambda).subtract(p.x.shiftLeft(1)).mod(P);
        BigInteger y3 = lambda.multiply(p.x.subtract(x3)).subtract(p.y).mod(P);
        return new Point(x3, y3);
    }

    /** Double-and-add scalar multiplication. */
    public static Point scalarMult(BigInteger k, Point p) {
        BigInteger e = k.mod(N);
        Point result = Point.INFINITY;
        Point addend = p;
        while (e.signum() > 0) {
            if (e.testBit(0)) {
                result = add(result, addend);
            }
            addend = doublePoint(addend);
            e = e.shiftRight(1);
        }
        return result;
    }

    public static boolean isOnCurve(Point p) {
        if (p.infinity) {
            return true;
        }
        BigInteger lhs = p.y.multiply(p.y).mod(P);
        BigInteger rhs = p.x.multiply(p.x).multiply(p.x)
                .add(A.multiply(p.x)).add(B).mod(P);
        return lhs.equals(rhs);
    }

    /** Uncompressed encoding {@code 0x04 || x(32) || y(32)}. */
    public static byte[] encode(Point p) {
        byte[] out = new byte[65];
        out[0] = 0x04;
        copyFixed(p.x, out, 1);
        copyFixed(p.y, out, 33);
        return out;
    }

    /**
     * Decodes an uncompressed point and rejects anything that is not a valid
     * affine point of P-256: a bad prefix/length, a coordinate outside [0, p),
     * or a point off the curve (BSI TR-03110-3 A.3.4.1 / TR-03111 §4.3.3).
     * The identity is not representable in the uncompressed form.
     */
    public static Point decode(byte[] encoded) {
        if (encoded.length != 65 || encoded[0] != 0x04) {
            throw new IllegalArgumentException("not an uncompressed P-256 point");
        }
        BigInteger x = new BigInteger(1, Arrays.copyOfRange(encoded, 1, 33));
        BigInteger y = new BigInteger(1, Arrays.copyOfRange(encoded, 33, 65));
        if (x.compareTo(P) >= 0 || y.compareTo(P) >= 0) {
            throw new IllegalArgumentException("P-256 coordinate is not reduced");
        }
        Point point = new Point(x, y);
        if (!isOnCurve(point)) {
            throw new IllegalArgumentException("point is not on the P-256 curve");
        }
        return point;
    }

    /** The x-coordinate as the 32-byte shared secret. */
    public static byte[] x(Point p) {
        byte[] out = new byte[32];
        copyFixed(p.x, out, 0);
        return out;
    }

    /** A uniform random scalar in [1, n-1]. */
    public static BigInteger randomScalar(SecureRandom random) {
        byte[] buf = new byte[32];
        BigInteger k;
        do {
            random.nextBytes(buf);
            k = new BigInteger(1, buf);
        } while (k.signum() == 0 || k.compareTo(N) >= 0);
        return k;
    }

    private static void copyFixed(BigInteger value, byte[] out, int off) {
        byte[] raw = value.toByteArray();
        int start = raw.length > 32 ? raw.length - 32 : 0;
        int len = raw.length - start;
        System.arraycopy(raw, start, out, off + 32 - len, len);
    }
}
