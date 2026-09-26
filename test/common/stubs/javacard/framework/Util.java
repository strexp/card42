package javacard.framework;

/**
 * Minimal plain-JVM stand-in for the Java Card {@code Util} class, used only by
 * the pure-JVM unit tests (docs/specs/common/toolchain.md §6).  It is placed before the
 * {@code api_classic} jar on the classpath so the card sources link against
 * this implementation instead of the native one.  Only the methods the tested
 * card classes call are provided.
 */
public final class Util {

    private Util() {
    }

    public static short arrayCopy(byte[] src, short srcOff,
                                  byte[] dest, short destOff, short length) {
        System.arraycopy(src, srcOff, dest, destOff, length);
        return (short) (destOff + length);
    }

    public static short arrayCopyNonAtomic(byte[] src, short srcOff,
                                           byte[] dest, short destOff, short length) {
        System.arraycopy(src, srcOff, dest, destOff, length);
        return (short) (destOff + length);
    }

    public static short arrayFillNonAtomic(byte[] bArray, short bOff, short bLen, byte bValue) {
        for (short i = 0; i < bLen; i++) {
            bArray[(short) (bOff + i)] = bValue;
        }
        return (short) (bOff + bLen);
    }

    public static byte arrayCompare(byte[] src, short srcOff,
                                    byte[] dest, short destOff, short length) {
        for (short i = 0; i < length; i++) {
            int a = src[(short) (srcOff + i)] & 0xFF;
            int b = dest[(short) (destOff + i)] & 0xFF;
            if (a != b) {
                return (byte) (a < b ? -1 : 1);
            }
        }
        return 0;
    }

    public static short makeShort(byte b1, byte b2) {
        return (short) (((b1 & 0xFF) << 8) | (b2 & 0xFF));
    }

    public static short getShort(byte[] bArray, short bOff) {
        return makeShort(bArray[bOff], bArray[(short) (bOff + 1)]);
    }

    public static short setShort(byte[] bArray, short bOff, short sValue) {
        bArray[bOff] = (byte) (sValue >> 8);
        bArray[(short) (bOff + 1)] = (byte) sValue;
        return (short) (bOff + 2);
    }
}
