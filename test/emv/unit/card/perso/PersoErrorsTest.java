package card42.test;

import javacard.framework.ISOException;

import card42.emv.PersoErrors;

/**
 * Pure-JVM tests for the personalization failure mapping
 * (docs/specs/common/toolchain.md §6): an {@link ISOException} is propagated unchanged, a
 * {@code CryptoException} maps to 6985 and any other failure to 6F00.
 *
 * <p>Tool coverage of the project error mapping (docs/specs/common/toolchain.md §6),
 * not an EMV/ICAO/BSI/CPS clause.
 */
final class PersoErrorsTest {

    private PersoErrorsTest() {
    }

    static void run() {
        System.out.println("PersoErrors");

        ISOException original;
        try {
            ISOException.throwIt((short) 0x6A80);
            original = null;
        } catch (ISOException e) {
            original = e;
        }
        final ISOException iso = original;
        Asserts.sw((short) 0x6A80, () -> PersoErrors.throwMapped(iso),
                "ISOException is propagated unchanged");

        Asserts.sw((short) 0x6985, () -> PersoErrors.throwMapped(
                        new javacard.security.CryptoException((short) 0x01)),
                "CryptoException -> 6985");
        Asserts.sw((short) 0x6F00, () -> PersoErrors.throwMapped(
                        new IllegalStateException("boom")),
                "other exception -> 6F00");
    }
}
