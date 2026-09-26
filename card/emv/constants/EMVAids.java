package card42.emv;

import card42.common.*;

/* The AIDs used by card42-emv (docs/specs/common/architecture.md §1).
 *
 * The payment instance AIDs derive from the shared card42 RID (CARDB =
 * 43 41 52 44 42); the directory AIDs are the standard EMV PSE / PPSE names and
 * keep their alias RID.  Java Card forbids different RIDs for a *CAP applet*
 * AID, but an *instance* AID chosen at INSTALL time is not restricted
 * (docs/specs/common/architecture.md §1, §2), which is why all four instances live in
 * one package.
 *
 * The arrays are compile-time literal `static final` fields: the converter only
 * rejects `invokestatic` in `<clinit>` (e.g. a factory call in a field
 * initializer), not `newarray`.  See Defaults for the same pattern.
 *
 * @author card42
 */

public final class EMVAids {

    /** Payment applet class / contact instance AID: 43415244420101 (CARDB + 01 01). */
    public static final byte[] PAYMENT_CONTACT = {
            0x43, 0x41, 0x52, 0x44, 0x42, 0x01, 0x01 };

    /** Contactless payment instance AID: 43415244420102 (CARDB + 01 02). */
    public static final byte[] PAYMENT_CONTACTLESS = {
            0x43, 0x41, 0x52, 0x44, 0x42, 0x01, 0x02 };

    /** Contact PSE AID: 1PAY.SYS.DDF01. */
    public static final byte[] PSE = {
            0x31, 0x50, 0x41, 0x59, 0x2E, 0x53, 0x59, 0x53,
            0x2E, 0x44, 0x44, 0x46, 0x30, 0x31 };

    /** Contactless PPSE AID: 2PAY.SYS.DDF01. */
    public static final byte[] PPSE = {
            0x32, 0x50, 0x41, 0x59, 0x2E, 0x53, 0x59, 0x53,
            0x2E, 0x44, 0x44, 0x46, 0x30, 0x31 };

    private EMVAids() {
    }
}
