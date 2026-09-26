package card42.host.emv.kernel.analysis;

import static card42.host.emv.kernel.data.Cvm.CVM_ENCIPHERED_PIN_ICC;
import static card42.host.emv.kernel.data.Cvm.CVM_ENCIPHERED_PIN_SIGNATURE;
import static card42.host.emv.kernel.data.Cvm.CVM_FAIL;
import static card42.host.emv.kernel.data.Cvm.CVM_NO_CVM;
import static card42.host.emv.kernel.data.Cvm.CVM_ONLINE_PIN;
import static card42.host.emv.kernel.data.Cvm.CVM_PLAINTEXT_PIN_ICC;
import static card42.host.emv.kernel.data.Cvm.CVM_PLAINTEXT_PIN_SIGNATURE;
import static card42.host.emv.kernel.data.Cvm.CVM_SIGNATURE;
import static card42.host.emv.kernel.data.Cvm.NO_CVM_PERFORMED;
import static card42.host.emv.kernel.data.Cvm.RESULT_FAILED;
import static card42.host.emv.kernel.data.Cvm.RESULT_SUCCESSFUL;
import static card42.host.emv.kernel.data.Cvm.RESULT_UNKNOWN;

import card42.host.emv.kernel.data.Tvr;

/**
 * Cardholder Verification processing of the CVM List (EMV v4.4 Book 3 §10.5,
 * Annex C3; EMV v4.4 Book 4 §6.3.4.5 and Table 2).
 *
 * <p>The CVM List is amount X, amount Y followed by pairs of (CVM code,
 * condition code).  Both X and Y are 4-byte binary amounts (EMV v4.4 Book 3 §10.5).
 * The terminal walks the list in order, evaluates the condition, and performs
 * the first rule whose CVM it recognises and supports.  The outcome is reported
 * in the CVM Results ('9F34'): performed CVM, its condition and the result
 * (00 unknown, 01 failed, 02 successful), together with the TVR bits of
 * EMV v4.4 Book 4 Table 2.
 *
 * <p>The kernel supports No CVM required, Signature, Online PIN and, when the
 * {@link CvmPerformer} performs them, the offline PIN and combination CVMs; other
 * EMV-defined methods are recognised but not supported.  Biometrics are out of
 * scope.
 */
public final class CvmList {

    private CvmList() {
    }

    /** The three-byte CVM Results (performed code, condition, result). */
    public static final class Result {
        public final int code;
        public final int condition;
        public final int result;
        /**
         * True when the 'Cardholder verification was performed' bit in the TSI
         * must be set.  Per EMV v4.4 Book 4 Table 2 this is the case whenever CVM List
         * processing ran with at least one CV Rule, including when no condition
         * was satisfied or no CVM was supported (TSI = 1 in those rows).  Only
         * an absent CVM List or a list without CV Rules leaves TSI = 0.
         */
        public final boolean performed;
        /**
         * True when the CVM List has a formatting error (for example an odd
         * length).  The terminal shall then terminate the transaction
         * (EMV v4.4 Book 3 §10.5 / §7.5).
         */
        public final boolean formatError;

        Result(int code, int condition, int result, boolean performed, boolean formatError) {
            this.code = code;
            this.condition = condition;
            this.result = result;
            this.performed = performed;
            this.formatError = formatError;
        }

        /** The CVM Results value, most significant byte first. */
        public byte[] toBytes() {
            return new byte[] { (byte) code, (byte) condition, (byte) result };
        }
    }

    /** The CVM Results for "no CVM performed" (EMV v4.4 Book 4 Table 2). */
    public static Result none() {
        return new Result(NO_CVM_PERFORMED, 0x00, RESULT_UNKNOWN, false, false);
    }

    /**
     * Processes the CVM List and updates the TVR, using the full transaction
     * context of EMV v4.4 Book 3 Table 44.
     *
     * @param cvmList          the ICC CVM List ('8E'), or null
     * @param amountMinorUnits the Amount, Authorised in minor units
     * @param amountOther      the Amount, Other in minor units (cashback)
     * @param onlinePin        terminal supports online PIN
     * @param signature        terminal supports signature
     * @param cvmRequiredLimit CVM required limit: No CVM is supported only when
     *                         the amount does not exceed this limit (0 = no limit)
     * @param transactionInApplicationCurrency true when the Transaction Currency
     *                         Code equals the Application Currency Code
     * @param transactionType  Transaction Type ('9C'): a cash transaction fails
     *                         the '02' condition even when Amount, Other is zero
     * @param tvr              the TVR to update
     * @return the CVM Results, never null
     */
    public static Result process(byte[] cvmList, long amountMinorUnits, long amountOther,
            boolean onlinePin, boolean signature, long cvmRequiredLimit,
            boolean transactionInApplicationCurrency, int transactionType, byte[] tvr) {
        return process(cvmList, amountMinorUnits, amountOther, onlinePin, signature,
                cvmRequiredLimit, transactionInApplicationCurrency, transactionType,
                CvmPerformer.UNSUPPORTED, tvr);
    }

    /**
     * Processes the CVM List, optionally executing an offline CVM through
     * {@code performer} (EMV v4.4 Book 3 §10.5).
     *
     * @param performer the offline CVM executor; {@link CvmPerformer#UNSUPPORTED}
     *                  when the terminal performs no offline PIN (the contactless
     *                  kernel).  The offline PIN methods the performer supports
     *                  are performed and their outcome is reported in the CVM
     *                  Results (successful / failed) and the TVR
     */
    public static Result process(byte[] cvmList, long amountMinorUnits, long amountOther,
            boolean onlinePin, boolean signature, long cvmRequiredLimit,
            boolean transactionInApplicationCurrency, int transactionType,
            CvmPerformer performer, byte[] tvr) {
        return process(cvmList, amountMinorUnits, amountOther, onlinePin, signature,
                cvmRequiredLimit, transactionInApplicationCurrency, transactionType,
                performer, false, tvr);
    }

    /**
     * As above with the terminal's environment: {@code unattended} selects the
     * CVM conditions 'if unattended cash' (01) / 'if manual cash' (04)
     * (EMV v4.4 Book 3 Table 44).
     */
    public static Result process(byte[] cvmList, long amountMinorUnits, long amountOther,
            boolean onlinePin, boolean signature, long cvmRequiredLimit,
            boolean transactionInApplicationCurrency, int transactionType,
            CvmPerformer performer, boolean unattended, byte[] tvr) {
        if (cvmList == null) {
            // CVM List not present: CVM is not performed, TVR unchanged and
            // TSI = 0 (EMV v4.4 Book 4 Table 2).
            return none();
        }
        if (cvmList.length < 8 || (cvmList.length & 1) != 0) {
            // A CVM List is at least amount X || amount Y and every CV Rule is
            // two bytes; a shorter or odd-length list contains an incomplete CV
            // Rule and is a formatting error, so the terminal terminates the
            // transaction (EMV v4.4 Book 3 §10.5 / §7.5).
            return new Result(NO_CVM_PERFORMED, 0x00, RESULT_UNKNOWN, false, true);
        }
        if (cvmList.length == 8) {
            // X and Y but no CV Rules: the same as the CVM List not being
            // present, TVR unchanged and TSI = 0 (EMV v4.4 Book 3 §10.5; EMV v4.4 Book 4 Table 2).
            return none();
        }

        // X and Y are 4-byte binary amounts (EMV v4.4 Book 3 §10.5).
        long x = binaryToLong(cvmList, 0);
        long y = binaryToLong(cvmList, 4);

        // The last CVM that was actually performed and failed, when its CV Rule
        // had b7=1 (apply succeeding CVM): CVM Results reflect it only if no
        // later CVM is performed.  CVM Results byte 1 is the CVM Code of the
        // last performed CVM as it appears in the CVM List, so b7 is preserved
        // (EMV v4.4 Book 4 §6.3.4.5 / Table 2).
        int lastFailedCode = -1;
        int lastFailedCondition = 0;

        for (int p = 8; p + 1 < cvmList.length; p += 2) {
            int code = cvmList[p] & 0xFF;
            int condition = cvmList[p + 1] & 0xFF;
            int method = code & 0x3F;
            boolean applySucceeding = (code & 0x40) != 0;

            if (!conditionSatisfied(condition, method, amountMinorUnits, amountOther, x, y,
                    onlinePin, signature, cvmRequiredLimit,
                    transactionInApplicationCurrency, transactionType, performer, unattended)) {
                continue;
            }

            if (method == CVM_FAIL) {
                // 'Fail CVM processing': CVM Results 00 <cond> 01, TVR bit 8 = 1
                // (EMV v4.4 Book 4 Table 2).
                Tvr.set(tvr, 2, Tvr.CVM_NOT_SUCCESSFUL);
                return new Result(code, condition, RESULT_FAILED, true, false);
            }

            if (supported(method, amountMinorUnits, onlinePin, signature, cvmRequiredLimit,
                    performer)) {
                if (performer.supports(method)) {
                    // The terminal performs the CVM (offline PIN, online PIN,
                    // signature or a combined method); the outcome sets the CVM
                    // Results result byte and, on failure, 'CVM not successful'
                    // in the TVR (EMV v4.4 Book 3 §10.5, EMV v4.4 Book 4 Table 2).
                    int result = performer.perform(method, condition);
                    if (result != RESULT_SUCCESSFUL) {
                        if (applySucceeding) {
                            // b7=1: go to the next CV Rule; a later successful
                            // CVM supersedes this one in the CVM Results
                            // (EMV v4.4 Book 4 §6.3.4.5 / Table 2).
                            lastFailedCode = code;
                            lastFailedCondition = condition;
                            continue;
                        }
                        Tvr.set(tvr, 2, Tvr.CVM_NOT_SUCCESSFUL);
                    }
                    return new Result(code, condition, result, true, false);
                }
                perform(method, tvr);
                // 'Signature' and 'Online PIN' report an 'unknown' result,
                // 'No CVM required' a 'successful' one; byte 1 carries the CVM
                // Code of the CVM List, b7 included (EMV v4.4 Book 4 Table 2).
                int result = method == CVM_NO_CVM ? RESULT_SUCCESSFUL : RESULT_UNKNOWN;
                return new Result(code, condition, result, true, false);
            }

            // The condition was satisfied but the CVM cannot be performed:
            // CVM Results byte 1 = '3F' (no CVM performed) and byte 3 = '01';
            // TVR bit 8 = 1 (and bit 7 for an unrecognised code), TSI = 1
            // (EMV v4.4 Book 4 Table 2).  The specific 'Unrecognised CVM' /
            // 'PIN pad not present' bits are set as soon as the rule is
            // encountered; 'CVM not successful' only when processing stops here.
            if (!recognised(method)) {
                Tvr.set(tvr, 2, Tvr.UNRECOGNISED_CVM);
            } else if (method <= CVM_ENCIPHERED_PIN_SIGNATURE) {
                // A form of offline PIN the kernel cannot perform: EMV v4.4 Book 3 §10.5
                // also sets 'PIN entry required and PIN pad not present'.
                Tvr.set(tvr, 2, Tvr.PIN_PAD_NOT_PRESENT);
            } else if (method >= 0x06 && method <= 0x0F) {
                // A biometric type the kernel does not support (EMV v4.4 Book 3 §10.5,
                // Table 43): set 'A selected Biometric Type not supported'.
                Tvr.set(tvr, 3, Tvr.BIOMETRIC_TYPE_NOT_SUPPORTED);
            }
            if (!applySucceeding) {
                Tvr.set(tvr, 2, Tvr.CVM_NOT_SUCCESSFUL);
                return new Result(NO_CVM_PERFORMED, 0x00, RESULT_FAILED, true, false);
            }
        }

        // No CV Rule could be performed successfully.  When an offline CVM was
        // performed and failed with b7=1 and no later CVM was performed, the
        // CVM Results reflect that failed CVM; otherwise 'no CVM performed'.
        // Either way TVR bit 8 = 1 and TSI = 1 (EMV v4.4 Book 4 Table 2).
        Tvr.set(tvr, 2, Tvr.CVM_NOT_SUCCESSFUL);
        if (lastFailedCode >= 0) {
            return new Result(lastFailedCode, lastFailedCondition, RESULT_FAILED, true, false);
        }
        return new Result(NO_CVM_PERFORMED, 0x00, RESULT_FAILED, true, false);
    }

    /**
     * Convenience overload without the cashback / currency context (used by
     * tests and callers that only exercise the CVM method/condition logic).
     */
    public static Result process(byte[] cvmList, long amountMinorUnits,
            boolean onlinePin, boolean signature, long cvmRequiredLimit, byte[] tvr) {
        return process(cvmList, amountMinorUnits, 0, onlinePin, signature,
                cvmRequiredLimit, true, 0x00, tvr);
    }

    /** Evaluates a CVM condition code (EMV v4.4 Book 3 Table 44). */
    private static boolean conditionSatisfied(int condition, int method,
            long amount, long amountOther, long x, long y, boolean onlinePin,
            boolean signature, long cvmRequiredLimit,
            boolean transactionInApplicationCurrency, int transactionType,
            CvmPerformer performer, boolean unattended) {
        switch (condition) {
        case 0x00: // Always
            return true;
        case 0x01: // If unattended cash
            return unattended && isCash(transactionType);
        case 0x02: // If not unattended cash and not manual cash and not cashback
            // Amount, Other is the cashback amount; a cash transaction type is
            // cash even when Amount, Other is zero (EMV v4.4 Book 3 Table 44).
            return amountOther == 0 && !isCash(transactionType)
                    && transactionType != 0x09;
        case 0x03: // If terminal supports the CVM
            return supported(method, amount, onlinePin, signature, cvmRequiredLimit, performer);
        case 0x04: // If manual cash (attended cash)
            return !unattended && isCash(transactionType);
        case 0x05: // If purchase with cashback (Transaction Type '09' or Amount, Other != 0)
            return transactionType == 0x09 || amountOther != 0;
        case 0x06: // If transaction is in the application currency and is under X
            return transactionInApplicationCurrency && amount < x;
        case 0x07: // If transaction is in the application currency and is over X
            return transactionInApplicationCurrency && amount > x;
        case 0x08: // If transaction is in the application currency and is under Y
            return transactionInApplicationCurrency && amount < y;
        case 0x09: // If transaction is in the application currency and is over Y
            return transactionInApplicationCurrency && amount > y;
        default:
            return false; // unknown condition: bypass the rule
        }
    }

    /** True when the terminal supports performing the CVM method. */
    private static boolean supported(int method, long amount, boolean onlinePin,
            boolean signature, long cvmRequiredLimit, CvmPerformer performer) {
        switch (method) {
        case CVM_FAIL:
            // 'Fail CVM processing' is always considered supported
            // (EMV v4.4 Book 4 §6.3.4).
            return true;
        case CVM_ONLINE_PIN:
            // A performer that executes online PIN takes precedence over the
            // capability boolean (which alone reports an 'unknown' result
            // without capturing the PIN).
            return onlinePin || performer.supports(method);
        case CVM_SIGNATURE:
            return signature || performer.supports(method);
        case CVM_NO_CVM:
            return cvmRequiredLimit <= 0 || amount <= cvmRequiredLimit;
        default:
            // An offline PIN or combined method is supported only when the
            // performer can execute it.
            return isOfflinePin(method) && performer.supports(method);
        }
    }

    /** True for the CVM codes that require an offline PIN (EMV v4.4 Book 3 Table 43). */
    private static boolean isOfflinePin(int method) {
        return method == CVM_PLAINTEXT_PIN_ICC || method == CVM_PLAINTEXT_PIN_SIGNATURE
                || method == CVM_ENCIPHERED_PIN_ICC || method == CVM_ENCIPHERED_PIN_SIGNATURE;
    }

    /** True for CVM methods defined by EMV v4.4 Book 3 Table 43. */
    private static boolean recognised(int method) {
        return (method >= CVM_FAIL && method <= 0x0F) || method == CVM_SIGNATURE
                || method == CVM_NO_CVM;
    }

    /**
     * True when the Transaction Type ('9C') denotes cash (a cash advance or
     * cash disbursement).  The values follow the ISO 8583:1987 processing-code
     * convention used by EMV (EMV v4.4 Book 3 Annex A Table 37, "the actual
     * values are defined by the relevant payment system"); this project uses
     * '01' and '17' for cash, consistently with ProcessingRestrictions.
     */
    private static boolean isCash(int transactionType) {
        return transactionType == 0x01 || transactionType == 0x17;
    }

    /** Records the TVR side effect of a successful CVM. */
    private static void perform(int method, byte[] tvr) {
        if (method == CVM_ONLINE_PIN) {
            Tvr.set(tvr, 2, Tvr.ONLINE_PIN_ENTERED);
        }
    }

    /** Decodes a 4-byte big-endian binary amount (EMV v4.4 Book 3 §10.5). */
    private static long binaryToLong(byte[] b, int offset) {
        long value = 0;
        for (int i = 0; i < 4; i++) {
            value = (value << 8) | (b[offset + i] & 0xFFL);
        }
        return value;
    }
}
