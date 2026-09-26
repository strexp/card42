package card42.test;

import card42.host.emv.kernel.data.Cvm;
import card42.host.emv.kernel.analysis.CvmList;
import card42.host.emv.kernel.analysis.CvmPerformer;
import card42.host.emv.kernel.data.Tvr;
import card42.host.common.util.Hex;

/**
 * Unit tests for the offline CVM performer overload of {@link CvmList}
 * (EMV v4.4 Book 3 §10.5, EMV v4.4 Book 4 Table 2).
 *
 * <p>The default ({@link CvmPerformer#UNSUPPORTED}) path is covered by
 * {@link CvmListTest}; these cases exercise a contact kernel that performs
 * offline PIN.
 */
final class CvmListPerformerTest {

    private CvmListPerformerTest() {
    }

    static void run() {
        System.out.println("CvmListPerformerTest");

        // Offline PIN plaintext, condition always: 01 00.
        byte[] plaintext = Hex.parse("0000000000000000 01 00");
        // Offline PIN enciphered, condition always: 04 00.
        byte[] enciphered = Hex.parse("0000000000000000 04 00");

        // A performer that succeeds for the given method.
        int[] seen = new int[2];
        CvmPerformer success = performer(true, Cvm.RESULT_SUCCESSFUL, seen);
        byte[] tvr = Tvr.blank();
        CvmList.Result r = CvmList.process(plaintext, 500, 0, false, false, 0,
                true, 0x00, success, tvr);
        Asserts.eq(0x01, r.code, "offline PIN code reported");
        Asserts.eq(0x00, r.condition, "offline PIN condition reported");
        Asserts.eq(Cvm.RESULT_SUCCESSFUL, r.result, "offline PIN successful result");
        Asserts.check(r.performed, "offline PIN sets the TSI CVM bit");
        Asserts.check(!Tvr.isSet(tvr, 2, Tvr.CVM_NOT_SUCCESSFUL),
                "successful offline PIN leaves TVR byte 3 clear");
        Asserts.eq(0x01, seen[0], "performer called with the selected method");
        Asserts.eq(0x00, seen[1], "performer called with the condition");

        // A failed offline PIN sets 'CVM not successful'.
        tvr = Tvr.blank();
        r = CvmList.process(plaintext, 500, 0, false, false, 0,
                true, 0x00, performer(true, Cvm.RESULT_FAILED, null), tvr);
        Asserts.eq(Cvm.RESULT_FAILED, r.result, "failed offline PIN result");
        Asserts.bytes(Hex.parse("010001"), r.toBytes(), "failed offline PIN Results bytes");
        Asserts.check(Tvr.isSet(tvr, 2, Tvr.CVM_NOT_SUCCESSFUL),
                "failed offline PIN sets CVM not successful");

        // b7=1 (apply succeeding CVM): a failed offline PIN falls through to the
        // next CV Rule, and a later successful CVM supersedes it in the CVM
        // Results (EMV v4.4 Book 4 §6.3.4.5 / Table 2).
        byte[] applySucceeding = Hex.parse("0000000000000000 41 00 1F 00");
        tvr = Tvr.blank();
        r = CvmList.process(applySucceeding, 500, 0, false, false, 0,
                true, 0x00, performer(true, Cvm.RESULT_FAILED, null), tvr);
        Asserts.eq(0x1F, r.code, "apply-succeeding offline PIN falls through to No CVM");
        Asserts.eq(Cvm.RESULT_SUCCESSFUL, r.result, "later No CVM supersedes the failure");
        Asserts.check(!Tvr.isSet(tvr, 2, Tvr.CVM_NOT_SUCCESSFUL),
                "successful later CVM leaves TVR byte 3 clear");

        // b7=1 and the end of the list is reached: the CVM Results reflect the
        // failed CVM, TVR bit 8 = 1 (EMV v4.4 Book 4 Table 2).
        byte[] applySucceedingOnly = Hex.parse("0000000000000000 41 00");
        tvr = Tvr.blank();
        r = CvmList.process(applySucceedingOnly, 500, 0, false, false, 0,
                true, 0x00, performer(true, Cvm.RESULT_FAILED, null), tvr);
        Asserts.bytes(Hex.parse("410001"), r.toBytes(),
                "apply-succeeding failure at the end reports the CVM Code (b7 kept)");
        Asserts.check(Tvr.isSet(tvr, 2, Tvr.CVM_NOT_SUCCESSFUL),
                "apply-succeeding failure at the end sets CVM not successful");

        // Enciphered offline PIN is performed through the same path.
        tvr = Tvr.blank();
        r = CvmList.process(enciphered, 500, 0, false, false, 0,
                true, 0x00, performer(true, Cvm.RESULT_SUCCESSFUL, null), tvr);
        Asserts.eq(0x04, r.code, "enciphered PIN code reported");
        Asserts.eq(Cvm.RESULT_SUCCESSFUL, r.result, "enciphered PIN successful");

        // Condition 03 ('if terminal supports the CVM') also consults the performer.
        byte[] conditional = Hex.parse("0000000000000000 01 03");
        tvr = Tvr.blank();
        r = CvmList.process(conditional, 500, 0, false, false, 0,
                true, 0x00, performer(true, Cvm.RESULT_SUCCESSFUL, null), tvr);
        Asserts.eq(Cvm.RESULT_SUCCESSFUL, r.result,
                "condition 03 performs a supported offline PIN");

        // A performer that does not support the method leaves the old behaviour:
        // offline PIN unsupported -> 'PIN pad not present' and CVM not successful.
        tvr = Tvr.blank();
        r = CvmList.process(plaintext, 500, 0, false, false, 0,
                true, 0x00, performer(false, Cvm.RESULT_SUCCESSFUL, null), tvr);
        Asserts.eq(0x3F, r.code, "unsupported offline PIN -> no CVM performed");
        Asserts.eq(Cvm.RESULT_FAILED, r.result, "unsupported offline PIN fails");
        Asserts.check(Tvr.isSet(tvr, 2, Tvr.PIN_PAD_NOT_PRESENT),
                "unsupported offline PIN sets PIN pad not present");
        Asserts.check(Tvr.isSet(tvr, 2, Tvr.CVM_NOT_SUCCESSFUL),
                "unsupported offline PIN sets CVM not successful");

        // An UNSUPPORTED performer (the contactless kernel): same behaviour.
        tvr = Tvr.blank();
        r = CvmList.process(plaintext, 500, 0, false, false, 0, true, 0x00, tvr);
        Asserts.eq(0x3F, r.code, "unsupported performer -> offline PIN not performed");
        Asserts.check(Tvr.isSet(tvr, 2, Tvr.PIN_PAD_NOT_PRESENT),
                "unsupported performer sets PIN pad not present");
    }

    /**
     * A performer that supports the offline PIN methods when {@code supports} is
     * true and always returns {@code result}; records the last (method, condition)
     * into {@code seen} when it is not null.
     */
    private static CvmPerformer performer(final boolean supports, final int result,
                                          final int[] seen) {
        return new CvmPerformer() {
            @Override
            public boolean supports(int method) {
                return supports && (method == Cvm.CVM_PLAINTEXT_PIN_ICC
                        || method == Cvm.CVM_ENCIPHERED_PIN_ICC);
            }

            @Override
            public int perform(int method, int condition) {
                if (seen != null) {
                    seen[0] = method;
                    seen[1] = condition;
                }
                return result;
            }
        };
    }
}
