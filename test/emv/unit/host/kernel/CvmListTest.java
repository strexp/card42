package card42.test;
import card42.host.emv.kernel.analysis.CvmList;
import card42.host.emv.kernel.analysis.CvmPerformer;
import card42.host.common.util.Hex;
import card42.host.emv.kernel.data.Tvr;

/**
 * Unit tests for {@link CvmList} (EMV v4.4 Book 3 §10.5, EMV v4.4 Book 4 §6.3.4.5 and
 * Table 2).
 */
final class CvmListTest {

    private CvmListTest() {
    }

    static void run() {
        System.out.println("CvmListTest");

        // The contactless card's CVM List: No CVM required if the terminal
        // supports the CVM (condition 03).
        byte[] contactless = Hex.parse("00000000000000001F03");
        byte[] tvr = Tvr.blank();
        CvmList.Result r = CvmList.process(contactless, 500, false, false, 0, tvr);
        Asserts.eq(0x1F, r.code, "No CVM code");
        Asserts.eq(0x03, r.condition, "No CVM condition");
        Asserts.eq(0x02, r.result, "No CVM successful");
        Asserts.check(!Tvr.isSet(tvr, 2, Tvr.CVM_NOT_SUCCESSFUL),
                "No CVM leaves TVR byte 3 clear");
        Asserts.bytes(Hex.parse("1F0302"), r.toBytes(), "CVM Results bytes");

        // Above the CVM required limit No CVM is not offered; with no other
        // rule no condition is satisfied, so CVM Results = 3F 00 01 and TVR
        // byte 3 bit 8 is set (EMV v4.4 Book 4 Table 2).
        tvr = Tvr.blank();
        r = CvmList.process(contactless, 500, false, false, 100, tvr);
        Asserts.eq(0x3F, r.code, "No CVM above limit -> no CVM performed");
        Asserts.eq(0x01, r.result, "no condition satisfied -> failed");
        Asserts.bytes(Hex.parse("3F0001"), r.toBytes(), "no condition satisfied bytes");
        Asserts.check(Tvr.isSet(tvr, 2, Tvr.CVM_NOT_SUCCESSFUL),
                "No CVM above limit sets CVM not successful");
        Asserts.check(r.performed, "no condition satisfied still sets the TSI CVM bit");

        // Online PIN: performed when supported, sets 'Online PIN entered' and
        // reports an 'unknown' result (EMV v4.4 Book 4 Table 2).
        byte[] onlinePin = Hex.parse("00000000000000000203");
        tvr = Tvr.blank();
        r = CvmList.process(onlinePin, 500, true, false, 0, tvr);
        Asserts.eq(0x02, r.code, "Online PIN code");
        Asserts.eq(0x00, r.result, "Online PIN result is unknown");
        Asserts.check(Tvr.isSet(tvr, 2, Tvr.ONLINE_PIN_ENTERED),
                "Online PIN sets TVR 'Online PIN entered'");
        Asserts.bytes(Hex.parse("020300"), r.toBytes(), "Online PIN Results bytes");
        // Online PIN with condition 'always': not supported and b7 clear -> fail.
        tvr = Tvr.blank();
        r = CvmList.process(Hex.parse("00000000000000000200"), 500, false, false, 0, tvr);
        Asserts.eq(0x01, r.result, "Unsupported Online PIN fails");
        Asserts.eq(0x3F, r.code, "Unsupported Online PIN -> no CVM performed");
        Asserts.check(Tvr.isSet(tvr, 2, Tvr.CVM_NOT_SUCCESSFUL),
                "Unsupported Online PIN sets CVM not successful");

        // Signature (condition always): successful but result 'unknown'.
        tvr = Tvr.blank();
        r = CvmList.process(Hex.parse("00000000000000001E00"), 500, false, true, 0, tvr);
        Asserts.eq(0x1E, r.code, "Signature code");
        Asserts.eq(0x00, r.result, "Signature result is unknown");
        Asserts.check(!Tvr.isSet(tvr, 2, Tvr.CVM_NOT_SUCCESSFUL),
                "Signature leaves TVR byte 3 clear");

        // Fail CVM processing (code 00) stops the list with byte 3 = 01.
        tvr = Tvr.blank();
        r = CvmList.process(Hex.parse("00000000000000000000"), 500, false, false, 0, tvr);
        Asserts.eq(0x01, r.result, "Fail CVM result");
        Asserts.check(Tvr.isSet(tvr, 2, Tvr.CVM_NOT_SUCCESSFUL),
                "Fail CVM sets CVM not successful");

        // 'Fail CVM processing' is always considered supported, so condition 03
        // selects it even though the terminal supports no other CVM
        // (EMV v4.4 Book 4 §6.3.4).
        tvr = Tvr.blank();
        r = CvmList.process(Hex.parse("00000000000000000003"), 500, false, false, 0, tvr);
        Asserts.eq(0x00, r.code, "Fail CVM selected by condition 03");
        Asserts.eq(0x03, r.condition, "Fail CVM condition 03");
        Asserts.eq(0x01, r.result, "Fail CVM result");
        Asserts.bytes(Hex.parse("000301"), r.toBytes(), "Fail CVM results bytes");

        // An unrecognised CVM sets 'Unrecognised CVM' and, with b7 clear, fails
        // with CVM Results byte 1 = 3F (EMV v4.4 Book 4 Table 2).
        tvr = Tvr.blank();
        r = CvmList.process(Hex.parse("00000000000000007F00"), 500, false, false, 0, tvr);
        Asserts.eq(0x3F, r.code, "Unrecognised CVM -> no CVM performed");
        Asserts.eq(0x01, r.result, "Unrecognised CVM fails");
        Asserts.check(Tvr.isSet(tvr, 2, Tvr.UNRECOGNISED_CVM),
                "Unrecognised CVM sets the TVR bit");

        // An unsupported offline PIN sets 'PIN pad not present or not working'
        // and reports no CVM performed.
        tvr = Tvr.blank();
        r = CvmList.process(Hex.parse("00000000000000000100"), 500, false, false, 0, tvr);
        Asserts.eq(0x3F, r.code, "Unsupported offline PIN -> no CVM performed");
        Asserts.eq(0x01, r.result, "Unsupported offline PIN fails");
        Asserts.check(Tvr.isSet(tvr, 2, Tvr.PIN_PAD_NOT_PRESENT),
                "Offline PIN sets PIN pad not present");

        // A biometric CVM the kernel does not support sets 'A selected
        // Biometric Type not supported' (EMV v4.4 Book 3 §10.5).
        tvr = Tvr.blank();
        r = CvmList.process(Hex.parse("00000000000000000700"), 500, false, false, 0, tvr);
        Asserts.eq(0x3F, r.code, "Unsupported biometric -> no CVM performed");
        Asserts.eq(0x01, r.result, "Unsupported biometric fails");
        Asserts.check(Tvr.isSet(tvr, 3, Tvr.BIOMETRIC_TYPE_NOT_SUPPORTED),
                "Unsupported biometric sets the TVR byte 4 bit");

        // 'Apply succeeding CV Rule' (b7 set): the offline PIN is skipped and
        // the next rule (No CVM) succeeds.
        tvr = Tvr.blank();
        r = CvmList.process(Hex.parse("000000000000000041001F03"), 500, false, false, 0, tvr);
        Asserts.eq(0x1F, r.code, "succeeding rule reaches No CVM");
        Asserts.eq(0x02, r.result, "succeeding rule succeeds");
        Asserts.check(!Tvr.isSet(tvr, 2, Tvr.CVM_NOT_SUCCESSFUL),
                "succeeding rule clears CVM failure");

        // Amount conditions: X and Y are 4-byte binary amounts (EMV v4.4 Book 3 §10.5).
        // X = 1000, Y = 500; amount 500 is under X and not over Y.
        tvr = Tvr.blank();
        r = CvmList.process(Hex.parse("000003E8000001F41F06"), 500,
                false, false, 0, tvr);
        Asserts.eq(0x02, r.result, "under X condition satisfied");
        tvr = Tvr.blank();
        r = CvmList.process(Hex.parse("000003E8000001F41F09"), 500,
                false, false, 0, tvr);
        Asserts.eq(0x3F, r.code, "over Y not satisfied -> no CVM performed");
        Asserts.eq(0x01, r.result, "over Y not satisfied -> failed");
        Asserts.check(Tvr.isSet(tvr, 2, Tvr.CVM_NOT_SUCCESSFUL),
                "over Y not satisfied sets CVM not successful");

        // Condition 05 'purchase with cashback' depends on Amount, Other, and
        // conditions 06-09 require the transaction to be in the application
        // currency (EMV v4.4 Book 3 Table 44).
        tvr = Tvr.blank();
        r = CvmList.process(Hex.parse("00000000000000001F05"), 500, 100,
                false, false, 0, true, 0x00, tvr);
        Asserts.eq(0x02, r.result, "cashback condition satisfied");
        tvr = Tvr.blank();
        r = CvmList.process(Hex.parse("00000000000000001F05"), 500, 0,
                false, false, 0, true, 0x00, tvr);
        Asserts.eq(0x01, r.result, "no cashback -> condition 05 not satisfied");
        tvr = Tvr.blank();
        r = CvmList.process(Hex.parse("000003E8000001F41F06"), 500, 0,
                false, false, 0, false, 0x00, tvr);
        Asserts.eq(0x01, r.result, "other currency -> condition 06 not satisfied");
        tvr = Tvr.blank();
        r = CvmList.process(Hex.parse("000003E8000001F41F06"), 500, 0,
                false, false, 0, true, 0x00, tvr);
        Asserts.eq(0x02, r.result, "same currency -> condition 06 satisfied");

        // Condition 02 excludes cash and purchase-with-cashback transactions
        // even when Amount, Other is zero (EMV v4.4 Book 3 Table 44).
        tvr = Tvr.blank();
        r = CvmList.process(Hex.parse("00000000000000001F02"), 500, 0,
                false, false, 0, true, 0x01, tvr);
        Asserts.eq(0x01, r.result, "cash -> condition 02 not satisfied");
        tvr = Tvr.blank();
        r = CvmList.process(Hex.parse("00000000000000001F02"), 500, 0,
                false, false, 0, true, 0x09, tvr);
        Asserts.eq(0x01, r.result, "cashback type -> condition 02 not satisfied");
        tvr = Tvr.blank();
        r = CvmList.process(Hex.parse("00000000000000001F02"), 500, 0,
                false, false, 0, true, 0x00, tvr);
        Asserts.eq(0x02, r.result, "purchase -> condition 02 satisfied");

        // A present CVM List with a CV Rule reports that CVM was performed, so
        // the kernel may set the TSI CVM bit (EMV v4.4 Book 3 §10.5).
        tvr = Tvr.blank();
        r = CvmList.process(contactless, 500, false, false, 0, tvr);
        Asserts.check(r.performed, "a CVM List with a CV Rule was performed");
        Asserts.check(!r.formatError, "a well-formed CVM List has no format error");

        // An absent CVM List is not performed and leaves the TVR unchanged
        // (EMV v4.4 Book 4 Table 2).
        tvr = Tvr.blank();
        r = CvmList.process(null, 500, false, false, 0, tvr);
        Asserts.check(!r.performed, "absent CVM List was not performed");
        Asserts.eq(0x3F, r.code, "absent CVM List -> no CVM performed");
        Asserts.eq(0x00, r.result, "absent CVM List -> unknown result");
        Asserts.check(!Tvr.isSet(tvr, 2, Tvr.CVM_NOT_SUCCESSFUL),
                "absent CVM List leaves TVR byte 3 clear");

        // A CVM List with no CV Rules is the same as an absent one (EMV v4.4 Book 3 §10.5).
        tvr = Tvr.blank();
        r = CvmList.process(Hex.parse("0000000000000000"), 500, false, false, 0, tvr);
        Asserts.check(!r.performed, "CVM List with no CV Rules was not performed");
        Asserts.check(!r.formatError, "CVM List with no CV Rules is not a format error");
        Asserts.check(!Tvr.isSet(tvr, 2, Tvr.CVM_NOT_SUCCESSFUL),
                "CVM List with no CV Rules leaves TVR byte 3 clear");

        // An odd-length CVM List contains an incomplete CV Rule and is a
        // formatting error: the terminal terminates the transaction
        // (EMV v4.4 Book 3 §10.5 / §7.5).
        tvr = Tvr.blank();
        r = CvmList.process(Hex.parse("00000000000000001F03FF"), 500, false, false, 0, tvr);
        Asserts.check(r.formatError, "odd-length CVM List is a format error");
        Asserts.check(!r.performed, "a malformed CVM List was not performed");
        // A list shorter than amount X || amount Y is also a format error.
        tvr = Tvr.blank();
        r = CvmList.process(Hex.parse("00000000"), 500, false, false, 0, tvr);
        Asserts.check(r.formatError, "short CVM List is a format error");

        // Condition 01 'if unattended cash': satisfied at an unattended terminal
        // for a cash transaction (EMV v4.4 Book 3 Table 44).
        tvr = Tvr.blank();
        r = CvmList.process(Hex.parse("00000000000000001F01"), 500, 0,
                false, false, 0, true, 0x01, CvmPerformer.UNSUPPORTED, true, tvr);
        Asserts.eq(0x1F, r.code, "unattended cash condition satisfied");
        Asserts.check(!Tvr.isSet(tvr, 2, Tvr.CVM_NOT_SUCCESSFUL),
                "unattended cash No CVM succeeds");
        // The same rule at an attended terminal does not apply.
        tvr = Tvr.blank();
        r = CvmList.process(Hex.parse("00000000000000001F01"), 500, 0,
                false, false, 0, true, 0x01, CvmPerformer.UNSUPPORTED, false, tvr);
        Asserts.eq(0x3F, r.code, "attended cash does not satisfy condition 01");

        // Condition 04 'if manual cash' (attended cash).
        tvr = Tvr.blank();
        r = CvmList.process(Hex.parse("00000000000000001F04"), 500, 0,
                false, false, 0, true, 0x01, CvmPerformer.UNSUPPORTED, false, tvr);
        Asserts.eq(0x1F, r.code, "manual cash condition satisfied");
        // Condition 05 'if purchase with cashback': Transaction Type '09'
        // counts even when Amount, Other is zero (EMV v4.4 Book 3 Table 44).
        tvr = Tvr.blank();
        r = CvmList.process(Hex.parse("00000000000000001F05"), 500, 0,
                false, false, 0, true, 0x09, CvmPerformer.UNSUPPORTED, false, tvr);
        Asserts.eq(0x1F, r.code, "purchase with cashback by transaction type");

        // Conditions 07 (over X) and 08 (under Y): X = 1000, Y = 500
        // (EMV v4.4 Book 3 Table 44).
        tvr = Tvr.blank();
        r = CvmList.process(Hex.parse("000003E8000001F41F07"), 2000,
                false, false, 0, tvr);
        Asserts.eq(0x1F, r.code, "over X condition satisfied");
        tvr = Tvr.blank();
        r = CvmList.process(Hex.parse("000003E8000001F41F07"), 500,
                false, false, 0, tvr);
        Asserts.eq(0x01, r.result, "not over X -> condition 07 not satisfied");
        tvr = Tvr.blank();
        r = CvmList.process(Hex.parse("000003E8000001F41F08"), 100,
                false, false, 0, tvr);
        Asserts.eq(0x1F, r.code, "under Y condition satisfied");
        tvr = Tvr.blank();
        r = CvmList.process(Hex.parse("000003E8000001F41F08"), 600,
                false, false, 0, tvr);
        Asserts.eq(0x01, r.result, "not under Y -> condition 08 not satisfied");

        // An unknown condition code bypasses the rule; with no other rule the
        // CVM fails with 'no CVM performed' (EMV v4.4 Book 3 Table 44).
        tvr = Tvr.blank();
        r = CvmList.process(Hex.parse("00000000000000001F0A"), 500,
                false, false, 0, tvr);
        Asserts.eq(0x3F, r.code, "unknown condition bypasses the rule");
        Asserts.eq(0x01, r.result, "unknown condition -> failed");

        // Every biometric code 0x0A-0x0F is unrecognised-but-biometric and sets
        // 'A selected Biometric Type not supported' (EMV v4.4 Book 3 §10.5).
        for (int biometric = 0x0A; biometric <= 0x0F; biometric++) {
            tvr = Tvr.blank();
            r = CvmList.process(new byte[] { 0, 0, 0, 0, 0, 0, 0, 0,
                    (byte) biometric, 0x00 }, 500, false, false, 0, tvr);
            Asserts.eq(0x3F, r.code, "biometric 0x" + Integer.toHexString(biometric)
                    + " -> no CVM performed");
            Asserts.check(Tvr.isSet(tvr, 3, Tvr.BIOMETRIC_TYPE_NOT_SUPPORTED),
                    "biometric 0x" + Integer.toHexString(biometric)
                    + " sets the biometric TVR bit");
        }
    }
}
