package card42.test;

import java.util.Arrays;

import card42.emv.Defaults;
import card42.emv.EMVProtocolState;
import card42.emv.Iad;
import card42.emv.OfflineRisk;
import card42.host.common.util.Bytes;
import card42.host.common.util.Hex;

/**
 * Pure-JVM tests for the CCD Issuer Application Data / Card Verification
 * Results layout (EMV v4.4 Book 3 Annex C §C9): the fixed
 * 32-byte Format Code 'A' template, the CVR write window and the CVR bit
 * encodings aggregated from the protocol state and the offline risk
 * accumulators.
 */
final class IadCvrTest {

    private IadCvrTest() {
    }

    static void run() {
        System.out.println("Iad/CVR");

        // --- Format Code 'A' template ---------------------------------------
        Asserts.eq(32, Iad.LENGTH, "IAD length");
        Asserts.eq(32, Defaults.IAD.length, "default IAD length");
        Asserts.eq(0x0F, Defaults.IAD[0] & 0xFF, "IAD byte 1 length indicator");
        Asserts.eq(0xA5, Defaults.IAD[1] & 0xFF, "IAD CCI is Format Code 'A' / CV '5'");
        Asserts.eq(0x0F, Defaults.IAD[Iad.OFF_DISCRETIONARY_LENGTH] & 0xFF,
                "IAD byte 17 length indicator");

        // --- CVR write window ------------------------------------------------
        byte[] iad = Arrays.copyOf(Defaults.IAD, Defaults.IAD.length);
        byte[] cvr = Hex.parse("A5 5F 30 12 00");
        Iad.setCvr(iad, (short) 0, cvr, (short) 0);
        Asserts.bytes(cvr,
                Arrays.copyOfRange(iad, Iad.OFF_CVR, Iad.OFF_CVR + Iad.CVR_LENGTH),
                "setCvr writes bytes 4-8");
        // Bytes outside the CVR window are untouched.
        Asserts.eq(0x0F, iad[0] & 0xFF, "setCvr leaves byte 1");
        Asserts.eq(0xA5, iad[1] & 0xFF, "setCvr leaves the CCI");
        Asserts.eq(0x0F, iad[Iad.OFF_DISCRETIONARY_LENGTH] & 0xFF,
                "setCvr leaves byte 17");

        // --- CVR byte 1 bit encodings ---------------------------------------
        Asserts.eq(0x80, Iad.CVR1_AC2_NOT_REQUESTED & 0xFF, "AC2 not-requested code");
        Asserts.eq(0x40, Iad.CVR1_AC2_TC & 0xFF, "AC2 TC code");
        Asserts.eq(0x10, Iad.CVR1_AC1_TC & 0xFF, "AC1 TC code");
        Asserts.eq(0x20, Iad.CVR1_AC1_ARQC & 0xFF, "AC1 ARQC code");
        Asserts.eq(0x08, Iad.CVR1_CDA_PERFORMED & 0xFF, "CDA performed bit");
        Asserts.eq(0x04, Iad.CVR1_DDA_PERFORMED & 0xFF, "DDA performed bit");
        Asserts.eq(0x02, Iad.CVR1_ISSUER_AUTH_NOT_PERFORMED & 0xFF,
                "issuer auth not performed bit");
        Asserts.eq(0x01, Iad.CVR1_ISSUER_AUTH_FAILED & 0xFF, "issuer auth failed bit");

        // --- CVR byte 1 assembly (Iad.cvrByte1) ------------------------------
        // First AC response: second AC not requested (10b) and first AC ARQC (10b).
        Asserts.eq(0xA0, Iad.cvrByte1((byte) 2, (byte) 2, false, false, false, false) & 0xFF,
                "first AC ARQC, second AC not requested");
        // First AC response with a TC decision.
        Asserts.eq(0x90, Iad.cvrByte1((byte) 1, (byte) 2, false, false, false, false) & 0xFF,
                "first AC TC, second AC not requested");
        // Second AC response: first AC ARQC, second AC TC.
        Asserts.eq(0x60, Iad.cvrByte1((byte) 2, (byte) 1, false, false, false, false) & 0xFF,
                "first AC ARQC, second AC TC");
        // The status flags OR into the low bits.
        Asserts.eq(0xAF, Iad.cvrByte1((byte) 2, (byte) 2, true, true, true, true) & 0xFF,
                "first AC status flags");
        // Issuer authentication not performed (0x02) and failed (0x01) are
        // distinct bits (EMV v4.4 Book 3 §9.2.3.2).
        Asserts.eq(0xA2, Iad.cvrByte1((byte) 2, (byte) 2, false, false, true, false) & 0xFF,
                "issuer auth not performed only");
        Asserts.eq(0xA1, Iad.cvrByte1((byte) 2, (byte) 2, false, false, false, true) & 0xFF,
                "issuer auth failed only");
        Asserts.eq(0x01, Iad.CVR2_LAST_ONLINE_NOT_COMPLETED & 0xFF,
                "last online not completed bit");

        // --- Protocol state CVR flags ---------------------------------------
        EMVProtocolState state = new EMVProtocolState();
        Asserts.check(!state.isDdaPerformed(), "DDA not performed initially");
        Asserts.check(!state.isCdaPerformed(), "CDA not performed initially");
        state.setDdaPerformed();
        state.setCdaPerformed();
        Asserts.check(state.isDdaPerformed(), "DDA flag set");
        Asserts.check(state.isCdaPerformed(), "CDA flag set");
        state.startNewSession();
        Asserts.check(!state.isDdaPerformed(), "DDA flag reset on a new session");
        Asserts.check(!state.isCdaPerformed(), "CDA flag reset on a new session");

        // --- Go-online-on-next flag (CVR byte 4 b2) --------------------------
        OfflineRisk risk = new OfflineRisk();
        Asserts.check(!risk.isGoOnlineNext(), "go-online-next clear initially");
        risk.setGoOnlineNext();
        Asserts.check(risk.isGoOnlineNext(), "go-online-next set");
        risk.clearGoOnlineNext();
        Asserts.check(!risk.isGoOnlineNext(), "go-online-next cleared");
    }
}
