package card42.test;

import card42.host.common.util.Hex;
import card42.host.common.codec.Tags;

/**
 * Pure-JVM tests for the acquirer / clearing host message model
 * (EMV v4.4 Book 4 §12.1.x, Tables 17/19/20/22), including the tokenisation
 * elements PAR (9F24), Token Requestor ID (9F19) and Last 4 Digits of PAN
 * (9F25).
 */
final class ClearingHostTest {

    private ClearingHostTest() {
    }

    private static ClearingHost.TransactionData sample() {
        ClearingHost.TransactionData d = new ClearingHost.TransactionData();
        d.aip = Hex.parse("7900");
        d.ac = Hex.parse("AABBCCDDEEFF0011");
        d.cid = Hex.parse("40");
        d.iad = Hex.parse("0FA5110000000000");
        d.atc = Hex.parse("0007");
        d.unpredictableNumber = Hex.parse("12345678");
        d.tvr = Hex.parse("8000048000");
        d.auc = Hex.parse("FF00");
        d.cvmList = Hex.parse("1F03");
        d.cvmResults = Hex.parse("1F0300");
        d.terminalCapabilities = Hex.parse("E0F8C8");
        d.terminalType = Hex.parse("22");
        d.iacDefault = Hex.parse("0000000000");
        d.iacDenial = Hex.parse("0000000000");
        d.iacOnline = Hex.parse("FFFFFFFFFF");
        d.issuerScriptResults = Hex.parse("2000AABBCCDD");
        d.par = Hex.parse("5041523031323334353637383930313233343536");
        d.tokenRequestorId = Hex.parse("000000000001");
        d.last4Pan = Hex.parse("9012");
        return d;
    }

    private static boolean contains(int[] tags, int tag) {
        for (int t : tags) {
            if (t == tag) {
                return true;
            }
        }
        return false;
    }

    static void run() {
        System.out.println("ClearingHost");

        ClearingHost.TransactionData d = sample();

        // --- financial record (Table 17) ------------------------------------
        ClearingHost.Record fin = ClearingHost.financialRecord(d);
        Asserts.check(fin.isValid(), "financial record has all mandatory elements");
        Asserts.eq(0, fin.missingMandatory().length, "no missing mandatory elements");
        Asserts.check(fin.has(ClearingHost.TAG_PAR), "financial record carries PAR");
        Asserts.check(fin.has(ClearingHost.TAG_TOKEN_REQUESTOR_ID),
                "financial record carries Token Requestor ID");
        Asserts.check(fin.has(ClearingHost.TAG_LAST4_PAN),
                "financial record carries Last 4 Digits of PAN");
        Asserts.check(fin.has(ClearingHost.TAG_ISSUER_SCRIPT_RESULTS),
                "financial record carries Issuer Script Results");
        Asserts.bytes(Hex.parse("AABBCCDDEEFF0011"), fin.get(ClearingHost.TAG_AC),
                "financial record AC value");

        // TLV round trip.
        byte[] encoded = fin.encode();
        Asserts.bytes(Hex.parse("0007"), Tags.find(encoded, ClearingHost.TAG_ATC),
                "financial record TLV round trip (ATC)");
        Asserts.bytes(Hex.parse("7900"), Tags.find(encoded, ClearingHost.TAG_AIP),
                "financial record TLV round trip (AIP)");

        // --- missing mandatory element --------------------------------------
        // The TVR is unconditional in EMV v4.4 Book 4 Table 17, so its absence
        // is reported; the Unpredictable Number is conditional ("present if
        // input to application cryptogram calculation") and is not.
        ClearingHost.TransactionData incomplete = sample();
        incomplete.tvr = null;
        ClearingHost.Record finBad = ClearingHost.financialRecord(incomplete);
        Asserts.check(!finBad.isValid(), "missing TVR is invalid");
        Asserts.check(contains(finBad.missingMandatory(), ClearingHost.TAG_TVR),
                "missing mandatory reports 95");

        ClearingHost.TransactionData noUn = sample();
        noUn.unpredictableNumber = null;
        Asserts.check(ClearingHost.financialRecord(noUn).isValid(),
                "conditional Unpredictable Number may be absent");

        // CVM Results, Terminal Capabilities and Terminal Type are also
        // unconditional in EMV v4.4 Book 4 Table 17.
        ClearingHost.TransactionData noCvm = sample();
        noCvm.cvmResults = null;
        Asserts.check(contains(ClearingHost.financialRecord(noCvm).missingMandatory(),
                ClearingHost.TAG_CVM_RESULTS), "missing CVM Results is reported");
        ClearingHost.TransactionData noCap = sample();
        noCap.terminalCapabilities = null;
        Asserts.check(contains(ClearingHost.financialRecord(noCap).missingMandatory(),
                ClearingHost.TAG_TERM_CAPABILITIES),
                "missing Terminal Capabilities is reported");
        ClearingHost.TransactionData noType = sample();
        noType.terminalType = null;
        Asserts.check(contains(ClearingHost.financialRecord(noType).missingMandatory(),
                ClearingHost.TAG_TERM_TYPE), "missing Terminal Type is reported");

        // --- online advice (Table 20) ---------------------------------------
        ClearingHost.Record advice = ClearingHost.onlineAdvice(d);
        Asserts.check(advice.isValid(), "online advice has all mandatory elements");
        Asserts.check(contains(advice.mandatoryTags(), ClearingHost.TAG_CID),
                "online advice requires the CID");
        Asserts.check(advice.has(ClearingHost.TAG_PAR), "online advice carries PAR");

        // --- reversal (Table 22) --------------------------------------------
        ClearingHost.Record rev = ClearingHost.reversal(d);
        Asserts.check(rev.isValid(), "reversal has all mandatory elements");
        Asserts.check(!contains(rev.mandatoryTags(), ClearingHost.TAG_AC),
                "reversal does not require the AC");
        Asserts.check(rev.has(ClearingHost.TAG_TOKEN_REQUESTOR_ID),
                "reversal carries Token Requestor ID");
        // Table 22 lists Terminal Capabilities and Terminal Type but not CVM
        // Results, so a reversal without CVM Results is still valid.
        ClearingHost.TransactionData revNoCvm = sample();
        revNoCvm.cvmResults = null;
        Asserts.check(ClearingHost.reversal(revNoCvm).isValid(),
                "reversal does not require CVM Results");

        // --- reconciliation (Table 19) --------------------------------------
        // Table 19 has no ICC-specific elements, so the reconciliation record
        // must not carry the AIP/ATC/IAD/TVR (only tokenisation is modelled).
        ClearingHost.Record rec = ClearingHost.reconciliation(d);
        Asserts.check(rec.isValid(), "reconciliation has no mandatory elements");
        Asserts.check(!rec.has(ClearingHost.TAG_TVR),
                "reconciliation carries no ICC-specific TVR");
        Asserts.check(!rec.has(ClearingHost.TAG_AIP),
                "reconciliation carries no ICC-specific AIP");

        // --- an element list with no tokenisation still validates -----------
        ClearingHost.TransactionData noToken = sample();
        noToken.par = null;
        noToken.tokenRequestorId = null;
        noToken.last4Pan = null;
        ClearingHost.Record noTokenRec = ClearingHost.financialRecord(noToken);
        Asserts.check(noTokenRec.isValid(), "tokenisation elements are optional");
        Asserts.check(!noTokenRec.has(ClearingHost.TAG_PAR), "no PAR when absent");
    }
}
