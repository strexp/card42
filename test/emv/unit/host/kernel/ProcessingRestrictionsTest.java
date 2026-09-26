package card42.test;
import card42.host.common.util.Hex;
import card42.host.emv.kernel.analysis.ProcessingRestrictions;
import card42.host.emv.kernel.data.Tvr;

/**
 * Unit tests for {@link ProcessingRestrictions} (EMV v4.4 Book 3 §10.4).
 */
final class ProcessingRestrictionsTest {

    private ProcessingRestrictionsTest() {
    }

    static void run() {
        System.out.println("ProcessingRestrictionsTest");

        byte[] today = Hex.parse("260923"); // 2026-09-23
        byte[] expiry = Hex.parse("291231"); // 2029-12-31
        byte[] effective = Hex.parse("200101"); // 2020-01-01
        byte[] version2 = Hex.parse("0002");

        // A clean card: no restriction bits.
        byte[] tvr = Tvr.blank();
        ProcessingRestrictions.Result r = ProcessingRestrictions.check(tvr,
                version2, version2, expiry, effective, today, null, 0x00, true);
        Asserts.check(!r.restricted(), "clean card has no restrictions");
        Asserts.check(!Tvr.isSet(tvr, 1, Tvr.EXPIRED_APPLICATION), "not expired");

        // Application version mismatch.
        tvr = Tvr.blank();
        r = ProcessingRestrictions.check(tvr, Hex.parse("0001"), version2,
                expiry, effective, today, null, 0x00, true);
        Asserts.check(r.versionMismatch, "version mismatch detected");
        Asserts.check(Tvr.isSet(tvr, 1, Tvr.APPLICATION_VERSION_MISMATCH),
                "version mismatch sets the TVR bit");

        // Expired application.
        tvr = Tvr.blank();
        r = ProcessingRestrictions.check(tvr, null, null,
                Hex.parse("200101"), null, today, null, 0x00, true);
        Asserts.check(r.expired, "expired application detected");
        Asserts.check(Tvr.isSet(tvr, 1, Tvr.EXPIRED_APPLICATION), "expired sets the TVR bit");

        // A 20th-century expiration date must still be seen as expired: the
        // two-digit year is read as 19YY for YY 50-99, so '99' is 1999 and not
        // "after" the 2026 transaction (EMV v4.4 Book 4 §6.7.2/§6.7.3).
        tvr = Tvr.blank();
        r = ProcessingRestrictions.check(tvr, null, null,
                Hex.parse("991231"), null, today, null, 0x00, true);
        Asserts.check(r.expired, "1999 expiration is expired in 2026");
        Asserts.check(Tvr.isSet(tvr, 1, Tvr.EXPIRED_APPLICATION),
                "century-boundary expiry sets the TVR bit");

        // Not yet effective.
        tvr = Tvr.blank();
        r = ProcessingRestrictions.check(tvr, null, null,
                null, Hex.parse("300101"), today, null, 0x00, true);
        Asserts.check(r.notYetEffective, "future application detected");
        Asserts.check(Tvr.isSet(tvr, 1, Tvr.APPLICATION_NOT_YET_EFFECTIVE),
                "not yet effective sets the TVR bit");

        // Application Usage Control: international goods + non-ATM terminal,
        // domestic purchase.
        tvr = Tvr.blank();
        r = ProcessingRestrictions.check(tvr, null, null, null, null, today,
                Hex.parse("11"), 0x00, true);
        Asserts.check(r.serviceNotAllowed, "domestic purchase blocked by AUC");
        Asserts.check(Tvr.isSet(tvr, 1, Tvr.SERVICE_NOT_ALLOWED), "AUC sets the TVR bit");
        // The same card allows an international purchase.
        tvr = Tvr.blank();
        r = ProcessingRestrictions.check(tvr, null, null, null, null, today,
                Hex.parse("11"), 0x00, false);
        Asserts.check(!r.serviceNotAllowed, "international purchase allowed by AUC");
        // Domestic cash is blocked when only the goods bits are set.
        tvr = Tvr.blank();
        r = ProcessingRestrictions.check(tvr, null, null, null, null, today,
                Hex.parse("21"), 0x01, true);
        Asserts.check(r.serviceNotAllowed, "domestic cash blocked by goods-only AUC");

        // Application Usage Control services bits (EMV v4.4 Book 3 §10.4.2 Table 36):
        // a purchase is allowed when either the goods or the services bits are
        // set for the applicable geography.
        tvr = Tvr.blank();
        r = ProcessingRestrictions.check(tvr, null, null, null, null, today,
                Hex.parse("09"), 0x00, true);
        Asserts.check(!r.serviceNotAllowed, "domestic services AUC allows a purchase");
        tvr = Tvr.blank();
        r = ProcessingRestrictions.check(tvr, null, null, null, null, today,
                Hex.parse("05"), 0x00, false);
        Asserts.check(!r.serviceNotAllowed, "international services AUC allows a purchase");
        // Domestic services only must still block an international purchase
        // (EMV v4.4 Book 3 §10.4).
        tvr = Tvr.blank();
        r = ProcessingRestrictions.check(tvr, null, null, null, null, today,
                Hex.parse("09"), 0x00, false);
        Asserts.check(r.serviceNotAllowed, "domestic services AUC blocks international");
        // International services only must still block a domestic purchase
        // (EMV v4.4 Book 3 §10.4).
        tvr = Tvr.blank();
        r = ProcessingRestrictions.check(tvr, null, null, null, null, today,
                Hex.parse("05"), 0x00, true);
        Asserts.check(r.serviceNotAllowed, "international services AUC blocks domestic");

        // 'Valid at ATMs' (byte 1 b2) / 'Valid at terminals other than ATMs'
        // (b1): an ATM transaction needs b2, a non-ATM one b1 (EMV v4.4 Book 3 §10.4.2).
        tvr = Tvr.blank();
        r = ProcessingRestrictions.check(tvr, null, null, null, null, today,
                Hex.parse("11"), 0x00, false, true, false);
        Asserts.check(r.serviceNotAllowed, "non-ATM-only AUC blocks an ATM transaction");
        tvr = Tvr.blank();
        r = ProcessingRestrictions.check(tvr, null, null, null, null, today,
                Hex.parse("13"), 0x00, false, true, false);
        Asserts.check(!r.serviceNotAllowed, "AUC with the ATM bit allows an ATM transaction");
        tvr = Tvr.blank();
        r = ProcessingRestrictions.check(tvr, null, null, null, null, today,
                Hex.parse("12"), 0x00, false, false, false);
        Asserts.check(r.serviceNotAllowed, "ATM-only AUC blocks a non-ATM transaction");

        // Cashback bits (byte 2 b8 domestic / b7 international, EMV v4.4 Book 3 Table 36).
        tvr = Tvr.blank();
        r = ProcessingRestrictions.check(tvr, null, null, null, null, today,
                Hex.parse("2180"), 0x00, true, false, true);
        Asserts.check(!r.serviceNotAllowed, "domestic cashback allowed by AUC byte 2");
        tvr = Tvr.blank();
        r = ProcessingRestrictions.check(tvr, null, null, null, null, today,
                Hex.parse("2140"), 0x00, true, false, true);
        Asserts.check(r.serviceNotAllowed, "international-cashback-only AUC blocks domestic cashback");
        tvr = Tvr.blank();
        r = ProcessingRestrictions.check(tvr, null, null, null, null, today,
                Hex.parse("1140"), 0x00, false, false, true);
        Asserts.check(!r.serviceNotAllowed, "international cashback allowed by AUC byte 2");
        // A cashback transaction needs a second AUC byte at all.
        tvr = Tvr.blank();
        r = ProcessingRestrictions.check(tvr, null, null, null, null, today,
                Hex.parse("21"), 0x00, true, false, true);
        Asserts.check(r.serviceNotAllowed, "cashback without byte 2 is not allowed");

        // The 'Valid at ATMs' / 'Valid at terminals other than ATMs' check
        // applies whenever the AUC is present, even without the Issuer Country
        // Code (EMV v4.4 Book 3 §10.4.2).  AUC '12' is ATM-only (b2), so a
        // non-ATM transaction is not allowed.
        tvr = Tvr.blank();
        r = ProcessingRestrictions.check(tvr, null, null, null, null, today,
                Hex.parse("12"), false, 0x00, false, false, false);
        Asserts.check(r.serviceNotAllowed,
                "ATM-only AUC blocks a non-ATM transaction without 5F28");
        Asserts.check(Tvr.isSet(tvr, 1, Tvr.SERVICE_NOT_ALLOWED),
                "place-bit failure sets the TVR bit");

        // The Table 36 domestic/international checks additionally require the
        // Issuer Country Code; without it only the place bit is checked
        // (EMV v4.4 Book 3 §10.4.2).  AUC '01' has no goods/services bit, so
        // the check must be skipped when 5F28 is absent.
        tvr = Tvr.blank();
        r = ProcessingRestrictions.check(tvr, null, null, null, null, today,
                Hex.parse("01"), false, 0x00, false, false, false);
        Asserts.check(!r.serviceNotAllowed,
                "Table 36 is skipped without the Issuer Country Code");
        Asserts.check(!Tvr.isSet(tvr, 1, Tvr.SERVICE_NOT_ALLOWED),
                "missing Issuer Country Code leaves the TVR bit clear");

        // An absent ICC Application Version Number is compatible with the
        // terminal version (EMV v4.4 Book 3 §10.4.1).
        tvr = Tvr.blank();
        r = ProcessingRestrictions.check(tvr, null, version2, expiry, effective, today,
                null, 0x00, true);
        Asserts.check(!r.versionMismatch, "absent ICC version is compatible");

        // An expiration date equal to the transaction date is not yet expired
        // (EMV v4.4 Book 3 §10.4.3).
        tvr = Tvr.blank();
        r = ProcessingRestrictions.check(tvr, null, null, Hex.parse("260923"), null,
                today, null, 0x00, true);
        Asserts.check(!r.expired, "expiry equal to the transaction date is valid");

        // Positive cash bits: domestic cash requires AUC b8 and the non-ATM
        // place bit b1, international cash b7 and b1 (EMV v4.4 Book 3 Table 36).
        tvr = Tvr.blank();
        r = ProcessingRestrictions.check(tvr, null, null, null, null, today,
                Hex.parse("81"), 0x01, true);
        Asserts.check(!r.serviceNotAllowed, "domestic cash allowed by AUC b8");
        tvr = Tvr.blank();
        r = ProcessingRestrictions.check(tvr, null, null, null, null, today,
                Hex.parse("41"), 0x01, false);
        Asserts.check(!r.serviceNotAllowed, "international cash allowed by AUC b7");
    }
}
