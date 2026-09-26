package card42.host.emv.kernel.analysis;

import card42.host.emv.kernel.data.Tvr;

/**
 * Processing Restrictions (EMV v4.4 Book 3 §10.4).
 *
 * <p>Before cardholder verification the terminal checks the card's Application
 * Version Number, its effective/expiration dates and its Application Usage
 * Control against the transaction, and records the result in TVR byte 2.
 */
public final class ProcessingRestrictions {

    private ProcessingRestrictions() {
    }

    /** Outcome of the processing-restriction checks (all false = no restriction). */
    public static final class Result {
        public boolean versionMismatch;
        public boolean expired;
        public boolean notYetEffective;
        public boolean serviceNotAllowed;

        public boolean restricted() {
            return versionMismatch || expired || notYetEffective || serviceNotAllowed;
        }
    }

    /**
     * Applies the processing restrictions to the TVR.
     *
     * @param tvr                 the TVR to update
     * @param cardVersion         ICC Application Version Number ('9F08'), or null
     * @param terminalVersion     terminal Application Version Number ('9F09'), or null
     * @param expiry              ICC Application Expiration Date ('5F24', YYMMDD), or null
     * @param effective           ICC Application Effective Date ('5F25', YYMMDD), or null
     * @param today               transaction date ('9A', YYMMDD)
     * @param auc                 ICC Application Usage Control ('9F07'), or null
     * @param issuerCountryPresent true when the ICC Issuer Country Code ('5F28')
     *                            is present; the AUC checks require both the AUC
     *                            and the Issuer Country Code (EMV v4.4 Book 3 §10.4.2)
     * @param transactionType     Transaction Type ('9C')
     * @param domestic            true when the terminal country matches the issuer country
     * @param atAtm               true when the transaction is conducted at an ATM
     * @param cashback            true when the transaction has a cashback amount
     */
    public static Result check(byte[] tvr, byte[] cardVersion, byte[] terminalVersion,
            byte[] expiry, byte[] effective, byte[] today, byte[] auc,
            boolean issuerCountryPresent, int transactionType, boolean domestic,
            boolean atAtm, boolean cashback) {
        Result r = new Result();

        // Application Version Number: when present in the ICC and different from
        // the terminal's, set 'ICC and terminal have different application
        // versions' (EMV v4.4 Book 3 §10.4.1).  Absent ICC version = compatible.
        if (cardVersion != null && terminalVersion != null
                && !java.util.Arrays.equals(cardVersion, terminalVersion)) {
            r.versionMismatch = true;
        }

        // Effective / Expiration Date (EMV v4.4 Book 3 §10.4.3).
        if (expiry != null && today != null && compareDate(expiry, today) < 0) {
            r.expired = true;
        }
        if (effective != null && today != null && compareDate(effective, today) > 0) {
            r.notYetEffective = true;
        }

        // Application Usage Control (EMV v4.4 Book 3 §10.4.2).  The card does not
        // personalize 9F07, so the check is skipped when it is absent.  The
        // 'Valid at ATMs' / 'Valid at terminals other than ATMs' checks apply
        // whenever the AUC is present; the Table 36 domestic/international
        // checks additionally require the Issuer Country Code ('5F28').
        if (auc != null && auc.length >= 1) {
            boolean allowed = aucAllows(auc, transactionType, domestic, atAtm,
                    cashback, issuerCountryPresent);
            r.serviceNotAllowed = !allowed;
        }

        if (r.versionMismatch) {
            Tvr.set(tvr, 1, Tvr.APPLICATION_VERSION_MISMATCH);
        }
        if (r.expired) {
            Tvr.set(tvr, 1, Tvr.EXPIRED_APPLICATION);
        }
        if (r.notYetEffective) {
            Tvr.set(tvr, 1, Tvr.APPLICATION_NOT_YET_EFFECTIVE);
        }
        if (r.serviceNotAllowed) {
            Tvr.set(tvr, 1, Tvr.SERVICE_NOT_ALLOWED);
        }
        return r;
    }

    /**
     * Convenience overload without the ATM / cashback context (used by callers
     * and tests that only exercise the cash/goods/services bits).  The Issuer
     * Country Code is assumed present, matching the original AUC semantics.
     */
    public static Result check(byte[] tvr, byte[] cardVersion, byte[] terminalVersion,
            byte[] expiry, byte[] effective, byte[] today, byte[] auc,
            int transactionType, boolean domestic) {
        return check(tvr, cardVersion, terminalVersion, expiry, effective, today, auc,
                true, transactionType, domestic, false, false);
    }

    /**
     * Convenience overload for callers that supply the ATM / cashback context
     * but know the Issuer Country Code is present (EMV v4.4 Book 3 §10.4.2).
     */
    public static Result check(byte[] tvr, byte[] cardVersion, byte[] terminalVersion,
            byte[] expiry, byte[] effective, byte[] today, byte[] auc,
            int transactionType, boolean domestic, boolean atAtm, boolean cashback) {
        return check(tvr, cardVersion, terminalVersion, expiry, effective, today, auc,
                true, transactionType, domestic, atAtm, cashback);
    }

    /**
     * Whether the Application Usage Control allows a transaction of this type.
     * The 'Valid at ATMs' / 'Valid at terminals other than ATMs' bit is checked
     * whenever the AUC is present (EMV v4.4 Book 3 §10.4.2); the
     * domestic/international bits of Table 36 are checked only when the Issuer
     * Country Code is present.  A purchase requires the goods bits and/or the
     * services bits for the applicable geography, a cash advance the cash bits;
     * for a purchase with cashback the cashback bit must be set
     * (EMV v4.4 Book 3 §10.4.2 Table 36; Annex C2 Table 42).
     */
    private static boolean aucAllows(byte[] auc, int transactionType, boolean domestic,
            boolean atAtm, boolean cashback, boolean issuerCountryPresent) {
        int b1 = auc[0] & 0xFF;
        // 'Valid at ATMs' (b2) or 'Valid at terminals other than ATMs' (b1):
        // unconditional whenever the AUC is present (EMV v4.4 Book 3 §10.4.2).
        int placeBit = atAtm ? 0x02 : 0x01;
        if ((b1 & placeBit) == 0) {
            return false;
        }
        if (!issuerCountryPresent) {
            // The Table 36 checks require the Issuer Country Code too.
            return true;
        }
        boolean cash = transactionType == 0x01 || transactionType == 0x17;
        if (cash) {
            if ((b1 & (domestic ? 0x80 : 0x40)) == 0) {
                return false;
            }
        } else {
            // Purchase / purchase with cashback / refund: 'Valid for domestic
            // goods' (b6) and/or 'Valid for domestic services' (b4), or their
            // international equivalents (b5 / b3).
            if ((b1 & (domestic ? 0x28 : 0x14)) == 0) {
                return false;
            }
        }
        if (cashback) {
            // 'Domestic cashback allowed' (byte 2 b8) / 'International cashback
            // allowed' (byte 2 b7) (EMV v4.4 Book 3 Table 36/42).
            if (auc.length < 2) {
                return false;
            }
            int b2 = auc[1] & 0xFF;
            if ((b2 & (domestic ? 0x80 : 0x40)) == 0) {
                return false;
            }
        }
        return true;
    }

    /**
     * Compares two YYMMDD dates, returning a negative value when a is earlier
     * than b.  The two-digit year is interpreted with the EMV century rule
     * (YY 00-49 = 20YY, YY 50-99 = 19YY; EMV v4.4 Book 4 §6.7.2/§6.7.3), so a
     * 1999 expiration date is correctly seen as being before a 2026
     * transaction date instead of comparing as the byte strings '99' &gt; '26'.
     */
    static int compareDate(byte[] a, byte[] b) {
        int n = Math.min(a.length, b.length);
        if (n >= 1) {
            int yearA = absoluteYear(a[0] & 0xFF);
            int yearB = absoluteYear(b[0] & 0xFF);
            if (yearA != yearB) {
                return yearA - yearB;
            }
        }
        for (int i = 1; i < n; i++) {
            int x = a[i] & 0xFF;
            int y = b[i] & 0xFF;
            if (x != y) {
                return x - y;
            }
        }
        return a.length - b.length;
    }

    /** The absolute year of an EMV two-digit BCD year (EMV v4.4 Book 4 §6.7.3). */
    private static int absoluteYear(int bcd) {
        int yy = ((bcd >> 4) & 0x0F) * 10 + (bcd & 0x0F);
        return yy < 50 ? 2000 + yy : 1900 + yy;
    }
}
