package card42.host.emv.kernel;

/**
 * AFL syntax validation (EMV v4.4 Book 3 §7.5): an AFL with no entries, a
 * non-multiple-of-4 length, an SFI of 0 or 31, a starting record of 0, an
 * ending record before the starting record, or more ODA records than the entry
 * covers terminates the transaction.
 *
 * <p>Split out of {@link TransactionFlow} so the flow reads as the EMV step
 * sequence; it is a pure function of the AFL bytes.
 */
final class AflSyntax {

    private AflSyntax() {
    }

    /**
     * Validates an AFL.  Throws {@link IllegalStateException} with the offending
     * entry when the syntax is invalid.
     *
     * <p>The AFL is a list of 4-byte entries
     * {@code SFI(1) | first record(1) | last record(1) | ODA records(1)}
     * (EMV v4.4 Book 3 §10.2); §7.5 makes an unusable entry a transaction
     * termination.
     */
    static void validate(byte[] afl) {
        // Book 3 §7.5/§10.2: an empty or non-multiple-of-4 AFL terminates the transaction.
        if (afl == null || afl.length == 0 || (afl.length % 4) != 0) {
            throw new IllegalStateException("AFL syntax: empty or truncated AFL");
        }
        for (int e = 0; e + 3 < afl.length; e += 4) {
            int sfi = (afl[e] & 0xFF) >> 3;
            int first = afl[e + 1] & 0xFF;
            int last = afl[e + 2] & 0xFF;
            int odaRecords = afl[e + 3] & 0xFF;
            // Book 3 §7.5: SFI 1-30 (0 and 31 are reserved), a starting record
            // of at least 1, last >= first, and at most (last-first+1) ODA records.
            if (sfi == 0 || sfi == 31 || first == 0 || last < first
                    || odaRecords > (last - first + 1)) {
                throw new IllegalStateException("AFL syntax: SFI " + sfi
                        + " records " + first + ".." + last + " ODA " + odaRecords);
            }
        }
    }
}
