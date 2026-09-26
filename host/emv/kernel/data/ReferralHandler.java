package card42.host.emv.kernel.data;

/**
 * Handles an issuer-initiated voice referral on an attended terminal
 * (EMV v4.4 Book 4 §6.5.2.2).  When the Authorisation Response Code is a
 * referral, the terminal alerts the attendant and asks whether the transaction
 * is approved or declined; the terminal must not modify the ARC.
 */
public interface ReferralHandler {

    /**
     * @param arc the Authorisation Response Code returned by the issuer
     * @return {@link Boolean#TRUE} to approve, {@link Boolean#FALSE} to decline,
     *         or null when the referral cannot be performed (the terminal then
     *         follows its default procedures)
     */
    Boolean referral(byte[] arc);
}
