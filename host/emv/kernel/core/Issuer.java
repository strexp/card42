package card42.host.emv.kernel.core;

/**
 * The online host a terminal kernel asks to authorise an ARQC
 * (EMV v4.4 Book 2 §8.2).  The kernel never holds the ICC master key; the
 * issuer callback computes the ARPC and the Card Status Update.
 */
public interface Issuer {

    /**
     * Authorises an online transaction.
     *
     * @param arqc   the Application Cryptogram returned by the first AC
     * @param atc    the Application Transaction Counter of that AC
     * @param result the live transaction result (TVR, TSI, AID, records, ...)
     *               so the host can build the authorisation request from the
     *               transaction data the kernel observed
     * @return the authorisation, or null when the terminal cannot go online
     */
    Authorization authorize(byte[] arqc, int atc, TransactionResult result);
}
