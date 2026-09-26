package card42.host.emv.kernel.core;

/**
 * An online authorisation: the ARC and the Issuer Authentication Data
 * (EMV v4.4 Book 2 §8.2).
 */
public class Authorization {

    public final byte[] arc;
    public final byte[] issuerAuthData;
    /**
     * Optional issuer script templates (tags 71/72) to process after the
     * final GENERATE AC (EMV v4.4 Book 3 §10.10).  Null when none.
     */
    public final byte[][] issuerScripts;

    public Authorization(byte[] arc, byte[] issuerAuthData) {
        this(arc, issuerAuthData, null);
    }

    public Authorization(byte[] arc, byte[] issuerAuthData, byte[][] issuerScripts) {
        this.arc = arc;
        this.issuerAuthData = issuerAuthData;
        this.issuerScripts = issuerScripts;
    }
}
