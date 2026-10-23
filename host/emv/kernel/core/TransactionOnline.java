package card42.host.emv.kernel.core;

/** Read-only view of the online authorisation and issuer-script outcome. */
public interface TransactionOnline {

    boolean wentOnline();

    boolean issuerAuthPerformed();

    byte[] issuerAuthData();

    byte[] arc();

    boolean declined();

    boolean adviceRequired();

    boolean serviceNotAllowed();

    boolean cardCaptureRequested();

    boolean referralRequested();

    boolean attendantForcedAcceptance();

    boolean reversalRequired();

    byte[] issuerScriptResults();

    boolean issuerScriptFailedBeforeFinalAc();

    boolean issuerScriptFailedAfterFinalAc();

    Outcome outcome();

    TransactionResult.Decision decision();
}
