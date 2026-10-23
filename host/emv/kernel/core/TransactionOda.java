package card42.host.emv.kernel.core;

import card42.host.emv.lib.IssuerKey;

/** Read-only view of the offline-data-authentication outcome. */
public interface TransactionOda {

    byte[] tvr();

    byte[] tsi();

    boolean sdaPerformed();

    boolean sdaFailed();

    boolean ddaPerformed();

    boolean ddaFailed();

    boolean cdaPerformed();

    boolean cdaFailed();

    boolean cdaSelected();

    boolean odaAttempted();

    IssuerKey issuerKey();

    IssuerKey iccKey();

    byte[] dataAuthenticationCode();

    byte[] iccDynamicNumber();
}
