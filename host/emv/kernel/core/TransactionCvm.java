package card42.host.emv.kernel.core;

/** Read-only view of the cardholder-verification and signature outcome. */
public interface TransactionCvm {

    byte[] cvmResults();

    byte[] onlinePinBlock();

    byte[] signature();
}
