package card42.host.emv.kernel.core;

import card42.host.emv.lib.Responses;

/** Read-only view of the first/second GENERATE AC exchange. */
public interface TransactionCryptogram {

    byte requestedFirstAc();

    byte firstCid();

    byte secondCid();

    Responses.AcResponse firstAc();

    Responses.AcResponse secondAc();

    byte[] firstResponse();

    byte[] secondResponse();
}
