package card42.host.emv.kernel.core;

import java.util.Map;

/**
 * Read-only view of the transaction data a kernel collected from the card:
 * application selection, GPO/AFL data, the records and the first ICC value of
 * a tag.  A consumer that only renders or inspects a transaction can depend on
 * this view instead of the full {@link TransactionResult}.
 */
public interface TransactionData {

    String aidHex();

    byte[] fci();

    int aip();

    byte[] afl();

    byte[] pdolData();

    byte[] record1();

    byte[] cdol1Data();

    byte[] cdol2Data();

    /** The read-only records keyed by {@code (sfi << 8) | record}. */
    Map<Integer, byte[]> records();

    /** The record at (sfi, record), or null. */
    byte[] record(int sfi, int record);

    /** The first ICC-sourced value of a tag across the records, or null. */
    byte[] firstValue(int tag);
}
