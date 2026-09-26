package card42.host.emv.kernel.entry;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The reader's Entry Point Combination Table (EMV Contactless Book A v2.12
 * Table 5-1/5-6): the Combinations the reader supports, per transaction type.
 *
 * <p>Book A Table 5-6 defines four transaction types; a reader that supports no
 * Combination for the transaction type produces an empty Candidate List
 * (Contactless Application Not Allowed, Table 5-3).
 */
public final class CombinationTable {

    /** Purchase (EMV v4.4 Book 3 §5.5.1 Transaction Type '9C'). */
    public static final int PURCHASE = 0x00;
    /** Cash advance / cash disbursement. */
    public static final int CASH = 0x01;
    /** Purchase with cashback. */
    public static final int CASHBACK = 0x09;
    /** Refund. */
    public static final int REFUND = 0x20;

    private final Map<Integer, List<Combination>> byType =
            new LinkedHashMap<Integer, List<Combination>>();

    /**
     * The default Entry Point Configuration of the Combinations that do not
     * carry their own (EMV Contactless Book A v2.12 Table 5-2).
     */
    public EntryPointConfiguration defaultConfig;

    public CombinationTable() {
    }

    /** Sets the default Entry Point Configuration (Table 5-2). */
    public CombinationTable withDefaultConfig(EntryPointConfiguration config) {
        this.defaultConfig = config;
        return this;
    }

    /**
     * The Entry Point Configuration of a Combination: its own when set,
     * otherwise the table default, otherwise null (the caller falls back to its
     * own configuration).
     */
    public EntryPointConfiguration configFor(Combination combination) {
        return combination.config != null ? combination.config : defaultConfig;
    }

    /**
     * A table that offers the given AIDs for every transaction type, each with
     * the Kernel ID of the single kernel this reader implements
     * ({@link EntryPoint#READER_KERNEL_ID}).  This preserves the pre-H1
     * behaviour where a flat supported-AID list was used, but only for cards
     * that request that kernel (or a zero Requested Kernel ID): a brand card
     * that requests its brand default is not a candidate
     * (Book B §3.3.2.5 bullet D).
     */
    public static CombinationTable defaults(String... aids) {
        CombinationTable table = new CombinationTable();
        List<Combination> combinations = new ArrayList<Combination>();
        for (String aid : aids) {
            combinations.add(Combination.of(aid));
        }
        table.byType.put(PURCHASE, combinations);
        table.byType.put(CASH, combinations);
        table.byType.put(CASHBACK, combinations);
        table.byType.put(REFUND, combinations);
        return table;
    }

    /** Adds a Combination for one transaction type. */
    public CombinationTable add(int transactionType, Combination combination) {
        List<Combination> list = byType.get(transactionType);
        if (list == null) {
            list = new ArrayList<Combination>();
            byType.put(transactionType, list);
        }
        list.add(combination);
        return this;
    }

    /** The Combinations for the transaction type, or an empty list. */
    public List<Combination> forType(int transactionType) {
        List<Combination> list = byType.get(transactionType);
        return list == null ? Collections.<Combination>emptyList() : list;
    }

    /** True when the table has no Combination for any transaction type. */
    public boolean isEmpty() {
        return byType.isEmpty();
    }
}
