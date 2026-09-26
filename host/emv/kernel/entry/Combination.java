package card42.host.emv.kernel.entry;

/**
 * A reader Combination: an AID and the Kernel ID that processes it
 * (EMV Contactless Book A v2.12 Table 5-1).
 *
 * <p>The reader maintains one Combination Table per transaction type
 * ({@link CombinationTable}); a Directory Entry is a candidate only when its
 * ADF Name matches a Combination's AID and its Requested Kernel ID is zero or
 * the Combination's Kernel ID (Book B §3.3.2.5 bullet D).
 */
public final class Combination {

    /** The AID the reader supports. */
    public final String aid;
    /** The Kernel ID of this Combination. */
    public final int kernelId;
    /**
     * The Entry Point Configuration Data of this Combination (EMV Contactless
     * Book A v2.12 Table 5-2), or null to use the Combination Table default.
     * Pre-Processing Indicators are computed per Combination (Book A §5.7).
     */
    public final EntryPointConfiguration config;

    public Combination(String aid, int kernelId) {
        this(aid, kernelId, null);
    }

    /** A Combination with its own Entry Point Configuration (Book A Table 5-2). */
    public Combination(String aid, int kernelId, EntryPointConfiguration config) {
        this.aid = aid;
        this.kernelId = kernelId;
        this.config = config;
    }

    /**
     * A Combination for the single kernel this reader implements
     * ({@link EntryPoint#READER_KERNEL_ID}).  The reader does not implement any
     * brand kernel, so its Combinations must not claim one: a brand card that
     * requests its brand default (for example Visa Kernel 3) is then not a
     * candidate (Book B §3.3.2.5 bullet D) and Entry Point ends the application
     * cleanly instead of activating a kernel the reader cannot process.
     */
    public static Combination of(String aid) {
        return new Combination(aid, EntryPoint.READER_KERNEL_ID);
    }
}
