package card42.host.emv.kernel.entry;

import card42.host.common.codec.Tags;
import card42.host.common.util.Hex;

/**
 * Entry Point Combination Selection (EMV Contactless Book B v2.12 §3.3.2):
 * match every Directory Entry against the kernel's AID list, decode the
 * Requested Kernel ID ('9F2A') and select the highest priority entry.
 *
 * <p>This is the pure selection logic of the terminal kernel; it performs no
 * APDU exchange and holds no state.  {@code selectCandidate} is called with the
 * PPSE FCI the kernel received, {@code requestedKernelId} decodes one Directory
 * Entry on its own.
 */
public final class EntryPoint {

    /**
     * The Kernel ID of the single kernel this reader implements.  It is the
     * generic "kernel by ADF Name" (Book B §3.3.2.5 bullet D / Table 3-6), which
     * is the kernel the card42 card advertises with {@code 9F2A = 00}.  The
     * reader's Combination Table must carry this value (not the brand default),
     * so a brand card that requests its own kernel (for example Visa Kernel 3)
     * is removed at Entry Point and the transaction ends cleanly instead of
     * activating a kernel the reader does not implement.
     */
    public static final int READER_KERNEL_ID = 0;

    private EntryPoint() {
    }

    /**
     * A Combination added to the Candidate List (EMV Contactless Book B v2.12
     * §3.3.2.5 bullet E): the ADF Name, the AID of the reader Combination it
     * matched, the Kernel ID, the Application Priority Indicator when present
     * and the Extended Selection ('9F29') when present.
     */
    public static final class Candidate {
        /** The Directory Entry's ADF Name (used for SELECT). */
        public final String adfHex;
        /** The supported reader AID the ADF Name matched (full or prefix). */
        public final String aid;
        /** Application Priority Indicator b4-b1; 15 (lowest) when absent. */
        public final int priority;
        /** True when the Directory Entry carried an Application Priority Indicator. */
        public final boolean priorityPresent;
        /** Requested Kernel ID of the Combination. */
        public final int kernelId;
        /** Extended Selection ('9F29') value, or null when absent. */
        public final byte[] extendedSelection;
        /** The reader Combination this candidate matched (Book A Table 5-1). */
        public final Combination combination;
        /**
         * The Pre-Processing Indicators of this Combination's Entry Point
         * Configuration (Book A Table 5-3); filled by Entry Point selection.
         */
        public PreProcessingIndicators indicators;
        /** The Entry Point Start that produced the indicators (Outcome.START_*). */
        public int start;

        Candidate(String adfHex, String aid, int priority, boolean priorityPresent,
                int kernelId, byte[] extendedSelection, Combination combination) {
            this.adfHex = adfHex;
            this.aid = aid;
            this.priority = priority;
            this.priorityPresent = priorityPresent;
            this.kernelId = kernelId;
            this.extendedSelection = extendedSelection;
            this.combination = combination;
        }
    }

    /**
     * Selects the highest priority supported ADF Name from a PPSE FCI.
     *
     * <p>Only the Directory Entries that are direct children of the FCI Issuer
     * Discretionary Data ('BF0C') are considered: a '61' nested inside a
     * proprietary template within BF0C is not a Directory Entry and Entry Point
     * ignores it (EMV Contactless Book B v2.12 Table 3-2 note).
     *
     * @return the selected ADF Name in hex, or null when no entry matches
     */
    public static String selectCandidate(byte[] fci, String[] supportedAids) {
        java.util.List<Candidate> candidates = selectCandidates(fci, supportedAids);
        return candidates.isEmpty() ? null : candidates.get(0).adfHex;
    }

    /**
     * The supported Directory Entries of a PPSE FCI, ordered by priority (the
     * highest priority first, ties keeping their Directory Entry order).  The
     * kernel walks this list so that a failed {@code SELECT (ADF Name)} can
     * remove the candidate and retry (EMV Contactless Book B v2.12 §3.3.3.5).
     *
     * <p>This overload keeps the flat supported-AID list used before the Entry
     * Point configuration (H1); it is equivalent to a default Combination Table
     * for a purchase.
     */
    public static java.util.List<Candidate> selectCandidates(byte[] fci,
            String[] supportedAids) {
        return selectCandidates(fci, CombinationTable.defaults(supportedAids),
                CombinationTable.PURCHASE);
    }

    /**
     * The supported Directory Entries of a PPSE FCI for the transaction type,
     * using the reader's Combination Table (EMV Contactless Book A v2.12
     * Table 5-1/5-6): an entry is a candidate only when its ADF Name matches a
     * Combination's AID (full or prefix) and its Requested Kernel ID is zero or
     * the Combination's Kernel ID (Book B §3.3.2.5 bullets B/D).  An empty
     * Combination list yields an empty Candidate List (Contactless Application
     * Not Allowed, Book A Table 5-3).
     */
    public static java.util.List<Candidate> selectCandidates(byte[] fci,
            CombinationTable table, int transactionType) {
        java.util.List<Candidate> candidates = new java.util.ArrayList<Candidate>();
        java.util.List<Combination> combinations = table.forType(transactionType);
        if (combinations.isEmpty()) {
            return candidates;
        }
        byte[] discretionary = Tags.find(fci, 0xBF0C);
        if (discretionary == null) {
            return candidates;
        }
        for (byte[] entry : Tags.findAllDirect(discretionary, 0x61)) {
            byte[] adf = Tags.find(entry, 0x4F);
            if (adf == null) {
                continue;
            }
            // ADF Name = RID (5 bytes) + PIX (0-11 bytes), so 5-16 bytes; a
            // malformed one is not a Combination and is skipped
            // (EMV Contactless Book B v2.12 §3.3.2.5 bullet A).
            if (adf.length < 5 || adf.length > 16) {
                continue;
            }
            String adfHex = Hex.format(adf);
            int requested = requestedKernelId(entry, adfHex);
            if (requested < 0) {
                continue; // malformed Kernel Identifier ('9F2A')
            }
            int priority = priority(entry);
            boolean priorityPresent = priorityPresent(entry);
            byte[] extendedSelection = Tags.find(entry, 0x9F29);
            // EMV Contactless Book B v2.12 §3.3.2.5: process each Directory Entry
            // once per supported reader Combination whose AID matches (full or
            // prefix, bullet B).  A single Directory Entry can therefore yield
            // one Combination per matching AID/Kernel ID pair; the Directory
            // Entry order is preserved so the equal-priority tie-break of
            // §3.3.3.2 keeps the PPSE order.
            for (Combination combination : combinations) {
                if (!(adfHex.equals(combination.aid) || adfHex.startsWith(combination.aid))) {
                    continue; // the ADF Name must equal or begin with a supported AID
                }
                // Bullet D: a zero Requested Kernel ID (kernel by ADF Name) is
                // always supported; a non-zero one is supported only when it
                // equals the Kernel ID of this reader Combination for the
                // matching AID (Book B §3.3.2.5 bullet D / Table 3-6).
                if (requested != 0 && requested != combination.kernelId) {
                    continue;
                }
                candidates.add(new Candidate(adfHex, combination.aid, priority,
                        priorityPresent, combination.kernelId, extendedSelection, combination));
            }
        }
        // Stable sort by priority (Collections.sort is stable), so equal
        // priorities keep the Directory Entry order.
        java.util.Collections.sort(candidates, new java.util.Comparator<Candidate>() {
            @Override
            public int compare(Candidate a, Candidate b) {
                return Integer.compare(a.priority, b.priority);
            }
        });
        return candidates;
    }

    /**
     * The Requested Kernel ID of a Directory Entry (EMV Contactless Book B v2.12 Table 3-4/3-5).
     * When '9F2A' is absent or is the single-byte value '00', the default for
     * the ADF Name is used (EMV Contactless Book B v2.12 §3.3.2.5 bullet C / Table 3-6);
     * a multi-byte '9F2A' whose first byte is '00' is not the default but a
     * Requested Kernel ID of 0 (b8b7 = 00b, Short Kernel ID = 000000b).
     */
    public static int requestedKernelId(byte[] entry, String adfHex) {
        byte[] kernel = Tags.find(entry, 0x9F2A);
        if (kernel == null || kernel.length == 0) {
            return defaultKernelId(adfHex);
        }
        // The Kernel Identifier value field is at most eight bytes
        // (EMV Contactless Book B v2.12 Table A-1); a longer one is not a
        // Kernel Identifier and the entry is skipped.
        if (kernel.length > 8) {
            return -1;
        }
        int b8b7 = (kernel[0] & 0xC0) >> 6;
        if (b8b7 == 0 || b8b7 == 1) {
            // Bullet C: Requested Kernel ID = byte 1 (b8b7 || Short Kernel ID),
            // regardless of the total length.  A single-byte '00' means the
            // brand default (Table 3-6); a multi-byte value whose first byte is
            // '00' is a Requested Kernel ID of 0 (kernel by ADF Name).
            if (kernel.length == 1 && kernel[0] == 0x00) {
                return defaultKernelId(adfHex);
            }
            return kernel[0] & 0xFF;
        }
        if (kernel.length < 3) {
            return -1; // 10b/11b needs at least 3 bytes (Table 3-5)
        }
        return ((kernel[0] & 0xFF) << 16) | ((kernel[1] & 0xFF) << 8) | (kernel[2] & 0xFF);
    }

    /**
     * The default Requested Kernel ID for a brand's ADF Name (EMV Contactless
     * Book B v2.12 Table 3-6); any other ADF Name defaults to kernel 0.
     */
    public static int defaultKernelId(String adfHex) {
        if (adfHex.startsWith("A000000003")) {
            return 3; // Visa
        }
        if (adfHex.startsWith("A000000004")) {
            return 2; // Mastercard
        }
        if (adfHex.startsWith("A000000025")) {
            return 4; // American Express
        }
        if (adfHex.startsWith("A000000065")) {
            return 5; // JCB
        }
        if (adfHex.startsWith("A000000152")) {
            return 6; // Discover
        }
        if (adfHex.startsWith("A000000333")) {
            return 7; // UnionPay
        }
        return 0; // Other
    }

    /**
     * The supported AID that the ADF Name matches, or null.  Used by the contact
     * PSE selection; the contactless Entry Point applies the same full/prefix
     * match against each reader Combination in
     * {@link #selectCandidates(byte[], CombinationTable, int)}.
     */
    static String matchAid(String adfHex, String[] supportedAids) {
        for (String aid : supportedAids) {
            if (adfHex.equals(aid) || adfHex.startsWith(aid)) {
                return aid;
            }
        }
        return null;
    }

    static int priority(byte[] entry) {
        byte[] p = Tags.find(entry, 0x87);
        if (p == null || p.length == 0) {
            return 15;
        }
        int value = p[0] & 0x0F;
        return value == 0 ? 15 : value;
    }

    /**
     * True when the Directory Entry carries an Application Priority Indicator
     * ('87') with a value byte; the Combination records its presence separately
     * from the (lowest, 15) priority used when it is absent (EMV Contactless
     * Book B v2.12 §3.3.2.5 bullet E).
     */
    static boolean priorityPresent(byte[] entry) {
        byte[] p = Tags.find(entry, 0x87);
        return p != null && p.length >= 1;
    }

    /**
     * True when the Directory Entry requires confirmation by the cardholder
     * before selection ('87' b8; EMV v4.4 Book 1 Table 13).  A terminal that
     * offers no cardholder confirmation must skip such entries and select the
     * highest priority entry that does not require it
     * (EMV v4.4 Book 1 §12.4 step 5).
     */
    static boolean confirmationRequired(byte[] entry) {
        byte[] p = Tags.find(entry, 0x87);
        return p != null && p.length >= 1 && (p[0] & 0x80) != 0;
    }

    /**
     * True when a selected Combination must be removed because it is a Visa AID
     * processed on Kernel 3 whose FCI PDOL is absent or does not include tag
     * '9F66' (EMV Contactless Book B v2.12 §3.3.3.6).  Entry Point then returns
     * to Start C and tries the next Combination.
     */
    public static boolean visaKernel3WithoutTtq(byte[] fci, String adfHex, int kernelId) {
        if (kernelId != 3 || !adfHex.startsWith("A000000003")) {
            return false;
        }
        return !dolContainsTag(Tags.find(fci, 0x9F38), 0x9F66);
    }

    /** True when a DOL definition contains the given tag (a DOL is tag/length pairs). */
    public static boolean dolContainsTag(byte[] dol, int wanted) {
        if (dol == null) {
            return false;
        }
        int p = 0;
        while (p < dol.length) {
            int b = dol[p] & 0xFF;
            int tag;
            if ((b & 0x1F) == 0x1F) {
                if (p + 1 >= dol.length) {
                    break;
                }
                tag = (b << 8) | (dol[p + 1] & 0xFF);
                p += 2;
            } else {
                tag = b;
                p += 1;
            }
            if (p >= dol.length) {
                break;
            }
            int len = dol[p++] & 0xFF;
            if ((len & 0x80) != 0) {
                int n = len & 0x7F;
                for (int i = 0; i < n && p < dol.length; i++) {
                    p++;
                }
            }
            if (tag == wanted) {
                return true;
            }
        }
        return false;
    }
}
