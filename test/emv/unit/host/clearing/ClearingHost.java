package card42.test;

import java.io.ByteArrayOutputStream;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

import card42.host.common.codec.TlvWriter;
import card42.host.common.util.Hex;

/**
 * Acquirer / clearing host simulation (EMV v4.4 Book 4 §12.1.x).
 *
 * <p>It models the ICC-specific data elements of the clearing messages
 * (Table 17 batch data capture, Table 20 online advice, Table 22 reversal)
 * together with the tokenisation elements Payment Account Reference (9F24),
 * Token Requestor ID (9F19) and Last 4 Digits of PAN (9F25).  The "existing"
 * elements (Tables 18/19/21/23) are payment-system specific and are carried
 * through as opaque tag/value entries.
 *
 * <p>A {@link Record} is a tag/value list; {@link Record#encode()} serialises it
 * as a flat EMV TLV list for the test harness.  It is not an ISO 8583 wire
 * format (which the payment system defines).
 */
public final class ClearingHost {

    /** The clearing message types of Book 4 §12.1. */
    public enum MessageType {
        /** Batch data capture financial record (Table 17/18). */
        FINANCIAL,
        /** Batch data capture offline advice (Table 17/18). */
        OFFLINE_ADVICE,
        /** Reconciliation (Table 19). */
        RECONCILIATION,
        /** Online advice (Table 20/21). */
        ONLINE_ADVICE,
        /** Reversal (Table 22/23). */
        REVERSAL
    }

    // EMV data elements used by the ICC-specific tables.
    public static final int TAG_AIP = 0x82;
    public static final int TAG_AC = 0x9F26;
    public static final int TAG_CID = 0x9F27;
    public static final int TAG_IAD = 0x9F10;
    public static final int TAG_ATC = 0x9F36;
    public static final int TAG_UN = 0x9F37;
    public static final int TAG_TVR = 0x95;
    public static final int TAG_AUC = 0x9F07;
    public static final int TAG_CVM_LIST = 0x8E;
    public static final int TAG_CVM_RESULTS = 0x9F34;
    public static final int TAG_TERM_CAPABILITIES = 0x9F33;
    public static final int TAG_TERM_TYPE = 0x9F35;
    public static final int TAG_IAC_DEFAULT = 0x9F0D;
    public static final int TAG_IAC_DENIAL = 0x9F0E;
    public static final int TAG_IAC_ONLINE = 0x9F0F;
    public static final int TAG_ISSUER_SCRIPT_RESULTS = 0x9F5B;
    /** Payment Account Reference (EMV Book 4 / Tokenisation Framework). */
    public static final int TAG_PAR = 0x9F24;
    /** Token Requestor ID (EMV Book 4 / Tokenisation Framework). */
    public static final int TAG_TOKEN_REQUESTOR_ID = 0x9F19;
    /** Last 4 Digits of PAN (EMV Book 4 / Tokenisation Framework). */
    public static final int TAG_LAST4_PAN = 0x9F25;

    private ClearingHost() {
    }

    /** A clearing message as an ordered tag/value element list. */
    public static final class Record {
        private final MessageType type;
        private final Map<Integer, byte[]> elements = new LinkedHashMap<>();

        Record(MessageType type) {
            this.type = type;
        }

        public MessageType type() {
            return type;
        }

        /** Adds an element; a duplicate tag replaces the previous value. */
        public Record add(int tag, byte[] value) {
            if (value == null) {
                throw new IllegalArgumentException("null value for tag "
                        + Integer.toHexString(tag));
            }
            elements.put(tag, value.clone());
            return this;
        }

        /** Adds an element from a hex string. */
        public Record addHex(int tag, String hex) {
            return add(tag, Hex.parse(hex));
        }

        public boolean has(int tag) {
            return elements.containsKey(tag);
        }

        public byte[] get(int tag) {
            byte[] v = elements.get(tag);
            return v == null ? null : v.clone();
        }

        public int size() {
            return elements.size();
        }

        public Set<Integer> tags() {
            return Collections.unmodifiableSet(new LinkedHashSet<>(elements.keySet()));
        }

        /**
         * The elements this message type always carries, i.e. those the EMV
         * v4.4 Book 4 tables list without a condition.  Conditional elements
         * (Issuer Application Data "present if provided by ICC in GENERATE AC
         * command response" and Unpredictable Number "present if input to
         * application cryptogram calculation", EMV v4.4 Book 4 Table 17/20/22)
         * are not mandatory, so a message that omits them is still valid.
         */
        public int[] mandatoryTags() {
            switch (type) {
            case FINANCIAL:
            case OFFLINE_ADVICE:
                // EMV v4.4 Book 4 Table 17: AC*, AIP*, ATC*, CVM Results,
                // Terminal Capabilities, Terminal Type and TVR* have no condition.
                return new int[] { TAG_AC, TAG_AIP, TAG_ATC, TAG_CVM_RESULTS,
                        TAG_TERM_CAPABILITIES, TAG_TERM_TYPE, TAG_TVR };
            case ONLINE_ADVICE:
                // EMV v4.4 Book 4 Table 20: IAD and UN are conditional; AC, AIP,
                // ATC, CID, CVM Results, Terminal Capabilities, Terminal Type
                // and TVR have no condition.
                return new int[] { TAG_AC, TAG_AIP, TAG_ATC, TAG_CID, TAG_CVM_RESULTS,
                        TAG_TERM_CAPABILITIES, TAG_TERM_TYPE, TAG_TVR };
            case REVERSAL:
                // EMV v4.4 Book 4 Table 22: IAD is conditional; AIP, ATC,
                // Terminal Capabilities, Terminal Type and TVR have no condition.
                return new int[] { TAG_AIP, TAG_ATC, TAG_TERM_CAPABILITIES, TAG_TERM_TYPE,
                        TAG_TVR };
            case RECONCILIATION:
            default:
                return new int[0];
            }
        }

        /** The mandatory tags that are missing from this record. */
        public int[] missingMandatory() {
            int[] mandatory = mandatoryTags();
            int count = 0;
            for (int tag : mandatory) {
                if (!has(tag)) {
                    count++;
                }
            }
            int[] out = new int[count];
            int i = 0;
            for (int tag : mandatory) {
                if (!has(tag)) {
                    out[i++] = tag;
                }
            }
            return out;
        }

        public boolean isValid() {
            return missingMandatory().length == 0;
        }

        /** Serialises the element list as a flat EMV TLV list (tag, length, value). */
        public byte[] encode() {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            for (Map.Entry<Integer, byte[]> e : elements.entrySet()) {
                TlvWriter.writeTlv(out, e.getKey(), e.getValue());
            }
            return out.toByteArray();
        }
    }

    /**
     * The ICC / terminal data a clearing message is built from.  Unset fields
     * are omitted from the record.
     */
    public static final class TransactionData {
        public byte[] aip;
        public byte[] ac;
        public byte[] cid;
        public byte[] iad;
        public byte[] atc;
        public byte[] unpredictableNumber;
        public byte[] tvr;
        public byte[] auc;
        public byte[] cvmList;
        public byte[] cvmResults;
        public byte[] terminalCapabilities;
        public byte[] terminalType;
        public byte[] iacDefault;
        public byte[] iacDenial;
        public byte[] iacOnline;
        public byte[] issuerScriptResults;
        /** Optional tokenisation elements. */
        public byte[] par;
        public byte[] tokenRequestorId;
        public byte[] last4Pan;
    }

    /** Batch data capture financial record (Book 4 Table 17). */
    public static Record financialRecord(TransactionData d) {
        return batchRecord(MessageType.FINANCIAL, d);
    }

    /** Batch data capture offline advice (Book 4 Table 17). */
    public static Record offlineAdvice(TransactionData d) {
        return batchRecord(MessageType.OFFLINE_ADVICE, d);
    }

    /**
     * Reconciliation (Book 4 Table 19).  Its existing data elements are
     * payment-system specific (acquirer/merchant/terminal identifiers and
     * per-type totals) and it carries no ICC-specific elements such as the
     * AIP, ATC, IAD or TVR; only the tokenisation elements the test model adds
     * are included.
     */
    public static Record reconciliation(TransactionData d) {
        Record r = new Record(MessageType.RECONCILIATION);
        putTokenisation(r, d);
        return r;
    }

    /** Online advice (Book 4 Table 20). */
    public static Record onlineAdvice(TransactionData d) {
        Record r = new Record(MessageType.ONLINE_ADVICE);
        put(r, TAG_AC, d.ac);
        put(r, TAG_AIP, d.aip);
        put(r, TAG_ATC, d.atc);
        put(r, TAG_CID, d.cid);
        put(r, TAG_IAD, d.iad);
        put(r, TAG_TVR, d.tvr);
        put(r, TAG_UN, d.unpredictableNumber);
        put(r, TAG_TERM_CAPABILITIES, d.terminalCapabilities);
        put(r, TAG_TERM_TYPE, d.terminalType);
        put(r, TAG_CVM_RESULTS, d.cvmResults);
        put(r, TAG_ISSUER_SCRIPT_RESULTS, d.issuerScriptResults);
        putTokenisation(r, d);
        return r;
    }

    /** Reversal (Book 4 Table 22). */
    public static Record reversal(TransactionData d) {
        Record r = new Record(MessageType.REVERSAL);
        put(r, TAG_AIP, d.aip);
        put(r, TAG_ATC, d.atc);
        put(r, TAG_IAD, d.iad);
        put(r, TAG_TVR, d.tvr);
        put(r, TAG_TERM_CAPABILITIES, d.terminalCapabilities);
        put(r, TAG_TERM_TYPE, d.terminalType);
        put(r, TAG_ISSUER_SCRIPT_RESULTS, d.issuerScriptResults);
        putTokenisation(r, d);
        return r;
    }

    private static Record batchRecord(MessageType type, TransactionData d) {
        Record r = new Record(type);
        put(r, TAG_AC, d.ac);
        put(r, TAG_AIP, d.aip);
        put(r, TAG_ATC, d.atc);
        put(r, TAG_CID, d.cid);
        put(r, TAG_IAD, d.iad);
        put(r, TAG_TVR, d.tvr);
        put(r, TAG_UN, d.unpredictableNumber);
        put(r, TAG_AUC, d.auc);
        put(r, TAG_CVM_LIST, d.cvmList);
        put(r, TAG_CVM_RESULTS, d.cvmResults);
        put(r, TAG_TERM_CAPABILITIES, d.terminalCapabilities);
        put(r, TAG_TERM_TYPE, d.terminalType);
        put(r, TAG_IAC_DEFAULT, d.iacDefault);
        put(r, TAG_IAC_DENIAL, d.iacDenial);
        put(r, TAG_IAC_ONLINE, d.iacOnline);
        put(r, TAG_ISSUER_SCRIPT_RESULTS, d.issuerScriptResults);
        putTokenisation(r, d);
        return r;
    }

    private static void putTokenisation(Record r, TransactionData d) {
        put(r, TAG_PAR, d.par);
        put(r, TAG_TOKEN_REQUESTOR_ID, d.tokenRequestorId);
        put(r, TAG_LAST4_PAN, d.last4Pan);
    }

    private static void put(Record r, int tag, byte[] value) {
        if (value != null) {
            r.add(tag, value);
        }
    }
}
