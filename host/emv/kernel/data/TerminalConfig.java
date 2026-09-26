package card42.host.emv.kernel.data;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import card42.host.common.util.Hex;

/**
 * Terminal-resident configuration of a terminal kernel (EMV v4.4 Book 4
 * §A1; the contactless Terminal Transaction Qualifiers follow EMV Contactless
 * Book A v2.12 Table 5-4).  It is immutable: the caller builds it once per
 * terminal (with {@link #builder()} / {@link #forContact()}) and reuses it for
 * every transaction.  The per-transaction data lives in {@link TransactionRequest}
 * and the per-transaction outcome in {@link card42.host.emv.kernel.core.TransactionResult}.
 *
 * <p>It holds the identity and capabilities of the terminal, the Terminal Action
 * Codes and risk-management limits, and the CVM support the terminal advertises.
 * The one terminal-resident value that changes across transactions, the
 * Transaction Sequence Counter, is carried by the referenced {@link TerminalState}
 * so this configuration stays immutable (EMV v4.4 Book 4 §6.5.5).
 */
public final class TerminalConfig {

    // --- Terminal identification / capabilities (EMV v4.4 Book 4 §A1). ---------------

    /** Terminal Type ('9F35'): attended, merchant-controlled, offline with online capability
     * ('22', EMV v4.4 Book 4 Annex A1 Table 24). */
    public final int terminalType;
    /**
     * Terminal Capabilities ('9F33', 3 bytes).  Byte 1 (Card Data Input
     * Capability, EMV v4.4 Book 4 Annex A2 Table 25) advertises manual key
     * entry, magnetic stripe and IC contacts.  Byte 2 (CVM Capability, Table 26)
     * advertises only 'No CVM required' (b4), the only CVM this kernel performs;
     * the offline/online PIN and signature bits are clear because the kernel has
     * no PIN pad or signature capture.  Byte 3 (Security Capability, Table 27)
     * advertises SDA (b8), DDA (b7) and CDA (b4), the RSA ODA the kernel
     * performs; Card capture (b6) and XDA (b3) are not set.
     */
    public final byte[] terminalCapabilities;
    /** Additional Terminal Capabilities ('9F40', 5 bytes). */
    public final byte[] additionalTerminalCapabilities;
    /**
     * Terminal Transaction Qualifiers ('9F66', 4 bytes, Kernel 3 RSA profile;
     * EMV Contactless Book A v2.12 Table 5-4).  Byte 1 has EMV mode (b6), EMV
     * contact chip (b5) and ODA for online authorizations (b1) set; online PIN
     * (b3) and signature (b2) are clear because the kernel performs neither.
     * Byte 3 b8 advertises Issuer Update Processing, which the kernel performs
     * (issuer scripts and the second GENERATE AC).
     */
    public final byte[] ttq;
    /** Terminal Identification ('9F1C'). */
    public final byte[] terminalId;
    /** Interface Device Serial Number ('9F1E'). */
    public final byte[] ifdSerialNumber;
    /** Merchant Category Code ('9F15', 2 bytes). */
    public final byte[] merchantCategoryCode;
    /** Merchant Name and Location ('9F4E'). */
    public final byte[] merchantName;
    /** Acquirer Identifier ('9F01', 6 bytes). */
    public final byte[] acquirerIdentifier;
    /** Terminal Country Code ('9F1A', 2 bytes). */
    public final byte[] terminalCountryCode;
    /** Application Version Number of the terminal ('9F09', 2 bytes). */
    public final byte[] applicationVersionNumber;
    /**
     * POI Information ID '0001' Terminal Category (EMV Contactless Book B v2.12
     * Annex A.1 Table A-2, 2 bytes).  The terminal advertises its category to
     * the card in SEND POI INFORMATION and through SDOL tag '8B'; the default is
     * the standard "Cardholder and Cardholder's Device" category '0001'.  The
     * points of interaction the category identifies are listed in Book B
     * Table A-2.
     */
    public final byte[] terminalCategory;

    // --- Terminal Action Codes (EMV v4.4 Book 3 §10.7, terminal resident). -----------

    /** TAC-Denial; default all bits 0 (EMV v4.4 Book 3 §10.7). */
    public final byte[] tacDenial;
    /** TAC-Online; default all bits 0 (EMV v4.4 Book 3 §10.7). */
    public final byte[] tacOnline;
    /** TAC-Default; default all bits 0 (EMV v4.4 Book 3 §10.7). */
    public final byte[] tacDefault;

    // --- Terminal risk management (EMV v4.4 Book 3 §10.6). ---------------------------

    /** Terminal floor limit in minor units (BCD compare). */
    public final long floorLimit;
    /** Target Percentage for Random Selection (0-99, EMV v4.4 Book 3 §10.6.2). */
    public final int targetPercentage;
    /** Threshold Value for Biased Random Selection in minor units (EMV v4.4 Book 3 §10.6.2). */
    public final long biasedRandomThreshold;
    /** Maximum Target Percentage for Biased Random Selection (>= targetPercentage). */
    public final int maxTargetPercentage;

    /**
     * Optional issuer referral handler for attended terminals
     * (EMV v4.4 Book 4 §6.5.2.2); null means the terminal cannot perform a
     * referral and declines.
     */
    public final ReferralHandler referralHandler;

    /**
     * Optional terminal exception file (EMV v4.4 Book 4 §6.3.5): cards/applications
     * identified by PAN (and optional PAN Sequence Number) that must set the TVR
     * 'Card appears in exception file' bit.  Empty by default.
     */
    public final List<ExceptionEntry> exceptionFile;

    // --- CVM configuration (EMV v4.4 Book 3 §10.5, EMV v4.4 Book 4 §6.3.4). -------------------

    /** True when the terminal supports online PIN. */
    public final boolean onlinePinSupported;
    /** True when the terminal supports signature CVM. */
    public final boolean signatureSupported;
    /** CVM required limit in minor units; above it No CVM must not be offered
     * (EMV v4.4 Book 3 §10.5). */
    public final long cvmRequiredLimit;

    /** Terminal-resident state that persists across transactions (the TSC). */
    public final TerminalState state;

    /** One exception-file entry: an Application PAN with an optional PAN Sequence Number. */
    public static final class ExceptionEntry {
        public final byte[] pan;
        public final byte[] panSequenceNumber;

        public ExceptionEntry(byte[] pan, byte[] panSequenceNumber) {
            this.pan = pan;
            this.panSequenceNumber = panSequenceNumber;
        }
    }

    private TerminalConfig(Builder b) {
        this.terminalType = b.terminalType;
        this.terminalCapabilities = b.terminalCapabilities;
        this.additionalTerminalCapabilities = b.additionalTerminalCapabilities;
        this.ttq = b.ttq;
        this.terminalId = b.terminalId;
        this.ifdSerialNumber = b.ifdSerialNumber;
        this.merchantCategoryCode = b.merchantCategoryCode;
        this.merchantName = b.merchantName;
        this.acquirerIdentifier = b.acquirerIdentifier;
        this.terminalCountryCode = b.terminalCountryCode;
        this.applicationVersionNumber = b.applicationVersionNumber;
        this.terminalCategory = b.terminalCategory;
        this.tacDenial = b.tacDenial;
        this.tacOnline = b.tacOnline;
        this.tacDefault = b.tacDefault;
        this.floorLimit = b.floorLimit;
        this.targetPercentage = b.targetPercentage;
        this.biasedRandomThreshold = b.biasedRandomThreshold;
        this.maxTargetPercentage = b.maxTargetPercentage;
        this.referralHandler = b.referralHandler;
        this.exceptionFile = Collections.unmodifiableList(
                new ArrayList<ExceptionEntry>(b.exceptionFile));
        this.onlinePinSupported = b.onlinePinSupported;
        this.signatureSupported = b.signatureSupported;
        this.cvmRequiredLimit = b.cvmRequiredLimit;
        this.state = b.state != null ? b.state : new TerminalState();
    }

    /** A builder pre-filled with the kernel defaults (EMV v4.4 Book 4 §A1). */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * A builder pre-filled for a contact terminal (EMV v4.4 Book 4 §A1): the
     * Terminal Capabilities ('9F33') advertise the CVMs the contact kernel
     * performs: plaintext PIN for ICC verification (byte 2 b8), enciphered PIN
     * for offline verification (byte 2 b5) and 'No CVM required' (byte 2 b4);
     * byte 3 advertises SDA/DDA/CDA (EMV v4.4 Book 4 Annex A2 Tables 25/26/27).
     * Signature (b6) and online PIN (b7) default to off and are enabled together
     * with the corresponding support flags (TerminalPayCommand).  The
     * contactless-only Terminal Transaction Qualifiers ('9F66') are never
     * requested by a contact PDOL.
     */
    public static Builder forContact() {
        return new Builder()
                .terminalType(0x22)
                .terminalCapabilities(Hex.parse("E098C8"));
    }

    /** A builder pre-filled for a contactless terminal. */
    public static Builder forContactless() {
        return new Builder();
    }

    /**
     * True when this terminal is an ATM: Terminal Type '14', '15' or '16' with
     * the cash disbursement capability set in Additional Terminal Capabilities
     * byte 1 b8 (EMV v4.4 Book 4 §6.3.3 / Annex A).
     */
    public boolean isAtm() {
        int type = terminalType & 0xFF;
        boolean atmType = type == 0x14 || type == 0x15 || type == 0x16;
        boolean cash = additionalTerminalCapabilities.length >= 1
                && (additionalTerminalCapabilities[0] & 0x80) != 0;
        return atmType && cash;
    }

    /**
     * True when this is an unattended terminal: Terminal Type low nibble
     * 4-6 (EMV v4.4 Book 4 §5.1: attended is 'x1'/'x2'/'x3').  Drives the CVM
     * conditions 'if unattended cash' / 'if manual cash' (Book 3 Table 44).
     */
    public boolean isUnattended() {
        int low = terminalType & 0x0F;
        return low >= 4 && low <= 6;
    }

    /**
     * True when this is an attended terminal: Terminal Type low nibble 1-3
     * (EMV v4.4 Book 4 §5.1).  Drives voice referral support (§6.5.2.2).
     */
    public boolean isAttended() {
        int low = terminalType & 0x0F;
        return low >= 1 && low <= 3;
    }

    /**
     * True when this is an online-only terminal: Terminal Type low nibble 1 or 4
     * (EMV v4.4 Book 4 Annex A1 Table 24).  Such a terminal never approves a
     * transaction offline, so it always requests an ARQC
     * (EMV v4.4 Book 4 §12.2.1 / Book 3 §10.7).
     */
    public boolean isOnlineOnly() {
        int low = terminalType & 0x0F;
        return low == 1 || low == 4;
    }

    /**
     * True when this is an offline-only terminal: Terminal Type low nibble 3 or 6
     * (EMV v4.4 Book 4 Annex A1 Table 24).  Such a terminal can only complete the
     * transaction offline, so its first GENERATE AC uses the Denial pair and then
     * the Default pair (EMV v4.4 Book 3 §10.7 option 2).
     */
    public boolean isOfflineOnly() {
        int low = terminalType & 0x0F;
        return low == 3 || low == 6;
    }

    /**
     * True when the card (Application PAN, and PAN Sequence Number when the
     * entry carries one) appears in the terminal exception file
     * (EMV v4.4 Book 4 §6.3.5).  A null PAN never matches.
     */
    public boolean inExceptionFile(byte[] pan, byte[] panSequenceNumber) {
        if (pan == null) {
            return false;
        }
        for (ExceptionEntry entry : exceptionFile) {
            if (!java.util.Arrays.equals(entry.pan, pan)) {
                continue;
            }
            if (entry.panSequenceNumber == null
                    || java.util.Arrays.equals(entry.panSequenceNumber, panSequenceNumber)) {
                return true;
            }
        }
        return false;
    }

    /** A mutable builder for {@link TerminalConfig}. */
    public static final class Builder {
        private int terminalType = 0x22;
        private byte[] terminalCapabilities = Hex.parse("E008C8");
        private byte[] additionalTerminalCapabilities = Hex.parse("F000F0A001");
        private byte[] ttq = Hex.parse("31008000");
        private byte[] terminalId = Hex.parse("454D5634323030303030303030");
        private byte[] ifdSerialNumber = Hex.parse("3132333435363738");
        private byte[] merchantCategoryCode = Hex.parse("5999");
        private byte[] merchantName = Hex.parse("454D5634322054455354204D45524348414E54");
        private byte[] acquirerIdentifier = Hex.parse("000000000001");
        private byte[] terminalCountryCode = Hex.parse("0250");
        private byte[] applicationVersionNumber = Hex.parse("0002");
        private byte[] terminalCategory = { 0x00, 0x01 };
        private byte[] tacDenial = Tvr.blank();
        private byte[] tacOnline = Tvr.blank();
        private byte[] tacDefault = Tvr.blank();
        private long floorLimit = 0;
        private int targetPercentage = 0;
        private long biasedRandomThreshold = 0;
        private int maxTargetPercentage = 0;
        private ReferralHandler referralHandler;
        private final List<ExceptionEntry> exceptionFile = new ArrayList<ExceptionEntry>();
        private boolean onlinePinSupported = false;
        private boolean signatureSupported = false;
        private long cvmRequiredLimit = 0;
        private TerminalState state;

        public Builder terminalType(int value) {
            this.terminalType = value;
            return this;
        }

        public Builder terminalCapabilities(byte[] value) {
            this.terminalCapabilities = value;
            return this;
        }

        public Builder additionalTerminalCapabilities(byte[] value) {
            this.additionalTerminalCapabilities = value;
            return this;
        }

        public Builder ttq(byte[] value) {
            this.ttq = value;
            return this;
        }

        public Builder terminalId(byte[] value) {
            this.terminalId = value;
            return this;
        }

        public Builder ifdSerialNumber(byte[] value) {
            this.ifdSerialNumber = value;
            return this;
        }

        public Builder merchantCategoryCode(byte[] value) {
            this.merchantCategoryCode = value;
            return this;
        }

        public Builder merchantName(byte[] value) {
            this.merchantName = value;
            return this;
        }

        public Builder acquirerIdentifier(byte[] value) {
            this.acquirerIdentifier = value;
            return this;
        }

        public Builder terminalCountryCode(byte[] value) {
            this.terminalCountryCode = value;
            return this;
        }

        public Builder applicationVersionNumber(byte[] value) {
            this.applicationVersionNumber = value;
            return this;
        }

        /** POI Information ID '0001' Terminal Category (EMV Contactless Book B v2.12 Table A-2). */
        public Builder terminalCategory(byte[] value) {
            this.terminalCategory = value;
            return this;
        }

        public Builder tacDenial(byte[] value) {
            this.tacDenial = value;
            return this;
        }

        public Builder tacOnline(byte[] value) {
            this.tacOnline = value;
            return this;
        }

        public Builder tacDefault(byte[] value) {
            this.tacDefault = value;
            return this;
        }

        public Builder floorLimit(long value) {
            this.floorLimit = value;
            return this;
        }

        public Builder targetPercentage(int value) {
            this.targetPercentage = value;
            return this;
        }

        public Builder biasedRandomThreshold(long value) {
            this.biasedRandomThreshold = value;
            return this;
        }

        public Builder maxTargetPercentage(int value) {
            this.maxTargetPercentage = value;
            return this;
        }

        public Builder referralHandler(ReferralHandler value) {
            this.referralHandler = value;
            return this;
        }

        public Builder addException(byte[] pan, byte[] panSequenceNumber) {
            this.exceptionFile.add(new ExceptionEntry(pan, panSequenceNumber));
            return this;
        }

        public Builder onlinePinSupported(boolean value) {
            this.onlinePinSupported = value;
            return this;
        }

        public Builder signatureSupported(boolean value) {
            this.signatureSupported = value;
            return this;
        }

        public Builder cvmRequiredLimit(long value) {
            this.cvmRequiredLimit = value;
            return this;
        }

        public Builder state(TerminalState value) {
            this.state = value;
            return this;
        }

        public TerminalConfig build() {
            return new TerminalConfig(this);
        }
    }
}
