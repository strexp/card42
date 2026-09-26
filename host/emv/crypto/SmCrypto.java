package card42.host.emv.crypto;

import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.smartcardio.CommandAPDU;
import card42.host.common.util.Bytes;

/**
 * Terminal-side EMV secure messaging and issuer script helpers (EMV v4.4
 * EMV v4.4 Book 2 §9.2/§9.3).
 *
 * It implements the CCD convention used by the card: Format 1 commands (CLA low
 * nibble 'C'), ISO/IEC 9797-1 algorithm 3 MAC with padding method 2 and a MAC
 * chaining value that starts at the first GENERATE AC and continues with the
 * full MAC of the previous command (EMV v4.4 Book 2 sections 9.2.2/9.2.3).
 *
 * It also encodes the Issuer Script Results (tag 9F5B, EMV v4.4 Book 4 Annex A5) and
 * parses a 71/72 Issuer Script template into its Script Identifier and the
 * individual Issuer Script Command APDUs.
 */
public final class SmCrypto {

    /** Format 1 secure-messaging CLA (low nibble C) for the post-issuance set. */
    public static final int CLA_FORMAT1 = 0x8C;
    /** Format 1 CLA with the command-chaining bit (b5) set (EMV v4.4 Book 3 §6.5.13). */
    public static final int CLA_FORMAT1_CHAINED = 0x9C;

    private SmCrypto() {
    }

    /**
     * Builds the value of Issuer Script Results (tag 9F5B) for one script:
     * byte 1 = (result &lt;&lt; 4) | sequence, bytes 2-5 = the Script Identifier
     * (zero filled when absent).
     *
     * @param result 0 = not performed, 1 = failed, 2 = successful
     * @param sequence sequence number of the failing command (0 when none)
     */
    public static byte[] issuerScriptResults(int result, int sequence, byte[] scriptId) {
        byte[] out = new byte[5];
        out[0] = (byte) (((result & 0x0F) << 4) | (sequence & 0x0F));
        if (scriptId != null) {
            System.arraycopy(scriptId, 0, out, 1, Math.min(scriptId.length, 4));
        }
        return out;
    }

    /** Enciphers a PIN block for a Format 1 confidentiality object. */
    public static byte[] encipher(byte[] encKey16, byte[] plaintext)
            throws GeneralSecurityException {
        // ISO/IEC 7816-4 padding always takes place, even when the data field is
        // already a multiple of 8 (EMV v4.4 Book 2 Annex D2.2), so an 8-byte PIN block
        // enciphers to 16 bytes.
        byte[] cryptogram = AcCrypto.des3CbcEncrypt(encKey16, padIso7816(plaintext));
        byte[] out = new byte[cryptogram.length + 1];
        out[0] = 0x01; // padding indicator
        System.arraycopy(cryptogram, 0, out, 1, cryptogram.length);
        return out;
    }

    /** ISO/IEC 7816-4 padding: a mandatory 0x80 then 0x00 to a multiple of 8. */
    public static byte[] padIso7816(byte[] data) {
        int pad = 8 - (data.length % 8);
        byte[] padded = new byte[data.length + pad];
        System.arraycopy(data, 0, padded, 0, data.length);
        padded[data.length] = (byte) 0x80;
        return padded;
    }

    /** TVR byte 5 bit 6: script processing failed before the final AC. */
    public static final byte TVR_SCRIPT_FAILED_BEFORE_FINAL_AC = (byte) 0x20;
    /** TVR byte 5 bit 5: script processing failed after the final AC. */
    public static final byte TVR_SCRIPT_FAILED_AFTER_FINAL_AC = (byte) 0x10;

    /**
     * Sets the TVR "Script processing failed before/after final GENERATE AC"
     * bit (EMV v4.4 Book 3 §10.10 / Annex C §C5).
     */
    public static void setScriptFailure(byte[] tvr, boolean afterFinalAc) {
        tvr[4] |= afterFinalAc ? TVR_SCRIPT_FAILED_AFTER_FINAL_AC
                : TVR_SCRIPT_FAILED_BEFORE_FINAL_AC;
    }

    // --- Issuer script template (tag 71 / 72) -------------------------------

    /** A parsed Issuer Script: its tag ('71'/'72'), optional Identifier and command APDUs. */
    public static final class IssuerScript {
        /** The script template tag: '71' (before final AC) or '72' (after). */
        public final int tag;
        public final byte[] scriptId;
        /** Each entry is the raw command APDU carried by one tag 86. */
        public final List<byte[]> commands;

        IssuerScript(int tag, byte[] scriptId, List<byte[]> commands) {
            this.tag = tag;
            this.scriptId = scriptId;
            this.commands = commands;
        }
    }

    /** The tag ('71' or '72') of an Issuer Script template, or -1 if malformed. */
    public static int tagOf(byte[] template) {
        if (template == null || template.length < 1) {
            return -1;
        }
        int tag = template[0] & 0xFF;
        return (tag == 0x71 || tag == 0x72) ? tag : -1;
    }

    /**
     * Parses a 71/72 Issuer Script template (the tag and length are included):
     * optional 9F18 Script Identifier and any number of 86 command APDUs
     * (EMV v4.4 Book 3 Figure 11).
     */
    public static IssuerScript parseIssuerScript(byte[] template) {
        int p = 0;
        int tag = template[p++] & 0xFF;
        if (tag != 0x71 && tag != 0x72) {
            throw new IllegalArgumentException("Not an issuer script template: "
                    + String.format("%02X", tag));
        }
        int lb = template[p++] & 0xFF;
        int len;
        if ((lb & 0x80) == 0) {
            len = lb;
        } else {
            int n = lb & 0x7F;
            len = 0;
            for (int i = 0; i < n; i++) {
                len = (len << 8) | (template[p++] & 0xFF);
            }
        }
        int end = p + len;
        byte[] scriptId = null;
        List<byte[]> commands = new ArrayList<>();
        while (p < end) {
            int t = template[p++] & 0xFF;
            if ((t & 0x1F) == 0x1F) {
                t = (t << 8) | (template[p++] & 0xFF);
            }
            int vLen = template[p++] & 0xFF;
            if ((vLen & 0x80) != 0) {
                int n = vLen & 0x7F;
                vLen = 0;
                for (int i = 0; i < n; i++) {
                    vLen = (vLen << 8) | (template[p++] & 0xFF);
                }
            }
            byte[] value = Arrays.copyOfRange(template, p, p + vLen);
            p += vLen;
            if (t == 0x9F18) {
                scriptId = value;
            } else if (t == 0x86) {
                commands.add(value);
            }
        }
        return new IssuerScript(tag, scriptId, commands);
    }

    // --- MAC-chained Format 1 script session --------------------------------

    /**
     * A terminal-side secure-messaging session.  The MAC chain starts at the
     * first GENERATE AC and is updated with the full 8-byte MAC of every
     * command (EMV v4.4 Book 2 section 9.2.3.1).
     */
    public static final class ScriptSession {

        private final byte[] macKey;
        private final byte[] encKey;
        private byte[] icv;
        private byte[] macSessionKey;
        private byte[] encSessionKey;
        /** Transmitted MAC length (4..8); the chain always uses the full 8. */
        private int macLength = 8;

        public ScriptSession(byte[] macKey, byte[] encKey) {
            this.macKey = macKey;
            this.encKey = encKey;
        }

        /** Sets the transmitted MAC length (EMV v4.4 Book 2 section 9.2.1: 4..8 bytes). */
        public void setMacLength(int macLength) {
            this.macLength = macLength;
        }

        /**
         * Starts the chain with the Application Cryptogram of the first AC and
         * derives the MAC/Encipherment session keys from it (EMV v4.4 Book 2
         * section A1.3.1: the secure-messaging diversification value is the
         * first AC).
         */
        public void start(byte[] firstAc) throws GeneralSecurityException {
            byte[] ac = Arrays.copyOf(firstAc, 8);
            icv = ac;
            macSessionKey = AcCrypto.sessionKey(macKey, ac);
            encSessionKey = encKey == null ? null : AcCrypto.sessionKey(encKey, ac);
        }

        /** Builds one Format 1 command with no command data. */
        public CommandAPDU command(int ins, int p1, int p2)
                throws GeneralSecurityException {
            return command(ins, p1, p2, null, null);
        }

        /**
         * Builds one Format 1 command with the command-chaining bit (CLA b5)
         * set, i.e. a command that is not the last of a chain
         * (EMV v4.4 Book 3 §6.5.13).
         */
        public CommandAPDU commandChained(int ins, int p1, int p2)
                throws GeneralSecurityException {
            return build(CLA_FORMAT1_CHAINED, ins, p1, p2, null, null);
        }

        /**
         * Builds one Format 1 command.  Exactly one of plaintext/enciphered may
         * be non-null; enciphered is a PIN block that is CBC-enciphered with the
         * encipherment session key under a '87' object.
         */
        public CommandAPDU command(int ins, int p1, int p2,
                                   byte[] plaintext, byte[] enciphered)
                throws GeneralSecurityException {
            return build(CLA_FORMAT1, ins, p1, p2, plaintext, enciphered);
        }

        private CommandAPDU build(int cla, int ins, int p1, int p2,
                                  byte[] plaintext, byte[] enciphered)
                throws GeneralSecurityException {
            if (icv == null) {
                throw new IllegalStateException("ScriptSession.start() not called");
            }
            byte[] dataObjects;
            if (enciphered != null) {
                byte[] cryptogram = encipher(encSessionKey, enciphered);
                dataObjects = Bytes.concat(new byte[] { (byte) 0x87,
                        (byte) cryptogram.length }, cryptogram);
            } else if (plaintext != null) {
                dataObjects = Bytes.concat(new byte[] { (byte) 0x81,
                        (byte) plaintext.length }, plaintext);
            } else {
                dataObjects = new byte[0];
            }
            return buildFromObjects(cla, ins, p1, p2, dataObjects);
        }

        /**
         * Builds one Format 1 command from an arbitrary (already TLV-encoded)
         * data-object sequence; the MAC object is appended.  Used by the
         * boundary tests to send malformed or non-standard objects.
         */
        public CommandAPDU commandWithObjects(int ins, int p1, int p2,
                                              byte[] dataObjects)
                throws GeneralSecurityException {
            return buildFromObjects(CLA_FORMAT1, ins, p1, p2, dataObjects);
        }

        private CommandAPDU buildFromObjects(int cla, int ins, int p1, int p2,
                                             byte[] dataObjects)
                throws GeneralSecurityException {
            if (icv == null) {
                throw new IllegalStateException("ScriptSession.start() not called");
            }
            // Format 1 message to protect (EMV v4.4 Book 2 section 9.2.3 / Annex
            // D2.3.1): ICV || padded header || padded data object.
            byte[] header = new byte[] { (byte) cla, (byte) ins, (byte) p1, (byte) p2 };
            byte[] macInput;
            if (dataObjects.length > 0) {
                macInput = Bytes.concat(icv, header,
                        new byte[] { (byte) 0x80, 0x00, 0x00, 0x00 },
                        padIso7816(dataObjects));
            } else {
                macInput = Bytes.concat(icv, header,
                        new byte[] { (byte) 0x80, 0x00, 0x00, 0x00 });
            }
            byte[] fullMac = AcCrypto.macAlg3Padded(macSessionKey, macInput, 8);
            icv = fullMac; // the chain always advances with the full 8 bytes
            byte[] mac = Arrays.copyOfRange(fullMac, 0, macLength);

            byte[] dataField = Bytes.concat(dataObjects,
                    new byte[] { (byte) 0x8E, (byte) mac.length }, mac);
            return new CommandAPDU(cla, ins, p1, p2, dataField);
        }
    }
}
