package card42.host.emv.lib;

import javax.smartcardio.CommandAPDU;

import card42.host.common.util.Hex;

/**
 * Builders for the EMV command APDUs used by the host clients and test suites.
 *
 * Each method encodes one command; the raw variants exist so the test suites can
 * exercise the card's P1/P2 and length boundary conditions.
 */
public final class Apdus {

    private Apdus() {
    }

    /** SELECT by AID (hex string). */
    public static CommandAPDU select(String aidHex) {
        return select(Hex.parse(aidHex));
    }

    /** SELECT by AID (raw bytes). */
    public static CommandAPDU select(byte[] aid) {
        // Le='00' (EMV v4.4 Book 1 §11.3.2 Table 5 / Book 3 Table 5); the
        // javax.smartcardio ne=0 omits Le, so 256 encodes a trailing '00'.
        return new CommandAPDU(0x00, 0xA4, 0x04, 0x00, aid, 256);
    }

    /** READ RECORD from the given record and SFI. */
    public static CommandAPDU readRecord(int record, int sfi) {
        // Le='00' (EMV v4.4 Book 3 §6.5.11.2 Table 21).
        return new CommandAPDU(0x00, 0xB2, record, (sfi << 3) | 0x04, 256);
    }

    /** GET PROCESSING OPTIONS with an empty PDOL. */
    public static CommandAPDU gpo() {
        // Le='00' (EMV v4.4 Book 3 §6.5.8.2 Table 18).
        return new CommandAPDU(0x80, 0xA8, 0x00, 0x00, new byte[] { (byte) 0x83, 0x00 }, 256);
    }

    /** GET PROCESSING OPTIONS with the PDOL-related data of the terminal. */
    public static CommandAPDU gpo(byte[] pdolData) {
        byte[] data = new byte[pdolData.length + 2];
        data[0] = (byte) 0x83;
        data[1] = (byte) pdolData.length;
        System.arraycopy(pdolData, 0, data, 2, pdolData.length);
        return new CommandAPDU(0x80, 0xA8, 0x00, 0x00, data, 256);
    }

    /** GET PROCESSING OPTIONS with explicit P1/P2 and command data. */
    public static CommandAPDU gpoRaw(int p1, int p2, byte[] data) {
        return new CommandAPDU(0x80, 0xA8, p1, p2, data, 256);
    }

    /** GET PROCESSING OPTIONS with no data field (a missing '83' template). */
    public static CommandAPDU gpoNoData() {
        return new CommandAPDU(0x80, 0xA8, 0x00, 0x00, 256);
    }

    /**
     * Builds a '83' command template with an explicit declared length, so the
     * length-mismatch and trailing-byte cases can be exercised.
     */
    public static byte[] commandTemplate(int declaredLength, byte[] value) {
        byte[] data = new byte[2 + value.length];
        data[0] = (byte) 0x83;
        data[1] = (byte) declaredLength;
        System.arraycopy(value, 0, data, 2, value.length);
        return data;
    }

    /**
     * VERIFY of the plaintext offline PIN (P2=80): the fixed 8-byte EMV Table 25
     * block 'C N || BCD digits || F filler', with C=0010 and N=pin length
     * (EMV v4.4 Book 3 §6.5.12.2 Table 25).
     */
    public static CommandAPDU verifyOfflinePin(String pin) {
        byte[] data = new byte[8];
        java.util.Arrays.fill(data, (byte) 0xFF);
        data[0] = (byte) (0x20 | pin.length());
        byte[] digits = Hex.bcd(pin);
        System.arraycopy(digits, 0, data, 1, digits.length);
        return new CommandAPDU(0x00, 0x20, 0x00, 0x80, data);
    }

    /**
     * VERIFY of the enciphered offline PIN (P2=88): the RSA-enciphered Table 25
     * block (7F || PIN block || ICC UN || random padding), EMV v4.4 Book 2 §7.2.
     */
    public static CommandAPDU verifyEncryptedPin(byte[] encipheredPin) {
        return new CommandAPDU(0x00, 0x20, 0x00, 0x88, encipheredPin);
    }

    /** GENERATE AC with a data field of dataLength zero bytes. */
    public static CommandAPDU generateAc(byte p1, int dataLength) {
        // Le='00' (EMV v4.4 Book 3 §6.5.5.2 Table 11).
        return new CommandAPDU(0x80, 0xAE, p1, 0x00, new byte[dataLength], 256);
    }

    /** GENERATE AC with an explicit CDOL data field. */
    public static CommandAPDU generateAc(byte p1, byte[] data) {
        return new CommandAPDU(0x80, 0xAE, p1, 0x00, data, 256);
    }

    /** GENERATE AC with explicit P1/P2 and command data. */
    public static CommandAPDU generateAcRaw(int p1, int p2, byte[] data) {
        return new CommandAPDU(0x80, 0xAE, p1, p2, data, 256);
    }

    /** VERIFY with explicit P1/P2 and command data. */
    public static CommandAPDU verifyRaw(int p1, int p2, byte[] data) {
        return new CommandAPDU(0x00, 0x20, p1, p2, data);
    }

    /** INTERNAL AUTHENTICATE with explicit P1/P2 and command data. */
    public static CommandAPDU internalAuthenticateRaw(int p1, int p2, byte[] data) {
        // Le='00' (EMV v4.4 Book 3 §6.5.9.2 Table 19).
        return new CommandAPDU(0x00, 0x88, p1, p2, data, 256);
    }

    /** GET CHALLENGE: request an 8-byte ICC unpredictable number. */
    public static CommandAPDU getChallenge() {
        // Le='00' (EMV v4.4 Book 3 §6.5.6.2 Table 16).
        return new CommandAPDU(0x00, 0x84, 0x00, 0x00, 256);
    }

    /** INTERNAL AUTHENTICATE (DDA) with the DDOL data (P1=P2=00). */
    public static CommandAPDU internalAuthenticate(byte[] ddolData) {
        return new CommandAPDU(0x00, 0x88, 0x00, 0x00, ddolData, 256);
    }

    /**
     * EXTERNAL AUTHENTICATE with the Issuer Authentication Data (tag 91 value),
     * the generic issuer authentication path (EMV v4.4 Book 2 §8.2).
     */
    public static CommandAPDU externalAuthenticate(byte[] issuerAuthData) {
        // Le='00' (EMV v4.4 Book 3 §6.5.4.2 Table 9).
        return new CommandAPDU(0x00, 0x82, 0x00, 0x00, issuerAuthData, 256);
    }

    /** GET DATA for a 1- or 2-byte tag given as P1/P2 (e.g. 0x9F, 0x36 = ATC). */
    public static CommandAPDU getData(int p1, int p2) {
        // CLA='80' and Le='00' (EMV v4.4 Book 3 §6.5.7.2 Table 17).
        return new CommandAPDU(0x80, 0xCA, p1, p2, 256);
    }

    /**
     * SEND POI INFORMATION (CLA=80 INS=1A, EMV Contactless Book B v2.12 Annex C):
     * wraps the SDOL values followed by the POI Information objects in the '83'
     * Command Template.  Le='00'.
     */
    public static CommandAPDU sendPoiInformation(byte[] value) {
        byte[] data = new byte[value.length + 2];
        data[0] = (byte) 0x83;
        data[1] = (byte) value.length;
        System.arraycopy(value, 0, data, 2, value.length);
        return new CommandAPDU(0x80, 0x1A, 0x00, 0x00, data, 256);
    }

    /** SEND POI INFORMATION with explicit P1/P2 and raw command data. */
    public static CommandAPDU sendPoiInformationRaw(int p1, int p2, byte[] data) {
        return new CommandAPDU(0x80, 0x1A, p1, p2, data, 256);
    }

    /** A parsed plaintext command APDU: its INS/P1/P2 and raw data field. */
    public static final class Command {
        public final int ins;
        public final int p1;
        public final int p2;
        public final byte[] data;

        Command(int ins, int p1, int p2, byte[] data) {
            this.ins = ins;
            this.p1 = p1;
            this.p2 = p2;
            this.data = data;
        }
    }

    /**
     * Parses a short command APDU from hex (4 bytes, optionally a 1-byte
     * {@code Lc} and data, or a bare {@code Le}), for secure-messaging wrapping.
     */
    public static Command parse(String hex) {
        byte[] raw = Hex.parse(hex);
        if (raw.length < 4) {
            throw new IllegalArgumentException("not a command APDU: " + hex);
        }
        int ins = raw[1] & 0xFF;
        int p1 = raw[2] & 0xFF;
        int p2 = raw[3] & 0xFF;
        if (raw.length == 4) {
            return new Command(ins, p1, p2, new byte[0]);
        }
        int lc = raw[4] & 0xFF;
        if (raw.length == 5 && lc == 0) {
            return new Command(ins, p1, p2, new byte[0]); // a bare Le
        }
        if (raw.length != 5 + lc) {
            throw new IllegalArgumentException("bad Lc in command APDU: " + hex);
        }
        return new Command(ins, p1, p2, java.util.Arrays.copyOfRange(raw, 5, raw.length));
    }
}
