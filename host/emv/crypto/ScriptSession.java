package card42.host.emv.crypto;

import java.security.GeneralSecurityException;
import java.util.Arrays;

import javax.smartcardio.CommandAPDU;

import card42.host.common.util.Bytes;

/**
 * A terminal-side EMV Format&nbsp;1 secure-messaging session (EMV v4.4 Book 2
 * §9.2).  The MAC chain starts at the first GENERATE AC and is updated with the
 * full 8-byte MAC of every command (EMV v4.4 Book 2 §9.2.3.1).
 *
 * <p>It builds the secured post-issuance / issuer-script commands the card
 * verifies with {@link SmCrypto}: the CLA, the MAC and the optional enciphered
 * PIN block.  The primitives (PIN encipherment, ISO/IEC 7816-4 padding) live in
 * {@link SmCrypto}.
 */
public final class ScriptSession {

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
        if (macLength < 4 || macLength > 8) {
            throw new IllegalArgumentException("-mac-length must be 4..8 bytes: " + macLength);
        }
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
        return build(SmCrypto.CLA_FORMAT1_CHAINED, ins, p1, p2, null, null);
    }

    /**
     * Builds one Format 1 command.  Exactly one of plaintext/enciphered may
     * be non-null; enciphered is a PIN block that is CBC-enciphered with the
     * encipherment session key under a '87' object.
     */
    public CommandAPDU command(int ins, int p1, int p2,
                               byte[] plaintext, byte[] enciphered)
            throws GeneralSecurityException {
        return build(SmCrypto.CLA_FORMAT1, ins, p1, p2, plaintext, enciphered);
    }

    private CommandAPDU build(int cla, int ins, int p1, int p2,
                              byte[] plaintext, byte[] enciphered)
            throws GeneralSecurityException {
        if (icv == null) {
            throw new IllegalStateException("ScriptSession.start() not called");
        }
        byte[] dataObjects;
        if (enciphered != null) {
            byte[] cryptogram = SmCrypto.encipher(encSessionKey, enciphered);
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
        return buildFromObjects(SmCrypto.CLA_FORMAT1, ins, p1, p2, dataObjects);
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
                    SmCrypto.padIso7816(dataObjects));
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
