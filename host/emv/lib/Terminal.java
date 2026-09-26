package card42.host.emv.lib;

import javax.smartcardio.CardChannel;
import javax.smartcardio.ResponseAPDU;

import card42.host.common.codec.Tags;

/**
 * EMV terminal: the generic {@link card42.host.common.transport.Terminal}
 * (transmit/select) extended with the APDU conveniences of the EMV terminal
 * flow.  It only pairs the {@link Apdus} builders with the channel; it holds no
 * EMV logic and no state beyond the channel.
 */
public final class Terminal extends card42.host.common.transport.Terminal {

    public Terminal(CardChannel channel) {
        super(channel);
    }

    /** Wraps a generic terminal (e.g. a traced session terminal). */
    public Terminal(card42.host.common.transport.Terminal base) {
        super(base.getChannel());
    }

    /** READ RECORD from the given record and SFI. */
    public ResponseAPDU readRecord(int record, int sfi) throws Exception {
        return transmit(Apdus.readRecord(record, sfi));
    }

    /** GET PROCESSING OPTIONS with an empty PDOL. */
    public ResponseAPDU gpo() throws Exception {
        return transmit(Apdus.gpo());
    }

    /** GET PROCESSING OPTIONS with the PDOL-related data. */
    public ResponseAPDU gpo(byte[] pdolData) throws Exception {
        return transmit(Apdus.gpo(pdolData));
    }

    /** GET PROCESSING OPTIONS with explicit P1/P2 and command data. */
    public ResponseAPDU gpoRaw(int p1, int p2, byte[] data) throws Exception {
        return transmit(Apdus.gpoRaw(p1, p2, data));
    }

    /** GET PROCESSING OPTIONS with no data field (a missing '83' template). */
    public ResponseAPDU gpoNoData() throws Exception {
        return transmit(Apdus.gpoNoData());
    }

    /** GET DATA for a 1- or 2-byte tag given as P1/P2. */
    public ResponseAPDU getData(int p1, int p2) throws Exception {
        return transmit(Apdus.getData(p1, p2));
    }

    /**
     * Reads the Application Transaction Counter (9F36) and returns it, or -1
     * when the response is not 9F36 02 xxxx.  The caller interprets the -1.
     */
    public int readAtc() throws Exception {
        ResponseAPDU r = getData(0x9F, 0x36);
        byte[] atc = r.getSW() == 0x9000 ? Tags.find(r.getData(), 0x9F36) : null;
        if (atc == null || atc.length != 2) {
            return -1;
        }
        return ((atc[0] & 0xFF) << 8) | (atc[1] & 0xFF);
    }

    /** VERIFY of the plaintext offline PIN (P2=80). */
    public ResponseAPDU verifyOfflinePin(String pin) throws Exception {
        return transmit(Apdus.verifyOfflinePin(pin));
    }

    /** VERIFY of the enciphered offline PIN (P2=88). */
    public ResponseAPDU verifyEncryptedPin(byte[] encipheredPin) throws Exception {
        return transmit(Apdus.verifyEncryptedPin(encipheredPin));
    }

    /** GENERATE AC with a data field of dataLength zero bytes. */
    public ResponseAPDU generateAc(byte p1, int dataLength) throws Exception {
        return transmit(Apdus.generateAc(p1, dataLength));
    }

    /** GENERATE AC with an explicit CDOL data field. */
    public ResponseAPDU generateAc(byte p1, byte[] data) throws Exception {
        return transmit(Apdus.generateAc(p1, data));
    }

    /** GENERATE AC with explicit P1/P2 and command data. */
    public ResponseAPDU generateAcRaw(int p1, int p2, byte[] data) throws Exception {
        return transmit(Apdus.generateAcRaw(p1, p2, data));
    }

    /** VERIFY with explicit P1/P2 and command data. */
    public ResponseAPDU verifyRaw(int p1, int p2, byte[] data) throws Exception {
        return transmit(Apdus.verifyRaw(p1, p2, data));
    }

    /** INTERNAL AUTHENTICATE with explicit P1/P2 and command data. */
    public ResponseAPDU internalAuthenticateRaw(int p1, int p2, byte[] data) throws Exception {
        return transmit(Apdus.internalAuthenticateRaw(p1, p2, data));
    }

    /** GET CHALLENGE: request an 8-byte ICC unpredictable number. */
    public ResponseAPDU getChallenge() throws Exception {
        return transmit(Apdus.getChallenge());
    }

    /**
     * SEND POI INFORMATION (CLA=80 INS=1A, EMV Contactless Book B v2.12
     * Annex C) with the SDOL values and POI Information objects in the '83'
     * Command Template.
     */
    public ResponseAPDU sendPoiInformation(byte[] value) throws Exception {
        return transmit(Apdus.sendPoiInformation(value));
    }

    /** SEND POI INFORMATION with explicit P1/P2 and raw command data. */
    public ResponseAPDU sendPoiInformationRaw(int p1, int p2, byte[] data) throws Exception {
        return transmit(Apdus.sendPoiInformationRaw(p1, p2, data));
    }

    /** INTERNAL AUTHENTICATE (DDA) with the DDOL data. */
    public ResponseAPDU internalAuthenticate(byte[] ddolData) throws Exception {
        return transmit(Apdus.internalAuthenticate(ddolData));
    }

    /** EXTERNAL AUTHENTICATE with the Issuer Authentication Data (tag 91). */
    public ResponseAPDU externalAuthenticate(byte[] issuerAuthData) throws Exception {
        return transmit(Apdus.externalAuthenticate(issuerAuthData));
    }
}
