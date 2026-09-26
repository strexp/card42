package card42.emv;

import card42.common.*;

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.MessageDigest;
import javacard.security.RandomData;

/* Dynamic Data Authentication (INTERNAL AUTHENTICATE) and Combined DDA/AC
 * (CDA) signing (EMV v4.4 Book 2 §6.5, §6.6).
 *
 * DDA signs the terminal DDOL data (EMV v4.4 Book 2 Table 15) with the ICC private key
 * and returns the SDAD as Format 2 (77 { 9F4B }) for a CCD application or as
 * Format 1 (primitive '80') for the generic profile.  CDA assembles the dynamic
 * application data (EMV v4.4 Book 2 Table 18), hashes the PDOL/CDOL data into the
 * Transaction Data Hash Code and returns 77 { 9F27, 9F36, 9F4B, 9F10 }.
 *
 * The transient scratch buffers (authMessage, cdaHeader) and the SHA-1 digest
 * live here; the Unpredictable Number scratch is filled by the AC processor
 * through copyUn() before the AC is computed.
 *
 * @author card42
 */

public class DynamicAuth implements ISO7816 {

    /** Scratch buffer for the ISO 9796-2 message of DDA/CDA (EMV v4.4 Book 2 Tables 15 and 18). */
    private byte[] authMessage;
    /** SHA-1 for the CDA Transaction Data Hash Code. */
    private final MessageDigest sha1;
    /** CID, ATC, IAD framing shared by the CDA response hash (EMV v4.4 Book 3 §10.8). */
    private final byte[] cdaHeader;
    /** CDA Unpredictable Number scratch (EMV v4.4 Book 2 §6.6). */
    private final byte[] cdaUn;

    private final EMVStaticData staticData;
    private final EMVProtocolState protocolState;
    private final DdaCrypto ddaCrypto;
    private final RandomData randomData;

    public DynamicAuth(EMVStaticData staticData, EMVProtocolState protocolState,
            DdaCrypto ddaCrypto, RandomData randomData) {
        this.staticData = staticData;
        this.protocolState = protocolState;
        this.ddaCrypto = ddaCrypto;
        this.randomData = randomData;

        authMessage = null;
        cdaHeader = JCSystem.makeTransientByteArray(
                (short) 48, JCSystem.CLEAR_ON_DESELECT);
        cdaUn = JCSystem.makeTransientByteArray(
                (short) 4, JCSystem.CLEAR_ON_DESELECT);
        sha1 = MessageDigest.getInstance(MessageDigest.ALG_SHA, false);
    }

    /**
     * The DDA/CDA message buffer is the shared work scratch, sized to at least
     * the ISO 9796-2 message length (up to Table 43's 247-byte ICC modulus).
     * DDA/CDA is never active together with the other large scratch users
     * (docs/specs/common/cryptography.md §6, §9).
     */
    private void ensureAuthMessage(short needed) {
        authMessage = protocolState.getWorkScratch(needed);
    }

    /*
     * INTERNAL AUTHENTICATE (EMV v4.4 Book 3 section 6.5.9): DDA.  The card signs the
     * DDOL data sent by the terminal (EMV v4.4 Book 2 Table 15) with the ICC private
     * key.  A CCD application returns Format 2 (77 { 9F4B }, EMV v4.4 Book 3 CCD
     * §6.5.9.4 / Table CCD 5); a generic application returns Format 1, a
     * primitive '80' SDAD (EMV v4.4 Book 3 §6.5.9.4).  A missing key yields 6985; wrong
     * P1/P2 yields 6A81 (EMV v4.4 Book 3 Table 19 / Table 4).
     */
    public void internalAuthenticate(APDU apdu, byte[] apduBuffer, byte[] response) {
        // The command parameters are validated first (EMV v4.4 Book 3 §6.5.9.3):
        // a P1/P2 other than 00 is 6A81 even when this instance has no DDA key.
        if (apduBuffer[OFFSET_P1] != 0x00 || apduBuffer[OFFSET_P2] != 0x00) {
            ISOException.throwIt(SW_FUNC_NOT_SUPPORTED); // 6A81
        }
        if (!ddaCrypto.isAvailable()) {
            ISOException.throwIt(SW_CONDITIONS_NOT_SATISFIED); // no DDA key
        }

        short lc = ApduIo.receive(apdu, apduBuffer);

        short nic = ddaCrypto.getKeyLength();
        if (nic < 22 || nic > response.length) {
            ISOException.throwIt(SW_CONDITIONS_NOT_SATISFIED);
        }

        // ICC Dynamic Data: 1-byte length of the ICC Dynamic Number + 4 bytes.
        short ldd = (short) 5;
        short prefix = (short) (nic - 22);
        ensureAuthMessage((short) (prefix + lc));
        if ((short) (prefix + lc) > authMessage.length) {
            // A DDOL longer than the scratch buffer cannot be signed.
            ISOException.throwIt(SW_WRONG_LENGTH);
        }
        authMessage[0] = (byte) 0x05; // Signed Data Format
        authMessage[1] = (byte) 0x01; // Hash Algorithm Indicator (SHA-1)
        authMessage[2] = (byte) ldd;
        authMessage[3] = (byte) 0x04; // ICC Dynamic Number length
        randomData.generateData(authMessage, (short) 4, (short) 4);
        fillPad((short) (3 + ldd), prefix);

        // Terminal Dynamic Data (the DDOL data) follows the recoverable part.
        Util.arrayCopyNonAtomic(apduBuffer, OFFSET_CDATA, authMessage, prefix, lc);
        short msgLength = (short) (prefix + lc);

        // The response format follows the application profile (EMV v4.4 Book 3 §6.5.9.4
        // and CCD §6.5.9.4): CCD returns Format 2 77 { 9F4B }, the generic
        // profile returns Format 1 (primitive '80' SDAD).
        boolean ccd = !staticData.externalAuthenticateSupported(protocolState.getRole());
        short p = 0;
        if (ccd) {
            short body = (short) (2 + Tlv.lengthSize(nic) + nic);
            response[p++] = (byte) 0x77;
            p = Tlv.appendLength(body, response, p);
            p = Tlv.appendTag(TlvTags.TAG_SIGNED_DYNAMIC_APPLICATION_DATA, response, p);
        } else {
            response[p++] = (byte) 0x80; // format 1: primitive SDAD
        }
        p = Tlv.appendLength(nic, response, p);
        if (ddaCrypto.sign(authMessage, (short) 0, msgLength, response, p) != nic) {
            ISOException.throwIt(SW_CONDITIONS_NOT_SATISFIED);
        }
        p += nic;
        protocolState.setDdaPerformed(); // CVR byte 1 b3 (EMV v4.4 Book 3 Annex C §C9)

        apdu.setOutgoing();
        apdu.setOutgoingLength(p);
        apdu.sendBytesLong(response, (short) 0, p);
    }

    /** Fills authMessage[from..to) with the EMV pad pattern 0xBB. */
    private void fillPad(short from, short to) {
        for (short i = from; i < to; i++) {
            authMessage[i] = (byte) 0xBB;
        }
    }

    /*
     * Assembles and signs the CDA dynamic application data (EMV v4.4 Book 2 section
     * 6.6, tables 17/18) for a first or second AC, and writes a format 2
     * response (tag '77') containing 9F27, 9F36 and 9F4B (EMV v4.4 Book 2 §6.6).
     *
     * cdol1Data is the terminal data of the first GENERATE AC (the current
     * command for the first AC, the stored copy for the second); cdol2Data is
     * the current command data for the second AC, or null for the first.
     */
    public void generateCda(APDU apdu, byte cid, short atc, byte[] ac,
                            byte[] cdol1Data, short cdol1Offset, short cdol1Length,
                            byte[] cdol2Data, short cdol2Offset, short cdol2Length,
                            byte[] response) {
        byte[] iad = staticData.getIad();
        short iadLength = staticData.getIadLength();
        protocolState.setCdaPerformed(); // CVR byte 1 b4 (EMV v4.4 Book 3 Annex C §C9)

        // The Transaction Data Hash Code covers the PDOL data, the CDOL data
        // and the response data elements except the SDAD, i.e. 9F27, 9F36 and
        // 9F10 in the order they are returned (EMV v4.4 Book 2 section 6.6.1 step 2b).
        short h = 0;
        cdaHeader[h++] = (byte) 0x9F;
        cdaHeader[h++] = 0x27;
        cdaHeader[h++] = 0x01;
        cdaHeader[h++] = cid;
        cdaHeader[h++] = (byte) 0x9F;
        cdaHeader[h++] = 0x36;
        cdaHeader[h++] = 0x02;
        Util.setShort(cdaHeader, h, atc);
        h += 2;
        h = Tlv.appendTag(TlvTags.TAG_IAD, cdaHeader, h);
        h = Tlv.appendLength(iadLength, cdaHeader, h);
        Util.arrayCopyNonAtomic(iad, (short) 0, cdaHeader, h, iadLength);
        h += iadLength;

        sha1.reset();
        short pdolLength = protocolState.getPdolDataLength();
        if (pdolLength > 0) {
            sha1.update(protocolState.getPdolData(), (short) 0, pdolLength);
        }
        sha1.update(cdol1Data, cdol1Offset, cdol1Length);
        if (cdol2Length > 0) {
            sha1.update(cdol2Data, cdol2Offset, cdol2Length);
        }
        sha1.doFinal(cdaHeader, (short) 0, h, response, (short) 0);
        // response[0..19] now holds the 20-byte Transaction Data Hash Code.

        short nic = ddaCrypto.getKeyLength();
        if (nic < 22 || nic > response.length) {
            ISOException.throwIt(SW_CONDITIONS_NOT_SATISFIED);
        }
        short prefix = (short) (nic - 22);
        // Size the ISO 9796-2 message to the actual modulus so a large ICC key
        // does not overrun a fixed buffer (docs/specs/common/cryptography.md §6).
        ensureAuthMessage((short) (prefix + 4));
        if ((short) (prefix + 4) > authMessage.length) {
            ISOException.throwIt(SW_CONDITIONS_NOT_SATISFIED);
        }

        // ICC Dynamic Data (EMV v4.4 Book 2 table 18): dynamic number, CID, AC, hash.
        short ldd = (short) 34;
        authMessage[0] = (byte) 0x05;
        authMessage[1] = (byte) 0x01;
        authMessage[2] = (byte) ldd;
        authMessage[3] = (byte) 0x04; // ICC Dynamic Number length
        randomData.generateData(authMessage, (short) 4, (short) 4);
        authMessage[8] = cid;
        Util.arrayCopyNonAtomic(ac, (short) 0, authMessage, (short) 9, (short) 8);
        Util.arrayCopyNonAtomic(response, (short) 0, authMessage, (short) 17, (short) 20);
        fillPad((short) (3 + ldd), prefix);

        // Terminal data: the 4-byte Unpredictable Number (EMV v4.4 Book 2 table 17).
        Util.arrayCopyNonAtomic(cdaUn, (short) 0, authMessage, prefix, (short) 4);
        short msgLength = (short) (prefix + 4);

        // Format 2 response: 77 { 9F27, 9F36, 9F4B, 9F10 } (EMV v4.4 Book 2 table 19).
        short sdadField = (short) (2 + Tlv.lengthSize(nic) + nic);
        short bodyLength = (short) (4 + 5 + sdadField + 3 + iadLength);
        short total = (short) (1 + Tlv.lengthSize(bodyLength) + bodyLength);
        if (total > response.length) {
            ISOException.throwIt(SW_CONDITIONS_NOT_SATISFIED);
        }

        short p = 0;
        response[p++] = (byte) 0x77;
        p = Tlv.appendLength(bodyLength, response, p);
        p = Tlv.appendTag(TlvTags.TAG_CID, response, p);
        response[p++] = 0x01;
        response[p++] = cid;
        p = Tlv.appendTag(TlvTags.TAG_ATC, response, p);
        response[p++] = 0x02;
        Util.setShort(response, p, atc);
        p += 2;
        p = Tlv.appendTag(TlvTags.TAG_SIGNED_DYNAMIC_APPLICATION_DATA, response, p);
        p = Tlv.appendLength(nic, response, p);
        if (ddaCrypto.sign(authMessage, (short) 0, msgLength, response, p) != nic) {
            ISOException.throwIt(SW_CONDITIONS_NOT_SATISFIED);
        }
        p += nic;
        p = Tlv.appendTag(TlvTags.TAG_IAD, response, p);
        p = Tlv.appendLength(iadLength, response, p);
        Util.arrayCopyNonAtomic(iad, (short) 0, response, p, iadLength);
        p += iadLength;

        apdu.setOutgoing();
        apdu.setOutgoingLength(p);
        apdu.sendBytesLong(response, (short) 0, p);
    }

    /** Copies the 4-byte Unpredictable Number at unOffset into cdaUn. */
    void copyUn(short unOffset, short dataLength, byte[] data) {
        if (unOffset < 0 || (short) (unOffset + 4) > dataLength) {
            ISOException.throwIt(SW_CONDITIONS_NOT_SATISFIED);
        }
        Util.arrayCopyNonAtomic(data, (short) (OFFSET_CDATA + unOffset),
                cdaUn, (short) 0, (short) 4);
    }
}
