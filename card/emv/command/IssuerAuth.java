package card42.emv;

import card42.common.*;

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;

/* Issuer authentication (EMV v4.4 Book 2 §8.2, EMV v4.4 Book 3 Annex C §C9.3/§C10).
 *
 * Two paths are supported: the CCD inline Issuer Authentication Data (tag 91)
 * carried in CDOL2 of the second GENERATE AC, and the generic EXTERNAL
 * AUTHENTICATE command (INS=82) advertised by AIP byte 1 bit 3.  A CCD Card
 * Status Update (CSU) delivered with a successful ARPC is applied here, and it
 * can block the application or the whole card.
 *
 * @author card42
 */

public class IssuerAuth implements ISO7816 {

    private final EMVAppletBase applet;
    private final EMVStaticData staticData;
    private final EMVProtocolState protocolState;
    private final OfflineRisk offlineRisk;
    private final OfflinePinState pin;
    private final Arpc arpc;

    public IssuerAuth(EMVAppletBase applet, EMVStaticData staticData,
            EMVProtocolState protocolState, OfflineRisk offlineRisk, OfflinePinState pin,
            Arpc arpc) {
        this.applet = applet;
        this.staticData = staticData;
        this.protocolState = protocolState;
        this.offlineRisk = offlineRisk;
        this.pin = pin;
        this.arpc = arpc;
    }

    /**
     * Verifies the Issuer Authentication Data (tag 91) carried in CDOL2 of the
     * second GENERATE AC (CCD, EMV v4.4 Book 3 §6.5.5.3).  The 8-byte value is
     * ARPC(4) || CSU(4); the ARPC is verified with Method 2 (EMV v4.4 Book 2 §8.2).
     * When tag 91 is absent the transaction simply does not perform issuer
     * authentication ("Issuer Authentication Not Performed").
     */
    public void performInlineIssuerAuth(byte[] apduBuffer, short cdol2Length,
            byte[] firstCdol, short firstCdolLength) {
        short offset = staticData.getCDOL2ValueOffset(TlvTags.TAG_ISSUER_AUTH_DATA);
        short length = staticData.getCDOL2ValueLength(TlvTags.TAG_ISSUER_AUTH_DATA);
        if (offset < 0 || length < 8 || (short) (offset + length) > cdol2Length) {
            return;
        }
        short dataOffset = (short) (OFFSET_CDATA + offset);
        if (arpc.verifyMethod2(apduBuffer, dataOffset, length)) {
            protocolState.issuerAuthSucceeded();
            // A successful issuer authentication clears the 'Set Go Online on
            // Next Transaction' flag set by an earlier CSU; applyCsu may set it
            // again from this CSU's b4 (EMV v4.4 Book 3 Annex C §C10).
            offlineRisk.clearGoOnlineNext();
            applyCsu(apduBuffer, dataOffset, length, firstCdol, firstCdolLength);
        } else {
            protocolState.issuerAuthFailed();
        }
    }

    /**
     * EXTERNAL AUTHENTICATE (INS=82, EMV v4.4 Book 3 section 6.5.4): the generic EMV
     * issuer authentication path, advertised by AIP byte 1 bit 3.  The data
     * field is the value of tag '91': an 8-byte cryptogram plus 0-8 proprietary
     * bytes (EMV v4.4 Book 3 §6.5.4.3).
     *
     * <p>Both ARPC methods are accepted.  Method 2 (EMV v4.4 Book 2 §8.2.2) needs no
     * ARC, so the standard 8-byte field (ARPC(4) || CSU(4)) verifies directly and
     * its CSU is applied.  Method 1 (EMV v4.4 Book 2 §8.2.1) needs the ARC; the
     * standard field does not carry it, so this project places the ARC in the
     * first two proprietary bytes and Method 1 applies from 10 bytes on
     * (docs/specs/emv/transaction.md §6).
     *
     * Only one EXTERNAL AUTHENTICATE is permitted per transaction; a later one
     * returns 6985.  Success returns 9000, a failed cryptogram 6300.
     */
    public void externalAuthenticate(APDU apdu, byte[] apduBuffer,
            byte[] firstCdol, short firstCdolLength) {
        if (protocolState.getLifecycle() != EMVRoles.READY) {
            ISOException.throwIt(SW_CONDITIONS_NOT_SATISFIED); // 6985
        }
        if (!staticData.externalAuthenticateSupported(protocolState.getRole())) {
            // The AIP says this profile does not use INS=82 (CCD, EMV v4.4 Book 2 §8.2).
            ISOException.throwIt(SW_CONDITIONS_NOT_SATISFIED); // 6985
        }
        if (apduBuffer[OFFSET_P1] != 0x00 || apduBuffer[OFFSET_P2] != 0x00) {
            ISOException.throwIt(SW_FUNC_NOT_SUPPORTED); // 6A81
        }
        if (protocolState.isExternalAuthUsed()) {
            // At most one EXTERNAL AUTHENTICATE per transaction.
            ISOException.throwIt(SW_CONDITIONS_NOT_SATISFIED); // 6985
        }
        if (protocolState.getFirstACGenerated() != EMVCodes.ARQC) {
            // No ARQC of this transaction to authenticate against.
            ISOException.throwIt(SW_CONDITIONS_NOT_SATISFIED); // 6985
        }

        short lc = ApduIo.receive(apdu, apduBuffer);
        if (lc < 8 || lc > 16) {
            ISOException.throwIt(SW_WRONG_LENGTH); // 6700
        }

        protocolState.setExternalAuthUsed();
        if (arpc.verifyMethod2(apduBuffer, OFFSET_CDATA, lc)) {
            // Method 2: the standard 8-byte field (ARPC(4) || CSU(4)) verifies
            // without an ARC, and the CSU it carries is applied.
            protocolState.issuerAuthSucceeded();
            offlineRisk.clearGoOnlineNext();
            protocolState.setLastOnlineATC(protocolState.getATC());
            applyCsu(apduBuffer, OFFSET_CDATA, lc, firstCdol, firstCdolLength);
            apdu.setOutgoingAndSend((short) 0, (short) 0); // 9000
        } else if (lc >= (short) 10
                && arpc.verifyMethod1(apduBuffer, OFFSET_CDATA, lc)) {
            // Method 1: the ARC is carried in the proprietary bytes, so the
            // field is at least 10 bytes.  A successful issuer authentication
            // completes the online session and clears the 'Set Go Online on
            // Next Transaction' flag; Method 1 has no CSU.
            protocolState.issuerAuthSucceeded();
            offlineRisk.clearGoOnlineNext();
            protocolState.setLastOnlineATC(protocolState.getATC());
            apdu.setOutgoingAndSend((short) 0, (short) 0); // 9000
        } else {
            protocolState.issuerAuthFailed();
            ISOException.throwIt(EMVStatus.SW_ISSUER_AUTHENTICATION_FAILED); // 6300
        }
    }

    /**
     * Applies the Card Status Update (CSU) carried by a CCD Issuer
     * Authentication Data value (91 = ARPC(4) || CSU(4), EMV v4.4 Book 3 Annex C §C9.3):
     * the Application/Card Block bits are honoured and the offline counters are
     * updated per the CSU 'Update Counters' bits (EMV v4.4 Book 3 Annex C §C10).
     */
    private void applyCsu(byte[] data, short off, short len,
            byte[] firstCdol, short firstCdolLength) {
        if (len < 8) {
            return;
        }
        protocolState.setCsuApplied();
        byte csu1 = data[(short) (off + 4)]; // CSU byte 1
        byte b = data[(short) (off + 5)]; // CSU byte 2
        // b8 "Issuer Approves Online Transaction" (EMV v4.4 Book 3 Annex C §C10).
        protocolState.setIssuerApprovedOnline((b & 0x80) != 0);
        if ((b & 0x40) != 0) { // Card Block
            protocolState.setLifecycle(EMVRoles.CARD_BLOCKED);
            applet.blockCard();
        } else if ((b & 0x20) != 0) { // Application Block
            protocolState.setLifecycle(EMVRoles.BLOCKED);
        }
        if ((b & 0x10) != 0) {
            // b5 "Update PIN Try Counter": the value is in bits b4-b1 of CSU
            // byte 1.  The persistent PTC is set to that value; 0 blocks the PIN
            // (EMV v4.4 Book 3 Annex C §C10).
            pin.setTriesRemaining((byte) (csu1 & 0x0F));
        }
        if ((b & 0x08) != 0) { // Set Go Online on Next Transaction
            offlineRisk.setGoOnlineNext();
        }
        short amountOff = staticData.getCDOL1ValueOffset(TlvTags.TAG_AMOUNT_AUTHORISED);
        short amountLen = staticData.getCDOL1ValueLength(TlvTags.TAG_AMOUNT_AUTHORISED);
        if (amountOff < 0 || amountLen <= 0
                || (short) (amountOff + amountLen) > firstCdolLength) {
            amountOff = 0;
            amountLen = 0;
        }
        offlineRisk.applyUpdateCounters(
                OfflineRisk.updateCountersApply(b) ? (byte) (b & 0x03) : (byte) 0x00,
                firstCdol, amountOff, amountLen);
    }
}
