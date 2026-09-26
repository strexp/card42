package card42.emv;

import card42.common.*;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;

/* Applies the personalization DGIs of a payment instance (EMV CPS v2.0 Annex A).
 *
 * PersoHandler reassembles the STORE DATA blocks and calls applyDgi() for each
 * container; this class owns the payment-specific state of that process: the
 * required-DGI flags and the ICC RSA key parts, which arrive as separate
 * modulus/exponent DGIs and are assembled once both are present.
 *
 * @author card42
 */

public class PaymentPerso implements ISO7816 {

    private final EMVStaticData staticData;
    private final EMVProtocolState protocolState;
    private final OfflineRisk offlineRisk;
    private final TransactionLog transactionLog;
    private final OfflinePinState pin;
    private final EMVCrypto theCrypto;
    private final SecureMessaging secureMessaging;
    private final DdaCrypto ddaCrypto;
    private final PinCrypto pinCrypto;

    /* Which required DGIs of the personalization sequence have been seen
     * (EMV CPS v2.0 Annex A). */
    private boolean sawKeys;
    private boolean sawFci;
    private boolean sawOfflinePin;

    /* ICC RSA key parts accumulated during personalization: the EMV CPS v2.0 DGIs
     * '8103'/'8101' (DDA) and '8104'/'8102' (PIN) carry the modulus and the
     * private exponent separately; the key is built once both have arrived
     * (EMV CPS v2.0 §A.2). */
    private final byte[] ddaModulus = new byte[(short) 256];
    private short ddaModulusLength;
    private final byte[] ddaExponent = new byte[(short) 256];
    private short ddaExponentLength;
    private final byte[] pinModulus = new byte[(short) 256];
    private short pinModulusLength;
    private final byte[] pinExponent = new byte[(short) 256];
    private short pinExponentLength;
    private final byte[] keyContainer = new byte[(short) 530];

    public PaymentPerso(EMVStaticData staticData, EMVProtocolState protocolState,
            OfflineRisk offlineRisk, TransactionLog transactionLog, OfflinePinState pin,
            EMVCrypto theCrypto, SecureMessaging secureMessaging,
            DdaCrypto ddaCrypto, PinCrypto pinCrypto) {
        this.staticData = staticData;
        this.protocolState = protocolState;
        this.offlineRisk = offlineRisk;
        this.transactionLog = transactionLog;
        this.pin = pin;
        this.theCrypto = theCrypto;
        this.secureMessaging = secureMessaging;
        this.ddaCrypto = ddaCrypto;
        this.pinCrypto = pinCrypto;
    }

    /**
     * Applies one DGI of the personalization sequence (EMV CPS v2.0 numbering).
     * Called inside a transaction; the applet is not necessarily selected.
     */
    public void applyDgi(short dgi, byte[] buf, short off, short len) {
        switch (dgi) {
        case TlvTags.DGI_FCI_RESPONSE:
            // SELECT response A5 template (EMV CPS v2.0 Annex A DGI '9102'): it must be an A5
            // containing the mandatory Application Label '50' (Table A-14).
            PersoRules.validateFciTemplate(buf, off, len,
                    TlvTags.TAG_APPLICATION_LABEL);
            staticData.setFciOverride(buf, off, len);
            sawFci = true;
            break;
        case TlvTags.DGI_GPO_RESPONSE:
            // GPO response data: 82 AIP / 94 AFL (EMV CPS v2.0 Annex A DGI '9104').
            staticData.applyPaymentConfig(buf, off, len);
            break;
        case TlvTags.DGI_APP_COMMON:
            // 9F36 ATC / 9F4F Log Format (EMV CPS v2.0 Annex A DGI '3000').
            applyAppCommon(buf, off, len);
            break;
        case TlvTags.DGI_APP_INTERNAL:
            // IAC / LCOL / UCOL / IAD and other internal tags (EMV CPS v2.0 Annex A DGI '3001').
            staticData.applyPaymentConfig(buf, off, len);
            configureRiskFromConfig();
            break;
        case TlvTags.DGI_BLOCK_KEYS:
            // CAM (ICC master) key || MAC UDK || ENC UDK (EMV CPS v2.0 Annex A DGI '8000').
            applyBlockKeys(buf, off, len);
            sawKeys = true;
            break;
        case TlvTags.DGI_KCV:
            // Key Check Values: accepted and ignored by the card, but the
            // length must be a well-formed KCV (EMV CPS v2.0 Annex A Table A-3:
            // 3-9 bytes).
            if (len < 3 || len > 9) {
                ISOException.throwIt(SW_WRONG_DATA);
            }
            break;
        case TlvTags.DGI_OFFLINE_PIN:
            // Reference PIN Block, ISO 9564-1 format 1 (EMV CPS v2.0 Annex A
            // Table A-4): '0' || N || BCD digits || 'F' padding, 8 bytes; the
            // 16-byte AES form adds 8 bytes of random padding that the card
            // discards (EMV CPS v2.0 §3.4.4).
            applyReferencePinBlock(buf, off, len);
            sawOfflinePin = true;
            break;
        case TlvTags.DGI_PIN_DATA:
            // PIN Try Counter || PIN Try Limit (EMV CPS v2.0 Annex A DGI '9010').
            // Both are 4-bit values; they configure the persistent PTC/PTL
            // (EMV v4.4 Book 3 Annex C §C10).
            if (len != 2 || (buf[off] & 0xFF) > 15
                    || (buf[(short) (off + 1)] & 0xFF) > 15) {
                ISOException.throwIt(SW_WRONG_DATA);
            }
            pin.configure(buf[off], buf[(short) (off + 1)]);
            break;
        case TlvTags.DGI_ICC_DDA_MODULUS:
            ddaModulusLength = copyKeyPart(buf, off, len, ddaModulus);
            buildDdaKey();
            break;
        case TlvTags.DGI_ICC_DDA_EXPONENT:
            ddaExponentLength = copyKeyPart(buf, off, len, ddaExponent);
            buildDdaKey();
            break;
        case TlvTags.DGI_ICC_PIN_MODULUS:
            pinModulusLength = copyKeyPart(buf, off, len, pinModulus);
            buildPinKey();
            break;
        case TlvTags.DGI_ICC_PIN_EXPONENT:
            pinExponentLength = copyKeyPart(buf, off, len, pinExponent);
            buildPinKey();
            break;
        case TlvTags.DGI_ICC_ECC_KEY:
        case TlvTags.DGI_ICC_ECC_OFFLINE_KEY:
            // XDA/ODE ECC keys are not implemented (docs/specs/emv/personalization.md §3).
            break;
        case TlvTags.DGI_OFFLINE_LIMITS:
            // Cumulative offline amount limits LCOTA/UCOTA (EMV v4.4 Book 3 Annex C §C9.3).
            offlineRisk.setAmountLimits(buf, off, len);
            break;
        case TlvTags.DGI_ALGORITHM:
            // Cryptogram algorithm selection (project DGI 'E003'): 9F69 is the
            // Cryptogram Version ('5' 3DES / '6' AES) and the optional 9F6A the
            // AES key length.  It must precede DGI '8000' so the key length is
            // known when the keys arrive (EMV CPS v2.0 Annex A §A.2).
            applyAlgorithm(buf, off, len);
            break;
        case TlvTags.DGI_COMPLETE:
            // Optional completion data; P1.b8 of the last block is the
            // authoritative signal (EMV CPS v2.0 §3.3).
            break;
        default:
            if (TlvTags.isRecordDgi(dgi)) {
                // EMV CPS v2.0 file record: DGI == (SFI << 8) | record (EMV CPS v2.0 Annex A).
                staticData.setRecord(dgi, buf, off, len);
            } else {
                // Unrecognised DGI: the card must reject it (EMV CPS v2.0 §5.4.2.3).
                ISOException.throwIt(EMVStatus.SW_REFERENCED_DATA_NOT_FOUND); // 6A88
            }
            break;
        }
    }

    /**
     * Applies a Reference PIN Block (EMV CPS v2.0 Annex A Table A-4, ISO 9564-1
     * format 1): control nibble 0, N = 4..12, BCD digits padded with 'F'.  The
     * length is 8 bytes, or 16 for the AES form (8-byte PIN block + 8 bytes of
     * random padding); the random padding is discarded by only storing the BCD
     * digits (EMV CPS v2.0 §3.4.4).
     */
    private void applyReferencePinBlock(byte[] buf, short off, short len) {
        if (len != 8 && len != 16) {
            ISOException.throwIt(SW_WRONG_DATA);
        }
        byte first = buf[off];
        short control = (short) ((first >> 4) & 0x0F);
        short digits = (short) (first & 0x0F);
        if (control != 0 || digits < 4 || digits > 12) {
            ISOException.throwIt(SW_WRONG_DATA);
        }
        short byteCount = (short) ((short) (digits + 1) >> 1);
        if ((digits & 1) != 0
                && (buf[(short) (off + byteCount)] & 0x0F) != 0x0F) {
            ISOException.throwIt(SW_WRONG_DATA); // bad 'F' pad nibble
        }
        pin.update(buf, (short) (off + 1), (byte) byteCount);
    }

    /** Configures the log format and consecutive offline limits from 3001. */
    private void configureRiskFromConfig() {        transactionLog.setFormat(staticData.getLogFormat(), (short) 0,
                staticData.getLogFormatLength());
        if (staticData.hasLcol() || staticData.hasUcol()) {
            offlineRisk.setCountLimits(
                    staticData.hasLcol() ? staticData.getLcol() : (byte) 0,
                    staticData.hasUcol() ? staticData.getUcol() : (byte) 0);
        }
    }

    /** Parses the EMV CPS v2.0 Annex A DGI '3000' common internal data (9F36 ATC, 9F4F Log Format). */
    private void applyAppCommon(byte[] buf, short off, short len) {
        // Store 9F4F in the static data (applyPaymentConfig handles it) so a
        // later DGI '3001' does not overwrite it with the default when it
        // (re)applies the log format (EMV CPS v2.0 Annex A Table A-17).
        staticData.applyPaymentConfig(buf, off, len);
        TlvReader reader = new TlvReader(buf, off, len);
        while (reader.hasNext()) {
            reader.next();
            if (reader.tag() == TlvTags.TAG_ATC) {
                if (reader.valueLength() != 2) {
                    // ATC is 2 bytes (EMV CPS v2.0 Annex A Table A-17).
                    ISOException.throwIt(SW_WRONG_DATA);
                }
                protocolState.setATC((short) (((buf[reader.valueOffset()] & 0xFF) << 8)
                        | (buf[(short) (reader.valueOffset() + 1)] & 0xFF)));
            }
        }
        configureRiskFromConfig();
    }

    /**
     * Parses the EMV CPS v2.0 Annex A DGI '8000' block-cipher key container: CAM (ICC master) key
     * followed by the optional MAC and Encipherment UDKs.  The key length per
     * unit follows the selected profile: 16 bytes for the 3DES profile and for
     * AES-128 (the only AES length available on the simulator, EMV CPS v2.0 §A.2).
     */
    private void applyBlockKeys(byte[] buf, short off, short len) {
        short unit = theCrypto.getProfile().getKeyLength();
        if (len != unit && len != (short) (2 * unit) && len != (short) (3 * unit)) {
            ISOException.throwIt(SW_WRONG_DATA);
        }
        theCrypto.setMasterKey(buf, off, unit);
        if (len >= (short) (2 * unit)) {
            secureMessaging.setMacMasterKey(buf, (short) (off + unit), unit);
        }
        if (len >= (short) (3 * unit)) {
            secureMessaging.setEncMasterKey(buf, (short) (off + 2 * unit), unit);
        }
    }

    /**
     * Applies the project DGI 'E003' algorithm selection: tag 9F69 carries the
     * Cryptogram Version and the optional tag 9F6A the AES key length in bytes.
     * The CCI byte of the IAD is updated to match.
     */
    private void applyAlgorithm(byte[] buf, short off, short len) {
        if (sawKeys) {
            // Project DGI 'E003' must precede DGI '8000': once the keys have
            // arrived the profile (and therefore the key length) is fixed, so a
            // later algorithm change cannot be honoured
            // (docs/specs/emv/personalization.md §3).
            ISOException.throwIt(SW_WRONG_DATA);
        }
        TlvReader reader = new TlvReader(buf, off, len);
        byte cv = CryptoProfile.CV5;
        short keyLength = (short) 16;
        while (reader.hasNext()) {
            reader.next();
            if (reader.tag() == TlvTags.TAG_CRYPTOGRAM_VERSION) {
                if (reader.valueLength() != 1) {
                    ISOException.throwIt(SW_WRONG_DATA);
                }
                cv = buf[reader.valueOffset()];
            } else if (reader.tag() == TlvTags.TAG_AES_KEY_LENGTH) {
                if (reader.valueLength() != 1) {
                    ISOException.throwIt(SW_WRONG_DATA);
                }
                keyLength = (short) (buf[reader.valueOffset()] & 0xFF);
            }
        }
        if (cv != CryptoProfile.CV5 && cv != CryptoProfile.CV6) {
            ISOException.throwIt(SW_WRONG_DATA);
        }
        if (keyLength != 16) {
            // Only AES-128 is available on the simulator (docs/specs/common/cryptography.md §1);
            // EMV CPS v2.0 §A.2 defines AES-128/256, and the 256-bit form is out of
            // scope here.
            ISOException.throwIt(SW_WRONG_DATA);
        }
        theCrypto.selectAlgorithm(cv);
        staticData.setCryptogramVersion(cv);
    }

    /** Copies one RSA key part, rejecting an overlong value with 6A80. */
    private static short copyKeyPart(byte[] buf, short off, short len, byte[] dst) {
        if (len < 1 || len > dst.length) {
            ISOException.throwIt(SW_WRONG_DATA);
        }
        Util.arrayCopyNonAtomic(buf, off, dst, (short) 0, len);
        return len;
    }

    /** Builds the ICC DDA/CDA key once its modulus and exponent are present. */
    private void buildDdaKey() {
        if (ddaModulusLength == 0 || ddaExponentLength == 0) {
            return;
        }
        short p = buildKeyContainer(ddaModulus, ddaModulusLength,
                ddaExponent, ddaExponentLength);
        ddaCrypto.setPrivateKey(keyContainer, (short) 0, p);
        ddaModulusLength = 0;
        ddaExponentLength = 0;
    }

    /** Builds the ICC PIN encipherment key once modulus and exponent arrive. */
    private void buildPinKey() {
        if (pinModulusLength == 0 || pinExponentLength == 0) {
            return;
        }
        short p = buildKeyContainer(pinModulus, pinModulusLength,
                pinExponent, pinExponentLength);
        pinCrypto.setPrivateKey(keyContainer, (short) 0, p);
        pinModulusLength = 0;
        pinExponentLength = 0;
    }

    /** Assembles the RsaKey container 86 n 87 d into keyContainer. */
    private short buildKeyContainer(byte[] n, short nLen, byte[] d, short dLen) {
        short p = 0;
        keyContainer[p++] = (byte) 0x86;
        p = Tlv.appendLength(nLen, keyContainer, p);
        Util.arrayCopyNonAtomic(n, (short) 0, keyContainer, p, nLen);
        p += nLen;
        keyContainer[p++] = (byte) 0x87;
        p = Tlv.appendLength(dLen, keyContainer, p);
        Util.arrayCopyNonAtomic(d, (short) 0, keyContainer, p, dLen);
        p += dLen;
        return p;
    }

    /**
     * True once the mandatory EMV CPS v2.0 DGIs were received.  Completion itself is
     * signalled by P1.b8 of the last STORE DATA block; the optional '7FFF'
     * DGI does not affect the decision (EMV CPS v2.0 §3.3).
     */
    public boolean isComplete() {
        return sawKeys && sawOfflinePin && sawFci && staticData.hasMandatoryRecord1();
    }

    /**
     * Clears the completion markers and any partially received key parts when a
     * new personalization sequence starts or a sequence fails (see
     * PersoHandler).  Without this a partially applied sequence could leave a
     * stale marker set and an incomplete retry could be judged complete.
     */
    public void resetState() {
        sawKeys = false;
        sawFci = false;
        sawOfflinePin = false;
        ddaModulusLength = 0;
        ddaExponentLength = 0;
        pinModulusLength = 0;
        pinExponentLength = 0;
    }
}
