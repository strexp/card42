package card42.emv;

import card42.common.*;

import javacard.framework.APDU;
import javacard.framework.ISOException;
import javacard.framework.Util;
import javacard.security.RandomData;

/* A very basic EMV payment applet supporting SDA, DDA and CDA offline data
 * authentication, offline PIN (plaintext and enciphered), issuer authentication,
 * EMV secure messaging and issuer scripts (EMV v4.4 Book 2/EMV v4.4 Book 3).
 *
 * SELECT/FCI, command dispatch, the shared objects and personalization live in
 * EMVAppletBase; this class is the payment command entry point.  The command
 * families live in focused handlers: the offline PIN in OfflinePin, the
 * cryptogram path in AcProcessor, DDA/CDA signing in DynamicAuth, issuer
 * authentication in IssuerAuth, post-issuance commands in PostIssuance and the
 * personalization DGI application in PaymentPerso.
 *
 * The role is fixed by the instance AID (docs/specs/common/architecture.md §4): a CONTACT
 * instance enables the plaintext offline PIN; a CONTACTLESS instance advertises
 * no CVM and answers VERIFY with 6985.  Payment commands are only served once
 * personalization has completed (lifecycle READY, docs/specs/common/architecture.md §3).
 *
 * @author joeri (joeri@cs.ru.nl)
 * @author erikpoll (erikpoll@cs.ru.nl)
 * @author card42
 */
public class PaymentApplet extends EMVAppletBase {

    /* Transient byte array for constructing APDU responses (docs/specs/common/architecture.md §2). */
    private final byte[] response;

    final OfflinePinState pin;
    final RandomData randomData;
    final EMVCrypto theCrypto;
    final EMVStaticData staticData;
    final PinCrypto pinCrypto;
    final DdaCrypto ddaCrypto;
    final SecureMessaging secureMessaging;
    final TransactionLog transactionLog;
    final OfflineRisk offlineRisk;

    private final OfflinePin offlinePin;
    private final DynamicAuth dynamicAuth;
    private final IssuerAuth issuerAuth;
    private final AcProcessor acProcessor;
    private final PostIssuance postIssuance;
    private final PaymentPerso perso;

    private PaymentApplet() {
        super();

        // Short-APDU response buffer, shared by every instance of this package
        // (transient, CLEAR_ON_DESELECT); it is allocated once at install, not
        // per instance and never during a command.  A full 256 bytes covers the
        // 254-byte EMV record limit (EMV v4.4 Book 3 §7) as well as an RSA-2048
        // CDA SDAD (docs/specs/common/risks.md).
        response = EmvScratch.response;

        // Offline PIN: BCD, up to 8 bytes; the length is taken from the APDU
        // (docs/specs/common/architecture.md §4).  Default "1234".  This is the EMV transaction
        // PIN (VERIFY P2=80).
        pin = new OfflinePinState((byte) 3, (byte) 8);
        pin.update(new byte[] { (byte) 0x12, (byte) 0x34 }, (short) 0, (byte) 2);
        randomData = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);

        staticData = new EMVStaticData();
        theCrypto = new EMVCrypto(protocolState, staticData);
        pinCrypto = new PinCrypto();
        ddaCrypto = new DdaCrypto();
        secureMessaging = new SecureMessaging(protocolState, theCrypto.getProfile(),
                theCrypto.getRetailMac(), theCrypto.getAesCmac(),
                theCrypto.getSessionKeyDerivation());
        transactionLog = new TransactionLog();
        offlineRisk = new OfflineRisk();

        offlinePin = new OfflinePin(pin, pinCrypto, protocolState);
        dynamicAuth = new DynamicAuth(staticData, protocolState, ddaCrypto, randomData);
        issuerAuth = new IssuerAuth(this, staticData, protocolState, offlineRisk, pin,
                new Arpc(theCrypto, protocolState));
        acProcessor = new AcProcessor(protocolState, staticData, theCrypto, ddaCrypto,
                offlineRisk, transactionLog, secureMessaging, pin, dynamicAuth, issuerAuth);
        postIssuance = new PostIssuance(this, protocolState, secureMessaging, pin);
        perso = new PaymentPerso(staticData, protocolState, offlineRisk, transactionLog,
                pin, theCrypto, secureMessaging, ddaCrypto, pinCrypto);
    }

    /**
     * Installs an instance of the applet.
     * 
     * @see javacard.framework.Applet#install(byte[], byte, byte)
     */
    public static void install(byte[] buffer, short offset, byte length) {
        PaymentApplet applet = new PaymentApplet();
        // Register under the instance AID from the install parameters (Java Card
        // 3.0.5 JCRE §11.2.1).  The no-arg register() would use the CAP applet (class) AID
        // instead, which would break the multi-instance deployment (docs/specs/common/architecture.md §1).
        applet.register(buffer, (short) (offset + 1), buffer[offset]);
        applet.captureInstallParameters(buffer, offset, length);
    }

    /**
     * Determines the payment role from the instance AID (docs/specs/common/architecture.md §1),
     * falling back to the applet data in the install parameters.
     */
    protected void initRole() {
        byte role;
        byte[] aid;
        if (instanceAidEquals(EMVAids.PAYMENT_CONTACTLESS)) {
            role = EMVRoles.ROLE_CONTACTLESS;
            aid = EMVAids.PAYMENT_CONTACTLESS;
        } else if (instanceAidEquals(EMVAids.PAYMENT_CONTACT)) {
            role = EMVRoles.ROLE_CONTACT;
            aid = EMVAids.PAYMENT_CONTACT;
        } else {
            role = roleFromInstallData(EMVRoles.ROLE_CONTACT, EMVRoles.ROLE_CONTACT,
                    EMVRoles.ROLE_CONTACTLESS, EMVRoles.ROLE_CONTACTLESS, EMVRoles.ROLE_CONTACT);
            aid = role == EMVRoles.ROLE_CONTACTLESS ? EMVAids.PAYMENT_CONTACTLESS
                    : EMVAids.PAYMENT_CONTACT;
        }
        protocolState.setRole(role);
        staticData.setAid(aid);
    }

    protected byte[] getFCI() {
        return staticData.getFCI(protocolState.getRole());
    }

    /**
     * Resets the per-session secure-messaging script state (CVR byte 4 b8-b5)
     * so a transaction that runs no issuer script does not report the previous
     * transaction's count in its first GENERATE AC (EMV v4.4 Book 3 §9.2.3.2).
     */
    protected void onNewSession() {
        secureMessaging.startNewTransaction();
    }

    /**
     * Zeroizes session-derived secret material on deselection: the AC session
     * keys and MAC subkeys (EMV v4.4 Book 2 §A1.2.2) and the secure-messaging
     * session keys.  The ICC master keys and the personalized secure-messaging
     * master keys persist.
     */
    @Override
    protected void onDeselect() {
        theCrypto.zeroizeSessionKeys();
        secureMessaging.zeroizeSessionKeys();
    }

    protected short getFCILength() {
        return staticData.getFCILength(protocolState.getRole());
    }

    /**
     * Handles the payment command set.
     * 
     * @see card42.EMVAppletBase#processCommand(javacard.framework.APDU, byte[])
     */
    protected void processCommand(APDU apdu, byte[] apduBuffer) {
        byte ins = apduBuffer[OFFSET_INS];
        byte lifecycle = protocolState.getLifecycle();

        // CARD BLOCK disables every application; no command is served except a
        // repeated CARD BLOCK, which reports 9000 whether the card was already
        // blocked or not (EMV v4.4 Book 3 §6.5.3.1, §6.5.3.5).
        if ((lifecycle == EMVRoles.CARD_BLOCKED || isCardBlocked()) && ins != EMVCommands.INS_CARD_BLOCK) {
            ISOException.throwIt(SW_FUNC_NOT_SUPPORTED); // 6A81
        }

        // ISO/IEC 7816-4 command chaining (EMV v4.4 Book 3 §6.5.13): only
        // VERIFY and PIN CHANGE/UNBLOCK may be chained.  CLA b5=1 marks a
        // command that is not the last of a chain.
        boolean chained = (apduBuffer[OFFSET_CLA] & 0x10) != 0;
        boolean chainable = ins == EMVCommands.INS_VERIFY || ins == EMVCommands.INS_PIN_CHANGE_UNBLOCK;
        if (protocolState.isChainActive()) {
            // The card expects the last command of the chain: only a
            // continuation of the same chainable command is accepted, anything
            // else means the last command was not received (6883).
            if (!chainable || ins != protocolState.getChainIns()) {
                protocolState.resetChain();
                ISOException.throwIt(SW_LAST_COMMAND_EXPECTED); // 6883
            }
        } else if (chained && !chainable) {
            // Chaining is not supported for any other command (6884).
            ISOException.throwIt(SW_COMMAND_CHAINING_NOT_SUPPORTED); // 6884
        }

        // A GET CHALLENGE challenge is valid only for the next issued command
        // (EMV v4.4 Book 3 §6.5.6.1).  The only command that may consume it is a
        // single (non-chained) VERIFY; every other command -- including a
        // non-final chained VERIFY fragment, which does not perform the PIN
        // check -- invalidates it.  GET CHALLENGE itself issues a new one.
        boolean consumesChallenge = ins == EMVCommands.INS_VERIFY && !chained
                && !protocolState.isChainActive();
        if (ins != EMVCommands.INS_GET_CHALLENGE && !consumesChallenge) {
            protocolState.clearChallengeValid();
        }

        // GET DATA (ATC, PIN counters) is available during personalization too.
        if (ins == EMVCommands.INS_GET_DATA) {
            getData(apdu, apduBuffer);
            return;
        }
        // VERIFY P2=80 is the offline PIN (plaintext), P2=88 the enciphered
        // offline PIN; both are handled by OfflinePin.
        if (ins == EMVCommands.INS_VERIFY) {
            verify(apdu, apduBuffer, response, chained);
            return;
        }

        // Every other payment command requires a personalized (READY) card
        // (docs/specs/common/architecture.md §3).  An invalidated application (BLOCKED) still
        // serves them, but GENERATE AC is forced to AAC below (EMV v4.4 Book 2 Annex D3).
        if (lifecycle == EMVRoles.PERSONALISATION) {
            ISOException.throwIt(SW_CONDITIONS_NOT_SATISFIED); // 6985
        }

        switch (ins) {

        case EMVCommands.INS_GET_CHALLENGE: // 0x84
            getChallenge(apdu, apduBuffer);
            break;

        case EMVCommands.INS_READ_RECORD: // 0xB2
            readRecord(apdu, apduBuffer);
            break;

        case EMVCommands.INS_GET_PROCESSING_OPTIONS: // 0xA8
            getProcessingOptions(apdu, apduBuffer);
            break;

        case EMVCommands.INS_INTERNAL_AUTHENTICATE: // 0x88
            dynamicAuth.internalAuthenticate(apdu, apduBuffer, response);
            break;

        case EMVCommands.INS_GENERATE_AC: // 0xAE
            // P2 is fixed to 00 (EMV v4.4 Book 3 Table 11).
            if (apduBuffer[OFFSET_P2] != 0x00) {
                ISOException.throwIt(SW_FUNC_NOT_SUPPORTED); // 6A81
            }
            // get remaining data
            short len = (short) (apduBuffer[OFFSET_LC] & 0xFF);
            if (len != apdu.setIncomingAndReceive()) {
                ISOException.throwIt(SW_WRONG_LENGTH);
            }
            if (protocolState.getFirstACGenerated() == EMVCodes.NONE) {
                // The command data must be exactly the CDOL1-related data
                // (EMV v4.4 Book 3 §6.5.5.3).
                if (len != staticData.getCDOL1DataLength()) {
                    ISOException.throwIt(SW_WRONG_LENGTH);
                }
                acProcessor.generateFirstAC(apdu, apduBuffer, response);
            } else if (protocolState.getSecondACGenerated() == EMVCodes.NONE) {
                if (len != staticData.getCDOL2DataLength()) {
                    ISOException.throwIt(SW_WRONG_LENGTH);
                }
                acProcessor.generateSecondAC(apdu, apduBuffer, response);
            } else
                // At most two GENERATE AC per transaction; the third and later
                // return 6985 and no cryptogram (EMV v4.4 Book 3 section 9.3.2).
                ISOException.throwIt(SW_CONDITIONS_NOT_SATISFIED);
            break;

        case INS_EXTERNAL_AUTHENTICATE: // 0x82
            issuerAuth.externalAuthenticate(apdu, apduBuffer,
                    acProcessor.getFirstCdol(), acProcessor.getFirstCdolLength());
            break;

        // post-issuance commands, protected by EMV secure messaging
        // (EMV v4.4 Book 2 §9.2, EMV v4.4 Book 3 §10.10)
        case EMVCommands.INS_APPLICATION_BLOCK:
        case EMVCommands.INS_APPLICATION_UNBLOCK:
        case EMVCommands.INS_CARD_BLOCK:
        case EMVCommands.INS_PIN_CHANGE_UNBLOCK:
            dispatchPostIssuance(apdu, apduBuffer, ins, chained);
            break;

        default:
            ISOException.throwIt(SW_INS_NOT_SUPPORTED);
            break;
        }
    }

    /**
     * Handles a VERIFY, including its command chain (EMV v4.4 Book 3 §6.5.13).
     * The command data of the non-final fragments (CLA b5=1) is accumulated and
     * answered with 9000; the last fragment runs the PIN check.  A GET CHALLENGE
     * challenge is valid only for the next command (EMV v4.4 Book 3 §6.5.6.1),
     * so a non-final fragment invalidates it and an enciphered PIN cannot be
     * chained.  A chained VERIFY whose accumulation fails is reported as 6800
     * (EMV v4.4 Book 3 §6.5.12.5).
     */
    private void verify(APDU apdu, byte[] apduBuffer, byte[] response, boolean chained) {
        try {
            short lc = ApduIo.receive(apdu, apduBuffer);
            // Reject a bad fragment before it is accumulated (EMV v4.4 Book 3 Table 23/24).
            offlinePin.check(apduBuffer);

            boolean continuation = protocolState.isChainActive();
            if (!continuation && !chained) {
                // A single (non-chained) VERIFY: process it directly.
                offlinePin.verify(apdu, apduBuffer, response, apduBuffer,
                        OFFSET_CDATA, lc);
                return;
            }

            if (!continuation) {
                protocolState.startChain(EMVCommands.INS_VERIFY);
            }
            if (!protocolState.appendChain(apduBuffer, OFFSET_CDATA, lc)) {
                protocolState.resetChain();
                ISOException.throwIt(EMVStatus.SW_COMMAND_CHAINING_FAILED); // 6800
            }
            if (chained) {
                // Not the last command of the chain: completed so far.
                apdu.setOutgoingAndSend((short) 0, (short) 0); // 9000
                return;
            }
            // Last fragment: run the PIN check over the accumulated data.
            byte[] data = protocolState.getChainData();
            short length = protocolState.getChainLength();
            protocolState.resetChain();
            offlinePin.verify(apdu, apduBuffer, response, data, (short) 0, length);
        } catch (ISOException e) {
            // A failed fragment aborts the chain: the terminal must not send
            // the remainder after a non-9000 response (EMV v4.4 Book 3 §6.5.12.5).
            protocolState.resetChain();
            throw e;
        }
    }

    /**
     * Runs a post-issuance command, applying the chain semantics of
     * PIN CHANGE/UNBLOCK: a non-final fragment (CLA b5=1) is unwrapped and
     * verified but the state change is deferred to the last command
     * (EMV v4.4 Book 3 §6.5.13).
     */
    private void dispatchPostIssuance(APDU apdu, byte[] apduBuffer, byte ins, boolean chained) {
        boolean continuation = protocolState.isChainActive();
        try {
            postIssuance.postIssuance(apdu, apduBuffer, ins, response, chained);
        } catch (ISOException e) {
            protocolState.resetChain();
            throw e;
        }
        if (chained) {
            if (!continuation) {
                protocolState.startChain(ins);
            }
        } else {
            protocolState.resetChain();
        }
    }

    /*
     * The GET CHALLENGE command generates an 8 byte unpredictable number.
     */
    private void getChallenge(APDU apdu, byte[] apduBuffer) {
        // P1 and P2 are fixed to 00 (EMV v4.4 Book 3 Table 16).
        if (apduBuffer[OFFSET_P1] != 0x00 || apduBuffer[OFFSET_P2] != 0x00) {
            ISOException.throwIt(SW_FUNC_NOT_SUPPORTED); // 6A81
        }
        randomData.generateData(apduBuffer, (short) 0, (short) 8);
        // Keep the ICC Unpredictable Number of the session so an enciphered
        // offline PIN can be bound to it (EMV v4.4 Book 2 §7.2 step 2/7).
        protocolState.setChallenge(apduBuffer, (short) 0);
        apdu.setOutgoingAndSend((short) 0, (short) 8);
    }

    /*
     * The GET DATA command is used to retrieve a primitive data object not
     * encapsulated in a record within the current application.
     *
     * The usage of GET DATA in this implementation is limited to the ATC,
     * the PIN Try Counter, and the last online ATC (which stays 0 until
     * written online; docs/specs/emv/personalization.md §6).
     */
    private void getData(APDU apdu, byte[] apduBuffer) {
        /*
         * buffer[OFFSET_P1..OFFSET_P2] should contains of the following tags
         *  9F36 - ATC 
         *  9F17 - PIN Try Counter 
         *  9F13 - Last online ATC 
         *  9F4F - Log Format
         */
        if (apduBuffer[OFFSET_P1] != (byte) 0x9F) {
            // Anything but a 9Fxx tag is a wrong P1/P2 / unsupported function
            // (EMV v4.4 Book 3 Table 4/5).
            ISOException.throwIt(SW_FUNC_NOT_SUPPORTED); // 6A81
        }
        // The tag is already in apduBuffer[OFFSET_P1..OFFSET_P2]; only the
        // length and value are written after it and sent from OFFSET_P1.
        switch (apduBuffer[OFFSET_P2]) {
        case 0x36: // ATC
            apduBuffer[OFFSET_P2 + 1] = (byte) 0x02; // length 2 bytes
            Util.setShort(apduBuffer, (short) (OFFSET_P2 + 2), protocolState.getATC()); // value
            // send the 5 byte long TLV for ATC
            apdu.setOutgoingAndSend(OFFSET_P1, (short) 5);
            break;

        case 0x17: // PIN Try Counter
            apduBuffer[OFFSET_P2 + 1] = (byte) 0x01; // length 1 byte
            apduBuffer[OFFSET_P2 + 2] = pin.getTriesRemaining(); // value
            // send the 4 byte TLV for PIN Try counter
            apdu.setOutgoingAndSend(OFFSET_P1, (short) 4);
            break;

        case 0x13: // Last online ATC
            apduBuffer[OFFSET_P2 + 1] = (byte) 0x02; // length 2 bytes
            Util.setShort(apduBuffer, (short) (OFFSET_P2 + 2), protocolState.getLastOnlineATC()); // value
            // send the 5 byte long TLV for last online ATC
            apdu.setOutgoingAndSend(OFFSET_P1, (short) 5);
            break;

        case 0x4F: // Log Format (EMV v4.4 Book 3 Annex D4)
            // The Log Format is a plain list of (tag, length) entries; it is
            // returned with the 9F4F tag and BER length like the other objects.
            // The length is encoded in the short form below; the format buffer
            // is capped at 32 bytes (TransactionLog.setFormat), so this can
            // never overflow, but guard it explicitly anyway.
            short formatLength = transactionLog.getFormatLength();
            if (formatLength > 127) {
                ISOException.throwIt(SW_WRONG_LENGTH);
            }
            apduBuffer[OFFSET_P2 + 1] = (byte) formatLength;
            Util.arrayCopyNonAtomic(transactionLog.getFormat(), (short) 0,
                    apduBuffer, (short) (OFFSET_P2 + 2), formatLength);
            apdu.setOutgoingAndSend(OFFSET_P1, (short) (3 + formatLength));
            break;

        default:
            ISOException.throwIt(EMVStatus.SW_REFERENCED_DATA_NOT_FOUND); // 6A88
            break;
        }
    }    private void readRecord(APDU apdu, byte[] apduBuffer) {
        // P2 b3-b1 must be 100 (EMV v4.4 Book 3 Table 22 / EMV v4.4 Book 1 Table 4); other values are RFU.
        if ((apduBuffer[OFFSET_P2] & 0x07) != 0x04) {
            ISOException.throwIt(SW_FUNC_NOT_SUPPORTED); // 6A81
        }
        short sfi = (short) ((apduBuffer[OFFSET_P2] & 0xFF) >> 3);
        if (sfi == TransactionLog.SFI) {
            // The cyclic transaction log (EMV v4.4 Book 3 Annex D4): it is not in
            // the AFL and its records carry no '70' template.  A record number
            // beyond the stored entries is a missing record (6A83).
            short rec = (short) (apduBuffer[OFFSET_P1] & 0xFF);
            short logLength = transactionLog.readRecord(rec, response, (short) 0);
            if (logLength < 0) {
                ISOException.throwIt(SW_RECORD_NOT_FOUND); // 6A83
            }
            ApduIo.send(apdu, response, (short) 0, logLength);
            return;
        }

        // A stored record whose '70' length is already exact is served straight
        // from the persistent pool, saving the transient response copy; a
        // placeholder length or a built-in default goes through the response
        // buffer, where the length is normalised (EMV v4.4 Book 3 §7.1).
        RecordBuilder.View direct = staticData.directRecord(apduBuffer);
        if (direct != null) {
            ApduIo.send(apdu, direct.pool, direct.offset, direct.length);
            return;
        }

        staticData.readRecord(apduBuffer, response, protocolState.getRole());

        // The length is taken from the 70 template itself, so a long-form
        // length would be handled too (docs/specs/emv/personalization.md §3).
        short length = Tlv.totalLength(response, (short) 0);
        ApduIo.send(apdu, response, (short) 0, length);
    }

    private void getProcessingOptions(APDU apdu, byte[] apduBuffer) {
        // P1 and P2 are fixed to 00 (EMV v4.4 Book 3 Table 18).
        if (apduBuffer[OFFSET_P1] != 0x00 || apduBuffer[OFFSET_P2] != 0x00) {
            ISOException.throwIt(SW_FUNC_NOT_SUPPORTED); // 6A81
        }

        short lc = ApduIo.receive(apdu, apduBuffer);

        // The command data is the PDOL-related data introduced by tag '83'
        // (EMV v4.4 Book 3 section 6.5.8.3).  Without a PDOL the terminal still sends
        // '83 00'; a missing command data field is a wrong-length condition.
        short pdolDataOffset = OFFSET_CDATA;
        short pdolDataLength = 0;
        if (lc == 0) {
            ISOException.throwIt(SW_WRONG_LENGTH); // 6700: no '83' template
        }
        if (lc < 2 || apduBuffer[OFFSET_CDATA] != (byte) TlvTags.TAG_COMMAND_TEMPLATE) {
            ISOException.throwIt(SW_WRONG_DATA); // missing '83' template
        }
        short lengthField = Tlv.lengthFieldLength(apduBuffer,
                (short) (OFFSET_CDATA + 1));
        if (lengthField == 0) {
            ISOException.throwIt(SW_WRONG_DATA);
        }
        pdolDataLength = Tlv.getLength(apduBuffer, (short) (OFFSET_CDATA + 1));
        pdolDataOffset = (short) (OFFSET_CDATA + 1 + lengthField);
        if ((short) (pdolDataOffset + pdolDataLength) != (short) (OFFSET_CDATA + lc)) {
            // Bytes after the '83' value are a wrong-data condition
            // (EMV v4.4 Book 3 §6.5.8.3).
            ISOException.throwIt(SW_WRONG_DATA);
        }

        // The value length must match the personalised PDOL exactly (EMV v4.4 Book 3 §6.5.8): a
        // mismatch is a wrong-length condition, a malformed template a
        // wrong-data condition.
        short expectedPdol = staticData.getPdolDataLength();
        if (pdolDataLength != expectedPdol) {
            ISOException.throwIt(SW_WRONG_LENGTH); // 6700
        }
        if (!protocolState.pdolFits(expectedPdol)) {
            // The PDOL expands beyond the on-card session buffer: refuse the
            // command instead of overrunning it (docs/specs/common/toolchain.md §6).
            ISOException.throwIt(SW_CONDITIONS_NOT_SATISFIED); // 6985
        }
        protocolState.setPdolData(apduBuffer, pdolDataOffset, pdolDataLength);

        // EMV v4.4 Book 2 Annex D3: the ATC is advanced exactly
        // once per transaction, during a successful GET PROCESSING OPTIONS,
        // not on SELECT.  Reaching 0xFFFF invalidates the application.  A
        // rejected GPO above must not consume an ATC value.
        if (!protocolState.isGpoDone()) {
            protocolState.setGpoDone();
            protocolState.advanceATC();
        }

        // The response is built from the AIP/AFL (EMV CPS v2.0 Annex A DGI '9104' or structured).
        byte[] gpo = staticData.getGpo(protocolState.getRole());
        short length = staticData.getGpoLength(protocolState.getRole());

        ApduIo.send(apdu, gpo, (short) 0, length);
    }

    // --- Personalization (EMV CPS v2.0 Annex A, docs/specs/emv/personalization.md §1)

    /**
     * Applies one DGI of the personalization sequence (EMV CPS v2.0 numbering).
     * Called inside a transaction; the applet is not necessarily selected.
     */
    protected void applyPersoDgi(short dgi, byte[] buf, short off, short len) {
        perso.applyDgi(dgi, buf, off, len);
    }

    /**
     * True once the mandatory EMV CPS v2.0 DGIs were received.  Completion itself is
     * signalled by P1.b8 of the last STORE DATA block; the optional '7FFF'
     * DGI does not affect the decision (EMV CPS v2.0 §3.3).
     */
    protected boolean persoCheckComplete() {
        return perso.isComplete();
    }

    /** Clears the payment personalization completion markers (see PersoHandler). */
    protected void resetPersoState() {
        perso.resetState();
    }
}
