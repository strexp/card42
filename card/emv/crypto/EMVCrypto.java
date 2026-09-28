package card42.emv;

import card42.common.*;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.DESKey;
import javacard.security.KeyBuilder;

/* Computes the Application Cryptograms of a payment instance (EMV v4.4 Book 2
 * §8.1.2, Common Core Definitions).
 *
 * The AC is an ISO/IEC 9797-1 MAC over the terminal CDOL data, the AIP, the ATC
 * and the IAD, keyed with the AC session key.  The algorithm follows the
 * Cryptogram Version of the profile (CryptoProfile):
 *
 *   CV '5' -> Algorithm 3 with Triple DES, s = 8
 *   CV '6' -> Algorithm 5 (CMAC) with AES, s = 8
 *
 * The session key is derived once per transaction from the ICC master key and
 * the ATC (EMV v4.4 Book 2 Annex A1.3.1); the ARPC verification that uses the
 * same key lives in Arpc, and the response framing in AcResponseBuilder.
 *
 * The ICC master key is replaced by personalization (EMV CPS v2.0 Annex A
 * §A.2).  The protocol state and the static data are injected as constructor
 * parameters so this class does not depend back on PaymentApplet
 * (docs/specs/common/architecture.md §2).
 *
 * @author joeri (joeri@cs.ru.nl)
 * @author erikpoll (erikpoll@cs.ru.nl)
 * @author card42
 */

public class EMVCrypto implements ISO7816 {

	/* The session state and the AIP provider (docs/specs/common/architecture.md §2). */
	private final EMVProtocolState protocolState;
	private final EMVStaticData staticData;

	/** The CV '5' / CV '6' selection shared with the secure messaging. */
	private final CryptoProfile profile;

	/** Session key bytes: 16 for 3DES, 16/32 for AES. */
	private final byte[] sessionkey;

	/** 3DESKey ICC Master Key, shared with the bank. */
	private final DESKey mkDes;
	/** AES ICC Master Key (128-bit), shared with the bank. */
	private final AESKey mkAes;

	/** 3DES/AES session key objects. */
	private final DESKey skDes;
	private final AESKey skAes;

	/** ISO/IEC 9797-1 algorithm 3 (CV '5', EMV v4.4 Book 2 §8.1.2). */
	private final RetailMac retailMac;
	/** ISO/IEC 9797-1 algorithm 5 / CMAC (CV '6', EMV v4.4 Book 2 §8.1.2). */
	private final AesCmac aesCmac;

	/** Shared session-key derivation (EMV v4.4 Book 2 §8.2, §9.2/§9.3). */
	private final SessionKey sessionKeyDerivation;

	/**
	 * Small transient scratch: the 2-byte AIP and 2-byte ATC fed into the AC
	 * MAC.  The AC input is streamed so no 256-byte CDOL buffer is needed
	 * (EMV v4.4 Book 2 §6.6.1).
	 */
	private final byte[] scratch;

	/** Full MAC block of the last AC (8 for 3DES, 16 for AES) and the ARQC stash. */
	private final byte[] lastAc;

	public EMVCrypto(EMVProtocolState protocolState, EMVStaticData staticData) {
		this.protocolState = protocolState;
		this.staticData = staticData;
		this.profile = new CryptoProfile();

		// Package-shared transient buffers, allocated once at install (see
		// EmvScratch): no command path allocates a transient array.
		EmvScratch.init();
		sessionkey = EmvScratch.sessionKey;
		scratch = EmvScratch.acScratch;
		lastAc = EmvScratch.lastAc;

		retailMac = new RetailMac();
		aesCmac = new AesCmac();
		sessionKeyDerivation = new SessionKey();

		mkDes = (DESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_DES,
				KeyBuilder.LENGTH_DES3_2KEY, false);
		mkDes.setKey(new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
				0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16 },
				(short) 0);
		skDes = (DESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_DES,
				KeyBuilder.LENGTH_DES3_2KEY, false);

		mkAes = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES,
				KeyBuilder.LENGTH_AES_128, false);
		skAes = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES,
				KeyBuilder.LENGTH_AES_128, false);
	}

	/** The cryptogram profile shared with the secure messaging and the ARPC. */
	public CryptoProfile getProfile() {
		return profile;
	}

	/** The 3DES MAC (CV '5') shared with the ARPC and the secure messaging. */
	RetailMac getRetailMac() {
		return retailMac;
	}

	/** The AES CMAC (CV '6') shared with the ARPC and the secure messaging. */
	AesCmac getAesCmac() {
		return aesCmac;
	}

	/**
	 * The session-key derivation shared with the secure messaging.  The AC
	 * derivation runs before any secure-messaging command of the transaction,
	 * so one derivation object and its 16-byte scratch cover both users and
	 * save 16 bytes of the shared transient budget per instance
	 * (docs/specs/common/cryptography.md §9).
	 */
	SessionKey getSessionKeyDerivation() {
		return sessionKeyDerivation;
	}

	/**
	 * Selects the cryptogram version (DGI 'E003', tags 9F69/9F6A).  The profile
	 * must be selected before the EMV CPS v2.0 Annex A DGI '8000' key container is applied, because
	 * the key length depends on it.
	 */
	public void selectAlgorithm(byte cryptogramVersion) {
		profile.select(cryptogramVersion);
	}

	/**
	 * Replaces the ICC master key with the value of EMV CPS v2.0 Annex A DGI '8000'
	 * (EMV CPS v2.0 Annex A).  The length must match the selected profile:
	 * 16 bytes for 3DES or AES-128.
	 */
	public void setMasterKey(byte[] buf, short off, short len) {
		if (profile.isAes()) {
			if (len != 16) {
				ISOException.throwIt(SW_WRONG_DATA);
			}
			mkAes.setKey(buf, off);
		} else {
			if (len != 16) {
				ISOException.throwIt(SW_WRONG_DATA);
			}
			mkDes.setKey(buf, off);
		}
	}

	/* Sets the current session key, based on the Application Transaction
	 * Counter (ATC) and the selected profile (EMV v4.4 Book 2 Annex A1.3.1). */
	private void setSessionKey() {
		short keyLength = profile.getKeyLength();
		if (profile.isAes()) {
			sessionKeyDerivation.deriveAes(mkAes, keyLength,
					protocolState.getATC(), sessionkey, (short) 0);
			skAes.setKey(sessionkey, (short) 0);
		} else {
			sessionKeyDerivation.derive(mkDes, protocolState.getATC(),
					sessionkey, (short) 0);
			skDes.setKey(sessionkey, (short) 0);
		}
	}

	/** The current AC session key bytes, shared with the ARPC verification (Arpc). */
	byte[] getSessionKey() {
		return sessionkey;
	}

	/**
	 * Zeroizes the session-derived AC material: the session-key bytes, the last
	 * Application Cryptogram and the session-key objects, and the shared MAC
	 * subkeys.  The ICC master keys persist.  EMV v4.4 Book 2 §A1.2.2 requires
	 * the intermediate values of the cryptogram to be kept secret; the next
	 * transaction re-derives the session key from the ATC.
	 */
	public void zeroizeSessionKeys() {
		Util.arrayFillNonAtomic(sessionkey, (short) 0, (short) 16, (byte) 0);
		Util.arrayFillNonAtomic(lastAc, (short) 0, (short) 16, (byte) 0);
		if (skDes.isInitialized()) {
			skDes.clearKey();
		}
		if (skAes.isInitialized()) {
			skAes.clearKey();
		}
		retailMac.zeroize();
		aesCmac.zeroize();
	}

	/** The current AC session key as a DESKey, for the 3DES ARPC Method 1 encryption. */
	DESKey getSessionDESKey() {
		return skDes;
	}

	/** The current AC session key as an AESKey, for the AES ARPC Method 1 encryption. */
	AESKey getSessionAESKey() {
		return skAes;
	}

	/*
	 * Computes a cryptogram, as described in EMV v4.4 Book 2, Sec 8.1, and stores it in
	 * the lastAc buffer.
	 *
	 * The cryptogram is an 8 byte MAC over data supplied by the terminal
	 * (as specified by the CDOL1 or CDOL2) and data provided by the ICC.
	 */
	private void computeAC(byte[] apduBuffer, short length) {
		/* Feed the AC input to the MAC: the terminal data, the AIP, the ATC and
		 * the IAD (EMV v4.4 Book 2 section 8.1.1 / Table CCD 3, EMV v4.4 Book 2
		 * section 8.1.2).  The message is spread over several buffers, so the
		 * streaming MAC is used and no large scratch array is needed. */
		short aip = staticData.getAIP(protocolState.getRole());
		scratch[0] = (byte) (aip >> 8);
		scratch[1] = (byte) aip;
		short atc = protocolState.getATC();
		scratch[2] = (byte) (atc >> 8);
		scratch[3] = (byte) atc;

		byte[] iad = staticData.getIad();
		short iadLength = staticData.getIadLength();

		MacAlgorithm mac = profile.isAes() ? (MacAlgorithm) aesCmac
				: (MacAlgorithm) retailMac;
		mac.start(sessionkey, (short) 0, profile.getKeyLength());
		mac.update(apduBuffer, OFFSET_CDATA, length);
		mac.update(scratch, (short) 0, (short) 4);
		mac.update(iad, (short) 0, iadLength);
		// The AC is always the leftmost 8 bytes (EMV v4.4 Book 2 section 8.1.2); the
		// 16-byte CMAC output is truncated by the consumers of lastAc.
		mac.doFinal(lastAc, (short) 0);
	}

	/** The last Application Cryptogram computed (ARQC stash, EMV v4.4 Book 2 §8.2). */
	public byte[] getLastAc() {
		return lastAc;
	}

	/*
	 * Compute the first AC response APDU.  format2 selects the response coding:
	 * format 1 (tag '80') or format 2 (tag '77', EMV v4.4 Book 3 Table CCD 2).  This
	 * method also sets the session key.
	 */
	public void generateFirstACReponse(byte cid, byte[] apduBuffer, short length,
			                           byte[] response,  short offset, boolean format2) 
	{
		setSessionKey();
		computeAC(apduBuffer, length);
		AcResponseBuilder.build(format2, cid, protocolState.getATC(),
				staticData.getIad(), staticData.getIadLength(), lastAc, response, offset);
	}

	/**
	 * Computes just the 8-byte first AC (setting the session key first) into
	 * out/outOff.  Used by the CDA path, which assembles the response itself
	 * (EMV v4.4 Book 2 §6.6).
	 */
	public void computeFirstAC(byte[] apduBuffer, short length,
	                           byte[] out, short outOff) {
		setSessionKey();
		computeAC(apduBuffer, length);
		Util.arrayCopyNonAtomic(lastAc, (short) 0, out, outOff, (short) 8);
	}

	/**
	 * Computes just the 8-byte second AC into out/outOff.  The session key was
	 * already set by the first AC of this session (EMV v4.4 Book 2 §6.6).
	 */
	public void computeSecondAC(byte[] apduBuffer, short length,
	                            byte[] out, short outOff) {
		computeAC(apduBuffer, length);
		Util.arrayCopyNonAtomic(lastAc, (short) 0, out, outOff, (short) 8);
	}
	
	/*
	 * Compute the second AC response APDU.  format2 selects the response
	 * coding, as for the first AC.
	 */
	public void generateSecondACReponse(byte cid, byte[] apduBuffer, short length,
                                        byte[] response,  short offset, boolean format2) {
		computeAC(apduBuffer, length);
		AcResponseBuilder.build(format2, cid, protocolState.getATC(),
				staticData.getIad(), staticData.getIadLength(), lastAc, response, offset);
	}
}
