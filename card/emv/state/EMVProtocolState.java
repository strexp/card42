package card42.emv;

import card42.common.*;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;

/* Class to track the transient - ie. "session" - state of the EMV protocol,
 * as well as the persistent state.
 *
 * ATC (EMV v4.4 Book 2 Annex D3): the counter is persistent and is
 * advanced exactly once per transaction, during a successful GET PROCESSING
 * OPTIONS - not on SELECT.  It must not roll over: when it reaches 0xFFFF the
 * application is invalidated (APPLICATION BLOCK semantics, EMV v4.4 Book 3 section
 * 6.5.1) instead.
 *
 * card42 additions (docs/specs/common/architecture.md §3, §1): the per-instance role, the
 * directory type, the interface media reported for the current session and the
 * persistent lifecycle state.  Role / directory type / media / lifecycle are
 * ordinary instance fields (not transient): the same package context is shared
 * by every applet instance (docs/specs/common/architecture.md §2), so transient or static state
 * would leak across instances.
 *
 * ATC persistence: the ATC is a persistent instance field; the Last Online ATC
 * Register (9F13) is written when a transaction completes online (EMV v4.4
 * EMV v4.4 Book 2 §8.2).
 *
 * @author joeri (joeri@cs.ru.nl)
 * @author erikpoll (erikpoll@cs.ru.nl)
 *
 */

public class EMVProtocolState implements ISO7816 {

	/** Index of the "GPO already advanced the ATC" session flag. */
	private static final short VOL_GPO_DONE = 3;
	/** Index of the issuer authentication state of the session. */
	private static final short VOL_ISSUER_AUTH = 4;
	/** Index of the "EXTERNAL AUTHENTICATE already attempted" session flag. */
	private static final short VOL_EXTERNAL_AUTH_USED = 5;
	/** Index of the CCD CSU "Issuer Approves Online Transaction" flag. */
	private static final short VOL_ISSUER_APPROVED = 6;
	/** Index of the "a CSU has been applied this transaction" flag. */
	private static final short VOL_CSU_APPLIED = 7;
	/** Index of the "Offline DDA performed" CVR flag (EMV v4.4 Book 3 Annex C §C9). */
	private static final short VOL_DDA_PERFORMED = 8;
	/** Index of the "CDA performed" CVR flag (EMV v4.4 Book 3 Annex C §C9). */
	private static final short VOL_CDA_PERFORMED = 9;

	/** Last ATC value before the counter would roll over (EMV v4.4 Book 2 Annex D3). */
	private static final short MAX_ATC = (short)0xFFFF;

	private short atc;
	private short lastOnlineATC;

	/* ARQC of the first GENERATE AC of the current transaction, kept for the
	 * ARPC verification (EMV v4.4 Book 2 §8.2).  Session state. */
	private final byte[] arqc;

	/* Persistent "Issuer Authentication Failed" indicator (EMV v4.4 Book 2 §8.2);
	 * reset on a successful issuer authentication. */
	private boolean issuerAuthFailedPersistent;

	/* Persistent "Issuer Script Processing Failed" CVR bit (EMV v4.4 Book 3
	 * §9.2.3.2): set when a secure-messaging command fails, reset only by a
	 * successful issuer authentication or a successful online transaction. */
	private boolean scriptFailedPersistent;

	/* Persistent "Last Online Transaction Not Completed" CVR bit (EMV v4.4
	 * EMV v4.4 Book 3 §9.2.3.2): set by a first AC that requested to go online, cleared
	 * by the second AC or a successful issuer authentication. */
	private boolean lastOnlineNotCompleted;

	/* "Issuer Authentication Not Performed" CVR bit of the most recent second
	 * GENERATE AC response (EMV v4.4 Book 3 §9.2.3.2): the first GENERATE AC of
	 * the next transaction reports this value. */
	private boolean issuerAuthNotPerformedPrevious;

	/* "Offline Data Authentication Failed on Previous Transaction" CVR bit
	 * (EMV v4.4 Book 3 §9.2.3.2): set from the TVR of a transaction whose
	 * SDA/DDA/CDA failed, reset after a transaction that went online or was
	 * approved offline. */
	private boolean odaFailedPrevious;

	/* ICC Unpredictable Number of the current session, issued by GET CHALLENGE
	 * and checked against the recovered enciphered PIN block (EMV v4.4 Book 2
	 * §7.2 steps 2/7).  Transient; the validity flag is reset per session. */
	private final byte[] challenge;
	private boolean challengeValid;

	/* ISO/IEC 7816-4 command chaining of the current session (EMV v4.4 Book 3
	 * §6.5.13).  A chain is active between a non-final VERIFY or PIN
	 * CHANGE/UNBLOCK command (CLA b5=1) and its final command (b5=0); the
	 * accumulated command data is transient and reset on SELECT.  The buffer is
	 * the package-shared {@link EmvScratch#chain}, so it is allocated once for
	 * every instance and never during a command (docs/specs/common/risks.md). */
	private boolean chainActive;
	private byte chainIns;
	private short chainLength;

	/** Upper bound of a PDOL-related data expansion accepted by the GPO handler
	 *  (EMV v4.4 Book 3 §6.5.8); a longer expansion is refused with 6985. */
	private static final short MAX_PDOL_DATA = (short) 64;

	/* PDOL-related data of the current GPO (EMV v4.4 Book 3 §6.5.8), kept for the
	 * Card Action Analysis and the CDA Transaction Data Hash Code.  The buffer
	 * is the package-shared {@link EmvScratch#pdol} (transient, cleared on
	 * deselect); the length is reset by startNewSession. */
	private short pdolDataLength;

	/* Persistent, per-instance state (docs/specs/common/architecture.md §2: never static). */
	private byte role;
	private byte directoryType;
	private byte lifecycle;

	/* Interface media of the current session, recorded from APDU.getProtocol(). */
	private byte media;
	
	/** 
	 * Volatile protocol state; records if CVM has been performed, and if ACs
	 * have been generated
	 */
	private final byte volatileState[];
	
	public byte getFirstACGenerated() {
		return volatileState[1];
	}

	public void setFirstACGenerated(byte ACType) {
		volatileState[1] = ACType;
	}

	public byte getSecondACGenerated() {
		return volatileState[2];
	}

	public void setSecondACGenerated(byte ACType) {
		volatileState[2] = ACType;
	}

	/**
	 * Whether GET PROCESSING OPTIONS has already advanced the ATC for this
	 * session.  Guarantees the counter is incremented at most once per
	 * transaction (EMV v4.4 Book 2 Annex D3).
	 */
	public boolean isGpoDone() {
		return volatileState[VOL_GPO_DONE] != 0;
	}

	public void setGpoDone() {
		volatileState[VOL_GPO_DONE] = 1;
	}

	/** CVM performed in this session: NONE, EMVCodes.PLAINTEXT_PIN or EMVCodes.ENCRYPTED_PIN.
	 *  Written by PaymentApplet and read by AcProcessor.prepareIad for the CVR
	 *  PIN performed/failed bits (docs/specs/emv/personalization.md §6). */
	public byte getCVMPerformed() {
		return volatileState[0];
	}

	public void setCVMPerformed(byte CVMType) {
		volatileState[0] = CVMType;
	}

	/** Fixed role of this instance: EMVRoles.ROLE_CONTACT or EMVRoles.ROLE_CONTACTLESS. */
	public byte getRole() {
		return role;
	}

	public void setRole(byte newRole) {
		role = newRole;
	}

	/** Directory type served by this instance: EMVRoles.DIR_NONE, EMVRoles.DIR_PSE or EMVRoles.DIR_PPSE. */
	public byte getDirectoryType() {
		return directoryType;
	}

	public void setDirectoryType(byte type) {
		directoryType = type;
	}

	/** Persistent lifecycle state: PERSONALISATION, READY, BLOCKED
	 *  (invalidated) or CARD_BLOCKED. */
	public byte getLifecycle() {
		return lifecycle;
	}

	public void setLifecycle(byte state) {
		lifecycle = state;
	}

	/**
	 * Interface media recorded for the current session (docs/specs/common/architecture.md §1).
	 * Only one of the MEDIA_* constants; the simulator always reports contact.
	 */
	public byte getMedia() {
		return media;
	}

	public void setMedia(byte newMedia) {
		media = newMedia;
	}

	public short getATC() {
		return atc;
	}

	/**
	 * Sets the persistent ATC, used by personalization (EMV CPS v2.0 Annex A DGI '3000' tag
	 * 9F36) to start the counter at an intermediate value.
	 */
	public void setATC(short value) {
		atc = value;
	}

	/**
	 * PDOL-related data sent by the terminal in GET PROCESSING OPTIONS
	 * (EMV v4.4 Book 3 §6.5.8).  Valid for the current session; the contents are
	 * transient and the length is reset on SELECT.  Returns null when the
	 * current transaction carried no PDOL data
	 * ({@link #getPdolDataLength()} == 0): the buffer is only allocated for a
	 * non-empty expansion (docs/specs/common/risks.md).
	 */
	public byte[] getPdolData() {
		return EmvScratch.pdol;
	}

	public short getPdolDataLength() {
		return pdolDataLength;
	}

	/**
	 * Whether a PDOL expansion of the given length fits the session buffer
	 * (EMV v4.4 Book 3 §6.5.8): a longer expansion is refused with 6985 by the
	 * GPO handler before the data is copied.
	 */
	public boolean pdolFits(short len) {
		return len >= 0 && len <= MAX_PDOL_DATA;
	}

	public void setPdolData(byte[] buf, short off, short len) {
		if (len < 0 || len > MAX_PDOL_DATA) {
			// Defensive backstop: the GPO handler already refuses an over-long
			// expansion with 6985 via pdolFits() (docs/specs/common/toolchain.md §6).
			ISOException.throwIt(SW_WRONG_LENGTH);
		}
		if (len == 0) {
			// No PDOL data: keep the shared buffer untouched
			// (docs/specs/common/risks.md).
			pdolDataLength = 0;
			return;
		}
		// The shared PDOL buffer is a fixed 64 bytes, the on-card bound
		// (MAX_PDOL_DATA); GPO refuses a longer expansion before this point.
		Util.arrayCopyNonAtomic(buf, off, EmvScratch.pdol, (short) 0, len);
		pdolDataLength = len;
	}

	/**
	 * Advances the persistent ATC by one for a new transaction.  Called from a
	 * successful GET PROCESSING OPTIONS (EMV v4.4 Book 2 Annex D3): the counter is
	 * incremented at the start of each transaction, once per session.  When it
	 * reaches 0xFFFF it is not rolled over; the application is invalidated
	 * instead (APPLICATION BLOCK semantics, EMV v4.4 Book 3 section 6.5.1), so
	 * GENERATE AC returns no cryptogram.
	 */
	public void advanceATC() {
		if (atc == MAX_ATC) {
			// Already at the limit: keep the value and stay invalidated.
			setLifecycle(EMVRoles.BLOCKED);
			return;
		}
		atc = (short)(atc+1);
		if (atc == MAX_ATC) {
			setLifecycle(EMVRoles.BLOCKED);
		}
	}
	
	/**
	 * Last online ATC: the ATC of the transaction in which online processing was
	 * last completed (EMV v4.4 Book 3 §6.5.7).  Written when
	 * the second GENERATE AC completes an ARQC transaction, or when EXTERNAL
	 * AUTHENTICATE succeeds.
	 */
	public short getLastOnlineATC() {
		return lastOnlineATC;
	}

	public void setLastOnlineATC(short value) {
		lastOnlineATC = value;
	}

	/** ARQC of the first GENERATE AC, kept for ARPC verification. */
	public void setArqc(byte[] buf, short off) {
		Util.arrayCopyNonAtomic(buf, off, arqc, (short) 0, (short) 8);
	}

	public byte[] getArqc() {
		return arqc;
	}

	/** Issuer authentication state of the current transaction. */
	private void setIssuerAuthStatus(byte status) {
		volatileState[VOL_ISSUER_AUTH] = status;
	}

	public boolean isIssuerAuthPerformed() {
		return volatileState[VOL_ISSUER_AUTH] != EMVStatus.ISSUER_AUTH_NONE;
	}

	public boolean isIssuerAuthFailed() {
		return volatileState[VOL_ISSUER_AUTH] == EMVStatus.ISSUER_AUTH_FAILED;
	}

	/** True once an EXTERNAL AUTHENTICATE was attempted this transaction. */
	public boolean isExternalAuthUsed() {
		return volatileState[VOL_EXTERNAL_AUTH_USED] != 0;
	}

	public void setExternalAuthUsed() {
		volatileState[VOL_EXTERNAL_AUTH_USED] = 1;
	}

	/**
	 * CCD CSU "Issuer Approves Online Transaction" (EMV v4.4 Book 3
	 * §10.11.1.1 / Annex C §C10): when a CSU was applied and this is false, the
	 * second GENERATE AC declines the transaction (AAC).
	 */
	public boolean isIssuerApprovedOnline() {
		return volatileState[VOL_ISSUER_APPROVED] != 0;
	}

	public void setIssuerApprovedOnline(boolean approved) {
		volatileState[VOL_ISSUER_APPROVED] = approved ? (byte) 1 : (byte) 0;
	}

	/** True once a Card Status Update was applied this transaction. */
	public boolean isCsuApplied() {
		return volatileState[VOL_CSU_APPLIED] != 0;
	}

	public void setCsuApplied() {
		volatileState[VOL_CSU_APPLIED] = 1;
	}

	/** True once an Offline DDA (INTERNAL AUTHENTICATE) succeeded (CVR byte 1). */
	public boolean isDdaPerformed() {
		return volatileState[VOL_DDA_PERFORMED] != 0;
	}

	public void setDdaPerformed() {
		volatileState[VOL_DDA_PERFORMED] = 1;
	}

	/** True once a Combined DDA/AC was generated (CVR byte 1). */
	public boolean isCdaPerformed() {
		return volatileState[VOL_CDA_PERFORMED] != 0;
	}

	public void setCdaPerformed() {
		volatileState[VOL_CDA_PERFORMED] = 1;
	}

	/** Persistent "Issuer Authentication Failed" indicator (EMV v4.4 Book 2 §8.2). */
	public boolean isIssuerAuthFailedPersistent() {
		return issuerAuthFailedPersistent;
	}

	/** Records a successful issuer authentication: clears the failure state. */
	public void issuerAuthSucceeded() {
		setIssuerAuthStatus(EMVStatus.ISSUER_AUTH_SUCCESS);
		// Same-value guarded: the persistent CVR bits are usually already
		// clear, and each write costs an EEPROM programming cycle.
		if (issuerAuthFailedPersistent) {
			issuerAuthFailedPersistent = false;
		}
		// A successful issuer authentication also clears the persistent
		// "Issuer Script Processing Failed" and "Last Online Transaction Not
		// Completed" CVR bits (EMV v4.4 Book 3 §9.2.3.2).
		if (scriptFailedPersistent) {
			scriptFailedPersistent = false;
		}
		if (lastOnlineNotCompleted) {
			lastOnlineNotCompleted = false;
		}
	}

	/** Records a failed issuer authentication: sets the persistent indicator. */
	public void issuerAuthFailed() {
		setIssuerAuthStatus(EMVStatus.ISSUER_AUTH_FAILED);
		if (!issuerAuthFailedPersistent) {
			issuerAuthFailedPersistent = true;
		}
	}

	/** Persistent "Issuer Script Processing Failed" CVR bit (EMV v4.4 Book 3 §9.2.3.2). */
	public boolean isScriptFailedPersistent() {
		return scriptFailedPersistent;
	}

	public void setScriptFailedPersistent(boolean failed) {
		// Same value: skip the write, a same-value byte may still cost an
		// EEPROM programming cycle on a real card.
		if (scriptFailedPersistent != failed) {
			scriptFailedPersistent = failed;
		}
	}

	/** Persistent "Last Online Transaction Not Completed" CVR bit (EMV v4.4 Book 3 §9.2.3.2). */
	public boolean isLastOnlineNotCompleted() {
		return lastOnlineNotCompleted;
	}

	public void setLastOnlineNotCompleted(boolean notCompleted) {
		if (lastOnlineNotCompleted != notCompleted) {
			lastOnlineNotCompleted = notCompleted;
		}
	}

	/** The "Issuer Authentication Not Performed" bit of the last second AC. */
	public boolean isIssuerAuthNotPerformedPrevious() {
		return issuerAuthNotPerformedPrevious;
	}

	public void setIssuerAuthNotPerformedPrevious(boolean notPerformed) {
		if (issuerAuthNotPerformedPrevious != notPerformed) {
			issuerAuthNotPerformedPrevious = notPerformed;
		}
	}

	/** The "ODA Failed on Previous Transaction" CVR bit (EMV v4.4 Book 3 §9.2.3.2). */
	public boolean isOdaFailedPrevious() {
		return odaFailedPrevious;
	}

	public void setOdaFailedPrevious(boolean failed) {
		if (odaFailedPrevious != failed) {
			odaFailedPrevious = failed;
		}
	}

	/**
	 * Stores the ICC Unpredictable Number returned by GET CHALLENGE (EMV v4.4
	 * EMV v4.4 Book 2 §7.2 step 2); VERIFY P2=88 checks the recovered value against it.
	 */
	public void setChallenge(byte[] buf, short off) {
		Util.arrayCopyNonAtomic(buf, off, challenge, (short) 0, (short) 8);
		challengeValid = true;
	}

	public byte[] getChallenge() {
		return challenge;
	}

	public boolean isChallengeValid() {
		return challengeValid;
	}

	/**
	 * Invalidates a pending GET CHALLENGE.  A challenge is valid only for the
	 * next command (EMV v4.4 Book 3 §6.5.6.1): the dispatcher clears it for
	 * every command except VERIFY, which reads it before clearing.
	 */
	public void clearChallengeValid() {
		challengeValid = false;
	}

	/** True while a non-final VERIFY / PIN CHANGE/UNBLOCK fragment is pending. */
	public boolean isChainActive() {
		return chainActive;
	}

	/** The INS of the active command chain (VERIFY or PIN CHANGE/UNBLOCK). */
	public byte getChainIns() {
		return chainIns;
	}

	public short getChainLength() {
		return chainLength;
	}

	/**
	 * The accumulated command data of the active chain.  The package-shared
	 * {@link EmvScratch#chain} buffer (transient, cleared on deselect), so a
	 * card that never chains still spends nothing extra and no allocation
	 * happens during a command (docs/specs/common/risks.md).
	 */
	public byte[] getChainData() {
		return EmvScratch.chain;
	}

	/**
	 * A shared work buffer for the mutually exclusive large scratch users: the
	 * enciphered-PIN recovery block, the DDA/CDA ISO 9796-2 message and the
	 * ARPC / secure-messaging MAC input.  They are never active at the same
	 * time (a single command uses one of them), so the package-shared
	 * {@link EmvScratch#work} buffer serves every instance and the transient
	 * budget holds a single allocation (docs/specs/common/risks.md).  The
	 * {@code minLength} argument is kept for callers that size their own work
	 * against the returned length.
	 */
	public byte[] getWorkScratch(short minLength) {
		return EmvScratch.work;
	}

	/** Starts a chain for the given chainable command (EMV v4.4 Book 3 §6.5.13). */
	public void startChain(byte ins) {
		chainActive = true;
		chainIns = ins;
		chainLength = 0;
	}

	/**
	 * Appends one non-final command-data fragment.  Returns false when the
	 * accumulated data would not fit the short-APDU maximum (255 bytes); the
	 * caller then reports the chaining failure.
	 */
	public boolean appendChain(byte[] buf, short off, short len) {
		byte[] data = getChainData();
		if (len < 0 || (short) (chainLength + len) > data.length) {
			return false;
		}
		Util.arrayCopyNonAtomic(buf, off, data, chainLength, len);
		chainLength = (short) (chainLength + len);
		return true;
	}

	/** Abandons the active chain (completed, failed or interrupted). */
	public void resetChain() {
		chainActive = false;
		chainLength = 0;
	}

	public EMVProtocolState(){
		// Allocate the package-shared transient buffers once, at install time:
		// no command path allocates a transient array (docs/specs/common/risks.md).
		EmvScratch.init();

		// [0] CVM performed, [1] first AC, [2] second AC, [3] GPO done,
		// [4] issuer authentication state, [5] EXTERNAL AUTHENTICATE used,
		// [6] CCD CSU "Issuer Approves Online Transaction", [7] CSU applied,
		// [8] Offline DDA performed, [9] CDA performed.
		volatileState = EmvScratch.volatileState;

		// PDOL-related data of the current GPO (EMV v4.4 Book 3 §6.5.8) is
		// stored in the shared buffer; only the length is per instance.
		pdolDataLength = 0;

		// Issuer authentication session state (EMV v4.4 Book 2 §8.2).
		arqc = EmvScratch.arqc;

		// ICC Unpredictable Number of the current session (GET CHALLENGE).
		challenge = EmvScratch.challenge;
		challengeValid = false;
		issuerAuthNotPerformedPrevious = false;
		odaFailedPrevious = false;
		scriptFailedPersistent = false;
		lastOnlineNotCompleted = false;

		// A fresh instance starts in PERSONALISATION and moves to READY when it
		// receives its completion marker (docs/specs/common/architecture.md §3).
		role = EMVRoles.ROLE_CONTACT;
		directoryType = EMVRoles.DIR_NONE;
		lifecycle = EMVRoles.PERSONALISATION;
		media = EMVRoles.MEDIA_CONTACT;
	}
	
	/* Starts a new session.  This resets all session data, but does not touch
	 * the ATC: the counter is advanced later, once per transaction, from a
	 * successful GET PROCESSING OPTIONS (EMV v4.4 Book 2 Annex D3).
	 * It does not generate a session key yet either.
	 */
	public void startNewSession(){
		setFirstACGenerated(EMVCodes.NONE);
		setSecondACGenerated(EMVCodes.NONE);
		setCVMPerformed(EMVCodes.NONE);
		volatileState[VOL_GPO_DONE] = 0;
		volatileState[VOL_ISSUER_AUTH] = EMVStatus.ISSUER_AUTH_NONE;
		volatileState[VOL_EXTERNAL_AUTH_USED] = 0;
		volatileState[VOL_ISSUER_APPROVED] = 0;
		volatileState[VOL_CSU_APPLIED] = 0;
		volatileState[VOL_DDA_PERFORMED] = 0;
		volatileState[VOL_CDA_PERFORMED] = 0;
		pdolDataLength = 0;
		challengeValid = false;
		resetChain();
	}
	
}
