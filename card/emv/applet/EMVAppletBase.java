package card42.emv;

import card42.common.*;

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;

import org.globalplatform.Personalization;

/* Common base class for the card42 applets.
 *
 * It owns the objects shared by all roles (the protocol state and the transient
 * response buffer), determines the role of the instance from its AID, handles
 * SELECT (including the interface/role restrictions) and dispatches every other
 * command to the concrete applet through processCommand().
 *
 * The role is resolved from the instance AID, preferring JCSystem.getAID() and
 * falling back to the instance AID carried in the install parameters (Java Card
 * 3.0.5 JCRE §11.2.1); see docs/specs/common/architecture.md §1.  The resolution is done lazily on the first
 * SELECT, because JCSystem.getAID() is guaranteed to be available once the
 * applet is selected, and because the concrete applet needs the role to build
 * its role-dependent default data.
 *
 * Personalization (docs/specs/emv/personalization.md §1) is shared by all applets: the base
 * implements org.globalplatform.Personalization so that the Security Domain can
 * forward STORE DATA over the SCP03 secure channel.  PersoHandler reassembles
 * the blocks; the concrete applet only has to apply the individual DGIs
 * (applyPersoDgi) and validate the required set (persoCheckComplete).
 *
 * @author joeri (joeri@cs.ru.nl)
 * @author erikpoll (erikpoll@cs.ru.nl)
 * @author card42
 */

public abstract class EMVAppletBase extends AppletBase implements ISO7816, Personalization {

	protected final EMVProtocolState protocolState;

	/* Personalization support (docs/specs/emv/personalization.md §1). */
	protected final PersoHandler persoHandler;

	/* The install parameters (instance AID and applet data, Java Card 3.0.5
	 * JCRE §11.2.1) and
	 * the interface media / role resolution they feed. */
	private final InstallParameters install;

	private boolean initialized;

	/* CARD BLOCK is a card-level state (EMV v4.4 Book 3 section 6.5.3): it disables
	 * every application, so it is shared by all applet instances of the package
	 * context rather than kept per instance (EMV v4.4 Book 3 §10.10). */
	private static boolean cardBlocked;

	protected EMVAppletBase() {
		protocolState = new EMVProtocolState();

		persoHandler = new PersoHandler(this);

		install = new InstallParameters();
	}

	/**
	 * Validates the class byte: it must use only the inter-industry ('0x') or
	 * proprietary-to-this-specification ('8x') nibble, and the CLA category must
	 * match the INS (EMV v4.4 Book 3 §6.3.1 Table 2/3, §6.3.2 Table 3).
	 */
	protected void validateCla(byte[] apduBuffer) {
		// The class byte shall use only the inter-industry ('0x') or
		// proprietary-to-this-specification ('8x') nibble; any other value is
		// outside the scope of EMV (EMV v4.4 Book 3 §6.3.1 Table 2/3).  b5 is
		// the command-chaining control and is ignored here.
		short cla = (short) (apduBuffer[OFFSET_CLA] & (short) 0xFF);
		short classNibble = (short) (((cla & (short) 0xEF) & (short) 0xF0) >> 4);
		if (classNibble != (short) 0 && classNibble != (short) 8) {
			ISOException.throwIt(SW_FUNC_NOT_SUPPORTED); // 6A81
		}

		// The CLA category must match the INS per EMV v4.4 Book 3 §6.3.2
		// Table 3: '0x' for SELECT/READ RECORD/VERIFY/GET CHALLENGE/INTERNAL
		// and EXTERNAL AUTHENTICATE, '8x' for GET DATA/GPO/GENERATE AC and the
		// post-issuance commands.  A mismatch is not a command of this
		// specification (6A81).  An unknown INS is left to the dispatcher.
		short required = requiredClassNibble(apduBuffer[OFFSET_INS]);
		if (required >= 0 && classNibble != required) {
			ISOException.throwIt(SW_FUNC_NOT_SUPPORTED); // 6A81
		}
	}

	/** Handles a SELECT that selected this instance (see {@link AppletBase}). */
	protected void onSelect(APDU apdu, byte[] apduBuffer) {
		initIfNeeded();

		// Record the interface the terminal is using for this session
		// (docs/specs/common/architecture.md §1); the simulator always reports contact.
		protocolState.setMedia((byte) (APDU.getProtocol() & EMVRoles.MEDIA_MASK));

		// SELECT P1 must be '04' (select by name) and P2 '00' (first or
		// only occurrence); the next-occurrence option and any RFU bits are
		// not supported (EMV v4.4 Book 1 §11.3.2 Table 6/7, Book 3 Table 4
		// -> 6A81).
		if (apduBuffer[OFFSET_P1] != 0x04 || apduBuffer[OFFSET_P2] != 0x00) {
			ISOException.throwIt(SW_FUNC_NOT_SUPPORTED); // 6A81
		}

		// CARD BLOCK disables every application: all SELECTs answer 6A81
		// and perform no other action (EMV v4.4 Book 3 §6.5.3).
		if (cardBlocked || protocolState.getLifecycle() == EMVRoles.CARD_BLOCKED) {
			ISOException.throwIt(SW_FUNC_NOT_SUPPORTED);
		}

		// Reset all the flags recording the protocol state.
		// This should already have happened by the clearing of the
		// transient array used for them.
		protocolState.startNewSession();

		// Let the concrete applet reset per-session state that lives
		// outside EMVProtocolState (e.g. the secure-messaging script
		// counter of CVR byte 4).
		onNewSession();

		if (!isSelectableOnCurrentMedia()) {
			// e.g. PPSE on the contact interface, or a contactless payment
			// instance on the contact interface (docs/specs/common/architecture.md §6, §7).
			ISOException.throwIt(SW_FILE_NOT_FOUND);
		}

		// An invalidated application (APPLICATION BLOCK or ATC overflow)
		// still answers SELECT, but with the warning 6283 (EMV v4.4 Book 3
		// §6.5.1); GENERATE AC then only returns AAC (EMV v4.4 Book 2 Annex D3).
		if (protocolState.getLifecycle() == EMVRoles.BLOCKED) {
			ISOException.throwIt(EMVStatus.SW_SELECTED_FILE_INVALIDATED);
		}

		sendFCI(apdu, apduBuffer);
	}

	/**
	 * The CLA category (high nibble 0 or 8) prescribed by EMV v4.4 Book 3
	 * §6.3.2 Table 3 for an INS, or -1 when the INS is not one of this
	 * specification's commands.
	 */
	private static short requiredClassNibble(byte ins) {
		switch (ins) {
		case INS_SELECT: // A4
		case EMVCommands.INS_READ_RECORD: // B2
		case EMVCommands.INS_VERIFY: // 20
		case EMVCommands.INS_GET_CHALLENGE: // 84
		case EMVCommands.INS_INTERNAL_AUTHENTICATE: // 88
		case INS_EXTERNAL_AUTHENTICATE: // 82
			return 0;
		case EMVCommands.INS_GET_DATA: // CA
		case EMVCommands.INS_GET_PROCESSING_OPTIONS: // A8
		case EMVCommands.INS_GENERATE_AC: // AE
		case EMVCommands.INS_SEND_POI_INFORMATION: // 1A
		case EMVCommands.INS_APPLICATION_BLOCK: // 1E
		case EMVCommands.INS_APPLICATION_UNBLOCK: // 18
		case EMVCommands.INS_CARD_BLOCK: // 16
		case EMVCommands.INS_PIN_CHANGE_UNBLOCK: // 24
			return 8;
		default:
			return -1;
		}
	}

	/**
	 * GP main personalization path (docs/specs/emv/personalization.md §1): the Security
	 * Domain forwards each STORE DATA command here, byte for byte, without
	 * reassembling blocks.
	 */
	public short processData(byte[] inBuf, short inOff, short inLen,
	                         byte[] outBuf, short outOff) {
		return persoHandler.processData(inBuf, inOff, inLen, outBuf, outOff);
	}

	/**
	 * Captures the instance AID and applet data from the install parameters
	 * (Java Card 3.0.5 JCRE §11.2.1, see docs/specs/common/research-notes.md §3).
	 */
	protected final void captureInstallParameters(byte[] buffer, short offset, short length) {
		install.capture(buffer, offset, length);
	}

	/** Resolves the role once, on the first SELECT or personalization block. */
	void initIfNeeded() {
		if (initialized) {
			return;
		}

		// Prefer the AID of the applet context (docs/specs/common/architecture.md §1); fall back
		// to the AID from the install parameters when it is not available.
		install.setCurrentAid(JCSystem.getAID());

		initRole();
		initialized = true;
	}

	/**
	 * Determines the role of this instance and builds the role-dependent data.
	 * Implemented by the concrete applet.
	 */
	protected abstract void initRole();

	/** True if the resolved instance AID (or the install AID) equals candidate. */
	protected final boolean instanceAidEquals(byte[] candidate) {
		return install.instanceAidEquals(candidate);
	}

	/**
	 * Resolves a one-byte role/directory code from the applet data of the
	 * install parameters (docs/specs/common/research-notes.md §3).  Returns roleA when the first
	 * applet data byte is validA, roleB when it is validB, and fallback
	 * otherwise (including when no applet data is present).
	 */
	protected final byte roleFromInstallData(byte validA, byte roleA,
			byte validB, byte roleB, byte fallback) {
		return install.roleFromInstallData(validA, roleA, validB, roleB, fallback);
	}

	/**
	 * Whether this instance may be selected on the interface of the current
	 * session.  PPSE and contactless payment instances must be refused on the
	 * contact interface (docs/specs/common/architecture.md §6, §7); the test build switch
	 * BuildConfig.ALLOW_CONTACTLESS_ON_CONTACT relaxes this so that the
	 * simulator can exercise the contactless flow.
	 */
	protected boolean isSelectableOnCurrentMedia() {
		if (protocolState.getMedia() == EMVRoles.MEDIA_CONTACT
				&& !BuildConfig.ALLOW_CONTACTLESS_ON_CONTACT) {
			if (protocolState.getRole() == EMVRoles.ROLE_CONTACTLESS) {
				return false;
			}
			if (protocolState.getDirectoryType() == EMVRoles.DIR_PPSE) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Called at the start of a new session (SELECT), after
	 * {@link EMVProtocolState#startNewSession()}.  The concrete applet resets
	 * per-session state that lives outside the protocol state; the default is
	 * a no-op.
	 */
	protected void onNewSession() {
	}

	/**
	 * Zeroizes session-derived secret material when the applet is deselected
	 * (EMV v4.4 Book 2 §A1.2.2).  The concrete applet clears the session keys
	 * and MAC subkeys here so they do not persist in EEPROM between
	 * transactions; the default is a no-op.
	 */
	/** Called on deselection; the concrete applet zeroizes its session keys. */
	protected void onDeselect() {
	}

	/**
	 * Sends the File Control Information for the current application.
	 */
	protected void sendFCI(APDU apdu, byte[] apduBuffer) {
		// Cache both accessors so the (possibly rebuilt) FCI and its length
		// agree even if getFCI() invalidates the cached length (docs/specs/common/architecture.md §2).
		byte[] fci = getFCI();
		short length = getFCILength();
		ApduIo.send(apdu, fci, (short)0, length);
	}

	/** The FCI of this instance (built for its role). */
	protected abstract byte[] getFCI();

	protected abstract short getFCILength();

	/**
	 * Handles a command APDU addressed to this applet (ie. after SELECT).
	 * The concrete applet implements the role-specific command set here.
	 */
	protected abstract void processCommand(APDU apdu, byte[] apduBuffer);

	/**
	 * Applies one DGI from a personalization sequence (EMV CPS v2.0 Annex A).
	 * Called inside a transaction while the applet is not necessarily selected.
	 */
	protected abstract void applyPersoDgi(short dgi, byte[] buf, short off, short len);

	/**
	 * True if every DGI required by this applet was received.  Called after the
	 * last block; returning false aborts the personalization with 6A80
	 * (EMV CPS v2.0 §3.3).
	 */
	protected abstract boolean persoCheckComplete();

	/**
	 * Marks the instance as personalized: switches the lifecycle to READY.
	 * Called by PersoHandler inside the Security Domain's transaction.
	 */
	protected void persoComplete() {
		protocolState.setLifecycle(EMVRoles.READY);
	}

	/**
	 * Clears the per-instance completion markers of a personalization sequence.
	 * Called by PersoHandler when a new sequence starts (P2=0) and after a
	 * failed sequence, so a partially applied sequence cannot be judged
	 * complete (GP {@code Personalization.processData} leaves atomicity to the
	 * application).  The default is a no-op.
	 */
	protected void resetPersoState() {
	}

	/** True once a CARD BLOCK disabled the whole card (EMV v4.4 Book 3 §10.10). */
	protected final boolean isCardBlocked() {
		return cardBlocked;
	}

	/** Applies CARD BLOCK to every application of this card (EMV v4.4 Book 3 §10.10). */
	protected final void blockCard() {
		cardBlocked = true;
	}

}
