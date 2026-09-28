package card42.emv;

import card42.common.*;

import javacard.framework.APDU;
import javacard.framework.ISOException;
import javacard.framework.Util;

/* The EMV directory applet (EMV CPS v2.0 §A.3).
 *
 * A single class serves both directory roles, distinguished by the instance AID:
 *
 *   - PSE  (1PAY.SYS.DDF01): contact only.  Its FCI is the EMV CPS v2.0 Annex A DGI '9102' SELECT
 *     response A5 template (advertising 88 01 01) and the candidate list is
 *     read with READ RECORD from SFI 1, where the record is the EMV CPS v2.0 Annex A DGI '0101'
 *     value (a 70 { 61 { ... } } template).
 *   - PPSE (2PAY.SYS.DDF01): contactless only.  Its FCI is the EMV CPS v2.0 Annex A DGI '9102' A5
 *     template with the candidate list embedded under BF0C; READ RECORD is not
 *     supported.  (PPSE is not part of the EMV CPS v2.0; it reuses the same containers.)
 *
 * The directory type is not stored here (docs/specs/common/architecture.md §4): the single
 * source of truth is EMVProtocolState.getDirectoryType().
 *
 * @author card42
 */
public class DirectoryApplet extends EMVAppletBase {

	/**
	 * Built FCI buffer.  EMV v4.4 Book 1 §11.3.4 allows an FCI template up to
	 * 252 bytes, so 256 bytes covers the 6F wrapper plus the largest A5 content.
	 */
	private final byte[] fci = new byte[(short)256];
	private short fciLength;

	/** EMV CPS v2.0 Annex A DGI '9102' SELECT response A5 template, when personalized. */
	private final byte[] fciOverride = new byte[(short)256];
	private short fciOverrideLength;

	/** Directory SFI ('88') advertised by the PSE FCI, 1-10 (EMV v4.4 Book 1 §12.2.3). */
	private short directorySfi = (short)1;

	/**
	 * Personalized directory records keyed by DGI (SFI<<8)|record.  EMV v4.4
	 * Book 1 §12.2.3 allows the directory file at any SFI 1-10 and more than one
	 * record, so the records are stored keyed instead of in one override buffer.
	 */
	private final DirectoryRecords records = new DirectoryRecords();

	/** Outgoing buffer for the built-in default record. */
	private final byte[] directoryRecord = new byte[(short)128];
	private short directoryRecordLength;

	/** Scratch buffers used while building the default FCI and record. */
	private final byte[] scratch1 = new byte[(short)64];
	private final byte[] scratch2 = new byte[(short)64];

	private boolean sawFci;

	private DirectoryApplet() {
		super();
	}

	/**
	 * Installs an instance of the applet.
	 * 
	 * @see javacard.framework.Applet#install(byte[], byte, byte)
	 */
	public static void install(byte[] buffer, short offset, byte length) {
		DirectoryApplet applet = new DirectoryApplet();
		// Register under the instance AID from the install parameters (Java Card
		// 3.0.5 JCRE §11.2.1); see PaymentApplet.install for why register() is not used.
		applet.register(buffer, (short) (offset + 1), buffer[offset]);
		applet.captureInstallParameters(buffer, offset, length);
	}

	/**
	 * Determines whether this instance is the PSE or the PPSE from the instance
	 * AID (docs/specs/common/architecture.md §1), falling back to the applet data.
	 */
	protected void initRole() {
		byte dir;
		if (instanceAidEquals(EMVAids.PPSE)) {
			dir = EMVRoles.DIR_PPSE;
		} else if (instanceAidEquals(EMVAids.PSE)) {
			dir = EMVRoles.DIR_PSE;
		} else {
			dir = roleFromInstallData(EMVRoles.DIR_PSE, EMVRoles.DIR_PSE, EMVRoles.DIR_PPSE, EMVRoles.DIR_PPSE, EMVRoles.DIR_PSE);
		}
		protocolState.setDirectoryType(dir);
		protocolState.setRole(EMVRoles.ROLE_CONTACT);
	}

	/** The DF name of this directory instance. */
	private byte[] directoryAid() {
		return protocolState.getDirectoryType() == EMVRoles.DIR_PPSE ? EMVAids.PPSE : EMVAids.PSE;
	}

	/** The EMV CPS v2.0 Annex A DGI '0101' default record: 70 { 61 { 4F, 50, 87 } }. */
	private void buildDefaultRecord() {
		byte[] aid = protocolState.getDirectoryType() == EMVRoles.DIR_PPSE
				? EMVAids.PAYMENT_CONTACTLESS : EMVAids.PAYMENT_CONTACT;
		byte[] label = protocolState.getDirectoryType() == EMVRoles.DIR_PPSE
				? Defaults.LABEL_CONTACTLESS : Defaults.LABEL_CONTACT;
		// Candidate entry: 61 { 4F || 50 || 87 }; the PSE entry has no 9F2A.
		short entryTlv = DirectoryBuilder.appendDirectoryEntry(scratch1, (short)0,
				aid, (short) aid.length, label, (short) label.length, (byte) 0x01,
				false, null, (short) 0);
		short p = 0;
		p = Tlv.appendTag(TlvTags.TAG_RECORD_TEMPLATE, directoryRecord, p);
		p = Tlv.appendLength(entryTlv, directoryRecord, p);
		Util.arrayCopyNonAtomic(scratch1, (short)0, directoryRecord, p, entryTlv);
		directoryRecordLength = (short)(p + entryTlv);
	}

	protected byte[] getFCI() {
		if (fciLength > 0) {
			return fci;
		}
		byte[] content;
		short contentLength;
		if (fciOverrideLength > 0) {
			// EMV CPS v2.0 Annex A DGI '9102': the A5 SELECT response template verbatim.
			content = fciOverride;
			contentLength = fciOverrideLength;
		} else if (protocolState.getDirectoryType() == EMVRoles.DIR_PSE) {
			// Default PSE: A5 { 88 01 <directorySfi> }.
			scratch1[0] = (byte)0x88;
			scratch1[1] = (byte)0x01;
			scratch1[2] = (byte) directorySfi;
			contentLength = Tlv.append(TlvTags.TAG_FCI_PROPRIETARY,
					scratch1, (short)0, (short)3, scratch2, (short)0);
			content = scratch2;
		} else {
			// Default PPSE: A5 { BF0C { 61 { 4F, 50, 87, 9F2A } } } (EMV Contactless Book B v2.12
			// Table 3-2).  The Kernel Identifier is 00, i.e. the kernel is
			// resolved from the ADF Name (EMV Contactless Book B v2.12 Table 3-4/3-5).
			short entries = DirectoryBuilder.appendDirectoryEntry(scratch1, (short)0,
					EMVAids.PAYMENT_CONTACTLESS,
					(short) EMVAids.PAYMENT_CONTACTLESS.length,
					Defaults.LABEL_CONTACTLESS,
					(short) Defaults.LABEL_CONTACTLESS.length, (byte) 0x01,
					true,
					Defaults.PPSE_KERNEL_IDENTIFIER,
					(short) Defaults.PPSE_KERNEL_IDENTIFIER.length);
			// Advertise SPI support in the PPSE FCI (EMV Contactless Book B v2.12
			// Annex C): the Terminal Categories Supported List (9F3E) and the
			// Supported Data Object List (9F3F), both inside BF0C.
			entries = Tlv.append(TlvTags.TAG_TERMINAL_CATEGORIES_SUPPORTED,
					Defaults.SPI_TERMINAL_CATEGORIES, (short)0,
					(short) Defaults.SPI_TERMINAL_CATEGORIES.length, scratch1, entries);
			entries = Tlv.append(TlvTags.TAG_SDOL, Defaults.SPI_SDOL, (short)0,
					(short) Defaults.SPI_SDOL.length, scratch1, entries);
			contentLength = DirectoryBuilder.buildPpseA5(scratch1, entries, scratch2);
			content = scratch2;
		}
		byte[] aid = directoryAid();
		// Defensive bounds check: Tlv.appendFci does not bound its output, and
		// the FCI template is limited to 252 bytes (EMV v4.4 Book 1 §11.3.4).
		short valueLength = (short) (2 + aid.length + contentLength);
		if ((short) (1 + Tlv.lengthSize(valueLength) + valueLength) > fci.length) {
			ISOException.throwIt(SW_WRONG_DATA);
		}
		fciLength = Tlv.appendFci(aid, (short)0, (short)aid.length,
				content, (short)0, contentLength, fci, (short)0);
		return fci;
	}

	protected short getFCILength() {
		if (fciLength == 0) {
			getFCI();
		}
		return fciLength;
	}

	/**
	 * Handles the directory command set.
	 * 
	 * @see card42.EMVAppletBase#processCommand(javacard.framework.APDU, byte[])
	 */
	protected void processCommand(APDU apdu, byte[] apduBuffer) {
		// CARD BLOCK disables every application; no command is served
		// (EMV v4.4 Book 3 §6.5.3).
		if (protocolState.getLifecycle() == EMVRoles.CARD_BLOCKED || isCardBlocked()) {
			ISOException.throwIt(SW_FUNC_NOT_SUPPORTED); // 6A81
		}

		byte ins = apduBuffer[OFFSET_INS];

		switch (ins) {
		case EMVCommands.INS_READ_RECORD: // 0xB2
			// P2 b3-b1 must be 100 (EMV v4.4 Book 3 Table 22 / EMV v4.4 Book 1 Table 4); other values are RFU.
			if ((apduBuffer[OFFSET_P2] & 0x07) != 0x04) {
				ISOException.throwIt(SW_FUNC_NOT_SUPPORTED); // 6A81
			}
			if (protocolState.getDirectoryType() != EMVRoles.DIR_PSE) {
				// PPSE embeds its candidate list in the FCI (docs/specs/common/architecture.md §6).
				ISOException.throwIt(SW_FILE_NOT_FOUND);
			}
			short sfi = (short) ((apduBuffer[OFFSET_P2] & 0xFF) >> 3);
			if (sfi != directorySfi) {
				// Only the directory file advertised by '88' is served; any other
				// SFI is a missing file (EMV v4.4 Book 3 §6.5.11).
				ISOException.throwIt(SW_FILE_NOT_FOUND);
			}
			short rec = (short) (apduBuffer[OFFSET_P1] & 0xFF);
			short key = (short) ((sfi << 8) | rec);
			short offset = records.offsetOf(key);
			if (offset >= 0) {
				apdu.setOutgoing();
				apdu.setOutgoingLength(records.lengthOf(key));
				apdu.sendBytesLong(records.pool(), offset, records.lengthOf(key));
				break;
			}
			if (rec == 1) {
				// The built-in default record 1 when no DGI was personalized
				// (EMV v4.4 Book 1 §12.2.3).  It only depends on the directory
				// type, which is fixed for this instance, so it is built once
				// and reused instead of rewriting the 128-byte record buffer on
				// every READ RECORD (perso clears directoryRecordLength).
				if (directoryRecordLength == 0) {
					buildDefaultRecord();
				}
				apdu.setOutgoing();
				apdu.setOutgoingLength(directoryRecordLength);
				apdu.sendBytesLong(directoryRecord, (short)0, directoryRecordLength);
				break;
			}
			// The directory file exists but has no such record
			// (EMV v4.4 Book 3 §6.5.11).
			ISOException.throwIt(SW_RECORD_NOT_FOUND); // 6A83
			break;

		case EMVCommands.INS_SEND_POI_INFORMATION: // 0x1A
			// SEND POI INFORMATION is a PPSE command (EMV Contactless Book B v2.12
			// Annex C): the terminal sends its POI data and the card returns the
			// candidate-list FCI, optionally adjusted for the Terminal Category.
			if (protocolState.getDirectoryType() != EMVRoles.DIR_PPSE) {
				ISOException.throwIt(SW_FUNC_NOT_SUPPORTED); // 6A81
			}
			if (apduBuffer[OFFSET_P1] != 0x00 || apduBuffer[OFFSET_P2] != 0x00) {
				ISOException.throwIt(SW_FUNC_NOT_SUPPORTED); // 6A81
			}
			short lc = ApduIo.receive(apdu, apduBuffer);
			validateSpiCommand(apduBuffer, OFFSET_CDATA, lc);
			byte[] spiFci = getFCI();
			short spiLength = getFCILength();
			apdu.setOutgoing();
			apdu.setOutgoingLength(spiLength);
			apdu.sendBytesLong(spiFci, (short)0, spiLength);
			break;

		default:
			ISOException.throwIt(SW_INS_NOT_SUPPORTED);
			break;
		}
	}

	/**
	 * Validates the SEND POI INFORMATION command data (EMV Contactless Book B
	 * v2.12 Annex C): a '83' Command Template whose value is the SDOL-requested
	 * data followed by one or more POI Information objects (ID(2) L(1) V).
	 * Throws 6A80 on any violation.  The card serves a single candidate list, so
	 * the Terminal Category is parsed but does not change the selection.
	 */
	private static void validateSpiCommand(byte[] buf, short off, short len) {
		if (len < 2 || (buf[off] & 0xFF) != TlvTags.TAG_COMMAND_TEMPLATE) {
			ISOException.throwIt(SW_WRONG_DATA); // 6A80
		}
		short lenOff = Tlv.lengthOffset(buf, off);
		short lengthField = Tlv.lengthFieldLength(buf, lenOff);
		if (lengthField == 0) {
			ISOException.throwIt(SW_WRONG_DATA);
		}
		short valueOff = Tlv.valueOffset(buf, off);
		short valueLen = Tlv.getLength(buf, lenOff);
		if (valueLen < 0 || (short) (valueOff + valueLen) > (short) (off + len)) {
			ISOException.throwIt(SW_WRONG_DATA);
		}
		short end = (short) (valueOff + valueLen);
		// Skip the data the card requested with its SDOL (tag/length pairs).
		short pos = valueOff;
		byte[] sdol = Defaults.SPI_SDOL;
		for (short p = 0; p < sdol.length; ) {
			p += (sdol[p] & 0x1F) == 0x1F ? (short) 2 : (short) 1;
			if (p >= sdol.length) {
				ISOException.throwIt(SW_WRONG_DATA);
			}
			pos += (short) (sdol[p] & 0xFF);
			p++;
		}
		if (pos > end) {
			ISOException.throwIt(SW_WRONG_DATA);
		}
		// A command carrying only SDOL data (no POI Information object) is
		// valid: the terminal only includes POI objects when its category is on
		// the card's list (EMV Contactless Book B v2.12 Annex C.1.3).
		while (pos < end) {
			if ((short) (pos + 3) > end) {
				ISOException.throwIt(SW_WRONG_DATA);
			}
			short poiLength = (short) (buf[(short) (pos + 2)] & 0xFF);
			pos += 3;
			if ((short) (pos + poiLength) > end) {
				ISOException.throwIt(SW_WRONG_DATA);
			}
			pos += poiLength;
		}
	}

	// --- Personalization (EMV CPS v2.0 Annex A) ---------

	protected void applyPersoDgi(short dgi, byte[] buf, short off, short len) {
		switch (dgi) {
		case TlvTags.DGI_FCI_RESPONSE:
			// EMV CPS v2.0 Annex A DGI '9102' SELECT response A5 template: the PSE requires the
			// directory SFI '88' and the PPSE the candidate list under 'BF0C'
			// (EMV CPS v2.0 Table A-21; EMV Contactless Book B v2.12 §3.3/Table 3-2).
			if (protocolState.getDirectoryType() == EMVRoles.DIR_PSE) {
				PersoRules.validatePseTemplate(buf, off, len);
				directorySfi = PersoRules.pseDirectorySfi(buf, off, len);
			} else {
				PersoRules.validatePpseTemplate(buf, off, len);
			}
			if (len > fciOverride.length) {
				ISOException.throwIt(SW_WRONG_DATA);
			}
			Util.arrayCopyNonAtomic(buf, off, fciOverride, (short)0, len);
			fciOverrideLength = len;
			fciLength = 0;
			sawFci = true;
			break;
		default:
			if (TlvTags.isRecordDgi(dgi)) {
				// EMV CPS v2.0 Annex A DGI '0101' directory record (a 70 { 61 { ... } } template).
				if (protocolState.getDirectoryType() == EMVRoles.DIR_PSE) {
					// The PSE record must be a well-formed 70 { 61 { 4F [, 50] [, 87] } }
					// template (EMV CPS v2.0 Annex A Table A-20).
					PersoRules.validatePseRecord(buf, off, len);
				}
				records.put(dgi, buf, off, len);
				directoryRecordLength = 0;
			} else {
				// Unrecognised DGI: the card must reject it (EMV CPS v2.0 §5.4.2.3).
				ISOException.throwIt(EMVStatus.SW_REFERENCED_DATA_NOT_FOUND); // 6A88
			}
			break;
		}
	}

	/** True once the EMV CPS v2.0 Annex A DGI '9102' FCI was seen. */
	protected boolean persoCheckComplete() {
		return sawFci;
	}

	/** Clears the directory personalization markers (see PersoHandler). */
	protected void resetPersoState() {
		sawFci = false;
		fciOverrideLength = 0;
		records.reset();
		directorySfi = (short) 1;
		directoryRecordLength = 0;
		fciLength = 0;
	}
}
