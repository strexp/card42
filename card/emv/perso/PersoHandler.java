package card42.emv;

import card42.common.*;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;

/* STORE DATA personalization handling, shared by both applets.
 *
 * The Security Domain forwards every STORE DATA command, byte for byte, to
 * Personalization.processData() (docs/specs/emv/personalization.md §1); the SD
 * has already checked the SCP03 MAC and the block number, so no applet-level
 * authentication is required.  The SD does *not* reassemble blocks, so the DGI
 * sequence is accumulated in a per-instance buffer and applied when the block
 * with P1.bit8 set (the last one) arrives.  The Security Domain already holds a
 * transaction over processData (EMV CPS v2.0 §4.3.4.5), so no nested
 * transaction is opened here.
 *
 * The class deliberately avoids CLEAR_ON_DESELECT transient arrays: processData
 * runs while the applet is not selected (docs/specs/emv/personalization.md §1).
 *
 * @author card42
 */

public class PersoHandler implements ISO7816 {

    /** Maximum size of one instance's complete DGI sequence (docs/specs/emv/personalization.md §1). */
    private static final short BUFFER_SIZE = (short) 2048;

    private final EMVAppletBase applet;

    /** Reassembly buffer for the DGI sequence of the current session. */
    private final byte[] buffer;
    private short bufferLength;

    /** Expected P2 of the next block; the first block must be P2=0
     * (EMV CPS v2.0 §4.3.4.6). */
    private short expectedBlock;

    public PersoHandler(EMVAppletBase applet) {
        this.applet = applet;
        buffer = new byte[BUFFER_SIZE];
        reset();
    }

    private void reset() {
        bufferLength = 0;
        expectedBlock = 0;
    }

    /**
     * GP path: the SD passes the complete STORE DATA command
     * (CLA INS P1 P2 Lc <data>) in inBuf, starting at inOff.
     */
    public short processData(byte[] inBuf, short inOff, short inLen,
                             byte[] outBuf, short outOff) {
        // The applet is not selected here, so make sure the role-dependent
        // data has been built (JCSystem.getAID() works in the applet context).
        applet.initIfNeeded();

        // The SD is expected to forward a well-formed STORE DATA command, but do
        // not index past a truncated buffer if it does not (docs/specs/common/architecture.md §2).
        if (inLen < (short) (OFFSET_LC + 1)) {
            ISOException.throwIt(SW_WRONG_LENGTH); // 6700
        }
        short p1 = (short) (inBuf[(short) (inOff + OFFSET_P1)] & 0xFF);
        short p2 = (short) (inBuf[(short) (inOff + OFFSET_P2)] & 0xFF);
        // Lc is 1 or 3 bytes (EMV CPS v2.0 Table 4-8): a leading '00' introduces
        // the two-byte extended length.
        short lcOffset = (short) (inOff + OFFSET_LC);
        short lcField = PersoRules.storeDataLcFieldLength(inBuf, lcOffset,
                (short) (inOff + inLen));
        if (lcField == 0) {
            ISOException.throwIt(SW_WRONG_LENGTH); // 6700
        }
        short lc = PersoRules.storeDataLc(inBuf, lcOffset, lcField);
        short dataOffset = (short) (lcOffset + lcField);
        // Lc must describe data that is actually present in the command; a
        // length inconsistency is 6A80 (EMV CPS v2.0 §4.3.4.5).
        if (inLen < (short) ((dataOffset - inOff) + lc)) {
            ISOException.throwIt(SW_WRONG_DATA); // 6A80
        }
        return handleBlock(p1, p2, inBuf, dataOffset, lc, outBuf, outOff);
    }

    /**
     * Shared block handling.  The Security Domain has already authenticated the
     * block (SCP03 MAC and block order) before it is forwarded here.
     */
    private short handleBlock(short p1, short p2, byte[] src, short off, short len,
                              byte[] outBuf, short outOff) {
        if (applet.protocolState.getLifecycle() != EMVRoles.PERSONALISATION) {
            // Already personalized: STORE DATA is refused (docs/specs/common/architecture.md §3).
            ISOException.throwIt(SW_CONDITIONS_NOT_SATISFIED);
        }

        // P2=0 starts a new DGI sequence (EMV CPS v2.0 §4.3.4.6; note 10 allows
        // the ICC to ignore P2).  Discard any half-received previous sequence
        // and clear the applet's completion markers so an aborted attempt
        // cannot make an incomplete retry look complete.
        if (p2 == 0) {
            if (expectedBlock != 0 || bufferLength != 0) {
                reset();
            }
            applet.resetPersoState();
        }
        if (p2 != expectedBlock) {
            ISOException.throwIt((short) 0x6A86);
        }
        if ((short) (bufferLength + len) > BUFFER_SIZE) {
            ISOException.throwIt(SW_WRONG_LENGTH);
        }
        Util.arrayCopyNonAtomic(src, off, buffer, bufferLength, len);
        bufferLength += len;

        // P1.b1 is "Response expected (R-MAC)" in EMV CPS v2.0 Table 4-9.
        // The project convention is to return an empty response body when it is
        // clear (GPPro --store-dgi-file sets b1=0); this is a tooling
        // convention, not a CPS rule.
        boolean allowReport = (p1 & 0x01) != 0;

        boolean last = (p1 & EMVCommands.STORE_DATA_LAST_BLOCK) != 0;
        if (!last) {
            expectedBlock++;
            return allowReport ? report(outBuf, outOff, (byte) 0x00, (byte) 0x00) : (short) 0;
        }

        short dgiCount;
        try {
            dgiCount = applyAll();
        } catch (ISOException e) {
            // Start the next personalization attempt from block 0 and clear the
            // completion markers of the aborted attempt.
            reset();
            applet.resetPersoState();
            throw e;
        }
        reset();
        return allowReport ? report(outBuf, outOff, (byte) 0x01, (byte) dgiCount) : (short) 0;
    }

    /**
     * Parses and applies the whole DGI sequence and checks the completion
     * marker.  Throws 6A80 if it is incomplete or invalid.
     *
     * The Security Domain runs {@code Personalization.processData} inside its
     * own STORE DATA transaction and rolls the whole personalization back on
     * failure, so the applet does not open a nested transaction of its own
     * (EMV CPS v2.0 §4.3.4.5; GP {@code Personalization.processData}).  A
     * nested {@code JCSystem.beginTransaction()} would overflow the shared
     * transaction buffer for a large DGI sequence, as observed on the Java Card
     * simulator.
     */
    private short applyAll() {
        short dgiCount = 0;
        try {
            DgiReader reader = new DgiReader(buffer, (short) 0, bufferLength);
            while (reader.hasNext()) {
                reader.next();
                applet.applyPersoDgi(reader.dgi(), buffer,
                        reader.valueOffset(), reader.valueLength());
                dgiCount++;
            }
            if (!applet.persoCheckComplete()) {
                ISOException.throwIt(SW_WRONG_DATA);
            }
            applet.persoComplete();
        } catch (Exception e) {
            // ISOException is propagated unchanged, a CryptoException maps to
            // 6985 and any other failure to 6F00 (docs/specs/common/cryptography.md §9).
            PersoErrors.throwMapped(e);
        }
        return dgiCount;
    }

    /**
     * Builds the personalization report: status, DGI count and the currently
     * available persistent memory (docs/specs/common/architecture.md §2,
     * docs/specs/common/risks.md).  The memory is reported as -1 (0xFFFF) when the
     * platform cannot answer the query.
     */
    private static short report(byte[] outBuf, short outOff, byte status, byte dgiCount) {
        outBuf[outOff] = status;
        outBuf[(short) (outOff + 1)] = dgiCount;
        short available = -1;
        try {
            available = JCSystem.getAvailableMemory(JCSystem.MEMORY_TYPE_PERSISTENT);
        } catch (Exception e) {
            available = -1;
        }
        outBuf[(short) (outOff + 2)] = (byte) (available >> 8);
        outBuf[(short) (outOff + 3)] = (byte) available;
        return 4;
    }
}
