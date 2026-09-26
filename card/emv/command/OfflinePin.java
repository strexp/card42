package card42.emv;

import card42.common.*;

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;

/* The offline PIN of a payment instance: VERIFY with a plaintext (P2=80) or an
 * RSA-enciphered (P2=88) ISO 9564-1 format 2 PIN block (EMV v4.4 Book 2 §7.2).
 *
 * Both encodings are only served on a CONTACT instance: a contactless instance
 * advertises no CVM and answers VERIFY with 6985.  The plaintext block is the
 * fixed 8-byte EMV format of Book 3 Table 25, whose N nibble carries the PIN
 * length; the enciphered block carries the length in its ISO 9564-1 format 2
 * header.  The command data is passed in by the caller so the dispatcher can
 * hand over the accumulated data of a chained VERIFY (EMV v4.4 Book 3 §6.5.13);
 * check() validates the data-independent parts (role, lifecycle, P1/P2).
 *
 * The enciphered path follows EMV v4.4 Book 2 §7.2: the card recovers the modulus-length
 * block '7F' || PIN Block(8) || ICC UN(8) || random padding with the RSA Signing
 * Function, checks the data header and the ICC Unpredictable Number issued by
 * the preceding GET CHALLENGE, and only then checks the PIN.  A recovery or
 * binding failure is reported as 6984 (EMV v4.4 Book 3 §10.5.1).
 *
 * @author card42
 */

public class OfflinePin implements ISO7816 {

    private final OfflinePinState pin;
    private final PinCrypto pinCrypto;
    private final EMVProtocolState protocolState;

    public OfflinePin(OfflinePinState pin, PinCrypto pinCrypto, EMVProtocolState protocolState) {
        this.pin = pin;
        this.pinCrypto = pinCrypto;
        this.protocolState = protocolState;
    }

    /*
     * Validates the parts of a VERIFY command that do not depend on the command
     * data (role, lifecycle, P1 and P2), so the command-chaining dispatcher can
     * reject a bad fragment before it is accumulated (EMV v4.4 Book 3
     * §6.5.12.2, Table 23/24).
     */
    public void check(byte[] apduBuffer) {
        if (protocolState.getRole() == EMVRoles.ROLE_CONTACTLESS) {
            ISOException.throwIt(SW_CONDITIONS_NOT_SATISFIED); // No CVM required
        }
        if (protocolState.getLifecycle() != EMVRoles.READY) {
            ISOException.throwIt(SW_CONDITIONS_NOT_SATISFIED); // not personalized
        }
        // P1 is fixed to 00 (EMV v4.4 Book 3 §6.5.12.2, Table 23).
        if (apduBuffer[OFFSET_P1] != 0x00) {
            ISOException.throwIt(SW_FUNC_NOT_SUPPORTED); // 6A81
        }
        byte p2 = apduBuffer[OFFSET_P2];
        if (p2 != (byte) 0x80 && p2 != (byte) 0x88) {
            // Only transaction_data PIN (P2=80) and enciphered PIN (P2=88).
            ISOException.throwIt(SW_FUNC_NOT_SUPPORTED); // 6A81
        }
    }

    /*
     * The VERIFY command checks the offline PIN.  Two encodings are supported
     * (docs/specs/common/architecture.md §4, EMV v4.4 Book 2 §7.2), both only on a CONTACT instance:
     *
     *   - P2=80: plaintext offline PIN, the fixed 8-byte EMV Table 25 block;
     *   - P2=88: enciphered offline PIN, the RSA-enciphered Table 25 block
     *     recovered with the ICC PIN private key.
     *
     * The command data is passed explicitly (rather than read from apduBuffer)
     * so a chained VERIFY can hand the accumulated fragments to the same code
     * (EMV v4.4 Book 3 §6.5.13).
     */
    public void verify(APDU apdu, byte[] apduBuffer, byte[] response,
            byte[] data, short dataOff, short dataLen) {
        // A GET CHALLENGE challenge is valid only for the next command
        // (EMV v4.4 Book 3 §6.5.6.1): consume it whatever the outcome, so a
        // later VERIFY P2=88 cannot reuse an old ICC Unpredictable Number.
        boolean challengeValid = protocolState.isChallengeValid();
        protocolState.clearChallengeValid();

        check(apduBuffer);
        byte p2 = apduBuffer[OFFSET_P2];
        if (p2 == (byte) 0x80) {
            verifyPlaintextPin(apdu, data, dataOff, dataLen);
        } else {
            verifyEncryptedPin(apdu, data, dataOff, dataLen, challengeValid);
        }
    }

    private void verifyPlaintextPin(APDU apdu, byte[] data, short dataOff, short dataLen) {
        // EMV plaintext offline PIN block: a fixed 16-nibble = 8-byte field
        // 'C N P P P P P/F x8 F F' (EMV v4.4 Book 3 §6.5.12.2 Table 25).  C is
        // fixed to 0010, N is the 4..12 digit count; the remaining PIN nibbles
        // and the final byte are 'F' filler.  The declared Lc is therefore
        // always 8, independent of N.
        if (dataLen != 8) {
            ISOException.throwIt(SW_WRONG_LENGTH); // 6700: not the fixed 8-byte block
        }
        byte format = data[dataOff];
        short control = (short) ((format >> 4) & 0x0F);
        short digits = (short) (format & 0x0F);
        if (control != 2 || digits < 4 || digits > 12) {
            ISOException.throwIt(SW_WRONG_DATA); // 6A80: bad format byte
        }
        short pinLength = (short) ((short) (digits + 1) >> 1); // BCD bytes of N digits
        // Odd N: the low nibble of the last PIN byte is the filler 'F'.
        if ((digits & 1) != 0
                && (data[(short) (dataOff + pinLength)] & 0x0F) != 0x0F) {
            ISOException.throwIt(SW_WRONG_DATA); // 6A80: bad pad nibble
        }
        // Every nibble after the PIN digits (including the trailing 'F' byte)
        // must be filler (EMV v4.4 Book 3 §6.5.12.2 Table 25).
        for (short i = (short) (dataOff + 1 + pinLength); i < (short) (dataOff + 8); i++) {
            if (data[i] != (byte) 0xFF) {
                ISOException.throwIt(SW_WRONG_DATA); // 6A80: bad filler
            }
        }

        if (pin.getTriesRemaining() == 0) {
            ISOException.throwIt(EMVStatus.SW_PIN_BLOCKED); // PIN blocked
            return;
        }

        // The offline PIN is "performed" whether or not it verifies, so the CVR
        // can report both the performed and the not-successfully-verified bit
        // (EMV v4.4 Book 3 Annex C §9.2.3.2).
        protocolState.setCVMPerformed(EMVCodes.PLAINTEXT_PIN);
        if (pin.check(data, (short) (dataOff + 1), (byte) pinLength)) {
            apdu.setOutgoingAndSend((short) 0, (short) 0); // return 9000
        } else {
            ISOException.throwIt((short) ((short) (0x63C0) + (short) pin.getTriesRemaining()));
        }
    }

    /*
     * Enciphered offline PIN (EMV v4.4 Book 2 §7.2): recover the Table 25 block
     * with the RSA Signing Function, validate the data header '7F' and the ICC
     * Unpredictable Number from the preceding GET CHALLENGE, then check the
     * ISO 9564-1 format 2 PIN block.  A missing key or an unavailable challenge
     * yields 6985/6984, an unrecoverable block 6984, a malformed PIN block 6A80,
     * a wrong PIN 63Cx and a locked PIN 6983.
     */
    private void verifyEncryptedPin(APDU apdu, byte[] data, short dataOff, short dataLen,
            boolean challengeValid) {
        if (!pinCrypto.isAvailable()) {
            ISOException.throwIt(SW_CONDITIONS_NOT_SATISFIED); // no PIN key
        }
        if (!challengeValid) {
            // No ICC Unpredictable Number: the terminal must send GET CHALLENGE
            // immediately before VERIFY (EMV v4.4 Book 2 §7.2 step 2, EMV v4.4 Book 3 §6.5.6.1);
            // the block cannot be bound.
            ISOException.throwIt(EMVStatus.SW_REFERENCE_DATA_NOT_USABLE); // 6984
        }

        if (dataLen < 1) {
            ISOException.throwIt(SW_WRONG_LENGTH);
        }

        if (pin.getTriesRemaining() == 0) {
            ISOException.throwIt(EMVStatus.SW_PIN_BLOCKED); // PIN blocked
        }

        // The recovered block is the shared work scratch: no other large scratch
        // user is active during a VERIFY (docs/specs/common/risks.md).
        byte[] recovered = protocolState.getWorkScratch((short) 256);
        short blockLength = pinCrypto.recover(data, dataOff, dataLen,
                recovered, (short) 0);
        if (blockLength < 17) {
            ISOException.throwIt(EMVStatus.SW_REFERENCE_DATA_NOT_USABLE); // 6984: recovery failed
        }

        // The recovered block is sensitive: clear it however this method returns
        // (docs/specs/common/cryptography.md §9).
        try {
            // Data header (EMV v4.4 Book 2 Table 25 / §7.2 step 8).
            if (recovered[0] != (byte) 0x7F) {
                ISOException.throwIt(EMVStatus.SW_REFERENCE_DATA_NOT_USABLE); // 6984
            }
            // ICC Unpredictable Number (EMV v4.4 Book 2 Table 25 / §7.2 step 7).
            if (!challengeEquals(recovered, (short) 9)) {
                ISOException.throwIt(EMVStatus.SW_REFERENCE_DATA_NOT_USABLE); // 6984
            }
            // ISO 9564-1 format 2: high nibble 2, low nibble = number of digits.
            short format = (short) ((recovered[1] >> 4) & 0x0F);
            short digits = (short) (recovered[1] & 0x0F);
            if (format != 2 || digits < 4 || digits > 12) {
                ISOException.throwIt(SW_WRONG_DATA); // 6A80: bad PIN block format
            }
            short pinLength = (short) (digits + 1);
            pinLength = (short) (pinLength >> 1);

            protocolState.setCVMPerformed(EMVCodes.ENCRYPTED_PIN);
            // The PIN block starts at recovered[1]; its format byte is at
            // recovered[1] and the BCD digits at recovered[2].
            if (pin.check(recovered, (short) 2, (byte) pinLength)) {
                apdu.setOutgoingAndSend((short) 0, (short) 0); // return 9000
            } else {
                ISOException.throwIt((short) ((short) (0x63C0) + (short) pin.getTriesRemaining()));
            }
        } finally {
            // Never leave the recovered block in the transient buffer.
            Util.arrayFillNonAtomic(recovered, (short) 0, blockLength, (byte) 0);
        }
    }

    /** Constant-time comparison of the recovered ICC UN with the challenge. */
    private boolean challengeEquals(byte[] block, short off) {
        byte[] challenge = protocolState.getChallenge();
        return ConstantTime.equals(challenge, (short) 0, block, off, (short) 8);
    }
}
