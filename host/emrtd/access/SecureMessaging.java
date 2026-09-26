package card42.host.emrtd.access;

import java.security.GeneralSecurityException;

/**
 * Terminal-side ISO/IEC 7816-4 secure messaging (BAC, PACE 3DES or PACE AES).
 * The two implementations differ only in the cipher/MAC primitives.
 */
public interface SecureMessaging {

    /** Wraps the command data field; returns {@code [DO87] [DO97] DO8E}. */
    byte[] wrapCommand(int cla, int ins, int p1, int p2, byte[] data, int le)
            throws GeneralSecurityException;

    /** Unwraps the response data field {@code [DO87] DO99 DO8E}. */
    byte[] unwrapResponse(byte[] data, short[] swOut) throws GeneralSecurityException;

    long getSendSequenceCounter();
}
