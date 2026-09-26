package card42.host.emrtd.aa;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.smartcardio.ResponseAPDU;

import card42.host.common.codec.DerWriter;
import card42.host.emrtd.lds.Dg15;
import card42.host.emrtd.transport.EmrtdTerminal;

/**
 * Terminal-side Active Authentication (ICAO Doc 9303-11 §6.1, H4.1): send an
 * 8-byte RND.IFD with INTERNAL AUTHENTICATE and verify the RSA signature with
 * the DG15 public key.
 *
 * <p>The card signs {@code M = RND.IC || RND.IFD} with the ISO/IEC 9796-2
 * Digital Signature Scheme 1 (message recovery, §6.1.2.2).  The response is the
 * signature sigma; the verifier recovers {@code M1 = RND.IC} and the embedded
 * {@code H(M)} and checks them against the RND.IFD it sent.
 */
public final class ActiveAuthentication {

    /** ISO/IEC 9796-2 trailer field option 1 (SHA-1). */
    private static final int TRAILER_SHA1 = 0xBC;
    /** ISO/IEC 9796-2 trailer field option 2 (rightmost octet). */
    private static final int TRAILER_OPTION2 = 0xCC;

    private ActiveAuthentication() {
    }

    /**
     * Runs AA with {@code challenge} (RND.IFD, 8 bytes) and returns true when
     * the recovered signature verifies against {@code dg15}.
     */
    public static boolean verify(EmrtdTerminal terminal, Dg15 dg15, byte[] challenge)
            throws Exception {
        ResponseAPDU r = terminal.internalAuthenticate(challenge);
        if (r.getSW() != 0x9000) {
            throw new IllegalStateException("INTERNAL AUTHENTICATE failed: "
                    + Integer.toHexString(r.getSW()));
        }
        return verifySignature(dg15, challenge, r.getData());
    }

    /**
     * Verifies an AA response independently of the transport: recovers the
     * ISO/IEC 9796-2 Scheme 1 message with the DG15 public key and checks the
     * hash over {@code M1 || RND.IFD}.
     */
    public static boolean verifySignature(Dg15 dg15, byte[] rndIfd, byte[] signature)
            throws Exception {
        if (dg15.ecdsa) {
            return verifyEcdsa(dg15.toPublicKey(), rndIfd, signature, "SHA-256");
        }
        return verifySignature(dg15.toPublicKey(), rndIfd, signature);
    }

    /**
     * Verifies an ECDSA Active Authentication response (Doc 9303-11 §6.1.2.3):
     * the signed message is RND.IFD and the signature uses the plain TR-03111
     * format {@code r || s}, converted here to the DER form the JDK expects.
     */
    public static boolean verifyEcdsa(PublicKey key, byte[] rndIfd, byte[] signature,
                                      String hashName) throws Exception {
        int coordinate = (ecFieldSize(key) + 7) / 8;
        if (signature.length != 2 * coordinate) {
            return false;
        }
        BigInteger r = new BigInteger(1, Arrays.copyOfRange(signature, 0, coordinate));
        BigInteger s = new BigInteger(1, Arrays.copyOfRange(signature, coordinate, 2 * coordinate));
        byte[] der = DerWriter.sequence(DerWriter.integer(r), DerWriter.integer(s));
        Signature verifier = Signature.getInstance(
                hashName.replace("-", "") + "withECDSA");
        verifier.initVerify(key);
        verifier.update(rndIfd);
        return verifier.verify(der);
    }

    private static int ecFieldSize(PublicKey key) {
        java.security.interfaces.ECPublicKey ec = (java.security.interfaces.ECPublicKey) key;
        return ec.getParams().getCurve().getField().getFieldSize();
    }

    /** As above with a raw JCE public key (also used by the pure-JVM tests). */
    public static boolean verifySignature(PublicKey publicKey, byte[] rndIfd, byte[] signature)
            throws Exception {
        Cipher rsa = Cipher.getInstance("RSA/ECB/NoPadding");
        rsa.init(Cipher.DECRYPT_MODE, publicKey);
        byte[] block = rsa.doFinal(signature);
        if (block.length < 2) {
            return false;
        }

        // Trailer: option 1 (0xBC, SHA-1) or option 2 (hash id || 0xCC).
        int trailerLength;
        String hashName;
        int last = block[block.length - 1] & 0xFF;
        if (last == TRAILER_SHA1) {
            trailerLength = 1;
            hashName = "SHA-1";
        } else if (last == TRAILER_OPTION2) {
            trailerLength = 2;
            switch (block[block.length - 2] & 0xFF) {
            case 0x34:
                hashName = "SHA-256";
                break;
            case 0x36:
                hashName = "SHA-384";
                break;
            case 0x35:
                hashName = "SHA-512";
                break;
            default:
                return false;
            }
        } else {
            return false; // not an ISO/IEC 9796-2 Scheme 1 signature
        }

        MessageDigest digest = MessageDigest.getInstance(hashName);
        int digestLength = digest.getDigestLength();
        int paddedMessageLength = block.length - trailerLength - digestLength;

        // Header: bits 8-7 = 01 and bit 6 = 1 for partial recovery.
        if ((block[0] & 0xC0) != 0x40 || (block[0] & 0x20) == 0) {
            return false;
        }
        // Padding ends at the first octet whose low nibble is 0xA; M1 follows.
        int separator = -1;
        for (int i = 0; i < block.length; i++) {
            if ((block[i] & 0x0F) == 0x0A) {
                separator = i;
                break;
            }
        }
        if (separator < 0 || paddedMessageLength <= separator + 1) {
            return false;
        }
        byte[] recovered = Arrays.copyOfRange(block, separator + 1, paddedMessageLength);
        byte[] embeddedHash = Arrays.copyOfRange(block, paddedMessageLength,
                paddedMessageLength + digestLength);

        // M = M1 || RND.IFD.
        digest.update(recovered);
        digest.update(rndIfd);
        byte[] computed = digest.digest();
        return MessageDigest.isEqual(embeddedHash, computed);
    }
}
