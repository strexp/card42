package card42.host.emv.app.issuer;

import java.io.ByteArrayOutputStream;
import java.security.GeneralSecurityException;
import java.util.Arrays;

import card42.host.emv.crypto.AcCrypto;
import card42.host.common.util.Hex;
import card42.host.common.codec.TlvWriter;

/**
 * Issuer-side host simulation for the online closed loop (EMV v4.4 Book 2 §8.2,
 * EMV v4.4 Book 3 Annex C §C9.3/§C10, EMV v4.4 Book 3 §10.10).
 *
 * <p>It derives the AC session key from the ICC master key and the ATC,
 * computes ARPC Method 1/2, builds the Card Status Update (CSU) and assembles
 * issuer script templates (tags 71/72).  It reuses the terminal-side crypto
 * helpers ({@link AcCrypto}) so the card and the host cannot diverge; the
 * independent vectors live in the unit suites.
 *
 * <p>This is a product module: the CLI closed-loop issuer of
 * {@code terminal pay -icc-key=...} and the integration suites share it.
 */
public final class IssuerHost {

    // CSU byte 2 bit (EMV v4.4 Book 3 Annex C Table CCD 11).
    public static final int CSU_APPROVE = 0x80;

    private final byte[] iccAcKey;
    private byte[] arqc;
    private int atc;

    public IssuerHost(byte[] iccAcKey) {
        this.iccAcKey = iccAcKey;
    }

    /** Records the first GENERATE AC cryptogram and the ATC it was made with. */
    public void setFirstAc(byte[] firstAc, int atc) {
        this.arqc = Arrays.copyOf(firstAc, 8);
        this.atc = atc;
    }

    /** SK_AC, the AC/ARPC session key for the recorded ATC (Book 2 §A1.3.1). */
    public byte[] sessionKeyAc() throws GeneralSecurityException {
        return AcCrypto.sessionKey(iccAcKey, atc);
    }

    /** ARPC Method 2 (CCD inline, Book 2 §8.2.2). */
    public byte[] arpcMethod2(byte[] csu, byte[] proprietary)
            throws GeneralSecurityException {
        return AcCrypto.computeArpcMethod2(sessionKeyAc(), arqc, csu, proprietary);
    }

    /** A 4-byte CSU with the given byte 2 and PIN Try Counter (byte 1 b4-b1). */
    public static byte[] csu(int byte2, int pinTryCounter) {
        return new byte[] { (byte) (pinTryCounter & 0x0F), (byte) byte2, 0x00, 0x00 };
    }

    /**
     * The CCD inline Issuer Authentication Data (tag 91) for the second
     * GENERATE AC: ARPC Method 2 (4 bytes) followed by the CSU (4 bytes).
     */
    public byte[] inlineIssuerAuthData(int byte2, int pinTryCounter)
            throws GeneralSecurityException {
        byte[] csu = csu(byte2, pinTryCounter);
        return concat(arpcMethod2(csu, new byte[0]), csu);
    }

    /**
     * An issuer script template (EMV v4.4 Book 3 Figure 11): tag 71 (before the
     * final AC) or 72 (after it), an optional 9F18 Script Identifier and one 86
     * per Issuer Script Command.
     */
    public static byte[] script(int tag, String scriptIdHex, byte[]... commands) {
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        if (scriptIdHex != null) {
            TlvWriter.writeTlv(body, 0x9F18, Hex.parse(scriptIdHex));
        }
        for (byte[] command : commands) {
            TlvWriter.writeTlv(body, 0x86, command);
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        TlvWriter.writeTlv(out, tag, body.toByteArray());
        return out.toByteArray();
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }
}
