package card42.emv;

import card42.common.*;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;

/* The offline-data-authentication certificate material of a payment applet:
 * the SDA certificate chain, the SSAD and the ICC PIN / ICC DDA-CDA public key
 * certificates (EMV v4.4 Book 2 §5, §6.5, §7.2).
 *
 * It is filled by personalization (EMV CPS v2.0 Annex A record DGIs) and read by
 * RecordBuilder, which serves records 2-5.  Extracted from PaymentData so the
 * certificate field set is a separate data model rather than part of the
 * general payment field set.
 *
 * @author card42
 */

public class SdaCertificateData implements ISO7816 {

    /** CA Public Key Index ('8F'). */
    private byte caPublicKeyIndex;
    private boolean hasCaPublicKeyIndex;

    /**
     * SDA certificate chain (EMV v4.4 Book 2 §5).  The fields are bounded by the
     * Table 43 modulus limits: the Issuer Public Key Certificate (tag 90) is
     * signed by the CA and is at most NCA = 248 bytes, the SSAD (tag 93) and the
     * ICC certificates (tags 9F46/9F2D) are signed by the issuer and are at most
     * NI = 247 bytes (EMV v4.4 Book 2 Table 43, Annex D1.1).
     */
    private final byte[] issuerCert = new byte[(short) 256];
    private short issuerCertLength;
    private final byte[] issuerRemainder = new byte[(short) 48];
    private short issuerRemainderLength;
    private final byte[] issuerExponent = new byte[(short) 3];
    private short issuerExponentLength;
    private final byte[] ssad = new byte[(short) 256];
    private short ssadLength;
    private final byte[] sdaTagList = new byte[(short) 8];
    private short sdaTagListLength;

    /**
     * ICC PIN encipherment public key certificate (EMV v4.4 Book 2 §7.2),
     * returned by READ RECORD as 9F2D/9F2F/9F2E.
     */
    private final byte[] pinCert = new byte[(short) 256];
    private short pinCertLength;
    private final byte[] pinRemainder = new byte[(short) 48];
    private short pinRemainderLength;
    private final byte[] pinExponent = new byte[(short) 3];
    private short pinExponentLength;

    /**
     * ICC DDA/CDA public key certificate (EMV v4.4 Book 2 §6.5, §6.6),
     * returned by READ RECORD as 9F46/9F48/9F47.
     */
    private final byte[] iccCert = new byte[(short) 256];
    private short iccCertLength;
    private final byte[] iccRemainder = new byte[(short) 48];
    private short iccRemainderLength;
    private final byte[] iccExponent = new byte[(short) 3];
    private short iccExponentLength;

    public SdaCertificateData() {
    }

    /**
     * Applies one personalization tag to this field set.  Returns true when the
     * tag belongs to the certificate model, so the caller can leave it out of
     * its own switch.
     */
    public boolean apply(short tag, byte[] buf, short valueOffset, short valueLength) {
        switch (tag) {
        case TlvTags.TAG_CA_PUBLIC_KEY_INDEX:
            if (valueLength >= 1) {
                caPublicKeyIndex = buf[valueOffset];
                hasCaPublicKeyIndex = true;
            }
            return true;
        case TlvTags.TAG_ISSUER_PUBLIC_KEY_CERT:
            issuerCertLength = copyInto(buf, valueOffset, valueLength,
                    issuerCert, EMVStatus.RSA_MAX_CA_MODULUS);
            return true;
        case TlvTags.TAG_ISSUER_PUBLIC_KEY_REMAINDER:
            issuerRemainderLength = copyInto(buf, valueOffset, valueLength,
                    issuerRemainder, (short) 48);
            return true;
        case TlvTags.TAG_ISSUER_PUBLIC_KEY_EXPONENT:
            issuerExponentLength = copyInto(buf, valueOffset, valueLength,
                    issuerExponent, (short) 3);
            return true;
        case TlvTags.TAG_SIGNED_STATIC_APPLICATION_DATA:
            ssadLength = copyInto(buf, valueOffset, valueLength,
                    ssad, EMVStatus.RSA_MAX_ISSUER_MODULUS_SDA);
            return true;
        case TlvTags.TAG_SDA_TAG_LIST:
            sdaTagListLength = copyInto(buf, valueOffset, valueLength,
                    sdaTagList, (short) 8);
            return true;
        case TlvTags.TAG_ICC_PIN_PUBLIC_KEY_CERT:
            pinCertLength = copyInto(buf, valueOffset, valueLength,
                    pinCert, EMVStatus.RSA_MAX_ISSUER_MODULUS);
            return true;
        case TlvTags.TAG_ICC_PIN_PUBLIC_KEY_REMAINDER:
            pinRemainderLength = copyInto(buf, valueOffset, valueLength,
                    pinRemainder, (short) 48);
            return true;
        case TlvTags.TAG_ICC_PIN_PUBLIC_KEY_EXPONENT:
            pinExponentLength = copyInto(buf, valueOffset, valueLength,
                    pinExponent, (short) 3);
            return true;
        case TlvTags.TAG_ICC_PUBLIC_KEY_CERT:
            iccCertLength = copyInto(buf, valueOffset, valueLength,
                    iccCert, EMVStatus.RSA_MAX_ISSUER_MODULUS);
            return true;
        case TlvTags.TAG_ICC_PUBLIC_KEY_REMAINDER:
            iccRemainderLength = copyInto(buf, valueOffset, valueLength,
                    iccRemainder, (short) 48);
            return true;
        case TlvTags.TAG_ICC_PUBLIC_KEY_EXPONENT:
            iccExponentLength = copyInto(buf, valueOffset, valueLength,
                    iccExponent, (short) 3);
            return true;
        default:
            return false;
        }
    }

    /**
     * Copies src into a fixed-size field and returns the length.  A value that
     * does not fit is rejected with 6A80 rather than silently truncated: a
     * truncated certificate would be corrupt yet still reported as applied
     * (EMV CPS v2.0 §4.3.4.5).
     */
    private static short copyInto(byte[] src, short off, short len,
            byte[] dst, short max) {
        if (len > max) {
            ISOException.throwIt(SW_WRONG_DATA);
        }
        Util.arrayCopyNonAtomic(src, off, dst, (short) 0, len);
        return len;
    }

    // --- Accessors for RecordBuilder ---------------------------------------

    byte getCaPublicKeyIndex() {
        return hasCaPublicKeyIndex ? caPublicKeyIndex : (byte) 0x01;
    }

    boolean hasCaPublicKeyIndex() {
        return hasCaPublicKeyIndex;
    }

    byte[] getIssuerCert() {
        return issuerCert;
    }

    short getIssuerCertLength() {
        return issuerCertLength;
    }

    byte[] getIssuerRemainder() {
        return issuerRemainder;
    }

    short getIssuerRemainderLength() {
        return issuerRemainderLength;
    }

    byte[] getIssuerExponent() {
        return issuerExponent;
    }

    short getIssuerExponentLength() {
        return issuerExponentLength;
    }

    byte[] getSsad() {
        return ssad;
    }

    short getSsadLength() {
        return ssadLength;
    }

    byte[] getSdaTagList() {
        return sdaTagList;
    }

    short getSdaTagListLength() {
        return sdaTagListLength;
    }

    byte[] getPinCert() {
        return pinCert;
    }

    short getPinCertLength() {
        return pinCertLength;
    }

    byte[] getPinRemainder() {
        return pinRemainder;
    }

    short getPinRemainderLength() {
        return pinRemainderLength;
    }

    byte[] getPinExponent() {
        return pinExponent;
    }

    short getPinExponentLength() {
        return pinExponentLength;
    }

    byte[] getIccCert() {
        return iccCert;
    }

    short getIccCertLength() {
        return iccCertLength;
    }

    byte[] getIccRemainder() {
        return iccRemainder;
    }

    short getIccRemainderLength() {
        return iccRemainderLength;
    }

    byte[] getIccExponent() {
        return iccExponent;
    }

    short getIccExponentLength() {
        return iccExponentLength;
    }
}
