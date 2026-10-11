package card42.host.emrtd.ta;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import card42.host.common.codec.Der;
import card42.host.common.codec.DerWriter;

/**
 * Reads and writes CV certificates (BSI TR-03110-3 C.1/Appendix D).  The body
 * is kept byte-for-byte so it can be sent to {@code PSO:Verify Certificate} and
 * so the signature (which covers the body TLV, tag and length included, C.1.8)
 * can be verified.
 */
public final class CvCertificateCodec {

    private CvCertificateCodec() {
    }

    // CV certificate data-object tags (BSI TR-03110-3 Table 27).
    static final int TAG_CV_CERTIFICATE = 0x7F21;
    static final int TAG_CERT_BODY = 0x7F4E;
    static final int TAG_SIGNATURE = 0x5F37;
    static final int TAG_PROFILE_ID = 0x5F29;
    static final int TAG_CAR = 0x42;
    static final int TAG_PUBLIC_KEY = 0x7F49;
    static final int TAG_CHR = 0x5F20;
    static final int TAG_CHAT = 0x7F4C;
    static final int TAG_EFFECTIVE = 0x5F25;
    static final int TAG_EXPIRATION = 0x5F24;
    static final int TAG_EXTENSIONS = 0x65;
    static final int TAG_DISCRETIONARY_TEMPLATE = 0x73;
    static final int TAG_OID = 0x06;
    static final int TAG_DISCRETIONARY = 0x53;
    static final int TAG_EC_PUBLIC_POINT = 0x86;

    /** Parses a CV certificate TLV. */
    public static CvCertificate parse(byte[] certificate) {
        Der.Tlv root = Der.read(certificate, 0);
        if (root.tag != TAG_CV_CERTIFICATE) {
            throw new IllegalArgumentException("not a CV certificate (tag 7F21)");
        }
        Der.Tlv bodyTlv = null;
        Der.Tlv signatureTlv = null;
        for (Der.Tlv child : Der.children(certificate, root)) {
            if (child.tag == TAG_CERT_BODY) {
                bodyTlv = child;
            } else if (child.tag == TAG_SIGNATURE) {
                signatureTlv = child;
            }
        }
        if (bodyTlv == null || signatureTlv == null) {
            throw new IllegalArgumentException("CV certificate needs a body (7F4E) and signature (5F37)");
        }

        int profileId = 0;
        CvcPrincipal car = null;
        String publicKeyOid = null;
        byte[] ecPublicKey = null;
        CvcPrincipal chr = null;
        Chat chat = null;
        String effective = null;
        String expiration = null;
        Map<String, byte[]> extensions = new LinkedHashMap<String, byte[]>();

        for (Der.Tlv field : Der.children(certificate, bodyTlv)) {
            switch (field.tag) {
            case TAG_PROFILE_ID:
                profileId = Der.intValue(certificate, field);
                break;
            case TAG_CAR:
                car = CvcPrincipal.parse(certificate, field.valueOffset, field.valueLength);
                break;
            case TAG_PUBLIC_KEY:
                PublicKey parsed = parsePublicKey(certificate, field);
                publicKeyOid = parsed.oid;
                ecPublicKey = parsed.ecPoint;
                break;
            case TAG_CHR:
                chr = CvcPrincipal.parse(certificate, field.valueOffset, field.valueLength);
                break;
            case TAG_CHAT:
                chat = Chat.parse(certificate, field);
                break;
            case TAG_EFFECTIVE:
                effective = date(certificate, field);
                break;
            case TAG_EXPIRATION:
                expiration = date(certificate, field);
                break;
            case TAG_EXTENSIONS:
                parseExtensions(certificate, field, extensions);
                break;
            default:
                break;
            }
        }
        if (car == null || chr == null || chat == null || publicKeyOid == null) {
            throw new IllegalArgumentException("CV certificate body is incomplete");
        }
        return new CvCertificate(profileId, car, publicKeyOid, ecPublicKey, chr, chat,
                effective, expiration, extensions,
                Der.value(certificate, signatureTlv), Der.encoded(certificate, bodyTlv),
                Der.encoded(certificate, root));
    }

    /** The {@code 5F37} signature TLV for the signature value (DO in PSO data). */
    public static byte[] signatureTlv(byte[] signature) {
        return DerWriter.tlv(TAG_SIGNATURE, signature);
    }

    /** Parses a concatenation of DER CV certificates (issuer-first). */
    public static java.util.List<CvCertificate> parseChain(byte[] certificates) {
        java.util.List<CvCertificate> out = new java.util.ArrayList<CvCertificate>();
        int off = 0;
        while (off < certificates.length) {
            Der.Tlv tlv = Der.read(certificates, off);
            if (tlv.tag != TAG_CV_CERTIFICATE) {
                throw new IllegalArgumentException("chain entry is not a CV certificate (tag 7F21)");
            }
            out.add(parse(java.util.Arrays.copyOfRange(certificates, off, tlv.end)));
            off = tlv.end;
        }
        return out;
    }

    /** Encodes a complete CV certificate around an already-encoded body and signature. */
    public static byte[] encode(byte[] body, byte[] signature) {
        return DerWriter.tlv(TAG_CV_CERTIFICATE, DerWriter.concat(body, signatureTlv(signature)));
    }

    /** Encodes a certificate body (not signed). */
    public static byte[] encodeBody(int profileId, CvcPrincipal car, String publicKeyOid,
                                    byte[] ecPublicKey, CvcPrincipal chr, Chat.Role role,
                                    byte[] relativeAuthorization, String effective,
                                    String expiration, Map<String, byte[]> extensions) {
        byte[] publicKey = DerWriter.tlv(TAG_PUBLIC_KEY, DerWriter.concat(
                DerWriter.oid(publicKeyOid), DerWriter.tlv(TAG_EC_PUBLIC_POINT, ecPublicKey)));
        byte[] chat = Chat.encode(role, relativeAuthorization);
        return DerWriter.tlv(TAG_CERT_BODY, DerWriter.concat(
                DerWriter.tlv(TAG_PROFILE_ID, new byte[] { (byte) profileId }),
                DerWriter.tlv(TAG_CAR, car.encode()),
                publicKey,
                DerWriter.tlv(TAG_CHR, chr.encode()),
                chat,
                DerWriter.tlv(TAG_EFFECTIVE, dateBytes(effective)),
                DerWriter.tlv(TAG_EXPIRATION, dateBytes(expiration)),
                extensions.isEmpty() ? new byte[0] : encodeExtensions(extensions)));
    }

    private static final class PublicKey {
        String oid;
        byte[] ecPoint;
    }

    private static PublicKey parsePublicKey(byte[] der, Der.Tlv publicKey) {
        PublicKey out = new PublicKey();
        for (Der.Tlv field : Der.children(der, publicKey)) {
            if (field.tag == TAG_OID) {
                out.oid = Der.oid(der, field);
            } else if (field.tag == TAG_EC_PUBLIC_POINT) {
                out.ecPoint = Der.value(der, field);
            }
        }
        if (out.oid == null) {
            throw new IllegalArgumentException("public key without an algorithm OID");
        }
        return out;
    }

    private static void parseExtensions(byte[] der, Der.Tlv extensions, Map<String, byte[]> out) {
        for (Der.Tlv template : Der.children(der, extensions)) {
            if (template.tag != TAG_DISCRETIONARY_TEMPLATE) {
                continue;
            }
            String oid = null;
            byte[] bits = null;
            for (Der.Tlv field : Der.children(der, template)) {
                if (field.tag == TAG_OID) {
                    oid = Der.oid(der, field);
                } else if (field.tag == TAG_DISCRETIONARY) {
                    bits = Der.value(der, field);
                }
            }
            if (oid != null && bits != null) {
                out.put(oid, bits);
            }
        }
    }

    private static byte[] encodeExtensions(Map<String, byte[]> extensions) {
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        for (Map.Entry<String, byte[]> e : extensions.entrySet()) {
            byte[] template = DerWriter.tlv(TAG_DISCRETIONARY_TEMPLATE, DerWriter.concat(
                    DerWriter.oid(e.getKey()), DerWriter.tlv(TAG_DISCRETIONARY, e.getValue())));
            out.write(template, 0, template.length);
        }
        return DerWriter.tlv(TAG_EXTENSIONS, out.toByteArray());
    }

    /** 6-octet unpacked BCD {@code YYMMDD} (TR-03110-3 D.2.1.3). */
    private static byte[] dateBytes(String yymmdd) {
        if (yymmdd == null || yymmdd.length() != 6) {
            throw new IllegalArgumentException("date must be YYMMDD");
        }
        byte[] out = new byte[6];
        for (int i = 0; i < 6; i++) {
            char c = yymmdd.charAt(i);
            if (c < '0' || c > '9') {
                throw new IllegalArgumentException("date must be YYMMDD");
            }
            out[i] = (byte) (c - '0');
        }
        return out;
    }

    private static String date(byte[] der, Der.Tlv tlv) {
        byte[] value = Der.value(der, tlv);
        if (value.length != 6) {
            throw new IllegalArgumentException("date is not 6 bytes");
        }
        StringBuilder out = new StringBuilder(6);
        for (byte b : value) {
            int digit = b & 0xFF;
            if (digit > 9) {
                throw new IllegalArgumentException("date is not unpacked BCD");
            }
            out.append((char) ('0' + digit));
        }
        return out.toString();
    }
}
