package card42.host.emrtd.ta;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * A card-verifiable (CV) certificate (BSI TR-03110-3 C.1, Table 23):
 * {@code 7F21 { 7F4E <body>, 5F37 <signature> }}.  The body nests the profile
 * identifier, the certification authority reference, the public key, the
 * certificate holder reference, the CHAT, the effective/expiration dates and,
 * for CVCA/DV certificates, the application authorization extensions.
 */
public final class CvCertificate {

    /** Public-key/signature OIDs supported for the terminal certificate. */
    public static final String OID_TA_ECDSA_SHA_256 = "0.4.0.127.0.7.2.2.2.2.3";
    public static final String OID_TA_RSA_PSS_SHA_256 = "0.4.0.127.0.7.2.2.2.1.4";

    /** Application authorization extension OIDs (ICAO Doc 9303-10 Table 99, §5.4.2). */
    public static final String OID_LDS2_TRAVEL = "2.23.136.1.1.9.1.3";
    public static final String OID_LDS2_VISA = "2.23.136.1.1.9.2.3";
    public static final String OID_LDS2_BIOMETRICS = "2.23.136.1.1.9.3.3";

    private final int profileId;
    private final CvcPrincipal car;
    private final String publicKeyOid;
    private final byte[] ecPublicKey;
    private final byte[] rsaModulus;
    private final byte[] rsaExponent;
    private final CvcPrincipal chr;
    private final Chat chat;
    private final String effectiveDate;
    private final String expirationDate;
    private final Map<String, byte[]> authorizationExtensions;
    private final byte[] signature;
    private final byte[] body;
    private final byte[] encoded;

    CvCertificate(int profileId, CvcPrincipal car, String publicKeyOid, byte[] ecPublicKey,
                  byte[] rsaModulus, byte[] rsaExponent, CvcPrincipal chr, Chat chat,
                  String effectiveDate, String expirationDate,
                  Map<String, byte[]> authorizationExtensions, byte[] signature, byte[] body,
                  byte[] encoded) {
        this.profileId = profileId;
        this.car = car;
        this.publicKeyOid = publicKeyOid;
        this.ecPublicKey = ecPublicKey;
        this.rsaModulus = rsaModulus;
        this.rsaExponent = rsaExponent;
        this.chr = chr;
        this.chat = chat;
        this.effectiveDate = effectiveDate;
        this.expirationDate = expirationDate;
        this.authorizationExtensions = new LinkedHashMap<String, byte[]>(authorizationExtensions);
        this.signature = signature;
        this.body = body;
        this.encoded = encoded;
    }

    CvCertificate(int profileId, CvcPrincipal car, String publicKeyOid, byte[] ecPublicKey,
                  CvcPrincipal chr, Chat chat, String effectiveDate, String expirationDate,
                  Map<String, byte[]> authorizationExtensions, byte[] signature, byte[] body,
                  byte[] encoded) {
        this(profileId, car, publicKeyOid, ecPublicKey, null, null, chr, chat, effectiveDate,
                expirationDate, authorizationExtensions, signature, body, encoded);
    }

    public int profileId() {
        return profileId;
    }

    public CvcPrincipal certificationAuthorityReference() {
        return car;
    }

    public CvcPrincipal certificateHolderReference() {
        return chr;
    }

    /** The public-key algorithm OID (e.g. {@link #OID_TA_ECDSA_SHA_256}). */
    public String publicKeyOid() {
        return publicKeyOid;
    }

    /** The uncompressed EC public point {@code 0x04||X||Y}, or null for RSA. */
    public byte[] ecPublicKey() {
        return ecPublicKey == null ? null : java.util.Arrays.copyOf(ecPublicKey, ecPublicKey.length);
    }

    public boolean isEc() {
        return ecPublicKey != null;
    }

    /** The RSA public modulus, or null for EC. */
    public byte[] rsaModulus() {
        return rsaModulus == null ? null : java.util.Arrays.copyOf(rsaModulus, rsaModulus.length);
    }

    /** The RSA public exponent, or null for EC. */
    public byte[] rsaExponent() {
        return rsaExponent == null ? null
                : java.util.Arrays.copyOf(rsaExponent, rsaExponent.length);
    }

    public boolean isRsa() {
        return rsaModulus != null;
    }

    public Chat chat() {
        return chat;
    }

    public String effectiveDate() {
        return effectiveDate;
    }

    public String expirationDate() {
        return expirationDate;
    }

    /** Application OID to relative authorization bits (may be empty). */
    public Map<String, byte[]> authorizationExtensions() {
        Map<String, byte[]> copy = new LinkedHashMap<String, byte[]>();
        for (Map.Entry<String, byte[]> e : authorizationExtensions.entrySet()) {
            copy.put(e.getKey(), java.util.Arrays.copyOf(e.getValue(), e.getValue().length));
        }
        return Collections.unmodifiableMap(copy);
    }

    /** The signature bytes (TR-03111 plain {@code r||s} for the ECDSA profile). */
    public byte[] signature() {
        return java.util.Arrays.copyOf(signature, signature.length);
    }

    /** The encoded certificate body TLV ({@code 7F4E ...}) that the signature covers. */
    public byte[] body() {
        return java.util.Arrays.copyOf(body, body.length);
    }

    /** The encoded certificate TLV ({@code 7F21 ...}). */
    public byte[] encoded() {
        return java.util.Arrays.copyOf(encoded, encoded.length);
    }
}
