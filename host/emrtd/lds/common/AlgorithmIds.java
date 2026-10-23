package card42.host.emrtd.lds.common;

/**
 * Maps the PKCS#1 / NIST algorithm OIDs used by EF.SOD to the JDK digest and
 * signature algorithm names (H3.1/H3.5).
 */
public final class AlgorithmIds {

    private AlgorithmIds() {
    }

    /** RSASSA-PSS: the JDK returns "RSASSA-PSS" and the caller sets the parameters. */
    public static final String RSASSA_PSS = "RSASSA-PSS";

    /** A JDK {@code MessageDigest} name for a digest OID. */
    public static String digest(String oid) {
        switch (oid) {
        case "1.3.14.3.2.26":
            return "SHA-1";
        case "2.16.840.1.101.3.4.2.4":
            return "SHA-224";
        case "2.16.840.1.101.3.4.2.1":
            return "SHA-256";
        case "2.16.840.1.101.3.4.2.2":
            return "SHA-384";
        case "2.16.840.1.101.3.4.2.3":
            return "SHA-512";
        default:
            return oid;
        }
    }

    /**
     * A JDK {@code Signature} name for a signature algorithm OID.  RSASSA-PSS
     * maps to {@link #RSASSA_PSS}: the JDK needs the PSS parameters from the
     * AlgorithmIdentifier, which the caller supplies (RFC 4055).
     */
    public static String signature(String oid) {
        switch (oid) {
        case "1.2.840.113549.1.1.5":
            return "SHA1withRSA";
        case "1.2.840.113549.1.1.11":
            return "SHA256withRSA";
        case "1.2.840.113549.1.1.12":
            return "SHA384withRSA";
        case "1.2.840.113549.1.1.13":
            return "SHA512withRSA";
        case "1.2.840.113549.1.1.10":
            return RSASSA_PSS;
        case "1.2.840.10045.4.1":
            return "SHA1withECDSA";
        case "1.2.840.10045.4.3.1":
            return "SHA224withECDSA";
        case "1.2.840.10045.4.3.2":
            return "SHA256withECDSA";
        case "1.2.840.10045.4.3.3":
            return "SHA384withECDSA";
        case "1.2.840.10045.4.3.4":
            return "SHA512withECDSA";
        default:
            return oid;
        }
    }
}
