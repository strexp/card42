package card42.host.emrtd.perso;

import java.io.File;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import card42.host.common.util.Hex;

/**
 * A human-readable eMRTD personalization script (H5.1/A2).  A section starts
 * with {@code @instance} and becomes one DGI sequence for one LDS1 instance:
 *
 * <pre>
 *   @instance &lt;AID-hex&gt;          start a section (default A0000002471001)
 *   @doc &lt;MRZ document number&gt;   BAC document number
 *   @dob &lt;YYMMDD&gt;               BAC date of birth
 *   @doe &lt;YYMMDD&gt;               BAC date of expiry
 *   @can &lt;6 digits&gt;            Card Access Number for PACE (password ref 0x02)
 *   @dg &lt;n&gt; &lt;hex&gt;               EF.DG&lt;n&gt; content (DG1 mandatory)
 *   @sod &lt;hex&gt;                  EF.SOD content
 *   @aa &lt;hex&gt;                   AA private key (modLen || modulus || expLen || exponent)
 *   @aa-alg sha1|sha256         AA signature algorithm (default sha1; DGI FF0A)
 *   @ca &lt;hex&gt;                   Chip Authentication P-256 private scalar (DGI FF03)
 *   @cardsecurity &lt;hex&gt;         LDS1 master-file EF.CardSecurity SignedData (DGI FF05)
 *   @ta-date &lt;YYMMDD&gt;           ICC current date (DGI FF08)
 *   @cvca &lt;W-hex&gt; &lt;CAR&gt; &lt;YYMMDD&gt; &lt;auth-hex&gt; [secondary]
 *                                CVCA trust point (DGI FF07, or FF09 with
 *                                {@code secondary}): EC public point, holder
 *                                reference, Effective Date, relative authorization
 *   @lds2 &lt;role&gt;               lds2 role: travel | visa | biometrics
 *   @record &lt;fid-hex&gt; &lt;hex&gt;     append one record to an LDS2 record EF
 *   @transparent &lt;fid-hex&gt; &lt;hex&gt;  set one LDS2 transparent EF (e.g. 0201)
 * </pre>
 *
 * <p>It is the input of the eMRTD perso tooling ({@code EmrtdPersoExporter});
 * a script without {@code @instance} is a single document with the default AID.
 * The single-document accessors ({@link #documentNumber()},
 * {@link #dataGroups()}, …) refer to the first entry.
 */
public final class LdsScript {

    /** Default LDS1 application identifier (ICAO Doc 9303-10 §5). */
    public static final String DEFAULT_AID = "A0000002471001";

    /** One instance section of the script. */
    public static final class Entry {
        public final String aid;
        /** {@code lds1} (default), {@code travel}, {@code visa} or {@code biometrics}. */
        public String role = "lds1";
        public String documentNumber;
        public String dateOfBirth;
        public String dateOfExpiry;
        /** Card Access Number for PACE with password reference 0x02 (optional). */
        public String can;
        /** DG number -> raw EF content, in script order. */
        public final Map<Integer, byte[]> dataGroups = new LinkedHashMap<Integer, byte[]>();
        public byte[] sod;
        public byte[] aaKey;
        /** AA signature algorithm: {@code sha1} (default) or {@code sha256}. */
        public String aaAlgorithm = "sha1";
        /** Chip Authentication static P-256 private scalar (DGI FF03). */
        public byte[] caKey;
        /** LDS2 EF.CardAccess / EF.CardSecurity content. */
        public byte[] cardAccess;
        public byte[] cardSecurity;
        /** LDS2 record EF FID -> records to append, in script order. */
        public final Map<Integer, java.util.List<byte[]>> records =
                new LinkedHashMap<Integer, java.util.List<byte[]>>();
        /** LDS2 transparent EF FID -> content (e.g. Additional Biometrics 0201). */
        public final Map<Integer, byte[]> transparent = new LinkedHashMap<Integer, byte[]>();
        /** ICC current date (DGI FF08), YYMMDD; null for the demo default. */
        public String taDate;
        /** CVCA trust points (DGI FF07/FF09), in script order. */
        public final List<TrustPoint> trustPoints = new ArrayList<TrustPoint>();

        Entry(String aid) {
            this.aid = aid;
        }

        public boolean isLds2() {
            return !"lds1".equals(role);
        }
    }

    /** A CVCA trust point from {@code @cvca} (ICAO Doc 9303-11 §7.1.4.3.1). */
    public static final class TrustPoint {
        /** EC public point W (65 bytes, {@code 04||X||Y}). */
        public final byte[] publicKey;
        /** Certificate Authority Reference (ISO 8859-1). */
        public final String car;
        /** Effective Date, 6 digits YYMMDD. */
        public final String effective;
        /** Relative authorization (4 bytes: ePassport CHAT + the LDS2 apps). */
        public final byte[] authorization;
        public final boolean secondary;

        TrustPoint(byte[] publicKey, String car, String effective, byte[] authorization,
                   boolean secondary) {
            this.publicKey = publicKey;
            this.car = car;
            this.effective = effective;
            this.authorization = authorization;
            this.secondary = secondary;
        }
    }

    public final List<Entry> entries = new ArrayList<Entry>();

    private LdsScript() {
    }

    public String documentNumber() {
        return entries.get(0).documentNumber;
    }

    public String dateOfBirth() {
        return entries.get(0).dateOfBirth;
    }

    public String dateOfExpiry() {
        return entries.get(0).dateOfExpiry;
    }

    public Map<Integer, byte[]> dataGroups() {
        return entries.get(0).dataGroups;
    }

    public byte[] sod() {
        return entries.get(0).sod;
    }

    public static LdsScript parse(String text) {
        LdsScript script = new LdsScript();
        Entry current = null;
        for (String raw : text.split("\n")) {
            String line = raw.trim();
            if (line.isEmpty() || line.startsWith("#")) {
                continue;
            }
            String[] parts = line.split("\\s+", 3);
            if (parts[0].equals("@instance")) {
                current = script.newEntry(parts[1]);
                continue;
            }
            if (current == null) {
                current = script.newEntry(DEFAULT_AID);
            }
            switch (parts[0]) {
            case "@doc":
                current.documentNumber = parts[1];
                break;
            case "@dob":
                current.dateOfBirth = parts[1];
                break;
            case "@doe":
                current.dateOfExpiry = parts[1];
                break;
            case "@can":
                current.can = parts[1];
                break;
            case "@dg":
                current.dataGroups.put(Integer.parseInt(parts[1]), Hex.parse(parts[2]));
                break;
            case "@sod":
                current.sod = Hex.parse(parts[1]);
                break;
            case "@aa":
                current.aaKey = Hex.parse(parts[1]);
                break;
            case "@aa-alg":
                current.aaAlgorithm = parts[1];
                break;
            case "@ca":
                current.caKey = Hex.parse(parts[1]);
                break;
            case "@lds2":
                current.role = parts[1];
                break;
            case "@cardaccess":
                current.cardAccess = Hex.parse(parts[1]);
                break;
            case "@cardsecurity":
                current.cardSecurity = Hex.parse(parts[1]);
                break;
            case "@ta-date":
                current.taDate = parts[1];
                break;
            case "@cvca": {
                String[] a = line.split("\\s+");
                if (a.length < 5) {
                    throw new IllegalArgumentException(
                            "@cvca needs <W-hex> <CAR> <YYMMDD> <auth-hex> [secondary]");
                }
                boolean secondary = a.length > 5 && "secondary".equals(a[5]);
                current.trustPoints.add(new TrustPoint(
                        Hex.parse(a[1]), a[2], a[3], Hex.parse(a[4]), secondary));
                break;
            }
            case "@record": {
                int fid = Integer.parseInt(parts[1], 16);
                java.util.List<byte[]> list = current.records.get(fid);
                if (list == null) {
                    list = new java.util.ArrayList<byte[]>();
                    current.records.put(fid, list);
                }
                list.add(Hex.parse(parts[2]));
                break;
            }
            case "@transparent": {
                // A transparent LDS2 EF written by FID (e.g. EF.Biometrics 0201,
                // Doc 9303-10 §5.3.3); the DGI is the FID itself (Lds2Perso).
                int fid = Integer.parseInt(parts[1], 16);
                current.transparent.put(fid, Hex.parse(parts[2]));
                break;
            }
            default:
                break;
            }
        }
        return script;
    }

    private Entry newEntry(String aid) {
        Entry entry = new Entry(aid.replaceAll("[^0-9A-Fa-f]", "").toUpperCase());
        entries.add(entry);
        return entry;
    }

    public static LdsScript parse(File file) throws Exception {
        return parse(new String(Files.readAllBytes(file.toPath()),
                java.nio.charset.StandardCharsets.UTF_8));
    }
}
