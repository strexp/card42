package card42.host.emv.app.perso;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import card42.host.common.codec.TlvWriter;
import card42.host.emv.crypto.EmvKeys;
import card42.host.emv.oda.Sda;
import card42.host.emv.oda.SdaKeys;
import card42.host.common.util.Hex;

/**
 * Parser for the card42 personalization script (EMV CPS v2.0 Annex A).
 *
 * The script is a flat, human-readable description of the DGIs that are pushed
 * to one instance with STORE DATA.  A section starts with {@code @instance} and
 * is turned into one DGI sequence:
 *
 * <pre>
 *   @instance &lt;AID-hex&gt;          start a section for this instance
 *   @offline-pin &lt;ascii-digits&gt;  DGI 8010 (ISO 9564-1 format 1 Reference PIN Block)
 *   @key icc|sm-mac|sm-enc &lt;hex&gt; DGI 8000 (CAM key, MAC UDK, ENC UDK)
 *   @key &lt;slot&gt; derive &lt;imk&gt; &lt;pan&gt; &lt;psn&gt; [3des|aes]
 *                                DGI 8000, key derived from an issuer master key
 *                                (EMV v4.4 Book 2 Annex A1.4; 3des = Option B)
 *   @key kcv &lt;hex&gt;               DGI 9000 (parsed but ignored)
 *   @dgi &lt;hex&gt;                  the following raw lines form this DGI
 *   @record sfi=n rec=n         the following raw line is DGI (SFI&lt;&lt;8 | record)
 *   @sda [records|dda|pin]      records 2-5 and/or the ICC DDA/CDA and PIN key
 *                               pairs; with no token all three are emitted,
 *                               otherwise only the named parts
 *   @no-complete                do not set P1.b8 on the last block
 *   &lt;tag&gt; &lt;value&gt; ...            internal tags, grouped into DGI 3001
 * </pre>
 *
 * A raw data line is a whitespace-separated list of hex bytes and/or quoted
 * ASCII strings, e.g. {@code A5 0F 50 0D "card42 CONTACT"}.  In the default
 * (3001) section a leading {@code DF21} pseudo-tag selects the block-key DGI
 * ({@code DF21->8000}).
 *
 * The parser performs no EMV validation; it only groups bytes.  The byte-level
 * encoders live in {@link Hex} and {@link TlvWriter}.
 */
public final class PersoScript {

    /** One instance section of the script. */
    public static final class Entry {
        public final String aid;
        /** DGI -> raw value, in script order. */
        public final Map<Integer, byte[]> dgis = new LinkedHashMap<>();
        /** Whether the last STORE DATA block sets P1.b8 (completion). */
        public boolean complete = true;

        Entry(String aid) {
            this.aid = aid;
        }

        void append(int dgi, byte[] value) {
            byte[] old = dgis.get(dgi);
            if (old == null) {
                dgis.put(dgi, value);
            } else {
                byte[] merged = new byte[old.length + value.length];
                System.arraycopy(old, 0, merged, 0, old.length);
                System.arraycopy(value, 0, merged, old.length, value.length);
                dgis.put(dgi, merged);
            }
        }
    }

    public final List<Entry> entries = new ArrayList<>();

    /** Parses a script file. */
    public static PersoScript parse(String path) throws IOException {
        return parse(path, null);
    }

    /**
     * Parses a script file, expanding any {@code @sda} directive with the given
     * SDA key profile (EMV v4.4 Book 2 §5).  A script without {@code @sda} does
     * not need a profile; a script with {@code @sda} and no profile is rejected.
     */
    public static PersoScript parse(String path, SdaKeys sdaKeys) throws IOException {
        PersoScript script = new PersoScript();
        try (BufferedReader in = new BufferedReader(new FileReader(path))) {
            String line;
            Entry current = null;
            Integer section = null;
            while ((line = in.readLine()) != null) {
                int hash = line.indexOf('#');
                if (hash >= 0) {
                    line = line.substring(0, hash);
                }
                line = line.trim();
                if (line.isEmpty()) {
                    continue;
                }

                if (line.startsWith("@")) {
                    String[] parts = line.split("\\s+");
                    String directive = parts[0];
                    if (directive.equals("@instance")) {
                        current = script.newEntry(parts[1]);
                        section = null;
                    } else if (directive.equals("@offline-pin")) {
                        // EMV CPS v2.0 Annex A DGI '8010': Reference PIN Block, ISO 9564-1 format 1
                        // (EMV CPS v2.0 Annex A Table A-4).
                        current.append(0x8010, Hex.iso9564Format1(parts[1]));
                    } else if (directive.equals("@key")) {
                        if (parts.length >= 3 && parts[2].equals("derive")) {
                            // Derive the ICC master key from an issuer master key
                            // (EMV v4.4 Book 2 Annex A1.4): Option B for the CV '5'
                            // profile, Option C for CV '6'.
                            current.append(keyDgi(parts[1]),
                                    deriveKey(parts[1], parts));
                        } else {
                            current.append(keyDgi(parts[1]), Hex.parse(parts[2]));
                        }
                    } else if (directive.equals("@dgi")) {
                        section = Integer.parseInt(parts[1], 16);
                    } else if (directive.equals("@record")) {
                        int sfi = 0;
                        int rec = 0;
                        for (int i = 1; i < parts.length; i++) {
                            if (parts[i].startsWith("sfi=")) {
                                sfi = Integer.parseInt(parts[i].substring(4));
                            } else if (parts[i].startsWith("rec=")) {
                                rec = Integer.parseInt(parts[i].substring(4));
                            }
                        }
                        section = (sfi << 8) | rec;
                    } else if (directive.equals("@sda")) {
                        // Generate the certificate chain/SSAD and the ICC key
                        // pairs from the record 1 value (EMV v4.4 Book 2
                        // §5–§7.2, EMV CPS v2.0 Annex A).  The optional tokens
                        // `records`, `dda` and `pin` select which parts are
                        // emitted; with no token all three are.  A card without
                        // ALG_RSA_SHA_ISO9796_MR can use `@sda records pin`
                        // (SDA + enciphered PIN, no DDA/CDA).
                        if (sdaKeys == null) {
                            throw new IOException("@sda requires an SDA key profile");
                        }
                        byte[] record1 = current.dgis.get(0x0101);
                        if (record1 == null) {
                            throw new IOException(
                                    "@sda requires a @record sfi=1 rec=1 before it");
                        }
                        boolean records = true;
                        boolean dda = true;
                        boolean pin = true;
                        if (parts.length >= 2) {
                            records = false;
                            dda = false;
                            pin = false;
                            for (int i = 1; i < parts.length; i++) {
                                switch (parts[i].toLowerCase()) {
                                case "records":
                                    records = true;
                                    break;
                                case "dda":
                                    dda = true;
                                    break;
                                case "pin":
                                    pin = true;
                                    break;
                                default:
                                    throw new IOException(
                                            "Unknown @sda option: " + parts[i]);
                                }
                            }
                        }
                        Sda.Result result = Sda.personalize(record1, sdaKeys);
                        if (records) {
                            current.append(0x0102, result.record2);
                            current.append(0x0103, result.record3);
                            current.append(0x0104, result.record4);
                            current.append(0x0105, result.record5);
                        }
                        if (dda) {
                            current.append(0x8103, result.ddaModulus);
                            current.append(0x8101, result.ddaExponent);
                        }
                        if (pin) {
                            current.append(0x8104, result.pinModulus);
                            current.append(0x8102, result.pinExponent);
                        }
                    } else if (directive.equals("@no-complete")) {
                        current.complete = false;
                    } else {
                        throw new IOException("Unknown directive: " + directive);
                    }
                    continue;
                }

                if (current == null) {
                    throw new IOException("Data before @instance: " + line);
                }
                if (section != null) {
                    current.append(section, parseValue(line));
                } else {
                    // Default section: structured internal tags (EMV CPS v2.0 Annex A DGI '3001').
                    // A leading DFxx pseudo-tag redirects the rest of the line
                    // to its DGI.
                    String head = line.split("\\s+", 2)[0];
                    int mapped = pseudoDgi(head);
                    if (mapped >= 0) {
                        String rest = line.substring(head.length()).trim();
                        current.append(mapped, parseValue(rest));
                    } else {
                        current.append(0x3001, parseValue(line));
                    }
                }
            }
        }
        if (script.entries.isEmpty()) {
            throw new IOException("No @instance section in " + path);
        }
        return script;
    }

    private Entry newEntry(String aid) {
        Entry e = new Entry(aid.replaceAll("[^0-9A-Fa-f]", "").toUpperCase());
        entries.add(e);
        return e;
    }

    /** The DGI sequence for an entry (completion is signalled by P1.b8). */
    public static byte[] sequence(Entry entry) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (Map.Entry<Integer, byte[]> dgi : entry.dgis.entrySet()) {
            TlvWriter.writeDgi(out, dgi.getKey(), dgi.getValue());
        }
        return out.toByteArray();
    }

    /** Parses a raw data line: hex bytes and/or quoted ASCII strings. */
    public static byte[] parseValue(String line) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int i = 0;
        int n = line.length();
        while (i < n) {
            char c = line.charAt(i);
            if (Character.isWhitespace(c)) {
                i++;
            } else if (c == '"') {
                i++;
                while (i < n && line.charAt(i) != '"') {
                    out.write(line.charAt(i) & 0xFF);
                    i++;
                }
                i++; // closing quote
            } else {
                int start = i;
                while (i < n && !Character.isWhitespace(line.charAt(i))) {
                    i++;
                }
                String token = line.substring(start, i);
                byte[] b = Hex.parse(token);
                out.write(b, 0, b.length);
            }
        }
        return out.toByteArray();
    }

    /** Splits a sequence into blocks of at most blockSize bytes. */
    public static List<byte[]> chunk(byte[] sequence, int blockSize) {
        List<byte[]> blocks = new ArrayList<>();
        for (int off = 0; off < sequence.length; off += blockSize) {
            blocks.add(Arrays.copyOfRange(sequence, off,
                    Math.min(off + blockSize, sequence.length)));
        }
        return blocks;
    }

    /**
     * Derives an ICC master key from an issuer master key at personalization
     * time (EMV v4.4 Book 2 Annex A1.4): Option B (Triple DES) by default, or
     * Option C (AES-128) when the mode is {@code aes}.
     */
    private static byte[] deriveKey(String slot, String[] parts) throws IOException {
        if (parts.length < 6) {
            throw new IOException("@key " + slot
                    + " derive needs <imk> <pan> <psn> [3des|aes]");
        }
        byte[] imk = Hex.parse(parts[3]);
        String pan = parts[4];
        int psn;
        try {
            psn = Integer.parseInt(parts[5], 16);
        } catch (NumberFormatException e) {
            throw new IOException("Bad PAN sequence number: " + parts[5], e);
        }
        String mode = parts.length >= 7 ? parts[6] : "3des";
        try {
            if (mode.equalsIgnoreCase("aes")) {
                return EmvKeys.aesMasterKey(imk, pan, psn, 16);
            }
            return EmvKeys.desMasterKey(imk, pan, psn);
        } catch (GeneralSecurityException e) {
            throw new IOException("Key derivation failed for " + slot, e);
        }
    }

    private static int keyDgi(String name) throws IOException {
        switch (name) {
        case "icc":
        case "sm-mac":
        case "sm-enc":
            // EMV CPS v2.0 Annex A DGI '8000': the CAM (ICC master) key, MAC UDK and ENC UDK are
            // concatenated in that order (EMV CPS v2.0 §A.2).
            return 0x8000;
        case "kcv":
            return 0x9000;
        default:
            throw new IOException("Unknown key name: " + name);
        }
    }

    private static int pseudoDgi(String tag) {
        switch (tag.toUpperCase()) {
        case "DF21":
            return 0x8000;
        default:
            return -1;
        }
    }
}
