package card42.test;

import javax.smartcardio.Card;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import card42.host.emv.kernel.entry.EntryPoint;
import card42.host.emv.lib.Terminal;
import card42.host.common.util.Args;
import card42.host.common.util.Hex;
import card42.host.common.codec.Tags;

/**
 * Directory (PSE / PPSE) structure test (docs/specs/common/toolchain.md §6,
 * docs/specs/emv/contactless.md).
 *
 * It checks the mandatory structure of the FCI and the candidate list against
 * EMV v4.4 Book 1 Tables 8/10/12 and EMV Contactless Book B v2.12 Table 3-2:
 *
 *   - PSE FCI: 6F { 84 = 1PAY.SYS.DDF01, A5 { 88 01 01 } }; 84 / A5 / 88
 *     must be present and 88 must point at the directory EF (SFI 1).
 *   - PSE READ RECORD SFI=1 rec=1: 70 { 61 { 4F AID, 50 label, 87 priority } };
 *     4F / 50 are mandatory, 87 is optional (EMV v4.4 Book 1 table 49).
 *   - PSE other record -> 6A83, other SFI -> 6A82.
 *   - PPSE FCI: 6F { 84 = 2PAY.SYS.DDF01, A5 { BF0C { 61 { 4F, 50, 87, 9F2A } } } };
 *     PPSE has no READ RECORD -> 6A82.
 *   - PPSE on the contact interface is refused with 6A82 unless the test build
 *     switch is set (docs/specs/common/architecture.md §7), so the PPSE structure is only fully
 *     checked in a TEST_CONTACTLESS=1 build.
 *
 * The PPSE candidate list is then used to simulate the Entry Point Combination
 * Selection (EMV Contactless Book B v2.12 §3.3.2): every Directory Entry is matched against a reader
 * {AID, Kernel ID} combination, the Kernel Identifier 9F2A is decoded
 * (Table 3-4/3-5), and the highest priority Combination (lowest 87 value,
 * Table 3-3) is selected.
 *
 * The candidate AID must match the role: PSE -> 43415244420101 (contact), PPSE ->
 * 43415244420102 (contactless).
 */
public class DirectoryTest {

    private static final String PSE_AID = "315041592E5359532E4444463031";
    private static final String PPSE_AID = "325041592E5359532E4444463031";
    private static final String CONTACT_AID = "43415244420101";
    private static final String CONTACTLESS_AID = "43415244420102";

    public static void main(String[] argv) throws Exception {
        Args args = new Args(argv, new String[] { "host" }, new String[0]);
        String host = args.get("host", "socket:localhost:9025");
        CardTerminal terminal = TestTerminals.getTerminal(host.split(":"));
        if (terminal == null || !terminal.waitForCardPresent(10000)) {
            throw new IllegalStateException("Connection to simulator failed on " + host);
        }

        Card card = terminal.connect("*");
        try {
            run(new Terminal(card.getBasicChannel()));
        } finally {
            card.disconnect(true);
        }

        if (Checks.failures() > 0) {
            System.out.println("FAILED: " + Checks.failures() + " directory check(s)");
            System.exit(1);
        }
        System.out.println("ALL DIRECTORY CHECKS PASSED");
    }

    static void run(Terminal terminal) throws Exception {
        testPse(terminal);
        testPpse(terminal);
    }

    private static void testPse(Terminal terminal) throws Exception {
        System.out.println("--- PSE (contact) ---");
        ResponseAPDU r = terminal.select(PSE_AID);
        Checks.check("SELECT PSE", r.getSW() == 0x9000, r);
        if (r.getSW() != 0x9000) {
            return;
        }

        // 6F { 84, A5 { 88 01 01 } } (EMV v4.4 Book 1 table 43).
        Checks.check("PSE FCI has the DF name (84)",
                Tags.find(r.getData(), 0x84) != null, r);
        byte[] a5 = Tags.find(r.getData(), 0xA5);
        Checks.check("PSE FCI has the proprietary template (A5)", a5 != null, r);
        byte[] sfi = a5 == null ? null : Tags.find(a5, 0x88);
        Checks.check("PSE A5 carries 88 01 01 (directory EF SFI)",
                sfi != null && sfi.length == 1 && sfi[0] == 0x01, r);
        // 88 must be nested inside A5, not merely present somewhere
        // (EMV v4.4 Book 1 §12.2.2).
        Checks.check("PSE 88 is nested inside A5",
                a5 != null && Tags.find(a5, 0x88) != null, r);

        // Read from the SFI the FCI advertises via '88' rather than a hard-coded
        // file (EMV v4.4 Book 1 §12.3.2 step 2); the default fixture advertises 1.
        int advertisedSfi = sfi == null || sfi.length != 1 ? 1 : (sfi[0] & 0xFF);
        ResponseAPDU rec = terminal.readRecord(1, advertisedSfi);
        Checks.check("PSE READ RECORD at the advertised SFI rec 1", rec.getSW() == 0x9000, rec);
        if (rec.getSW() == 0x9000) {
            byte[] data = rec.getData();
            byte[] template = Tags.find(data, 0x70);
            Checks.check("PSE record is a 70 template", template != null, rec);
            Checks.check("PSE record has a directory entry (61)",
                    Tags.find(data, 0x61) != null, rec);
            // 61 must be nested inside the 70 record template
            // (EMV v4.4 Book 1 §12.2.3).
            Checks.check("PSE 61 is nested inside 70",
                    template != null && Tags.find(template, 0x61) != null, rec);
            byte[] aid = Tags.find(data, 0x4F);
            Checks.check("PSE entry ADF name (4F) is the contact AID",
                    aid != null && Hex.format(aid).equals(CONTACT_AID), rec);
            byte[] label = Tags.find(data, 0x50);
            Checks.check("PSE entry has an application label (50)",
                    label != null && label.length > 0, rec);
            byte[] priority = Tags.find(data, 0x87);
            Checks.check("PSE entry has a priority indicator (87)",
                    priority != null && priority.length == 1, rec);
            // The PSE (contact) entry must not carry a contactless 9F2A.
            Checks.check("PSE entry has no Kernel Identifier (9F2A)",
                    Tags.find(data, 0x9F2A) == null, rec);
        }

        Checks.check("PSE READ RECORD unknown record -> 6A83",
                terminal.readRecord(2, advertisedSfi).getSW(), 0x6A83);
        Checks.check("PSE READ RECORD unknown SFI -> 6A82",
                terminal.readRecord(1, advertisedSfi == 1 ? 2 : 1).getSW(), 0x6A82);
        // P2 b3-b1 must be 100; any other value is RFU -> 6A81
        // (EMV v4.4 Book 1 Table 4).
        Checks.check("PSE READ RECORD P2 b3-b1 != 100 -> 6A81",
                terminal.transmit(new CommandAPDU(0x00, 0xB2, 0x01, 0x00)).getSW(), 0x6A81);
    }

    private static void testPpse(Terminal terminal) throws Exception {
        System.out.println("--- PPSE (contactless) ---");
        ResponseAPDU r = terminal.select(PPSE_AID);
        if (r.getSW() != 0x9000) {
            // The default build refuses PPSE on the contact interface (6A82);
            // the TEST_CONTACTLESS=1 build relaxes this (docs/specs/common/architecture.md §7).
            Checks.check("PPSE refused on contact -> 6A82", r.getSW(), 0x6A82);
            // A direct SELECT of the contactless payment instance is refused by
            // the same media gate (docs/specs/common/architecture.md §7).
            Checks.check("contactless payment instance refused on contact -> 6A82",
                    terminal.select(CONTACTLESS_AID).getSW(), 0x6A82);
            return;
        }

        // 6F { 84, A5 { BF0C { 61 { 4F, 50, 87, 9F2A } } } } (EMV Contactless Book B v2.12 Table 3-2).
        Checks.check("PPSE FCI has the DF name (84)",
                Tags.find(r.getData(), 0x84) != null, r);
        byte[] a5 = Tags.find(r.getData(), 0xA5);
        Checks.check("PPSE FCI has the proprietary template (A5)", a5 != null, r);
        byte[] bf0c = Tags.find(r.getData(), 0xBF0C);
        Checks.check("PPSE FCI has BF0C (issuer discretionary data)",
                bf0c != null, r);
        // BF0C is nested inside A5 and carries the 61 candidate entry.
        Checks.check("PPSE BF0C is nested inside A5",
                a5 != null && Tags.find(a5, 0xBF0C) != null, r);
        byte[] entry = bf0c == null ? null : Tags.find(bf0c, 0x61);
        Checks.check("PPSE FCI has a directory entry (61) inside BF0C",
                entry != null, r);
        byte[] aid = entry == null ? null : Tags.find(entry, 0x4F);
        Checks.check("PPSE entry ADF name (4F) is the contactless AID",
                aid != null && Hex.format(aid).equals(CONTACTLESS_AID), r);
        byte[] label = entry == null ? null : Tags.find(entry, 0x50);
        Checks.check("PPSE entry has an application label (50) of 1-16 bytes"
                + " (EMV v4.4 Book 3 Annex A Table 37)",
                label != null && label.length >= 1 && label.length <= 16, r);
        byte[] priority = entry == null ? null : Tags.find(entry, 0x87);
        Checks.check("PPSE entry has a priority indicator (87)",
                priority != null && priority.length == 1, r);
        Checks.check("PPSE entry priority (87 b4-b1) is 1..15",
                priority != null && priority.length == 1
                        && (priority[0] & 0x0F) >= 1 && (priority[0] & 0x0F) <= 15, r);
        // Kernel Identifier (EMV Contactless Book B v2.12 Table 3-2, conditional): byte 1 = 00 means
        // the kernel is associated with the ADF Name (Table 3-4/3-5).
        byte[] kernel = entry == null ? null : Tags.find(entry, 0x9F2A);
        Checks.check("PPSE entry has a Kernel Identifier (9F2A)",
                kernel != null, r);
        Checks.check("PPSE Kernel Identifier is 00 (kernel by ADF Name)",
                kernel != null && kernel.length == 1 && kernel[0] == 0x00, r);
        // 9F2A must be nested inside the 61 Directory Entry
        // (EMV Contactless Book B v2.12 §3.3).
        Checks.check("PPSE 9F2A is nested inside 61",
                entry != null && Tags.find(entry, 0x9F2A) != null, r);

        Checks.check("PPSE READ RECORD -> 6A82",
                terminal.readRecord(1, 1).getSW(), 0x6A82);

        // SEND POI INFORMATION (EMV Contactless Book B v2.12 Annex C): the card
        // advertises 9F3E/9F3F and answers with the candidate-list FCI.
        byte[] categories = bf0c == null ? null : Tags.find(bf0c, 0x9F3E);
        Checks.check("PPSE advertises the Terminal Categories Supported List (9F3E)",
                categories != null && categories.length >= 2, r);
        byte[] sdol = bf0c == null ? null : Tags.find(bf0c, 0x9F3F);
        Checks.check("PPSE advertises the Supported Data Object List (9F3F)",
                sdol != null && sdol.length >= 2, r);

        // Command value: the SDOL values (9F1A country, 5F2A currency) followed
        // by a POI Information object '0001' (Terminal Category) = 0001.
        byte[] spiValue = Hex.parse("02500978" + "0001020001");
        ResponseAPDU spi = terminal.sendPoiInformation(spiValue);
        Checks.check("SEND POI INFORMATION -> 9000", spi.getSW(), 0x9000);
        if (spi.getSW() == 0x9000) {
            byte[] spiFci = spi.getData();
            Checks.check("SPI response carries the candidate list (A5/BF0C/61)",
                    Tags.find(spiFci, 0xA5) != null && Tags.find(spiFci, 0xBF0C) != null
                            && Tags.find(spiFci, 0x61) != null, spi);
        }
        // Wrong P1/P2 and a malformed '83' are refused.
        Checks.check("SEND POI INFORMATION wrong P1/P2 -> 6A81",
                terminal.sendPoiInformationRaw(0x01, 0x00, Hex.parse("83020001")).getSW(),
                0x6A81);
        Checks.check("SEND POI INFORMATION malformed '83' -> 6A80",
                terminal.sendPoiInformationRaw(0x00, 0x00, Hex.parse("84020001")).getSW(),
                0x6A80);

        // Simulate Entry Point Combination Selection (EMV Contactless Book B v2.12 §3.3.2).
        selectByEntryPoint(terminal, r.getData());
    }

    /**
     * Drives the kernel's Entry Point Combination Selection (EMV Contactless Book B v2.12 §3.3.2)
     * over the PPSE FCI and selects the highest-priority Combination.  The
     * selection logic lives in {@link EntryPoint#selectCandidate}, so
     * the test does not re-implement it.
     */
    private static void selectByEntryPoint(Terminal terminal, byte[] fci) throws Exception {
        // Drive the kernel's own Combination Selection rather than
        // re-implementing it in the test (EMV Contactless Book B v2.12 §3.3.2).
        String best = EntryPoint.selectCandidate(fci, new String[] { CONTACTLESS_AID });
        Checks.check("Entry Point found a candidate Combination", best != null);
        if (best == null) {
            return;
        }
        System.out.println("  Entry Point selected " + best);
        ResponseAPDU selected = terminal.select(best);
        Checks.check("Entry Point SELECT (AID) -> 9000", selected.getSW() == 0x9000, selected);
    }
}
