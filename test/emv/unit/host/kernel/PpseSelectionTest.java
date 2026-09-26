package card42.test;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.Map;

import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import card42.host.common.codec.Tags;
import card42.host.common.codec.TlvWriter;
import card42.host.emv.kernel.ContactlessKernel;
import card42.host.emv.kernel.core.KernelListener;
import card42.host.emv.kernel.core.Outcome;
import card42.host.emv.kernel.core.TransactionResult;
import card42.host.emv.kernel.data.TerminalConfig;
import card42.host.emv.kernel.data.TransactionRequest;
import card42.host.emv.kernel.entry.Combination;
import card42.host.emv.kernel.entry.CombinationTable;
import card42.host.emv.kernel.entry.EntryPoint;
import card42.host.emv.kernel.entry.EntryPointConfiguration;
import card42.host.emv.kernel.entry.KernelActivation;
import card42.host.emv.kernel.entry.PpseSelection;
import card42.host.emv.kernel.entry.Spi;
import card42.host.emv.lib.Terminal;
import card42.host.common.util.Hex;

/**
 * Unit tests for {@link PpseSelection} Final Combination Selection
 * (EMV Contactless Book B v2.12 §3.3.3.5): a refused {@code SELECT (ADF Name)}
 * removes that Combination from the Candidate List and the next priority
 * candidate is tried.
 */
final class PpseSelectionTest {

    private static final String PPSE_AID = "325041592E5359532E4444463031";
    private static final String AID_A = "43415244420102";
    private static final String AID_B = "43415244420103";

    private PpseSelectionTest() {
    }

    static void run() throws Exception {
        System.out.println("PpseSelectionTest");

        String[] supported = { AID_A, AID_B };

        // The highest priority candidate is refused; the next one is selected.
        ScriptedChannel channel = new ScriptedChannel();
        channel.addSelect(PPSE_AID, 0x9000, ppseFci());
        channel.addSelect(AID_A, 0x6A82, null);
        channel.addSelect(AID_B, 0x9000, adfFci(AID_B));
        TransactionResult.Mutable result = new TransactionResult.Mutable();
        PpseSelection first = new PpseSelection(supported);
        String selected = first.select(new Terminal(channel), new TransactionRequest(TerminalConfig.builder().build()), result);
        Asserts.eq(AID_B, selected, "refused candidate falls back to the next one");
        Asserts.eq(AID_B, result.aidHex(), "result carries the selected AID");
        // H3: the activation data is built for the selected Combination.
        Asserts.check(first.activation() != null, "activation built after select");
        Asserts.eq(AID_B, first.activation().adfName, "activation carries the ADF Name");
        Asserts.check(first.ppseFci() != null, "activation carries the PPSE FCI");
        Asserts.check(first.indicators() != null, "Start A indicators computed");

        // A SELECT 9000 whose FCI DF Name does not match the ADF Name is a
        // format error: the Combination is dropped and the next is tried
        // (EMV Contactless Book B v2.12 §3.3.3.5).
        ScriptedChannel badFci = new ScriptedChannel();
        badFci.addSelect(PPSE_AID, 0x9000, ppseFci());
        badFci.addSelect(AID_A, 0x9000, adfFci(AID_B));
        badFci.addSelect(AID_B, 0x9000, adfFci(AID_B));
        TransactionResult.Mutable badFciResult = new TransactionResult.Mutable();
        Asserts.eq(AID_B, new PpseSelection(supported).select(
                        new Terminal(badFci), new TransactionRequest(TerminalConfig.builder().build()), badFciResult),
                "mismatched DF Name drops the Combination");

        // Every candidate is refused: the selection fails.
        ScriptedChannel allRefused = new ScriptedChannel();
        allRefused.addSelect(PPSE_AID, 0x9000, ppseFci());
        allRefused.addSelect(AID_A, 0x6A82, null);
        allRefused.addSelect(AID_B, 0x6A82, null);
        boolean failed = false;
        try {
            new PpseSelection(supported).select(new Terminal(allRefused),
                    new TransactionRequest(TerminalConfig.builder().build()), new TransactionResult.Mutable());
        } catch (card42.host.emv.kernel.core.EndApplicationException e) {
            failed = e.messageIdentifier()
                    == card42.host.emv.kernel.core.EndApplicationException.INSERT_SWIPE_OR_TRY_ANOTHER_CARD;
        }
        Asserts.check(failed, "all candidates refused -> End Application Outcome ('1C')");

        // A PPSE that cannot be selected adds no Combinations and proceeds to
        // End Application (Book B §3.3.2.3).
        ScriptedChannel noPpse = new ScriptedChannel();
        noPpse.addSelect(PPSE_AID, 0x6A82, null);
        boolean ppseFailed = false;
        try {
            new PpseSelection(supported).select(new Terminal(noPpse),
                    new TransactionRequest(TerminalConfig.builder().build()), new TransactionResult.Mutable());
        } catch (card42.host.emv.kernel.core.EndApplicationException e) {
            ppseFailed = true;
        }
        Asserts.check(ppseFailed, "PPSE 6A82 -> End Application (Book B §3.3.2.3)");

        // Combination Kernel ID matching (EMV Contactless Book B v2.12 §3.3.2.5
        // bullet D): the Requested Kernel ID must be 0 or equal to the Kernel ID
        // of the reader Combination for the matching AID.  The flat supported-AID
        // reader table carries the reader's implemented kernel 0.
        String[] custom = { AID_A };
        Asserts.eq(AID_A, EntryPoint.selectCandidate(
                        ppseFciWithKernel(AID_A, 0x01, new byte[] { 0x00 }), custom),
                "zero Requested Kernel ID is supported");
        Asserts.check(EntryPoint.selectCandidate(
                        ppseFciWithKernel(AID_A, 0x01, new byte[] { 0x03 }), custom) == null,
                "non-zero Requested Kernel ID not matching the Combination is skipped");

        // A reader that does implement Visa Kernel 3 accepts the brand default.
        String visa = "A0000000031010";
        CombinationTable visaKernel3 = new CombinationTable();
        visaKernel3.add(CombinationTable.PURCHASE, new Combination(visa, 3));
        Asserts.eq(visa, selected(ppseFciWithKernel(visa, 0x01, new byte[] { 0x03 }), visaKernel3),
                "Visa Requested Kernel ID 3 matches a Kernel-3 reader Combination");
        Asserts.eq(visa, selected(ppseFciWithKernel(visa, 0x01, null), visaKernel3),
                "Visa default Requested Kernel ID 3 matches a Kernel-3 reader Combination");
        Asserts.check(selected(ppseFciWithKernel(visa, 0x01, new byte[] { 0x04 }), visaKernel3) == null,
                "Visa Requested Kernel ID 4 is not supported");
        // The default reader table implements only kernel 0, so a real Visa
        // card (no 9F2A -> default Requested Kernel ID 3) is not a candidate
        // and the transaction ends cleanly (Book B §3.3.2.5 bullet D).
        String[] visaSupported = { visa };
        Asserts.check(EntryPoint.selectCandidate(
                        ppseFciWithKernel(visa, 0x01, null), visaSupported) == null,
                "Visa default Requested Kernel ID 3 is not supported by the kernel-0 reader");
        // The same card against the kernel ends cleanly with an End Application
        // Outcome instead of a deep transaction failure (Book B §3.3.2.7).
        ScriptedChannel visaEnd = new ScriptedChannel();
        visaEnd.addSelect(PPSE_AID, 0x9000, ppseFciWithKernel(visa, 0x01, null));
        TransactionResult endResult = new ContactlessKernel(
                        card42.host.common.util.Reporter.noop(), null, new java.util.Random(1), visa)
                .run(new Terminal(visaEnd),
                        new TransactionRequest(TerminalConfig.builder().build()), null);
        Asserts.check(endResult.outcome() != null
                        && endResult.outcome().finalOutcome == Outcome.END_APPLICATION,
                "Visa card on a kernel-0 reader -> End Application Outcome");
        Asserts.check(TransactionResult.Decision.END_APPLICATION == endResult.decision(),
                "End Application Outcome maps to the END_APPLICATION decision");

        // --- Book B §3.3.3.6: Visa AID + Kernel 3 needs '9F66' in the PDOL ---
        // A reader Combination Table that supports Visa Kernel 3 and the project
        // AID on kernel 0; the Visa Kernel 3 rule only applies to a reader that
        // actually declares that kernel.
        CombinationTable visaReader = new CombinationTable();
        visaReader.add(CombinationTable.PURCHASE, new Combination(visa, 3));
        visaReader.add(CombinationTable.PURCHASE, new Combination(AID_B, 0));
        EntryPointConfiguration visaConfig = new EntryPointConfiguration();
        ScriptedChannel visaNoTtq = new ScriptedChannel();
        visaNoTtq.addSelect(PPSE_AID, 0x9000,
                ppseFci(entry(visa, 0x01), entry(AID_B, 0x02)));
        visaNoTtq.addSelect(visa, 0x9000, adfFciWithPdol(visa, Hex.parse("9F0206")));
        visaNoTtq.addSelect(AID_B, 0x9000, adfFci(AID_B));
        Asserts.eq(AID_B, new PpseSelection(visaReader, visaConfig).select(
                        new Terminal(visaNoTtq), new TransactionRequest(TerminalConfig.builder().build()), new TransactionResult.Mutable()),
                "Visa Kernel 3 without 9F66 PDOL falls through to the next candidate");

        ScriptedChannel visaTtq = new ScriptedChannel();
        visaTtq.addSelect(PPSE_AID, 0x9000, ppseFciWithKernel(visa, 0x01, null));
        visaTtq.addSelect(visa, 0x9000, adfFciWithPdol(visa, Hex.parse("9F6604")));
        Asserts.eq(visa, new PpseSelection(visaReader, visaConfig).select(
                        new Terminal(visaTtq), new TransactionRequest(TerminalConfig.builder().build()), new TransactionResult.Mutable()),
                "Visa Kernel 3 with 9F66 PDOL is accepted");
        Asserts.check(EntryPoint.dolContainsTag(Hex.parse("9F02069F6604"), 0x9F66),
                "DOL tag scan finds 9F66");
        Asserts.check(!EntryPoint.dolContainsTag(Hex.parse("9F0206"), 0x9F66),
                "DOL tag scan misses 9F66");

        // --- reselect after a GET PROCESSING OPTIONS '6985' (Book 4 §6.3.1) ---
        ScriptedChannel reselectChannel = new ScriptedChannel();
        reselectChannel.addSelect(PPSE_AID, 0x9000, ppseFci());
        reselectChannel.addSelect(AID_A, 0x9000, adfFci(AID_A));
        reselectChannel.addSelect(AID_B, 0x9000, adfFci(AID_B));
        PpseSelection selection = new PpseSelection(supported);
        Terminal reselectTerminal = new Terminal(reselectChannel);
        Asserts.eq(AID_A, selection.select(reselectTerminal, new TransactionRequest(TerminalConfig.builder().build()),
                        new TransactionResult.Mutable()), "first candidate selected");
        Asserts.eq(AID_B, selection.reselect(reselectTerminal, new TransactionRequest(TerminalConfig.builder().build()),
                        new TransactionResult.Mutable()), "reselect returns the next candidate");
        Asserts.check(selection.reselect(reselectTerminal, new TransactionRequest(TerminalConfig.builder().build()),
                        new TransactionResult.Mutable()) == null,
                "reselect returns null when the candidate list is exhausted");

        // --- SPI (Book B Annex C) -------------------------------------------
        // The PPSE advertises 9F3E/9F3F; the card's SPI response carries AID_B
        // even though the PPSE FCI listed AID_A, so AID_B proves the SPI FCI
        // drove the Candidate List.
        ScriptedChannel spi = new ScriptedChannel();
        spi.addSelect(PPSE_AID, 0x9000, ppseFciWithSpi(entry(AID_A, 0x01)));
        spi.setSpi(0x9000, ppseFci(entry(AID_B, 0x01)));
        spi.addSelect(AID_B, 0x9000, adfFci(AID_B));
        Asserts.eq(AID_B, new PpseSelection(supported).select(
                        new Terminal(spi), new TransactionRequest(TerminalConfig.builder().build()), new TransactionResult.Mutable()),
                "SPI response FCI drives the Candidate List");
        Asserts.check(spi.spiSent, "SEND POI INFORMATION was sent");
        // The POI Information ID '0001' is two bytes on the wire
        // (Book B Annex C Figure C-1): the 4-byte SDOL data (9F1A/5F2A) is
        // followed by 00 01 02 <category>.
        Asserts.check(Hex.format(spi.lastSpiData).endsWith("0001020001"),
                "SPI command carries the 2-byte POI Information ID '0001'");

        // An SPI failure adds no Combinations and proceeds to End Application
        // (Book B §3.3.2.3b).
        ScriptedChannel spiFail = new ScriptedChannel();
        spiFail.addSelect(PPSE_AID, 0x9000, ppseFciWithSpi(entry(AID_A, 0x01)));
        spiFail.setSpi(0x6A80, null);
        boolean spiFailed = false;
        try {
            new PpseSelection(supported).select(
                    new Terminal(spiFail), new TransactionRequest(TerminalConfig.builder().build()), new TransactionResult.Mutable());
        } catch (card42.host.emv.kernel.core.EndApplicationException e) {
            spiFailed = true;
        }
        Asserts.check(spiFailed, "SPI failure -> End Application (Book B §3.3.2.3b)");

        // A '9F3E' list without the terminal category and no '9F3F' means SPI is
        // not sent and the PPSE FCI drives selection (Book B §3.3.2.3).
        ScriptedChannel noCategory = new ScriptedChannel();
        noCategory.addSelect(PPSE_AID, 0x9000,
                ppseFciWithCategories(entry(AID_A, 0x01), Hex.parse("0002")));
        noCategory.addSelect(AID_A, 0x9000, adfFci(AID_A));
        Asserts.eq(AID_A, new PpseSelection(supported).select(
                        new Terminal(noCategory), new TransactionRequest(TerminalConfig.builder().build()), new TransactionResult.Mutable()),
                "category absent from 9F3E: PPSE FCI drives selection");
        Asserts.check(!noCategory.spiSent,
                "SPI is not sent when the terminal category is absent and no 9F3F");

        // A '9F3E' list that contains the terminal category but no '9F3F': the
        // command carries only the POI Information object '0001'
        // (EMV Contactless Book B v2.12 §C.1.3).
        ScriptedChannel categoryOnly = new ScriptedChannel();
        categoryOnly.addSelect(PPSE_AID, 0x9000,
                ppseFciWithCategories(entry(AID_A, 0x01), Hex.parse("00010002")));
        categoryOnly.setSpi(0x9000, ppseFci(entry(AID_A, 0x01)));
        categoryOnly.addSelect(AID_A, 0x9000, adfFci(AID_A));
        Asserts.eq(AID_A, new PpseSelection(supported).select(
                        new Terminal(categoryOnly),
                        new TransactionRequest(TerminalConfig.builder().build()),
                        new TransactionResult.Mutable()),
                "category on 9F3E and no 9F3F still sends SPI");
        Asserts.check(Hex.format(categoryOnly.lastSpiData).endsWith("0001020001"),
                "SPI with no SDOL carries only the Terminal Category object");

        // A '9F3F' SDOL without a '9F3E' category list: the command carries only
        // the SDOL values, not the Terminal Category object (§C.1.3).
        ScriptedChannel sdolOnly = new ScriptedChannel();
        sdolOnly.addSelect(PPSE_AID, 0x9000,
                ppseFciWithCategoriesAndSdol(null, Hex.parse("9F1A02"), entry(AID_A, 0x01)));
        sdolOnly.setSpi(0x9000, ppseFci(entry(AID_A, 0x01)));
        sdolOnly.addSelect(AID_A, 0x9000, adfFci(AID_A));
        new PpseSelection(supported).select(new Terminal(sdolOnly),
                new TransactionRequest(TerminalConfig.builder().build()),
                new TransactionResult.Mutable());
        Asserts.check(Hex.format(sdolOnly.lastSpiData).endsWith("0250"),
                "SPI with only SDOL omits the Terminal Category object");

        // An SDOL that requests POI Information (tag '8B') is filled with the
        // Terminal Category value (Book B §C.1.3 / Annex A Table A-1).
        ScriptedChannel sdolPoi = new ScriptedChannel();
        sdolPoi.addSelect(PPSE_AID, 0x9000,
                ppseFciWithCategoriesAndSdol(null, Hex.parse("8B05"), entry(AID_A, 0x01)));
        sdolPoi.setSpi(0x9000, ppseFci(entry(AID_A, 0x01)));
        sdolPoi.addSelect(AID_A, 0x9000, adfFci(AID_A));
        new PpseSelection(supported).select(new Terminal(sdolPoi),
                new TransactionRequest(TerminalConfig.builder().build()),
                new TransactionResult.Mutable());
        Asserts.check(Hex.format(sdolPoi.lastSpiData).endsWith("0001020001"),
                "SDOL 8B is filled with the POI Information value");

        // --- Extended Selection (Book B §3.3.3.3) ---------------------------
        EntryPointConfiguration extended = new EntryPointConfiguration();
        extended.extendedSelectionSupported = true;
        ScriptedChannel ext = new ScriptedChannel();
        ext.addSelect(PPSE_AID, 0x9000, ppseFci(entryWithExtended(AID_A, "AABB")));
        ext.addSelect(AID_A + "AABB", 0x9000, adfFci(AID_A));
        PpseSelection extSel = new PpseSelection(CombinationTable.defaults(AID_A), extended);
        Asserts.eq(AID_A, extSel.select(
                        new Terminal(ext), new TransactionRequest(TerminalConfig.builder().build()),
                        new TransactionResult.Mutable()),
                "Extended Selection appends 9F29 to the SELECT ADF Name");
        Asserts.eq(AID_A + "AABB", ext.lastSelectAid,
                "SELECT carried the extended ADF Name");
        // The Final Outcome reports the ADF Name actually selected, with the
        // Extended Selection appended (Book B §3.5.1.5), and the Kernel
        // Identifier-Terminal (tag '96', Book B Table 3-7).
        Asserts.eq(AID_A + "AABB", extSel.activation().selectedAdfName,
                "activation reports the extended ADF Name");
        Asserts.bytes(new byte[] { 0, 0, 0, 0, 0, 0, 0, 0 },
                extSel.activation().kernelIdentifierTerminal(),
                "activation carries the 8-byte Kernel Identifier-Terminal");

        // --- KernelListener: the Entry Point Candidate List (Book B §3.3.2) --
        ScriptedChannel listenerChannel = new ScriptedChannel();
        listenerChannel.addSelect(PPSE_AID, 0x9000, ppseFci());
        listenerChannel.addSelect(AID_A, 0x9000, adfFci(AID_A));
        final java.util.List<String> candidateNames = new java.util.ArrayList<>();
        KernelListener listener = new KernelListener() {
            @Override
            public void onStep(KernelListener.Step step, TransactionResult result) {
            }

            @Override
            public void onCandidateList(java.util.List<String> adfNames) {
                candidateNames.addAll(adfNames);
            }
        };
        new PpseSelection(CombinationTable.defaults(supported), new EntryPointConfiguration(),
                listener).select(new Terminal(listenerChannel),
                        new TransactionRequest(TerminalConfig.builder().build()),
                        new TransactionResult.Mutable());
        Asserts.eq(2, candidateNames.size(), "listener receives both candidates");
        Asserts.eq(AID_A, candidateNames.get(0), "listener candidates are in priority order");
        Asserts.eq(AID_B, candidateNames.get(1), "listener candidates are in priority order");

        // --- Start C: activateNext resumes the Candidate List (H5) -----------
        ScriptedChannel resumeChannel = new ScriptedChannel();
        resumeChannel.addSelect(PPSE_AID, 0x9000, ppseFci());
        resumeChannel.addSelect(AID_A, 0x9000, adfFci(AID_A));
        resumeChannel.addSelect(AID_B, 0x9000, adfFci(AID_B));
        PpseSelection resume = new PpseSelection(supported);
        Terminal resumeTerminal = new Terminal(resumeChannel);
        Asserts.eq(AID_A, resume.activate(resumeTerminal, new TransactionRequest(TerminalConfig.builder().build()),
                        new TransactionResult.Mutable()).adfName, "first activation");
        Asserts.eq(AID_B, resume.activateNext(resumeTerminal, new TransactionRequest(TerminalConfig.builder().build()),
                        new TransactionResult.Mutable()).adfName, "activateNext resumes the Candidate List");
        Asserts.check(resume.activateNext(resumeTerminal, new TransactionRequest(TerminalConfig.builder().build()),
                        new TransactionResult.Mutable()) == null,
                "activateNext returns null when exhausted");

        // --- Per-Combination Entry Point Configuration (C13, Book A §5.7) ----
        // Combination A forbids the amount (Reader Contactless Transaction
        // Limit), so it is dropped and Combination B is selected; B's Start A
        // indicators reach the activation.
        EntryPointConfiguration limited = new EntryPointConfiguration();
        limited.readerContactlessTransactionLimitPresent = true;
        limited.readerContactlessTransactionLimit = 100;
        EntryPointConfiguration open = new EntryPointConfiguration();
        CombinationTable perCombo = new CombinationTable();
        perCombo.add(CombinationTable.PURCHASE, new Combination(AID_A, 0, limited));
        perCombo.add(CombinationTable.PURCHASE, new Combination(AID_B, 0, open));
        ScriptedChannel perComboChannel = new ScriptedChannel();
        perComboChannel.addSelect(PPSE_AID, 0x9000, ppseFci());
        perComboChannel.addSelect(AID_B, 0x9000, adfFci(AID_B));
        TransactionRequest perComboData = new TransactionRequest(TerminalConfig.builder().build());
        perComboData.amountAuthorised = Hex.parse("000000000200"); // 200 > limit
        PpseSelection perComboSel = new PpseSelection(perCombo, open);
        Asserts.eq(AID_B, perComboSel.select(new Terminal(perComboChannel), perComboData,
                        new TransactionResult.Mutable()),
                "a Combination over the Reader Contactless Transaction Limit is dropped");
        Asserts.check(!perComboSel.indicators().contactlessApplicationNotAllowed,
                "selected Combination indicators allow the application");
        Asserts.eq(Outcome.START_A, perComboSel.activation().start, "Start A activation");

        // Every Combination over the limit -> Try Another Interface.
        EntryPointConfiguration limited2 = new EntryPointConfiguration();
        limited2.readerContactlessTransactionLimitPresent = true;
        limited2.readerContactlessTransactionLimit = 100;
        CombinationTable allLimited = new CombinationTable();
        allLimited.add(CombinationTable.PURCHASE, new Combination(AID_A, 0, limited2));
        allLimited.add(CombinationTable.PURCHASE, new Combination(AID_B, 0, limited2));
        ScriptedChannel allLimitedChannel = new ScriptedChannel();
        allLimitedChannel.addSelect(PPSE_AID, 0x9000, ppseFci());
        boolean tryAnother = false;
        try {
            new PpseSelection(allLimited, limited2).select(new Terminal(allLimitedChannel),
                    perComboData, new TransactionResult.Mutable());
        } catch (card42.host.emv.kernel.core.EndApplicationException e) {
            tryAnother = e.messageIdentifier()
                    == card42.host.emv.kernel.core.EndApplicationException.TRY_ANOTHER_INTERFACE;
        }
        Asserts.check(tryAnother, "all Combinations CANA -> Try Another Interface");

        // --- Start B via Autorun (C14, Book A §8.1.1.6) ---------------------
        // Autorun is independent of Status Check: the reader activates Entry
        // Point directly at Start B even with Status Check Support off.
        EntryPointConfiguration autorun = new EntryPointConfiguration();
        autorun.autorun = true;
        ScriptedChannel startBChannel = new ScriptedChannel();
        startBChannel.addSelect(PPSE_AID, 0x9000, ppseFci());
        startBChannel.addSelect(AID_A, 0x9000, adfFci(AID_A));
        PpseSelection startBSel = new PpseSelection(CombinationTable.defaults(supported), autorun);
        startBSel.select(new Terminal(startBChannel), new TransactionRequest(TerminalConfig.builder().build()),
                new TransactionResult.Mutable());
        Asserts.eq(Outcome.START_B, startBSel.activation().start,
                "Autorun -> Start B without a status check");
        Asserts.check(!startBSel.indicators().statusCheckRequested,
                "Autorun Start B indicators are clear");

        // --- Try Again restarts the same Combination at Start B (Book B §3.5.1.3)
        ScriptedChannel tryAgainChannel = new ScriptedChannel();
        tryAgainChannel.addSelect(PPSE_AID, 0x9000, ppseFci());
        tryAgainChannel.addSelect(AID_A, 0x9000, adfFci(AID_A));
        PpseSelection tryAgainSel = new PpseSelection(CombinationTable.defaults(supported),
                new EntryPointConfiguration());
        Terminal tryAgainTerminal = new Terminal(tryAgainChannel);
        KernelActivation activated = tryAgainSel.activate(tryAgainTerminal,
                new TransactionRequest(TerminalConfig.builder().build()),
                new TransactionResult.Mutable());
        Asserts.eq(Outcome.START_A, activated.start, "initial activation is Start A");
        KernelActivation again = tryAgainSel.restartStartB(tryAgainTerminal,
                new TransactionRequest(TerminalConfig.builder().build()),
                new TransactionResult.Mutable());
        Asserts.check(again != null, "Try Again re-activates the current Combination");
        Asserts.eq(AID_A, again.adfName, "Try Again keeps the same ADF Name");
        Asserts.eq(Outcome.START_B, again.start, "Try Again restarts at Start B");
        Asserts.check(!again.indicators.statusCheckRequested,
                "Try Again Start B indicators are clear");

        // --- SPI response FCI strips 9F3E/9F3F (C15, Book B Annex C.1.4) -----
        byte[] spiFci = ppseFciWithSpi(entry(AID_A, 0x01));
        byte[] stripped = Spi.stripAdvertisement(spiFci);
        Asserts.check(Tags.find(stripped, 0x9F3E) == null
                        && Tags.find(stripped, 0x9F3F) == null,
                "SPI advertisement objects are stripped");
        Asserts.check(Tags.find(stripped, 0xBF0C) != null
                        && Tags.find(stripped, 0x4F) != null,
                "stripped FCI keeps the Directory Entry");
        byte[] noAdvertisement = ppseFci();
        Asserts.check(Spi.stripAdvertisement(noAdvertisement) == noAdvertisement,
                "FCI without the advertisement is returned unchanged");
    }

    /** A minimal ADF FCI: 6F { 84 <AID> }. */
    private static byte[] adfFci(String aidHex) {
        ByteArrayOutputStream fci = new ByteArrayOutputStream();
        TlvWriter.writeTlv(fci, 0x84, Hex.parse(aidHex));
        ByteArrayOutputStream t = new ByteArrayOutputStream();
        TlvWriter.writeTlv(t, 0x6F, fci.toByteArray());
        return t.toByteArray();
    }

    /** An ADF FCI carrying a PDOL: 6F { 84 <AID>, 9F38 <pdol> }. */
    private static byte[] adfFciWithPdol(String aidHex, byte[] pdol) {
        ByteArrayOutputStream fci = new ByteArrayOutputStream();
        TlvWriter.writeTlv(fci, 0x84, Hex.parse(aidHex));
        TlvWriter.writeTlv(fci, 0x9F38, pdol);
        ByteArrayOutputStream t = new ByteArrayOutputStream();
        TlvWriter.writeTlv(t, 0x6F, fci.toByteArray());
        return t.toByteArray();
    }

    /** A PPSE FCI with one Directory Entry carrying an optional Kernel Identifier. */
    private static byte[] ppseFciWithKernel(String aidHex, int priority, byte[] kernelId) {
        ByteArrayOutputStream bf0c = new ByteArrayOutputStream();
        TlvWriter.writeTlv(bf0c, 0x61, entry(aidHex, priority, kernelId));
        ByteArrayOutputStream a5 = new ByteArrayOutputStream();
        TlvWriter.writeTlv(a5, 0xBF0C, bf0c.toByteArray());
        ByteArrayOutputStream fci = new ByteArrayOutputStream();
        TlvWriter.writeTlv(fci, 0xA5, a5.toByteArray());
        return fci.toByteArray();
    }

    /** A PPSE FCI wrapping the given Directory Entry values. */
    private static byte[] ppseFci(byte[]... entries) {
        ByteArrayOutputStream bf0c = new ByteArrayOutputStream();
        for (byte[] entry : entries) {
            TlvWriter.writeTlv(bf0c, 0x61, entry);
        }
        ByteArrayOutputStream a5 = new ByteArrayOutputStream();
        TlvWriter.writeTlv(a5, 0xBF0C, bf0c.toByteArray());
        ByteArrayOutputStream fci = new ByteArrayOutputStream();
        TlvWriter.writeTlv(fci, 0xA5, a5.toByteArray());
        return fci.toByteArray();
    }

    /** A PPSE FCI with AID_A (priority 1) and AID_B (priority 2). */
    private static byte[] ppseFci() {
        ByteArrayOutputStream bf0c = new ByteArrayOutputStream();
        TlvWriter.writeTlv(bf0c, 0x61, entry(AID_A, 0x01));
        TlvWriter.writeTlv(bf0c, 0x61, entry(AID_B, 0x02));
        ByteArrayOutputStream a5 = new ByteArrayOutputStream();
        TlvWriter.writeTlv(a5, 0xBF0C, bf0c.toByteArray());
        ByteArrayOutputStream fci = new ByteArrayOutputStream();
        TlvWriter.writeTlv(fci, 0xA5, a5.toByteArray());
        return fci.toByteArray();
    }

    /** A PPSE FCI whose BF0C advertises SPI support ('9F3E'/'9F3F'). */
    private static byte[] ppseFciWithSpi(byte[]... entries) {
        return ppseFciWithCategoriesAndSdol(Hex.parse("00010002"),
                Hex.parse("9F1A025F2A02"), entries);
    }

    /** A PPSE FCI with a '9F3E' list and no '9F3F'. */
    private static byte[] ppseFciWithCategories(byte[] entry, byte[] categories) {
        return ppseFciWithCategoriesAndSdol(categories, null, entry);
    }

    private static byte[] ppseFciWithCategoriesAndSdol(byte[] categories, byte[] sdol,
            byte[]... entries) {
        ByteArrayOutputStream bf0c = new ByteArrayOutputStream();
        for (byte[] entry : entries) {
            TlvWriter.writeTlv(bf0c, 0x61, entry);
        }
        if (categories != null) {
            TlvWriter.writeTlv(bf0c, 0x9F3E, categories);
        }
        if (sdol != null) {
            TlvWriter.writeTlv(bf0c, 0x9F3F, sdol);
        }
        ByteArrayOutputStream a5 = new ByteArrayOutputStream();
        TlvWriter.writeTlv(a5, 0xBF0C, bf0c.toByteArray());
        ByteArrayOutputStream fci = new ByteArrayOutputStream();
        TlvWriter.writeTlv(fci, 0xA5, a5.toByteArray());
        return fci.toByteArray();
    }

    /** One Directory Entry with an ADF Name, priority 1 and an Extended Selection. */
    private static byte[] entryWithExtended(String aidHex, String extendedHex) {
        ByteArrayOutputStream entry = new ByteArrayOutputStream();
        TlvWriter.writeTlv(entry, 0x4F, Hex.parse(aidHex));
        TlvWriter.writeTlv(entry, 0x87, new byte[] { 0x01 });
        TlvWriter.writeTlv(entry, 0x9F29, Hex.parse(extendedHex));
        return entry.toByteArray();
    }

    /** One 61 Directory Entry with an ADF Name and priority. */
    private static byte[] entry(String aidHex, int priority) {
        return entry(aidHex, priority, null);
    }

    /** One 61 Directory Entry with an ADF Name, priority and optional Kernel Identifier. */
    private static byte[] entry(String aidHex, int priority, byte[] kernelId) {
        ByteArrayOutputStream entry = new ByteArrayOutputStream();
        TlvWriter.writeTlv(entry, 0x4F, Hex.parse(aidHex));
        TlvWriter.writeTlv(entry, 0x87, new byte[] { (byte) priority });
        if (kernelId != null) {
            TlvWriter.writeTlv(entry, 0x9F2A, kernelId);
        }
        return entry.toByteArray();
    }

    /** The first selected ADF Name for a reader Combination Table, or null. */
    private static String selected(byte[] fci, CombinationTable table) {
        java.util.List<EntryPoint.Candidate> list = EntryPoint.selectCandidates(
                fci, table, CombinationTable.PURCHASE);
        return list.isEmpty() ? null : list.get(0).adfHex;
    }

    /** A CardChannel that answers SELECT by AID with scripted responses. */
    private static final class ScriptedChannel extends CardChannel {
        private final Map<String, ResponseAPDU> selects = new HashMap<String, ResponseAPDU>();
        private ResponseAPDU spi;
        boolean spiSent;
        byte[] lastSpiData;
        String lastSelectAid;

        void addSelect(String aidHex, int sw, byte[] data) {
            selects.put(aidHex, response(sw, data));
        }

        void setSpi(int sw, byte[] data) {
            spi = response(sw, data);
        }

        private static ResponseAPDU response(int sw, byte[] data) {
            byte[] body = data == null ? new byte[0] : data;
            byte[] full = new byte[body.length + 2];
            System.arraycopy(body, 0, full, 0, body.length);
            full[body.length] = (byte) (sw >> 8);
            full[body.length + 1] = (byte) sw;
            return new ResponseAPDU(full);
        }

        @Override
        public Card getCard() {
            throw new UnsupportedOperationException();
        }

        @Override
        public int getChannelNumber() {
            return 0;
        }

        @Override
        public ResponseAPDU transmit(CommandAPDU command) throws CardException {
            if (command.getINS() == 0x1A) { // SEND POI INFORMATION
                spiSent = true;
                lastSpiData = command.getData();
                if (spi != null) {
                    return spi;
                }
                throw new CardException("unexpected SPI");
            }
            if (command.getINS() == 0xA4 && command.getP1() == 0x04) {
                lastSelectAid = Hex.format(command.getData());
                ResponseAPDU r = selects.get(lastSelectAid);
                if (r != null) {
                    return r;
                }
            }
            throw new CardException("unexpected command");
        }

        @Override
        public int transmit(ByteBuffer command, ByteBuffer response) throws CardException {
            throw new UnsupportedOperationException();
        }

        @Override
        public void close() throws CardException {
        }
    }
}
