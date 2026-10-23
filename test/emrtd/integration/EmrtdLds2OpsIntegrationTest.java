package card42.test;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;

import javax.smartcardio.Card;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.ResponseAPDU;

import card42.host.common.cli.Args;
import card42.host.common.codec.DerWriter;
import card42.host.common.transport.Terminal;
import card42.host.common.util.Hex;
import card42.host.emrtd.access.LdsReader;
import card42.host.emrtd.access.Pace;
import card42.host.emrtd.access.lds2.Lds2CertificateStore;
import card42.host.emrtd.access.lds2.Lds2Fmm;
import card42.host.emrtd.access.lds2.Lds2RecordWriter;
import card42.host.emrtd.access.lds2.Lds2Search;
import card42.host.emrtd.lds.common.LdsFileUtil;
import card42.host.emrtd.lds.lds2.BiometricsRecord;
import card42.host.emrtd.lds.lds2.BiometricsRecordBuilder;
import card42.host.emrtd.lds.lds2.CertificateRecord;
import card42.host.emrtd.lds.lds2.CertificateRecordBuilder;
import card42.host.emrtd.lds.lds2.Lds2Record;
import card42.host.emrtd.lds.lds2.TravelRecord;
import card42.host.emrtd.lds.lds2.TravelRecordBuilder;
import card42.host.emrtd.lds.lds2.VisaRecord;
import card42.host.emrtd.lds.lds2.VisaRecordBuilder;
import card42.host.emrtd.pa.CscaKeyStore;
import card42.host.emrtd.pa.Lds2Verifier;
import card42.host.emrtd.tools.EmrtdPersoExporter;
import card42.host.emrtd.tools.TaChain;
import card42.host.emrtd.transport.EmrtdTerminal;

/**
 * End-to-end LDS2 file and record operations (ICAO Doc 9303-10 §3.7/§3.8).
 *
 * <p>Complements the read-only Travel/Visa/Biometrics suites with the commands
 * they did not drive through the card:
 *
 * <ul>
 *   <li>FMM (Table 22-27): existing/remaining/total counts, P1=00 current EF,
 *       short EF identifier addressing and the "referenced EF becomes current"
 *       rule (§3.8.3).</li>
 *   <li>SEARCH RECORD (Table 14-17, Appendix I.1/J.1): file identifier and raw
 *       short EF identifier, window offset/length, stop-after-first and no-match
 *       '6282'.</li>
 *   <li>READ RECORD(S) P2 b2b1=01: multiple records in one response, and P1=00
 *       referencing the current record (Table 11/13, Appendix H.3).</li>
 *   <li>READ BINARY short EF identifier and multi-chunk reads of a
 *       &gt;223-byte transparent EF.</li>
 *   <li>UPDATE BINARY + ACTIVATE (Table 18-21): DO'54'/DO'53'/DO'C0' sequence,
 *       read-back before activation, activated-state read-only enforcement.</li>
 *   <li>APPEND RECORD (Table 8-10): Travel ExitRecords, VisaRecords and a new
 *       LDS2 Signer certificate in EF.Certificates; the certificate append also
 *       exercises the b4 authorization bit.</li>
 *   <li>APPEND errors: a 641-byte record in a 640-byte EF returns '6700'.</li>
 * </ul>
 *
 * <p>All writes are semantic-idempotent: a repeated run against a persistent
 * real card reuses the record with the same identifying fields instead of
 * appending another copy.  The biometrics EF 0202 is used instead of the
 * pre-personalized 0201 so the sample data stays untouched.
 */
public final class EmrtdLds2OpsIntegrationTest {

    private static final int FID_ENTRY = LdsFileUtil.FID_RECORDS;
    private static final int FID_EXIT = LdsFileUtil.FID_EXIT_RECORDS;
    private static final int FID_CERT = LdsFileUtil.FID_CERTIFICATES;
    private static final int BIO_EF = 0x0202;

    private static final int BIO_CHUNK = 200;

    private EmrtdLds2OpsIntegrationTest() {
    }

    public static void main(String[] argv) throws Exception {
        Args args = new Args(argv, new String[] { "host" }, new String[0]);
        String host = args.get("host", "socket:localhost:9025");
        CardTerminal cardTerminal = TestTerminals.getTerminal(host.split(":"));
        if (cardTerminal == null || !cardTerminal.waitForCardPresent(10000)) {
            throw new IllegalStateException("Connection to simulator failed on " + host);
        }
        Card card = cardTerminal.connect("*");
        try {
            run(new EmrtdTerminal(new Terminal(card.getBasicChannel())));
        } finally {
            card.disconnect(true);
        }
        if (Checks.failures() > 0) {
            System.out.println("FAILED: " + Checks.failures() + " LDS2 operation check(s)");
            System.exit(1);
        }
        System.out.println("ALL EMRTD LDS2 OPERATION CHECKS PASSED");
    }

    static void run(EmrtdTerminal terminal) throws Exception {
        authenticate(terminal, LdsFileUtil.AID_TRAVEL, "Travel");
        fmmAndSearch(terminal);
        readModes(terminal);
        readBinaryVariants(terminal);
        travelWrites(terminal);
        biometricsWrite(terminal);
        visaWrite(terminal);
        restrictedAuthorization(terminal);
    }

    // --- FMM and SEARCH (Doc 9303-10 §3.7.3/§3.8.3) -------------------------

    private static void fmmAndSearch(EmrtdTerminal terminal) throws Exception {
        Lds2Fmm.Info entry = Lds2Fmm.query(terminal, FID_ENTRY, Lds2Fmm.ALL);
        Checks.check("FMM P1=01 exists for the EntryRecords EF", entry.existingRecords >= 3);
        Checks.check("FMM P2 returns the total byte count", entry.totalBytes > 0);
        Checks.check("FMM P2 returns the remaining record count",
                entry.remainingRecords >= 0);

        Lds2Fmm.Info current = Lds2Fmm.queryCurrent(terminal, Lds2Fmm.TOTAL_BYTES);
        Checks.check("FMM P1=00 addresses the current EF",
                current.totalBytes == entry.totalBytes);
        Lds2Fmm.Info sfi = Lds2Fmm.querySfi(terminal,
                LdsFileUtil.sfi(FID_ENTRY), Lds2Fmm.EXISTING_RECORDS);
        Checks.check("FMM DO'51' short EF identifier form",
                sfi.existingRecords == entry.existingRecords);

        // After a successful FMM the referenced EF is the current EF (§3.8.3).
        byte[] first = LdsReader.readRecord(terminal, LdsFileUtil.sfi(FID_ENTRY), 1);
        ResponseAPDU currentRecord = terminal.readRecord(0, 1, false, LdsReader.RECORD_LE);
        Checks.check("FMM left the referenced EF current", currentRecord.getSW(), 0x9000);
        Checks.bytes(first, currentRecord.getData(), "current-EF READ RECORD");

        // Appendix I.1: window offset 3 (destination state), length 3, by FID.
        List<Integer> nld = Lds2Search.search(terminal, FID_ENTRY, 3, 3,
                "NLD".getBytes(java.nio.charset.StandardCharsets.US_ASCII), false);
        Checks.check("SEARCH RECORD by FID finds the NLD entry", nld.contains(2));
        // The same search with the raw short EF identifier and stop-after-first.
        List<Integer> raw = Lds2Search.searchSfi(terminal, LdsFileUtil.sfi(FID_ENTRY),
                3, 3, "NLD".getBytes(java.nio.charset.StandardCharsets.US_ASCII), true);
        Checks.check("SEARCH RECORD raw SFI + stop-after-first returns one match",
                raw.size() == 1 && raw.get(0) == 2);
        List<Integer> none = Lds2Search.search(terminal, FID_ENTRY, 3, 3,
                "ZZZ".getBytes(java.nio.charset.StandardCharsets.US_ASCII), false);
        Checks.check("SEARCH RECORD without a match -> 6282", none.isEmpty());

        // Appendix J.1: search EF.Certificates by country + serial (offset 3).
        List<byte[]> certificates = LdsReader.readAllRecords(terminal,
                LdsFileUtil.sfi(FID_CERT), 1);
        CertificateRecord signer = (CertificateRecord) Lds2Record.parse(
                Lds2Record.Kind.CERTIFICATE, certificates.get(0));
        List<Integer> certificateMatch = Lds2Search.searchSfi(terminal,
                LdsFileUtil.sfi(FID_CERT), 3, signer.serial.length, signer.serial, true);
        Checks.check("SEARCH RECORD finds EF.Certificates record 1 by 5F3A",
                certificateMatch.contains(1));
    }

    // --- READ RECORD and READ BINARY (Doc 9303-10 §3.6.3/§3.7.2) ------------

    private static void readModes(EmrtdTerminal terminal) throws Exception {
        int sfi = LdsFileUtil.sfi(FID_ENTRY);
        byte[] record2 = LdsReader.readRecord(terminal, sfi, 2);
        ResponseAPDU current = terminal.readRecord(sfi, 0, false, LdsReader.RECORD_LE);
        Checks.check("READ RECORD P1=00 returns the current record", current.getSW(), 0x9000);
        Checks.bytes(record2, current.getData(), "P1=00 current record data");

        List<byte[]> all = LdsReader.readAllRecords(terminal, sfi, 1);
        byte[] sequence = LdsReader.readRecordSequence(terminal, sfi, 1);
        Checks.bytes(concat(all), sequence, "READ RECORD P2=05 from record 1");
        Checks.check("READ RECORD P2=05 returns more than one record",
                sequence.length > all.get(0).length);

        byte[] tail = LdsReader.readRecordSequence(terminal, sfi, 2);
        Checks.bytes(concat(all.subList(1, all.size())), tail,
                "READ RECORD P2=05 from record 2");
    }

    private static void readBinaryVariants(EmrtdTerminal terminal) throws Exception {
        ResponseAPDU dir = terminal.readBinarySfi(0x1E, 0, 0x20);
        Checks.check("READ BINARY short EF identifier for EF.DIR", dir.getSW(), 0x9000);
        Checks.check("EF.DIR content is an application template",
                dir.getData().length > 2 && (dir.getData()[0] & 0xFF) == 0x61);

        ResponseAPDU atr = terminal.readBinarySfi(0x01, 0, 0x20);
        Checks.check("READ BINARY short EF identifier for EF.ATR/INFO", atr.getSW(), 0x9000);
        Checks.check("EF.ATR/INFO starts with the card capabilities tag",
                atr.getData().length > 0 && (atr.getData()[0] & 0xFF) == 0x47);
    }

    // --- APPEND RECORD (Doc 9303-10 §3.7.1) ---------------------------------

    private static void travelWrites(EmrtdTerminal terminal) throws Exception {
        PrivateKey signerKey = EmrtdPersoExporter.loadPrivateKey("perso/emrtd/lds2.key");
        X509Certificate signer = Lds2Verifier.loadCertificate(terminal, 1);
        CscaKeyStore trust = CscaKeyStore.fromFiles(new File("perso/emrtd/csca.crt"));

        // Travel ExitRecords: a Table 86 record not present in the sample.
        TravelRecordBuilder exitBuilder = new TravelRecordBuilder()
                .state("CAN")
                .travelDate("20260704")
                .inspectionAuthority("CBSA")
                .inspectionLocation("YYZ")
                .inspectorReference("YYZ00007")
                .modeOfTravel("A")
                .certificateReference(1);
        int exitIndex = appendTravelIfAbsent(terminal, FID_EXIT, exitBuilder, signerKey, "CAN");
        byte[] exitReadBack = LdsReader.readRecord(terminal, LdsFileUtil.sfi(FID_EXIT), exitIndex);
        TravelRecord exitRecord = (TravelRecord) Lds2Record.parse(
                Lds2Record.Kind.TRAVEL, exitReadBack);
        Checks.check("appended Travel Exit record is well formed", exitRecord.wellFormed);
        Checks.check("Travel Exit signature verifies",
                exitRecord.verify(signer.getPublicKey()));

        // A second LDS2 Signer certificate: findOrAppend must append (not reuse
        // record 1), which is exactly the EF.Certificates b4 append right.
        X509Certificate alternate = EmrtdPersoExporter.loadCertificate(
                "perso/emrtd/lds2-alt.crt");
        int alternateReference = Lds2CertificateStore.findOrAppend(terminal, alternate,
                "travel", trust);
        Checks.check("new LDS2 Signer certificate is appended or reused after record 1",
                alternateReference >= 2);
        byte[] alternateRecordBytes = LdsReader.readRecord(terminal,
                LdsFileUtil.sfi(FID_CERT), alternateReference);
        CertificateRecord alternateRecord = (CertificateRecord) Lds2Record.parse(
                Lds2Record.Kind.CERTIFICATE, alternateRecordBytes);
        Checks.bytes(alternate.getEncoded(), alternateRecord.certificate,
                "EF.Certificates record carries the alternative X.509 certificate");

        List<Integer> found = Lds2Search.searchSfi(terminal, LdsFileUtil.sfi(FID_CERT),
                3, alternateRecord.serial.length, alternateRecord.serial, true);
        Checks.check("SEARCH RECORD finds the appended certificate",
                found.contains(alternateReference));

        // A Travel record signed by the alternative key and referencing the
        // appended certificate proves the 5F38 indirection and b4 path.
        PrivateKey alternateKey = EmrtdPersoExporter.loadPrivateKey("perso/emrtd/lds2-alt.key");
        TravelRecordBuilder alternateEntry = new TravelRecordBuilder()
                .state("NOR")
                .travelDate("20260808")
                .inspectionAuthority("POL")
                .inspectionLocation("OSL")
                .inspectorReference("OSL00008")
                .modeOfTravel("A")
                .certificateReference(alternateReference);
        int alternateIndex = appendTravelIfAbsent(terminal, FID_ENTRY, alternateEntry,
                alternateKey, "NOR");
        byte[] alternateReadBack = LdsReader.readRecord(terminal,
                LdsFileUtil.sfi(FID_ENTRY), alternateIndex);
        TravelRecord alternateParsed = (TravelRecord) Lds2Record.parse(
                Lds2Record.Kind.TRAVEL, alternateReadBack);
        Checks.check("alternate-signer Travel record is well formed",
                alternateParsed.wellFormed);
        Checks.check("alternate-signer Travel record references the appended certificate",
                Integer.valueOf(alternateReference).equals(
                        alternateParsed.certificateReference));
        Checks.check("alternate-signer Travel signature verifies",
                alternateParsed.verify(alternate.getPublicKey()));

        // Table 9: a record longer than the 640-byte EF limit is '6700'.
        ResponseAPDU tooLong = terminal.appendRecord(LdsFileUtil.sfi(FID_ENTRY),
                new byte[641]);
        Checks.check("APPEND RECORD of 641 B into the 640 B EntryRecords -> 6700",
                tooLong.getSW(), 0x6700);
    }

    private static int appendTravelIfAbsent(EmrtdTerminal terminal, int fid,
                                            TravelRecordBuilder builder, PrivateKey key,
                                            String state) throws Exception {
        List<byte[]> before = LdsReader.readAllRecords(terminal, LdsFileUtil.sfi(fid), 1);
        for (int i = 0; i < before.size(); i++) {
            TravelRecord record = (TravelRecord) Lds2Record.parse(
                    Lds2Record.Kind.TRAVEL, before.get(i));
            if (state.equals(record.state)) {
                return i + 1;
            }
        }
        Lds2RecordWriter.append(terminal, fid, builder.build(key));
        return before.size() + 1;
    }

    // --- UPDATE BINARY + ACTIVATE (Doc 9303-10 §3.8) ------------------------

    private static void biometricsWrite(EmrtdTerminal terminal) throws Exception {
        terminal.setSecureMessaging(null);
        authenticate(terminal, LdsFileUtil.AID_BIOMETRICS, "Biometrics");

        byte[] biometrics = new byte[400];
        for (int i = 0; i < biometrics.length; i++) {
            biometrics[i] = (byte) (i * 7 + 1);
        }
        PrivateKey key = EmrtdPersoExporter.loadPrivateKey("perso/emrtd/lds2.key");
        byte[] record = new BiometricsRecordBuilder()
                .biometrics(biometrics)
                .certificateReference(1)
                .build(key);
        X509Certificate signer = Lds2Verifier.loadCertificate(terminal, 1);

        ResponseAPDU selected = terminal.selectFile(BIO_EF);
        Checks.check("SELECT EF.Biometrics2", selected.getSW(), 0x9000);

        boolean written = writeBiometrics(terminal, BIO_EF, record);
        if (!written) {
            // A previous run activated this EF; it is now permanently read-only.
            Checks.check("EF.Biometrics2 was already activated by an earlier run", true);
            ResponseAPDU denied = terminal.updateBinary(updateData(0, record, 0, 1, -1));
            Checks.check("UPDATE BINARY on the already Activated EF -> 6982",
                    denied.getSW(), 0x6982);
            verifyBiometrics(terminal, signer, "existing");
            return;
        }

        byte[] beforeActivate = LdsReader.read(terminal, BIO_EF);
        Checks.bytes(record, beforeActivate,
                "READ BINARY multi-chunk before ACTIVATE");

        Lds2Fmm.Info info = Lds2Fmm.query(terminal, BIO_EF, Lds2Fmm.TOTAL_BYTES);
        Checks.check("FMM transparent EF total bytes", info.totalBytes == record.length);
        ResponseAPDU records = terminal.fileMemoryManagement(0x01,
                Lds2Fmm.REMAINING_RECORDS,
                DerWriter.tlv(0x51, new byte[] { (byte) (BIO_EF >> 8), (byte) BIO_EF }));
        Checks.check("FMM record query on a transparent EF -> 6A86",
                records.getSW(), 0x6A86);

        Checks.check("ACTIVATE EF.Biometrics2", terminal.activate().getSW(), 0x9000);
        ResponseAPDU denied = terminal.updateBinary(updateData(0, record, 0, 1, -1));
        Checks.check("UPDATE BINARY after ACTIVATE -> 6982", denied.getSW(), 0x6982);
        Checks.bytes(record, LdsReader.read(terminal, BIO_EF),
                "reading the Activated EF still works");

        verifyBiometrics(terminal, signer, "written");
    }

    /**
     * Sends the Doc 9303-10 §3.8 writing sequence.  The first chunk carries the
     * optional DO'C0' and CLA bit 8 (Table 18); later chunks only DO'54'/DO'53'.
     *
     * @return false when the EF is already Activated (first UPDATE -> 6982)
     */
    private static boolean writeBiometrics(EmrtdTerminal terminal, int fid, byte[] record)
            throws Exception {
        for (int offset = 0; offset < record.length; offset += BIO_CHUNK) {
            int length = Math.min(BIO_CHUNK, record.length - offset);
            byte[] data = updateData(offset, record, offset, length,
                    offset == 0 ? record.length : -1);
            ResponseAPDU response = offset == 0
                    ? terminal.updateBinaryWithSize(data)
                    : terminal.updateBinary(data);
            if (response.getSW() != 0x9000) {
                if (offset == 0 && response.getSW() == 0x6982) {
                    return false;
                }
                throw new IllegalStateException("UPDATE BINARY " + String.format("%04X", fid)
                        + " @" + offset + " -> " + String.format("%04X", response.getSW()));
            }
        }
        return true;
    }

    private static byte[] updateData(int offset, byte[] record, int dataOffset, int length,
                                     int totalSize) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] offsetDo = DerWriter.tlv(0x54, unsigned(offset));
        byte[] dataDo = DerWriter.tlv(0x53, Arrays.copyOfRange(record, dataOffset,
                dataOffset + length));
        out.write(offsetDo, 0, offsetDo.length);
        out.write(dataDo, 0, dataDo.length);
        if (totalSize >= 0) {
            byte[] sizeDo = DerWriter.tlv(0xC0, unsigned(totalSize));
            out.write(sizeDo, 0, sizeDo.length);
        }
        return out.toByteArray();
    }

    private static byte[] unsigned(int value) {
        if (value <= 0xFF) {
            return new byte[] { (byte) value };
        }
        return new byte[] { (byte) (value >> 8), (byte) value };
    }

    private static void verifyBiometrics(EmrtdTerminal terminal, X509Certificate signer,
                                         String label) throws Exception {
        byte[] read = LdsReader.read(terminal, BIO_EF);
        BiometricsRecord record = (BiometricsRecord) Lds2Record.parse(
                Lds2Record.Kind.BIOMETRICS, read);
        Checks.check(label + " EF.Biometrics2 is a signed 7F2E wrapper",
                record.wellFormed);
        Checks.check(label + " EF.Biometrics2 signature verifies",
                record.verify(signer.getPublicKey()));
    }

    // --- Visa APPEND RECORD -------------------------------------------------

    private static void visaWrite(EmrtdTerminal terminal) throws Exception {
        terminal.setSecureMessaging(null);
        authenticate(terminal, LdsFileUtil.AID_VISA, "Visa");

        Lds2Fmm.Info visaInfo = Lds2Fmm.query(terminal,
                LdsFileUtil.FID_VISA_RECORDS, Lds2Fmm.ALL);
        Checks.check("FMM reports the sample Visa records",
                visaInfo.existingRecords >= 2);
        List<Integer> jpn = Lds2Search.search(terminal, LdsFileUtil.FID_VISA_RECORDS,
                3, 3, "JPN".getBytes(java.nio.charset.StandardCharsets.US_ASCII), false);
        Checks.check("SEARCH RECORD finds the JPN Visa record", jpn.contains(1));

        PrivateKey key = EmrtdPersoExporter.loadPrivateKey("perso/emrtd/lds2.key");
        X509Certificate signer = Lds2Verifier.loadCertificate(terminal, 1);
        VisaRecordBuilder builder = new VisaRecordBuilder()
                .issuingState("KOR")
                .documentType("VS")
                .placeOfIssue("SEOUL")
                .effectiveDate("20260901")
                .expirationDate("20280901")
                .documentNumber("Z7654321")
                .name("KIM MIN")
                .surname("KIM")
                .givenNames("MIN")
                .sex("M")
                .dateOfBirth("19920202")
                .nationality("KOR")
                .mrz("V<KORZ7654321<<KIM<<MIN<<<<<<<<<<<<<<<<<<<<<<<<")
                .certificateReference(1);

        List<byte[]> before = LdsReader.readAllRecords(terminal,
                LdsFileUtil.sfi(LdsFileUtil.FID_VISA_RECORDS), 1);
        int index = -1;
        for (int i = 0; i < before.size(); i++) {
            VisaRecord record = (VisaRecord) Lds2Record.parse(
                    Lds2Record.Kind.VISA, before.get(i));
            if ("KOR".equals(record.issuingState)
                    && "Z7654321".equals(record.field(0x5A))) {
                index = i + 1;
                break;
            }
        }
        if (index < 0) {
            Lds2RecordWriter.append(terminal, LdsFileUtil.FID_VISA_RECORDS,
                    builder.build(key));
            index = before.size() + 1;
        }
        byte[] readBack = LdsReader.readRecord(terminal,
                LdsFileUtil.sfi(LdsFileUtil.FID_VISA_RECORDS), index);
        VisaRecord visa = (VisaRecord) Lds2Record.parse(Lds2Record.Kind.VISA, readBack);
        Checks.check("appended Visa record is well formed", visa.wellFormed);
        Checks.check("Visa record fields are encoded",
                "KOR".equals(visa.issuingState) && "Z7654321".equals(visa.field(0x5A)));
        Checks.check("Visa record signature verifies", visa.verify(signer.getPublicKey()));
    }

    // --- Authorization bits (Doc 9303-10 §5.4.2 Table 96) -------------------

    /**
     * Authenticates with a terminal chain whose Travel extension is b1 only
     * (read/search/select/FMM of Entry/Exit) and proves b2/b3/b4 are denied:
     * append Entry, read Certificate and append Certificate all return 6982,
     * while reading Entry still succeeds.
     */
    private static void restrictedAuthorization(EmrtdTerminal terminal) throws Exception {
        terminal.setSecureMessaging(null);
        Checks.check("SELECT Travel Records for the restricted TA",
                terminal.selectApplication(LdsFileUtil.AID_TRAVEL).getSW(), 0x9000);
        SecureRandom random = new SecureRandom();
        Pace.Session pace = Pace.authenticate(terminal, EmrtdPersoExporter.DOCUMENT_NUMBER,
                EmrtdPersoExporter.DATE_OF_BIRTH, EmrtdPersoExporter.DATE_OF_EXPIRY);
        terminal.setSecureMessaging(pace.secureMessaging());
        TaSupport.authenticate(terminal, pace, random,
                TaChain.demo(random, (byte) 0x01));

        Checks.check("b1 grants READ RECORD on EntryRecords",
                terminal.readRecord(LdsFileUtil.sfi(FID_ENTRY), 1, false,
                        LdsReader.RECORD_LE).getSW(), 0x9000);
        Checks.check("b1 does not grant APPEND on EntryRecords",
                terminal.appendRecord(LdsFileUtil.sfi(FID_ENTRY),
                        Hex.parse("5F4403555341")).getSW(), 0x6982);
        Checks.check("b1 does not grant READ RECORD on EF.Certificates",
                terminal.readRecord(LdsFileUtil.sfi(FID_CERT), 1, false,
                        LdsReader.RECORD_LE).getSW(), 0x6982);
        Checks.check("b1 does not grant SELECT of EF.Certificates",
                terminal.selectFile(FID_CERT).getSW(), 0x6982);
        Checks.check("b1 does not grant FMM of EF.Certificates",
                terminal.fileMemoryManagement(0x01, Lds2Fmm.EXISTING_RECORDS,
                        DerWriter.tlv(0x51, new byte[] { (byte) (FID_CERT >> 8),
                                (byte) FID_CERT })).getSW(), 0x6982);

        X509Certificate alternate = EmrtdPersoExporter.loadCertificate(
                "perso/emrtd/lds2-alt.crt");
        byte[] certificateRecord = new CertificateRecordBuilder()
                .country("US")
                .serialNumber(alternate.getSerialNumber().toByteArray())
                .certificate(alternate.getEncoded())
                .build();
        Checks.check("b1 does not grant APPEND on EF.Certificates (b4)",
                terminal.appendRecord(LdsFileUtil.sfi(FID_CERT),
                        certificateRecord).getSW(), 0x6982);
        Checks.check("b1 does not grant SEARCH RECORD on EF.Certificates (b3)",
                terminal.searchRecord(Lds2Search.commandSfi(
                        LdsFileUtil.sfi(FID_CERT), 3, 18,
                        new byte[18], false)).getSW(), 0x6982);
    }

    // --- helpers ------------------------------------------------------------

    private static Pace.Session authenticate(EmrtdTerminal terminal, String aid, String label)
            throws Exception {
        Checks.check("SELECT " + label + " Records",
                terminal.selectApplication(aid).getSW(), 0x9000);
        Pace.Session pace = Pace.authenticate(terminal, EmrtdPersoExporter.DOCUMENT_NUMBER,
                EmrtdPersoExporter.DATE_OF_BIRTH, EmrtdPersoExporter.DATE_OF_EXPIRY);
        terminal.setSecureMessaging(pace.secureMessaging());
        Checks.check("PACE established on " + label, true);
        TaSupport.authenticate(terminal, pace, new SecureRandom());
        Checks.check("Chip + Terminal Authentication on " + label, true);
        return pace;
    }

    private static byte[] concat(List<byte[]> records) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] record : records) {
            out.write(record, 0, record.length);
        }
        return out.toByteArray();
    }
}
