package card42.test;

import java.io.ByteArrayInputStream;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.smartcardio.Card;
import javax.smartcardio.CardTerminal;

import card42.host.common.cli.Args;
import card42.host.common.transport.Terminal;
import card42.host.emrtd.access.LdsReader;
import card42.host.emrtd.access.Pace;
import card42.host.emrtd.lds.CertificateRecord;
import card42.host.emrtd.lds.Lds2Record;
import card42.host.emrtd.access.Lds2CertificateStore;
import card42.host.emrtd.access.Lds2RecordWriter;
import card42.host.emrtd.lds.LdsFileUtil;
import card42.host.emrtd.lds.TravelRecord;
import card42.host.emrtd.lds.TravelRecordBuilder;
import card42.host.emrtd.perso.EmrtdPersoExporter;
import card42.host.emrtd.transport.EmrtdTerminal;

/**
 * End-to-end structured LDS2 write: build a Table 86 Travel record, sign the
 * {@code 73} DO with the demo LDS2-TS key (the DSC fixture used by the sample
 * EF.Certificates record), APPEND it to EF.EntryRecords after PACE+TA, read it
 * back and verify the signature with the certificate read from the card.
 */
public final class EmrtdLds2WriteIntegrationTest {

    private static final int FID_ENTRY = 0x0101;

    private EmrtdLds2WriteIntegrationTest() {
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
            System.out.println("FAILED: " + Checks.failures() + " LDS2 write check(s)");
            System.exit(1);
        }
        System.out.println("ALL EMRTD LDS2 WRITE CHECKS PASSED");
    }

    static void run(EmrtdTerminal terminal) throws Exception {
        Checks.check("SELECT Travel Records",
                terminal.selectApplication(LdsFileUtil.AID_TRAVEL).getSW(), 0x9000);
        Pace.Session pace = Pace.authenticate(terminal, EmrtdPersoExporter.DOCUMENT_NUMBER,
                EmrtdPersoExporter.DATE_OF_BIRTH, EmrtdPersoExporter.DATE_OF_EXPIRY);
        terminal.setSecureMessaging(pace.secureMessaging());
        TaSupport.authenticate(terminal, pace, new java.security.SecureRandom());

        // The sample writes the DSC as a wrapped Table 83 record; parse it to
        // obtain the certificate used for the LDS2-TS signature check.
        byte[] certBytes = LdsReader.readRecord(terminal,
                LdsFileUtil.sfi(LdsFileUtil.FID_CERTIFICATES), 1);
        CertificateRecord certificateRecord = (CertificateRecord) Lds2Record.parse(
                "EF.Certificates (011A)", certBytes);
        Checks.check("EF.Certificates exposes the X.509 certificate",
                certificateRecord.certificate != null);
        X509Certificate certificate = (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(certificateRecord.certificate));

        int certificateReference = Lds2CertificateStore.findOrAppend(
                terminal, certificate, "US");
        Checks.check("EF.Certificates dedup returns record 1",
                certificateReference == 1);

        PrivateKey signerKey = EmrtdPersoExporter.loadPrivateKey("perso/emrtd/dsc.key");
        byte[] record = new TravelRecordBuilder()
                .state("SWE")
                .travelDate("20260701")
                .inspectionAuthority("POL")
                .inspectionLocation("ARN")
                .inspectorReference("ARN00005")
                .modeOfTravel("A")
                .certificateReference(certificateReference)
                .build(signerKey);

        List<byte[]> before = LdsReader.readAllRecords(terminal,
                LdsFileUtil.sfi(FID_ENTRY), 1);
        // Re-runnable: only append when this exact signed record is not already
        // on the card (the record EF has no delete).
        int index = -1;
        for (int i = 0; i < before.size(); i++) {
            if (java.util.Arrays.equals(record, before.get(i))) {
                index = i + 1;
                break;
            }
        }
        if (index < 0) {
            Lds2RecordWriter.append(terminal, FID_ENTRY, record);
            index = before.size() + 1;
        }
        byte[] readBack = LdsReader.readRecord(terminal, LdsFileUtil.sfi(FID_ENTRY), index);
        Checks.check("structured record read back byte-for-byte",
                java.util.Arrays.equals(record, readBack));

        TravelRecord parsed = (TravelRecord) Lds2Record.parse(
                "EF.EntryRecords (0101)", readBack);
        Checks.check("structured Travel record is well formed", parsed.wellFormed);
        Checks.check("state was encoded", "SWE".equals(parsed.state));
        Checks.check("travel date was encoded", "20260701".equals(parsed.travelDate()));
        Checks.check("inspection authority was encoded",
                "POL".equals(parsed.inspectionAuthority()));
        Checks.check("certificate reference was encoded",
                Integer.valueOf(certificateReference).equals(parsed.certificateReference));

        // The authenticity token covers 73 including its tag and length.
        Checks.check("LDS2-TS signature verifies with EF.Certificates record 1",
                parsed.verify(certificate.getPublicKey()));
    }

}
