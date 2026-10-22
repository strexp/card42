package card42.test;

import java.io.File;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;

import card42.host.emrtd.lds.CertificateRecord;
import card42.host.emrtd.lds.Lds2Record;
import card42.host.emrtd.lds.TravelRecord;
import card42.host.emrtd.lds.VisaRecord;
import card42.host.emrtd.perso.EmrtdPersoExporter;
import card42.host.emrtd.perso.LdsScript;

/**
 * Checks the checked-in {@code perso/emrtd/sample-*.perso} LDS2 records are the
 * spec-conformant Table 86/90/83 structures, not the old {@code 5F44 || 5F37}
 * demo blobs, and that every 5F37 token verifies with the EF.Certificates DSC.
 */
final class Lds2SampleTest {

    private Lds2SampleTest() {
    }

    static void run() throws Exception {
        System.out.println("Lds2Sample");
        LdsScript script = LdsScript.parse(new File("perso/emrtd/sample-sha256.perso"));
        X509Certificate dsc = EmrtdPersoExporter.loadCertificate("perso/emrtd/dsc.crt");

        int entries = 0;
        int exits = 0;
        int visas = 0;
        int certificates = 0;
        for (LdsScript.Entry entry : script.entries) {
            for (Map.Entry<Integer, List<byte[]>> group : entry.records.entrySet()) {
                int fid = group.getKey();
                String label = "EF." + Integer.toHexString(fid).toUpperCase();
                for (byte[] bytes : group.getValue()) {
                    Lds2Record record = Lds2Record.parse(label, bytes);
                    if (fid == 0x011A) {
                        CertificateRecord cert = (CertificateRecord) record;
                        Asserts.check(cert.wellFormed,
                                label + " certificate record uses 5F3A || 72");
                        Asserts.check(java.util.Arrays.equals(
                                        cert.certificate, dsc.getEncoded()),
                                label + " carries the DSC certificate");
                        certificates++;
                    } else if (fid == 0x0103) {
                        VisaRecord visa = (VisaRecord) record;
                        Asserts.check(visa.wellFormed, label + " visa record is Table 90");
                        Asserts.check(visa.verify(dsc.getPublicKey()),
                                label + " visa signature verifies");
                        visas++;
                    } else {
                        TravelRecord travel = (TravelRecord) record;
                        Asserts.check(travel.wellFormed,
                                label + " travel record is Table 86");
                        Asserts.check(travel.verify(dsc.getPublicKey()),
                                label + " travel signature verifies");
                        if (fid == 0x0101) {
                            entries++;
                        } else if (fid == 0x0102) {
                            exits++;
                        }
                    }
                }
            }
        }
        Asserts.eq(3, entries, "sample has three conformant Entry records");
        Asserts.eq(1, exits, "sample has one conformant Exit record");
        Asserts.eq(2, visas, "sample has two conformant Visa records");
        Asserts.eq(3, certificates, "each LDS2 app has one wrapped certificate record");
    }
}
