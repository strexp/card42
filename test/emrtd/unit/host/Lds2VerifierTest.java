package card42.test;

import java.io.File;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import card42.host.emrtd.lds.CertificateRecord;
import card42.host.emrtd.lds.CertificateRecordBuilder;
import card42.host.emrtd.lds.CmsSignedData;
import card42.host.emrtd.lds.Lds2Record;
import card42.host.emrtd.lds.Lds2Signature;
import card42.host.emrtd.lds.TravelRecord;
import card42.host.emrtd.lds.TravelRecordBuilder;
import card42.host.emrtd.pa.CscaKeyStore;
import card42.host.emrtd.pa.Lds2Verifier;
import card42.host.emrtd.pa.PassiveAuthentication;
import card42.host.emrtd.perso.EmrtdPersoExporter;
import card42.host.emrtd.perso.SodBuilder;

/** LDS2 Signer profile, 5F38 resolution and record-signature verification. */
final class Lds2VerifierTest {

    private Lds2VerifierTest() {
    }

    static void run() throws Exception {
        System.out.println("Lds2Verifier");
        X509Certificate signer = EmrtdPersoExporter.loadCertificate("perso/emrtd/lds2.crt");
        X509Certificate dsc = EmrtdPersoExporter.loadCertificate("perso/emrtd/dsc.crt");
        PrivateKey key = EmrtdPersoExporter.loadPrivateKey("perso/emrtd/lds2.key");
        CscaKeyStore trust = CscaKeyStore.fromFiles(new File("perso/emrtd/csca.crt"));

        byte[] certRecordBytes = new CertificateRecordBuilder()
                .country("US")
                .serialNumber(signer.getSerialNumber().toByteArray())
                .certificate(signer.getEncoded())
                .build();
        CertificateRecord certRecord = (CertificateRecord) Lds2Record.parse(
                "EF.Certificates (011A)", certRecordBytes);
        Lds2Verifier.CertificateCheck good = Lds2Verifier.checkCertificate(
                signer, certRecord, Lds2Verifier.APP_TRAVEL, trust);
        Asserts.check(good.profileValid && good.trusted && good.valid(),
                "LDS2 Signer profile and CSCA chain validate");

        byte[] travel = new TravelRecordBuilder()
                .state("USA").travelDate("20260101").inspectionAuthority("CBP")
                .inspectionLocation("SFO").inspectorReference("SFO00001")
                .certificateReference(1).build(key);
        Lds2Verifier.Verification result = Lds2Verifier.verifyRecord(
                travel, "EF.EntryRecords (0101)", signer, certRecord,
                Lds2Verifier.APP_TRAVEL, trust);
        Asserts.check(result.valid(), "LDS2 record signature + profile + trust validate");

        TravelRecord record = (TravelRecord) Lds2Record.parse(
                "EF.EntryRecords (0101)", travel);
        byte[] tampered = record.signedInfoTlv();
        tampered[tampered.length - 1] ^= 0x01;
        Asserts.check(!Lds2Signature.verify(signer.getPublicKey(), tampered,
                        record.signature),
                "tampered signed information is rejected");
        Asserts.check(!record.verify(dsc.getPublicKey()),
                "a different key does not verify the record");

        Lds2Verifier.CertificateCheck rejected = Lds2Verifier.checkCertificate(
                dsc, certRecord, Lds2Verifier.APP_TRAVEL, trust);
        Asserts.check(!rejected.profileValid,
                "a DSC (no LDS2 EKU / extra extensions) is not an LDS2 Signer");

        byte[] cms = SodBuilder.buildCms("2.23.136.1.1.1",
                new byte[] { 1, 2, 3, 4 }, key, signer);
        X509Certificate verified = PassiveAuthentication.verifyCms(
                CmsSignedData.parse(cms), trust);
        Asserts.check(verified.getSerialNumber().equals(signer.getSerialNumber()),
                "EC (ECDSA-SHA-256) CMS SignedData verifies through DscVerifier");
    }
}
