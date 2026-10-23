package card42.host.emrtd.pa;

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.smartcardio.ResponseAPDU;

import card42.host.emrtd.access.LdsReader;
import card42.host.emrtd.lds.common.LdsFileUtil;
import card42.host.emrtd.lds.lds2.CertificateRecord;
import card42.host.emrtd.lds.lds2.Lds2Record;
import card42.host.emrtd.transport.EmrtdTerminal;

/** Record-level LDS2 signature verification and EF.Certificates caching. */
final class Lds2RecordVerifier {

    private Lds2RecordVerifier() {
    }

    static Map<String, List<Lds2Verifier.Verification>> verifyGroups(EmrtdTerminal terminal,
                                                               Map<String, List<byte[]>> groups,
                                                               String application,
                                                               CscaKeyStore trust)
            throws Exception {
        Map<String, List<Lds2Verifier.Verification>> out =
                new LinkedHashMap<String, List<Lds2Verifier.Verification>>();
        if (groups == null) {
            return out;
        }
        Map<Integer, CertificateRecord> records = new LinkedHashMap<Integer, CertificateRecord>();
        Map<Integer, X509Certificate> certificates = new LinkedHashMap<Integer, X509Certificate>();
        List<byte[]> certificateBytes = LdsReader.readAllRecords(terminal,
                LdsFileUtil.sfi(LdsFileUtil.FID_CERTIFICATES), 1);
        for (int i = 0; i < certificateBytes.size(); i++) {
            CertificateRecord record = (CertificateRecord) Lds2Record.parse(
                    Lds2Record.Kind.CERTIFICATE, certificateBytes.get(i));
            records.put(i + 1, record);
            try {
                certificates.put(i + 1, Lds2Verifier.x509(record.certificate));
            } catch (Exception e) {
                certificates.put(i + 1, null);
            }
        }
        for (Map.Entry<String, List<byte[]>> group : groups.entrySet()) {
            List<Lds2Verifier.Verification> results = new ArrayList<Lds2Verifier.Verification>();
            for (byte[] raw : group.getValue()) {
                Lds2Record record = Lds2Record.parse(
                        Lds2Record.Kind.forLabel(group.getKey()), raw);
                if (record.kind() == Lds2Record.Kind.CERTIFICATE) {
                    CertificateRecord certificateRecord = (CertificateRecord) record;
                    Lds2Verifier.CertificateCheck check = Lds2Verifier.checkCertificate(
                            Lds2Verifier.x509(certificateRecord.certificate),
                            certificateRecord, application, trust);
                    results.add(new Lds2Verifier.Verification(group.getKey(), check.profileValid, check,
                            check.problems));
                } else {
                    results.add(verifyRecord(record, group.getKey(), records, certificates,
                            application, trust));
                }
            }
            out.put(group.getKey(), results);
        }
        return out;
    }

    private static Lds2Verifier.Verification verifyRecord(Lds2Record record, String label,
                                             Map<Integer, CertificateRecord> records,
                                             Map<Integer, X509Certificate> certificates,
                                             String application, CscaKeyStore trust) {
        List<String> problems = new ArrayList<String>();
        Integer reference = certificateReference(record);
        Lds2Verifier.CertificateCheck check = null;
        if (reference == null) {
            problems.add("record has no 5F38 certificate reference");
        } else {
            CertificateRecord certificateRecord = records.get(reference);
            X509Certificate certificate = certificates.get(reference);
            if (certificateRecord == null) {
                problems.add("5F38 references missing EF.Certificates record " + reference);
            } else if (certificate == null) {
                problems.add("EF.Certificates record " + reference + " has no X.509 certificate");
            } else {
                check = Lds2Verifier.checkCertificate(certificate, certificateRecord, application, trust);
            }
        }
        boolean signatureValid = false;
        if (check != null && check.certificate != null) {
            signatureValid = signature(record, check.certificate.getPublicKey());
            if (!signatureValid) {
                problems.add("5F37 signature does not verify");
            }
        }
        return new Lds2Verifier.Verification(label, signatureValid, check, problems);
    }

    static Lds2Verifier.Verification verifyRecord(byte[] raw, String label, X509Certificate signer,
                                            CertificateRecord signerRecord, String application,
                                            CscaKeyStore trust) {
        Lds2Record record = Lds2Record.parse(Lds2Record.Kind.forLabel(label), raw);
        Lds2Verifier.CertificateCheck check = Lds2Verifier.checkCertificate(signer, signerRecord, application, trust);
        boolean signatureValid = signer != null && record.verify(signer.getPublicKey());
        List<String> problems = new ArrayList<String>(check.problems);
        if (!signatureValid) {
            problems.add("5F37 signature does not verify");
        }
        return new Lds2Verifier.Verification(label, signatureValid, check, problems);
    }

    public static Integer certificateReference(Lds2Record record) {
        return record.certificateReference();
    }

    private static boolean signature(Lds2Record record, PublicKey key) {
        return record.verify(key);
    }
}
