package card42.host.emrtd.lds;

import java.security.cert.X509Certificate;
import java.util.List;

import card42.host.emrtd.access.LdsReader;
import card42.host.emrtd.transport.EmrtdTerminal;

/**
 * EF.Certificates reference management for LDS2 writing (Doc 9303-10 §5.1.2):
 * a Travel/Visa record refers to its LDS2-TS signer certificate by the one-byte
 * {@code 5F38} record number, so the writer must either reuse an existing
 * certificate record or append a new one and use its number.
 *
 * <p>{@link #findOrAppend} scans EF.Certificates, compares the X.509 bytes, and
 * returns the existing 1-based record number; otherwise it appends a Table 83
 * record ({@code 5F3A || 72}) and returns the next number.  The caller must
 * already hold PACE and the append authorization (TA), since the store cannot
 * grant access.
 */
public final class Lds2CertificateStore {

    private Lds2CertificateStore() {
    }

    public static int findOrAppend(EmrtdTerminal terminal, X509Certificate certificate,
                                   String country) throws Exception {
        byte[] encoded = certificate.getEncoded();
        List<byte[]> records = LdsReader.readAllRecords(terminal,
                LdsFileUtil.sfi(LdsFileUtil.FID_CERTIFICATES), 1);
        for (int i = 0; i < records.size(); i++) {
            CertificateRecord record = (CertificateRecord) Lds2Record.parse(
                    "EF.Certificates (011A)", records.get(i));
            if (record.certificate != null
                    && java.util.Arrays.equals(record.certificate, encoded)) {
                return i + 1;
            }
        }
        int reference = records.size() + 1;
        if (reference > 254) {
            throw new IllegalStateException("EF.Certificates record limit reached");
        }
        byte[] record = new CertificateRecordBuilder()
                .country(country)
                .serialNumber(certificate.getSerialNumber().toByteArray())
                .certificate(encoded)
                .build();
        Lds2RecordWriter.append(terminal, LdsFileUtil.FID_CERTIFICATES, record);
        return reference;
    }
}
