package card42.host.emrtd.cli.command;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.util.Map;

import card42.host.common.codec.Json;
import card42.host.emrtd.lds.CertificateRecordBuilder;
import card42.host.emrtd.lds.LdsFileUtil;
import card42.host.emrtd.lds.TravelRecordBuilder;
import card42.host.emrtd.lds.VisaRecordBuilder;
import card42.host.emrtd.perso.EmrtdPersoExporter;

/**
 * Parsed {@code lds2 -append=<json>} request: the target record EF and the
 * signed/encoded record bytes.  The JSON {@code type} selects the model
 * ({@code entry}, {@code exit}, {@code visa}, {@code certificate}); Travel and
 * Visa records are signed by the {@code -ts-key}, a certificate record is
 * encoded unsigned.
 */
final class Lds2AppendSpec {

    final int fid;
    final byte[] record;
    final String type;

    private Lds2AppendSpec(int fid, byte[] record, String type) {
        this.fid = fid;
        this.record = record;
        this.type = type;
    }

    /**
     * Builds the record.  {@code tsKeyPath} is required for travel/visa records
     * and ignored for a certificate record (which carries an X.509 certificate
     * but no LDS2-TS signature).
     */
    static Lds2AppendSpec parse(Path file, String tsKeyPath, int defaultCertRef)
            throws Exception {
        Map<String, Object> json = Json.parseObject(Files.readString(file));
        String type = Json.string(json, "type");
        if (type == null) {
            throw new IllegalArgumentException("append JSON needs a \"type\" field");
        }
        int certRef = Json.integer(json, "certificateReference", defaultCertRef);

        if ("certificate".equals(type)) {
            String country = Json.string(json, "country");
            String serialHex = Json.string(json, "serialHex");
            String certFile = Json.string(json, "certificateFile");
            if (certFile == null) {
                throw new IllegalArgumentException(
                        "certificate append needs \"certificateFile\"");
            }
            java.security.cert.X509Certificate certificate =
                    EmrtdPersoExporter.loadCertificate(certFile);
            CertificateRecordBuilder builder = new CertificateRecordBuilder()
                    .country(country == null ? "US" : country)
                    .serialNumber(serialHex == null
                            ? certificate.getSerialNumber().toByteArray()
                            : card42.host.common.util.Hex.parse(serialHex))
                    .certificate(certificate.getEncoded());
            return new Lds2AppendSpec(LdsFileUtil.FID_CERTIFICATES, builder.build(), type);
        }

        if (tsKeyPath == null) {
            throw new IllegalArgumentException(
                    "travel/visa append needs -ts-key=<PKCS#8 PEM>");
        }
        PrivateKey key = EmrtdPersoExporter.loadPrivateKey(tsKeyPath);

        if ("entry".equals(type) || "exit".equals(type)) {
            TravelRecordBuilder builder = new TravelRecordBuilder()
                    .state(Json.string(json, "state"))
                    .travelDate(Json.string(json, "travelDate"))
                    .inspectionAuthority(Json.string(json, "inspectionAuthority"))
                    .inspectionLocation(Json.string(json, "inspectionLocation"))
                    .inspectorReference(Json.string(json, "inspectorReference"))
                    .visaApprovals(Json.string(json, "visaApprovals"))
                    .inspectionResult(Json.string(json, "inspectionResult"))
                    .modeOfTravel(Json.string(json, "modeOfTravel"))
                    .conditions(Json.string(json, "conditions"))
                    .certificateReference(certRef);
            String duration = Json.string(json, "durationOfStayHex");
            if (duration != null) {
                builder.durationOfStay(card42.host.common.util.Hex.parse(duration));
            }
            return new Lds2AppendSpec("entry".equals(type)
                    ? LdsFileUtil.FID_RECORDS : LdsFileUtil.FID_EXIT_RECORDS,
                    builder.build(key), type);
        }

        if ("visa".equals(type)) {
            VisaRecordBuilder builder = new VisaRecordBuilder()
                    .issuingState(Json.string(json, "issuingState"))
                    .documentType(Json.string(json, "documentType"))
                    .machineReadableVisaA(Json.string(json, "machineReadableVisaA"))
                    .machineReadableVisaB(Json.string(json, "machineReadableVisaB"))
                    .passportNumber(Json.string(json, "passportNumber"))
                    .placeOfIssue(Json.string(json, "placeOfIssue"))
                    .effectiveDate(Json.string(json, "effectiveDate"))
                    .expirationDate(Json.string(json, "expirationDate"))
                    .documentNumber(Json.string(json, "documentNumber"))
                    .additionalInfo(Json.string(json, "additionalInfo"))
                    .name(Json.string(json, "name"))
                    .surname(Json.string(json, "surname"))
                    .givenNames(Json.string(json, "givenNames"))
                    .sex(Json.string(json, "sex"))
                    .dateOfBirth(Json.string(json, "dateOfBirth"))
                    .nationality(Json.string(json, "nationality"))
                    .mrz(Json.string(json, "mrz"))
                    .certificateReference(certRef);
            String entries = Json.string(json, "numberOfEntriesHex");
            if (entries != null) {
                builder.numberOfEntries(card42.host.common.util.Hex.parse(entries));
            }
            String duration = Json.string(json, "durationOfStayHex");
            if (duration != null) {
                builder.durationOfStay(card42.host.common.util.Hex.parse(duration));
            }
            String visaType = Json.string(json, "visaTypeHex");
            if (visaType != null) {
                builder.visaType(card42.host.common.util.Hex.parse(visaType));
            }
            String territory = Json.string(json, "territoryHex");
            if (territory != null) {
                builder.territory(card42.host.common.util.Hex.parse(territory));
            }
            String biometrics = Json.string(json, "biometricsReferenceHex");
            if (biometrics != null) {
                builder.biometricsReference(card42.host.common.util.Hex.parse(biometrics));
            }
            return new Lds2AppendSpec(LdsFileUtil.FID_VISA_RECORDS, builder.build(key), type);
        }

        throw new IllegalArgumentException("unknown append type: " + type);
    }
}
