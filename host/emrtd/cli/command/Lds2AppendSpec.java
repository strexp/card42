package card42.host.emrtd.cli.command;

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.Map;

import card42.host.common.codec.Json;
import card42.host.common.util.Hex;
import card42.host.emrtd.lds.lds2.BiometricsRecordBuilder;
import card42.host.emrtd.lds.lds2.CertificateRecordBuilder;
import card42.host.emrtd.lds.common.LdsFileUtil;
import card42.host.emrtd.lds.lds2.TravelRecordBuilder;
import card42.host.emrtd.lds.lds2.VisaRecordBuilder;
import card42.host.emrtd.pa.CscaKeyStore;
import card42.host.emrtd.pa.Lds2Verifier;
import card42.host.emrtd.tools.EmrtdPersoExporter;

/**
 * Parsed {@code lds2 -append=<json>} request: the target record EF and the
 * signed/encoded record bytes.  The JSON {@code type} selects the model
 * ({@code entry}, {@code exit}, {@code visa}, {@code certificate} or
 * {@code biometrics}).
 *
 * <p>Certificate records are validated against the LDS2 Signer profile and the
 * trusted CSCA store before they are encoded; their {@code 5F3A} country/serial
 * are derived from the certificate.  Travel/Visa/Biometrics records retain the
 * private key so the CLI can prove that it matches the EF.Certificates record
 * named by {@code 5F38} before appending.
 */
final class Lds2AppendSpec {

    private static final byte[] KEY_BINDING_PROBE =
            "card42-lds2-signer-key-binding".getBytes(java.nio.charset.StandardCharsets.US_ASCII);

    final int fid;
    final byte[] record;
    final String type;
    final int certificateReference;
    /** The certificate for a certificate append, else null. */
    final X509Certificate certificate;
    private final PrivateKey signerKey;

    private Lds2AppendSpec(int fid, byte[] record, String type, int certificateReference,
                           X509Certificate certificate, PrivateKey signerKey) {
        this.fid = fid;
        this.record = record;
        this.type = type;
        this.certificateReference = certificateReference;
        this.certificate = certificate;
        this.signerKey = signerKey;
    }

    /**
     * Builds the record.  {@code tsKeyPath} is required for travel/visa/
     * biometrics records and ignored for a certificate record.
     */
    static Lds2AppendSpec parse(Path file, String application, String tsKeyPath,
                                int defaultCertRef, CscaKeyStore trust) throws Exception {
        Map<String, Object> json = Json.parseObject(Files.readString(file));
        String type = Json.string(json, "type");
        if (type == null) {
            throw new IllegalArgumentException("append JSON needs a \"type\" field");
        }
        int certRef = Json.integer(json, "certificateReference", defaultCertRef);

        if ("certificate".equals(type)) {
            String certFile = Json.string(json, "certificateFile");
            if (certFile == null) {
                throw new IllegalArgumentException(
                        "certificate append needs \"certificateFile\"");
            }
            X509Certificate certificate = EmrtdPersoExporter.loadCertificate(certFile);
            Lds2Verifier.CertificateCheck check = Lds2Verifier.checkCertificate(
                    certificate, null, application, trust);
            if (!check.profileValid || (trust != null && !check.trusted)) {
                throw new IllegalArgumentException("LDS2 signer certificate rejected: "
                        + String.join("; ", check.problems));
            }
            String country = check.country;
            String requestedCountry = Json.string(json, "country");
            if (requestedCountry != null && country != null
                    && !requestedCountry.equalsIgnoreCase(country)) {
                throw new IllegalArgumentException("JSON country " + requestedCountry
                        + " does not match the certificate subject C " + country);
            }
            byte[] serial = certificate.getSerialNumber().toByteArray();
            String serialHex = Json.string(json, "serialHex");
            if (serialHex != null && !new BigInteger(Hex.parse(serialHex))
                    .equals(certificate.getSerialNumber())) {
                throw new IllegalArgumentException(
                        "JSON serialHex does not match the certificate serial");
            }
            CertificateRecordBuilder builder = new CertificateRecordBuilder()
                    .country(country)
                    .serialNumber(serial)
                    .certificate(certificate.getEncoded());
            return new Lds2AppendSpec(LdsFileUtil.FID_CERTIFICATES, builder.build(), type,
                    certRef, certificate, null);
        }

        if (tsKeyPath == null) {
            throw new IllegalArgumentException(
                    type + " append needs -ts-key=<PKCS#8 PEM>");
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
                builder.durationOfStay(Hex.parse(duration));
            }
            return new Lds2AppendSpec("entry".equals(type)
                    ? LdsFileUtil.FID_RECORDS : LdsFileUtil.FID_EXIT_RECORDS,
                    builder.build(key), type, certRef, null, key);
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
                builder.numberOfEntries(Hex.parse(entries));
            }
            String duration = Json.string(json, "durationOfStayHex");
            if (duration != null) {
                builder.durationOfStay(Hex.parse(duration));
            }
            String visaType = Json.string(json, "visaTypeHex");
            if (visaType != null) {
                builder.visaType(Hex.parse(visaType));
            }
            String territory = Json.string(json, "territoryHex");
            if (territory != null) {
                builder.territory(Hex.parse(territory));
            }
            String biometrics = Json.string(json, "biometricsReferenceHex");
            if (biometrics != null) {
                builder.biometricsReference(Hex.parse(biometrics));
            }
            return new Lds2AppendSpec(LdsFileUtil.FID_VISA_RECORDS, builder.build(key), type,
                    certRef, null, key);
        }

        if ("biometrics".equals(type)) {
            byte[] biometrics = biometrics(json);
            BiometricsRecordBuilder builder = new BiometricsRecordBuilder()
                    .biometrics(biometrics)
                    .certificateReference(certRef);
            return new Lds2AppendSpec(LdsFileUtil.FID_BIOMETRICS, builder.build(key), type,
                    certRef, null, key);
        }

        throw new IllegalArgumentException("unknown append type: " + type);
    }

    private static byte[] biometrics(Map<String, Object> json) throws Exception {
        String file = Json.string(json, "biometricsFile");
        if (file != null) {
            return Files.readAllBytes(java.nio.file.Paths.get(file));
        }
        String hex = Json.string(json, "biometricsHex");
        if (hex != null) {
            return Hex.parse(hex);
        }
        throw new IllegalArgumentException(
                "biometrics append needs \"biometricsFile\" or \"biometricsHex\"");
    }

    /** True when the private key used to sign matches the EF.Certificates key. */
    boolean keyMatches(X509Certificate certificate) {
        if (signerKey == null || certificate == null) {
            return false;
        }
        try {
            boolean ec = "EC".equalsIgnoreCase(signerKey.getAlgorithm());
            Signature signer = Signature.getInstance(ec ? "SHA256withECDSA" : "SHA256withRSA");
            signer.initSign(signerKey);
            signer.update(KEY_BINDING_PROBE);
            byte[] signature = signer.sign();
            Signature verifier = Signature.getInstance(ec ? "SHA256withECDSA" : "SHA256withRSA");
            verifier.initVerify(certificate.getPublicKey());
            verifier.update(KEY_BINDING_PROBE);
            return verifier.verify(signature);
        } catch (Exception e) {
            return false;
        }
    }
}
