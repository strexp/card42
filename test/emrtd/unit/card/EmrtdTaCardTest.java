package card42.test;

import java.io.ByteArrayOutputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.security.SecureRandom;
import java.util.Arrays;

import card42.emrtd.EmrtdApplet;
import card42.emrtd.EmrtdInstallParameters;
import card42.emrtd.EmrtdTags;
import card42.emrtd.ExternalAuthenticate;
import card42.emrtd.GetChallenge;
import card42.emrtd.Lds2Perso;
import card42.emrtd.Lds2Record;
import card42.emrtd.LdsPerso;
import card42.emrtd.Mse;
import card42.emrtd.PsoVerifyCertificate;
import card42.emrtd.TaContext;
import card42.host.common.crypto.Ecdsa;
import card42.host.emrtd.ta.CvCertificate;
import card42.host.emrtd.ta.CvCertificateCodec;
import card42.host.emrtd.ta.TaChain;

/**
 * Card-side Terminal Authentication: P3 certificate-chain verification and P4
 * the EXTERNAL AUTHENTICATE step, driven on a real LDS1 {@link EmrtdApplet}
 * against a host-issued CV certificate chain.  The CVCA trust point is set
 * through the FF07 personalization DGI and the PACE/CA key hashes are injected
 * directly (the PACE and Chip Authentication protocols are covered by their own
 * simulator suites).  ECDSA-SHA-256 plain verification runs on the JCE-backed
 * {@code Signature} stub.
 *
 * <p>Spec: ICAO Doc 9303-11 §7.1.5, BSI TR-03110-3 A.7.
 */
final class EmrtdTaCardTest {

    private EmrtdTaCardTest() {
    }

    static void run() throws Exception {
        System.out.println("EmrtdTaCard");
        verifyChain();
        rejectsTamperedCertificate();
        rejectsUnknownReference();
        rejectsWithoutTrustPoint();
        fullTerminalAuthentication();
        rejectsBadTerminalSignature();
        rejectsExternalAuthenticateWithoutMseAt();
        travelAuthorization();
    }

    private static void verifyChain() throws Exception {
        EmrtdApplet applet = lds1Applet();
        TaChain.Chain chain = TaChain.create(new SecureRandom());
        setTrustPoint(applet, chain);

        for (byte[] encoded : chain.toSend()) {
            CvCertificate certificate = CvCertificateCodec.parse(encoded);
            byte[] dst = mseSetDst(certificate);
            byte[] pso = pso(certificate);
            Asserts.noThrow(() -> Mse.process(applet, (byte) 0x81, (byte) 0xB6,
                            dst, (short) 0, (short) dst.length),
                    "MSE:Set DST accepts " + certificate.certificateHolderReference());
            Asserts.noThrow(() -> PsoVerifyCertificate.process(applet, pso,
                            (short) 0, (short) pso.length),
                    "PSO:Verify Certificate imports " + certificate.certificateHolderReference());
        }
    }

    private static void rejectsTamperedCertificate() throws Exception {
        EmrtdApplet applet = lds1Applet();
        TaChain.Chain chain = TaChain.create(new SecureRandom());
        setTrustPoint(applet, chain);

        byte[] tampered = chain.dv.encoded().clone();
        tampered[tampered.length - 1] ^= 0x01;
        CvCertificate certificate = CvCertificateCodec.parse(tampered);
        byte[] dst = mseSetDst(certificate);
        byte[] pso = pso(certificate);
        Asserts.sw((short) 0x6A80, () -> {
            Mse.process(applet, (byte) 0x81, (byte) 0xB6, dst, (short) 0, (short) dst.length);
            PsoVerifyCertificate.process(applet, pso, (short) 0, (short) pso.length);
        }, "a tampered CV certificate -> 6A80");
    }

    private static void rejectsUnknownReference() throws Exception {
        EmrtdApplet applet = lds1Applet();
        TaChain.Chain chain = TaChain.create(new SecureRandom());
        setTrustPoint(applet, chain);

        // MSE:Set DST accepts an unavailable reference; PSO rejects it with 6A88
        // (ICAO Doc 9303-11 §7.1.5.1 note).
        byte[] unknown = "ZZUNKNOWN0000000".getBytes(java.nio.charset.StandardCharsets.ISO_8859_1);
        byte[] certificate = chain.dv.encoded();
        byte[] pso = pso(CvCertificateCodec.parse(certificate));
        Asserts.sw((short) 0x6A88, () -> {
            Mse.process(applet, (byte) 0x81, (byte) 0xB6,
                    mseSetDstRef(unknown), (short) 0, (short) mseSetDstRef(unknown).length);
            PsoVerifyCertificate.process(applet, pso, (short) 0, (short) pso.length);
        }, "PSO:Verify Certificate with an unknown reference -> 6A88");
    }

    private static void rejectsWithoutTrustPoint() throws Exception {
        EmrtdApplet applet = lds1Applet();
        byte[] reference = "UTREF000000000000".getBytes(java.nio.charset.StandardCharsets.ISO_8859_1);
        Asserts.sw((short) 0x6985, () -> Mse.process(applet, (byte) 0x81, (byte) 0xB6,
                        mseSetDstRef(reference), (short) 0, (short) mseSetDstRef(reference).length),
                "MSE:Set DST without a trust point -> 6985");
    }

    private static void fullTerminalAuthentication() throws Exception {
        EmrtdApplet applet = lds1Applet();
        TaChain.Chain chain = TaChain.create(new SecureRandom());
        setTrustPoint(applet, chain);
        importChain(applet, chain);

        byte[] idIc = filled(32, (byte) 0x11);
        byte[] caKeyHash = filled(32, (byte) 0x22);
        TaContext ta = taOf(applet);
        ta.notePiccEphemeral(uncompressed(idIc), (short) 0, (short) 65);
        ta.noteTerminalEphemeral(uncompressed(caKeyHash), (short) 0, (short) 65);

        byte[] at = doTag(0x83, chain.terminal.certificateHolderReference().encode());
        Asserts.noThrow(() -> Mse.process(applet, (byte) 0x81, (byte) 0xA4,
                        at, (short) 0, (short) at.length),
                "MSE:Set AT selects the terminal key");
        Asserts.noThrow(() -> GetChallenge.process(applet), "GET CHALLENGE returns rIC");

        byte[] challenge = (byte[]) field(TaContext.class, "challenge").get(ta);
        byte[] input = concat(idIc, challenge, caKeyHash);
        byte[] signature = Ecdsa.sign(input, chain.terminalPrivateScalar, new SecureRandom());
        Asserts.noThrow(() -> ExternalAuthenticate.process(applet, signature,
                        (short) 0, (short) signature.length),
                "EXTERNAL AUTHENTICATE accepts the terminal signature");
        Asserts.check((Boolean) field(TaContext.class, "taDone").get(ta),
                "terminal authentication completed");

        // A second Terminal Authentication in the same session is refused.
        byte[] at2 = doTag(0x83, chain.terminal.certificateHolderReference().encode());
        Asserts.sw((short) 0x6982, () -> Mse.process(applet, (byte) 0x81, (byte) 0xA4,
                        at2, (short) 0, (short) at2.length),
                "a second MSE:Set AT -> 6982");
    }

    private static void rejectsBadTerminalSignature() throws Exception {
        EmrtdApplet applet = lds1Applet();
        TaChain.Chain chain = TaChain.create(new SecureRandom());
        setTrustPoint(applet, chain);
        importChain(applet, chain);

        byte[] idIc = filled(32, (byte) 0x11);
        byte[] caKeyHash = filled(32, (byte) 0x22);
        TaContext ta = taOf(applet);
        ta.notePiccEphemeral(uncompressed(idIc), (short) 0, (short) 65);
        ta.noteTerminalEphemeral(uncompressed(caKeyHash), (short) 0, (short) 65);

        byte[] at = doTag(0x83, chain.terminal.certificateHolderReference().encode());
        Mse.process(applet, (byte) 0x81, (byte) 0xA4, at, (short) 0, (short) at.length);
        GetChallenge.process(applet);
        byte[] challenge = (byte[]) field(TaContext.class, "challenge").get(ta);
        byte[] signature = Ecdsa.sign(concat(idIc, challenge, caKeyHash),
                chain.terminalPrivateScalar, new SecureRandom());
        signature[0] ^= 0x01;
        Asserts.sw((short) 0x6300, () -> ExternalAuthenticate.process(applet, signature,
                        (short) 0, (short) signature.length),
                "a bad terminal signature -> 6300");
    }

    private static void rejectsExternalAuthenticateWithoutMseAt() throws Exception {
        EmrtdApplet applet = lds1Applet();
        setTrustPoint(applet, TaChain.create(new SecureRandom()));
        byte[] signature = new byte[64];
        // Without MSE:Set AT the command falls through to the BAC path, which
        // rejects a 64-byte body with 6700 (wrong length).
        Asserts.sw((short) 0x6700, () -> ExternalAuthenticate.process(applet, signature,
                        (short) 0, (short) signature.length),
                "EXTERNAL AUTHENTICATE without MSE:Set AT -> BAC path 6700");
    }

    // --- helpers -------------------------------------------------------------

    /**
     * LDS2 authorization gating (Doc 9303-10 §5.4): with the Travel
     * authorization bit the record EF is reachable; without it the read is
     * refused with 6982 even after a successful Terminal Authentication.
     */
    private static void travelAuthorization() throws Exception {
        TaChain.Chain chain = TaChain.create(new SecureRandom());

        EmrtdApplet granted = travelApplet();
        setTravelTrustPoint(granted, chain, (byte) 0x0F);
        authenticateTerminal(granted, chain);
        Asserts.sw((short) 0x6A83,
                () -> Lds2Record.readRecord(granted, (byte) 1, (byte) 0x0C, (short) 0),
                "granted LDS2 read reaches the record EF (no records -> 6A83)");

        EmrtdApplet denied = travelApplet();
        setTravelTrustPoint(denied, chain, (byte) 0x00);
        authenticateTerminal(denied, chain);
        Asserts.sw((short) 0x6982,
                () -> Lds2Record.readRecord(denied, (byte) 1, (byte) 0x0C, (short) 0),
                "LDS2 read without the Travel authorization -> 6982");
    }

    private static void authenticateTerminal(EmrtdApplet applet, TaChain.Chain chain)
            throws Exception {
        importChain(applet, chain);
        byte[] idIc = filled(32, (byte) 0x11);
        byte[] caKeyHash = filled(32, (byte) 0x22);
        TaContext ta = taOf(applet);
        ta.notePiccEphemeral(uncompressed(idIc), (short) 0, (short) 65);
        ta.noteTerminalEphemeral(uncompressed(caKeyHash), (short) 0, (short) 65);
        byte[] at = doTag(0x83, chain.terminal.certificateHolderReference().encode());
        Mse.process(applet, (byte) 0x81, (byte) 0xA4, at, (short) 0, (short) at.length);
        GetChallenge.process(applet);
        byte[] challenge = (byte[]) field(TaContext.class, "challenge").get(ta);
        byte[] signature = Ecdsa.sign(concat(idIc, challenge, caKeyHash),
                chain.terminalPrivateScalar, new SecureRandom());
        ExternalAuthenticate.process(applet, signature, (short) 0, (short) signature.length);
    }

    /** Personalizes the LDS2 trust point (FF07) with the given Travel authorization. */
    private static void setTravelTrustPoint(EmrtdApplet applet, TaChain.Chain chain, byte travel)
            throws Exception {
        byte[] w = chain.cvca.ecPublicKey();
        byte[] car = chain.cvca.certificateHolderReference().encode();
        ByteArrayOutputStream value = new ByteArrayOutputStream();
        value.write(w, 0, w.length);
        value.write(car.length);
        value.write(car, 0, car.length);
        value.write(0x03); // ePassport CHAT
        value.write(travel);
        value.write(0x0F); // Visa
        value.write(0x0F); // Biometrics
        byte[] dgi = new byte[value.size() + 3];
        dgi[0] = (byte) 0xFF;
        dgi[1] = 0x07;
        dgi[2] = (byte) value.size();
        System.arraycopy(value.toByteArray(), 0, dgi, 3, value.size());

        Field field = EmrtdApplet.class.getDeclaredField("lds2Perso");
        field.setAccessible(true);
        Lds2Perso perso = (Lds2Perso) field.get(applet);
        perso.apply(dgi, (short) 0, (short) dgi.length);
    }

    private static EmrtdApplet travelApplet() throws Exception {
        Constructor<EmrtdApplet> ctor = EmrtdApplet.class.getDeclaredConstructor(
                byte.class, byte[].class, short.class);
        ctor.setAccessible(true);
        EmrtdApplet applet = ctor.newInstance(EmrtdInstallParameters.ROLE_LDS2_TRAVEL,
                EmrtdTags.DF_NAME_TRAVEL, (short) EmrtdTags.DF_NAME_TRAVEL.length);
        field(EmrtdApplet.class, "paceDone").setBoolean(applet, true);
        return applet;
    }

    private static void importChain(EmrtdApplet applet, TaChain.Chain chain) {
        for (byte[] encoded : chain.toSend()) {
            CvCertificate certificate = CvCertificateCodec.parse(encoded);
            byte[] dst = mseSetDst(certificate);
            byte[] pso = pso(certificate);
            Mse.process(applet, (byte) 0x81, (byte) 0xB6, dst, (short) 0, (short) dst.length);
            PsoVerifyCertificate.process(applet, pso, (short) 0, (short) pso.length);
        }
    }

    /** Writes the CVCA trust point DGI (FF07 = W(65) || refLen(1) || CAR). */
    private static void setTrustPoint(EmrtdApplet applet, TaChain.Chain chain) throws Exception {
        byte[] cvcaW = chain.cvca.ecPublicKey();
        byte[] car = chain.cvca.certificateHolderReference().encode();
        ByteArrayOutputStream value = new ByteArrayOutputStream();
        value.write(cvcaW, 0, cvcaW.length);
        value.write(car.length);
        value.write(car, 0, car.length);

        // A minimal valid LDS1 sequence: BAC seed + DG1 + the trust point, so
        // the perso completion check (seed and DG1 required) passes.
        ByteArrayOutputStream sequence = new ByteArrayOutputStream();
        writeDgi(sequence, EmrtdTags.DGI_BAC_SEED, new byte[16]);
        writeDgi(sequence, EmrtdTags.FID_DG1, new byte[] { 0x61, 0x03, 0x5F, 0x1F, 0x00 });
        writeDgi(sequence, EmrtdTags.DGI_TA_TRUST_POINT, value.toByteArray());
        byte[] bytes = sequence.toByteArray();

        Field field = EmrtdApplet.class.getDeclaredField("perso");
        field.setAccessible(true);
        LdsPerso perso = (LdsPerso) field.get(applet);
        perso.apply(bytes, (short) 0, (short) bytes.length);
    }

    private static TaContext taOf(EmrtdApplet applet) throws Exception {
        return (TaContext) field(EmrtdApplet.class, "ta").get(applet);
    }

    private static Field field(Class<?> type, String name) throws Exception {
        Field field = type.getDeclaredField(name);
        field.setAccessible(true);
        return field;
    }

    private static byte[] mseSetDst(CvCertificate certificate) {
        return mseSetDstRef(certificate.certificationAuthorityReference().encode());
    }

    private static byte[] mseSetDstRef(byte[] reference) {
        return doTag(0x83, reference);
    }

    private static byte[] pso(CvCertificate certificate) {
        return concat(certificate.body(), CvCertificateCodec.signatureTlv(certificate.signature()));
    }

    private static byte[] uncompressed(byte[] x) {
        byte[] out = new byte[65];
        out[0] = 0x04;
        System.arraycopy(x, 0, out, 1, x.length);
        return out;
    }

    private static byte[] filled(int length, byte value) {
        byte[] out = new byte[length];
        Arrays.fill(out, value);
        return out;
    }

    private static byte[] doTag(int tag, byte[] value) {
        byte[] out = new byte[2 + value.length];
        out[0] = (byte) tag;
        out[1] = (byte) value.length;
        System.arraycopy(value, 0, out, 2, value.length);
        return out;
    }

    private static void writeDgi(ByteArrayOutputStream out, short dgi, byte[] value) {
        out.write((dgi >> 8) & 0xFF);
        out.write(dgi & 0xFF);
        out.write(value.length);
        out.write(value, 0, value.length);
    }

    private static byte[] concat(byte[]... parts) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] part : parts) {
            out.write(part, 0, part.length);
        }
        return out.toByteArray();
    }

    private static EmrtdApplet lds1Applet() throws Exception {
        Constructor<EmrtdApplet> ctor = EmrtdApplet.class.getDeclaredConstructor(
                byte.class, byte[].class, short.class);
        ctor.setAccessible(true);
        return ctor.newInstance(EmrtdInstallParameters.ROLE_LDS1,
                EmrtdTags.DF_NAME_LDS1, (short) EmrtdTags.DF_NAME_LDS1.length);
    }
}
